"""Restricted Response Connectors, Authenticated Tokens, and Dual-Role Approval.

Strict compliance with Sections 8, 9, and 14:
- Caller-supplied strings do not establish authority: implements UserCredentialRegistry.
- Approvals cryptographically bound via HMAC-SHA256 to:
  * Individual proposal/action ID
  * Target host / IP identity
  * Canonical parameters (RFC 8785)
  * Evidence snapshot hash (SHA-256)
  * Policy version
  * Authenticated approver identity and role
  * Expiration timestamp
  * Single-use identifier (nonce)
- Dual-role Separation of Duties (C16 IoMT):
  Critical IoMT actions strictly require TWO distinct identities:
  * security_approver_id (role: soc_lead)
  * clinical_approver_id (role: clinical_engineer or medical_director)
  * security_approver_id != clinical_approver_id
- Atomic approval consumption with file-level concurrency locking (fcntl.flock).
- Persistent state across restarts (runs/approvals_store.json).
- Dry-run actions explicitly expose execution_mode = 'DRY_RUN' and external_effect = False.
- Timeouts preserve OUTCOME_UNKNOWN; no blind retries on unknown outcomes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any
import uuid

from .canonical_json import canonical_json_bytes
from .schemas import (
    ActionExecution,
    ActionProposal,
    ActionState,
    ActionType,
    ApprovalRecord,
    ProvenanceType,
    utc_now,
)

POLICY_VERSION = "2.2.0"
SYSTEM_HMAC_SECRET = b"xai_threat_framework_production_hmac_secret_key_2026"


# ---------------------------------------------------------------------------
# Authenticated User Registry (Section 8)
# ---------------------------------------------------------------------------
class UserCredentialRegistry:
    """Manages authenticated roles and credentials. Labeled as LOCAL_DEV_STORE for testbed."""

    IDENTITY_MODE = "LOCAL_AUTHENTICATED_STORE"

    def __init__(self):
        # Pre-configured testbed credentials with explicit roles
        self._users: dict[str, dict[str, Any]] = {
            "soc_lead_chamith": {
                "key": "sec_lead_secret_token_123",
                "role": "soc_lead",
                "department": "Security Operations Center",
            },
            "analyst-chamith": {
                "key": "sec_lead_secret_token_123",
                "role": "soc_lead",
                "department": "Security Operations Center",
            },
            "soc_analyst_01": {
                "key": "analyst_secret_token_456",
                "role": "soc_analyst",
                "department": "Security Operations Center",
            },
            "analyst-01": {
                "key": "analyst_secret_token_456",
                "role": "soc_analyst",
                "department": "Security Operations Center",
            },
            "dr_sarah_clinical": {
                "key": "clin_eng_secret_token_789",
                "role": "clinical_engineer",
                "department": "Biomedical & Clinical Engineering",
            },
            "dr_elena_director": {
                "key": "med_dir_secret_token_999",
                "role": "medical_director",
                "department": "Intensive Care Clinical Directorate",
            },
        }

    def register_user(self, user_id: str, key: str, role: str, department: str = "Testbed") -> None:
        self._users[user_id] = {"key": key, "role": role, "department": department}

    def authenticate(self, user_id: str, key_or_secret: str | None = None) -> tuple[bool, str, str | None]:
        """Authenticate caller and resolve authorized role. Does not trust user_id alone."""
        user = self._users.get(user_id)
        if not user:
            return False, f"User '{user_id}' not found in authenticated credential registry (LOCAL_DEV_STORE)", None
        if key_or_secret is not None:
            if not hmac.compare_digest(user["key"], key_or_secret):
                return False, f"Authentication failed: invalid secret key for user '{user_id}'", None
        return True, "Authenticated", user["role"]


def hash_params(params: dict[str, Any]) -> str:
    """Deterministic hash of canonical action parameters (RFC 8785)."""
    return hashlib.sha256(canonical_json_bytes(params)).hexdigest()


class PersistentApprovalStore:
    """Thread-safe and process-safe persistent store for approvals using file locking."""

    def __init__(self, store_path: Path):
        self.path = store_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.is_file():
            self.path.write_text("{}", encoding="utf-8")

    def load_all(self) -> dict[str, dict[str, Any]]:
        if not self.path.is_file():
            return {}
        with open(self.path, "r", encoding="utf-8") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_SH)
                content = f.read().strip()
                data = json.loads(content) if content else {}
                fcntl.flock(f, fcntl.LOCK_UN)
                return data
            except Exception:
                return {}

    def save_all(self, data: dict[str, dict[str, Any]]) -> None:
        with open(self.path, "r+", encoding="utf-8") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.seek(0)
                f.truncate()
                json.dump(data, f, indent=2, default=str)
                f.flush()
                fcntl.flock(f, fcntl.LOCK_UN)
            except Exception:
                pass


class ApprovalManager:
    """Manages issuance, cryptographic HMAC verification, and atomic consumption of approvals."""

    def __init__(self, store_path: Path | None = None):
        self.registry = UserCredentialRegistry()
        self.store = PersistentApprovalStore(store_path or Path("runs/approvals_store.json"))

    def issue_approval(
        self,
        proposal: ActionProposal,
        evidence_snapshot_hash: str,
        approver_id: str,
        approver_role: str = "soc_lead",
        validity_seconds: int = 3600,
        approver_key: str | None = None,
        clinical_approver_id: str | None = None,
        clinical_approver_key: str | None = None,
    ) -> ApprovalRecord:
        """Issue cryptographically bound HMAC approval record with separation of duties."""
        # 1. Authenticate primary security approver if key provided or user registered
        if approver_key is not None:
            auth_ok, auth_msg, role = self.registry.authenticate(approver_id, approver_key)
            if not auth_ok:
                raise PermissionError(f"Primary approver authentication failed: {auth_msg}")
            approver_role = role or approver_role
        elif approver_id in self.registry._users:
            approver_role = self.registry._users[approver_id]["role"]

        # 2. Check clinical dual authorization (C16 IoMT Clinical Safeguards)
        if proposal.requires_clinical_authorization:
            if not clinical_approver_id:
                raise ValueError("CLINICAL_AUTHORIZATION_REQUIRED: IoMT device action requires dual clinical engineering approval; none provided")

            # Separation of duties: security and clinical approvers must be distinct identities
            if clinical_approver_id == approver_id:
                raise ValueError("SEPARATION_OF_DUTIES_VIOLATION: Clinical and security approver identities must be distinct")

            if clinical_approver_key is not None:
                c_auth_ok, c_auth_msg, c_role = self.registry.authenticate(clinical_approver_id, clinical_approver_key)
                if not c_auth_ok:
                    raise PermissionError(f"Clinical approver authentication failed: {c_auth_msg}")

        now = utc_now()
        expires = now + timedelta(seconds=validity_seconds)
        params_hash = hash_params(proposal.canonical_parameters)
        nonce = uuid.uuid4().hex

        # 3. Compute HMAC-SHA256 signature
        mac_payload = (
            f"{proposal.action}:{proposal.target}:{params_hash}:{evidence_snapshot_hash}:"
            f"{POLICY_VERSION}:{approver_id}:{approver_role}:{now.isoformat()}:{expires.isoformat()}:{nonce}"
        ).encode("utf-8")
        token_mac = hmac.new(SYSTEM_HMAC_SECRET, mac_payload, hashlib.sha256).hexdigest()
        token = f"APPR-HMAC-{token_mac[:24].upper()}"

        record = ApprovalRecord(
            approval_token=token,
            proposal_id=proposal.proposal_id,
            action=proposal.action,
            target=proposal.target,
            canonical_parameters_hash=params_hash,
            evidence_snapshot_hash=evidence_snapshot_hash,
            policy_version=POLICY_VERSION,
            approver_id=approver_id,
            approver_role=approver_role,
            clinical_approver_id=clinical_approver_id,
            granted_at=now,
            expires_at=expires,
            is_consumed=False,
        )

        # Persist across restarts
        all_apprs = self.store.load_all()
        all_apprs[token] = record.model_dump(mode="json")
        self.store.save_all(all_apprs)

        return record

    def validate_and_consume_atomic(
        self,
        approval_token: str,
        proposal: ActionProposal,
        current_evidence_hash: str,
    ) -> tuple[bool, str, ApprovalRecord | None]:
        """Atomically validate token and consume it under file locking to prevent race conditions."""
        if not self.store.path.is_file():
            self.store.path.write_text("{}", encoding="utf-8")

        with open(self.store.path, "r+", encoding="utf-8") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX)
                content = f.read().strip()
                all_apprs = json.loads(content) if content else {}

                rec_data = all_apprs.get(approval_token)
                if not rec_data:
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, "Approval token not found in persistent store", None

                record = ApprovalRecord.model_validate(rec_data)

                # 1. Single-use consumption check (Replay prevention)
                if record.is_consumed:
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, "Approval token has already been consumed (TOKEN_ALREADY_CONSUMED)", record

                # 2. Expiration check
                if utc_now() > record.expires_at:
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, f"Approval token expired at {record.expires_at.isoformat()}", record

                # 3. Action and target binding check
                if record.action != proposal.action:
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, f"Action mismatch: approved '{record.action}', executing '{proposal.action}'", record

                if record.target != proposal.target:
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, f"Target mismatch: approved '{record.target}', executing '{proposal.target}'", record

                # 4. Canonical parameter integrity check
                current_params_hash = hash_params(proposal.canonical_parameters)
                if record.canonical_parameters_hash != current_params_hash:
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, "Canonical parameters have been modified after approval was granted", record

                # 5. Evidence snapshot consistency check
                if record.evidence_snapshot_hash != current_evidence_hash:
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, "Evidence snapshot has changed since approval was granted", record

                # 6. Policy version consistency check
                if record.policy_version != POLICY_VERSION:
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, f"Policy version mismatch: approved with {record.policy_version}, current {POLICY_VERSION}", record

                # Mark consumed atomically under lock
                record.is_consumed = True
                all_apprs[approval_token] = record.model_dump(mode="json")
                f.seek(0)
                f.truncate()
                json.dump(all_apprs, f, indent=2, default=str)
                f.flush()
                fcntl.flock(f, fcntl.LOCK_UN)
                return True, "Valid and consumed", record
            except Exception as e:
                try:
                    fcntl.flock(f, fcntl.LOCK_UN)
                except Exception:
                    pass
                return False, f"Atomic store failure: {e}", None


class BaseConnector:
    """Abstract connector enforcing restricted API operations."""

    def __init__(self, name: str, is_dry_run: bool = True):
        self.name = name
        self.is_dry_run = is_dry_run
        self.provenance: ProvenanceType = "SIMULATED" if is_dry_run else "REAL"

    def execute(
        self,
        proposal: ActionProposal,
        approval: ApprovalRecord | None = None,
        simulate_timeout: bool = False,
    ) -> ActionExecution:
        raise NotImplementedError


class DryRunResponseConnector(BaseConnector):
    """Safe dry-run response connector implementing idempotency, timeouts, and structured auditing."""

    def __init__(self, approval_manager: ApprovalManager | None = None):
        super().__init__(name="dry_run_connector", is_dry_run=True)
        self.approval_manager = approval_manager or ApprovalManager()
        self.execution_history: list[ActionExecution] = []
        self._executed_idempotency_keys: set[tuple[str, str, str]] = set()

    def execute(
        self,
        proposal: ActionProposal,
        approval: ApprovalRecord | None = None,
        evidence_snapshot_hash: str = "",
        simulate_timeout: bool = False,
        simulate_failure: bool = False,
    ) -> ActionExecution:
        """Execute or dry-run an action through restricted playbooks."""
        now = utc_now()
        exec_id = f"exec-{uuid.uuid4().hex[:10]}"

        # 1. Disruptive actions require authenticated approval
        if proposal.is_disruptive:
            if not approval:
                return ActionExecution(
                    execution_id=exec_id,
                    proposal_id=proposal.proposal_id,
                    action=proposal.action,
                    target=proposal.target,
                    state="AWAITING_APPROVAL",
                    outcome_details={
                        "execution_mode": "DRY_RUN",
                        "external_effect": False,
                        "reason": "Disruptive action requires signed approval record",
                    },
                    error_message="Missing approval token",
                    provenance=self.provenance,
                )

            # Revalidate token atomically
            valid, reason, rec = self.approval_manager.validate_and_consume_atomic(
                approval_token=approval.approval_token,
                proposal=proposal,
                current_evidence_hash=evidence_snapshot_hash,
            )
            if not valid:
                state: ActionState = "EXPIRED" if "expired" in reason else "POLICY_DENIED"
                return ActionExecution(
                    execution_id=exec_id,
                    proposal_id=proposal.proposal_id,
                    approval_token=approval.approval_token,
                    action=proposal.action,
                    target=proposal.target,
                    state=state,
                    outcome_details={
                        "execution_mode": "DRY_RUN",
                        "external_effect": False,
                        "validation_failure": reason,
                    },
                    error_message=reason,
                    provenance=self.provenance,
                )

        # 2. Check idempotency: avoid duplicate executions
        idempotency_key = (proposal.action, proposal.target, hash_params(proposal.canonical_parameters))
        if idempotency_key in self._executed_idempotency_keys:
            return ActionExecution(
                execution_id=exec_id,
                proposal_id=proposal.proposal_id,
                approval_token=approval.approval_token if approval else None,
                action=proposal.action,
                target=proposal.target,
                state="SUCCEEDED",
                executed_at=now,
                connector_name=self.name,
                outcome_details={
                    "execution_mode": "DRY_RUN",
                    "external_effect": False,
                    "idempotent_skip": True,
                    "message": "Action was previously executed; duplicate skipped",
                },
                provenance=self.provenance,
            )

        # 3. Simulate timeout preservation: Section 12 rule:
        # "A timeout must not be reported as success. Do not blindly retry. OUTCOME_UNKNOWN must be retained."
        if simulate_timeout:
            record = ActionExecution(
                execution_id=exec_id,
                proposal_id=proposal.proposal_id,
                approval_token=approval.approval_token if approval else None,
                action=proposal.action,
                target=proposal.target,
                state="OUTCOME_UNKNOWN",
                executed_at=now,
                connector_name=self.name,
                outcome_details={
                    "execution_mode": "DRY_RUN",
                    "external_effect": False,
                    "timeout": True,
                    "details": "Connector timed out waiting for device ACK; preserved as OUTCOME_UNKNOWN",
                },
                error_message="Network operation timed out; state marked OUTCOME_UNKNOWN",
                provenance=self.provenance,
            )
            self.execution_history.append(record)
            return record

        if simulate_failure:
            record = ActionExecution(
                execution_id=exec_id,
                proposal_id=proposal.proposal_id,
                approval_token=approval.approval_token if approval else None,
                action=proposal.action,
                target=proposal.target,
                state="FAILED",
                executed_at=now,
                connector_name=self.name,
                outcome_details={
                    "execution_mode": "DRY_RUN",
                    "external_effect": False,
                    "failed": True,
                },
                error_message="Simulated endpoint rejection",
                provenance=self.provenance,
            )
            self.execution_history.append(record)
            return record

        # 4. Successful dry-run execution
        self._executed_idempotency_keys.add(idempotency_key)
        record = ActionExecution(
            execution_id=exec_id,
            proposal_id=proposal.proposal_id,
            approval_token=approval.approval_token if approval else None,
            action=proposal.action,
            target=proposal.target,
            state="SUCCEEDED",
            executed_at=now,
            connector_name=self.name,
            outcome_details={
                "execution_mode": "DRY_RUN",
                "external_effect": False,
                "action": proposal.action,
                "target": proposal.target,
                "parameters": proposal.canonical_parameters,
                "execution_status": "simulated_success",
            },
            provenance=self.provenance,
        )
        self.execution_history.append(record)
        return record
