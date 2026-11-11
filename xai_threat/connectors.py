"""Restricted Response Connectors and Approval Binding (Agent 06: Response Orchestration).

Implements Section 14:
- Explicit Action States:
  PROPOSED, POLICY_DENIED, AWAITING_APPROVAL, APPROVED, EXECUTING,
  SUCCEEDED, FAILED, EXPIRED, CANCELLED, OUTCOME_UNKNOWN.
- One-time cryptographically bound approval tokens verifying:
  action, target, canonical parameters, evidence snapshot hash,
  policy version, approver identity and role, and expiry timestamp.
- Revalidates immediately before execution.
- Idempotency checks.
- Timeouts preserve OUTCOME_UNKNOWN; never blindly retries unknown states.
- Dry-run connectors first; restricted connector APIs (no arbitrary shell commands).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any
import uuid

from .ledger import canonical_json_bytes
from .schemas import (
    ActionExecution,
    ActionProposal,
    ActionState,
    ActionType,
    ApprovalRecord,
    ProvenanceType,
    utc_now,
)

POLICY_VERSION = "2.1.0"


def hash_params(params: dict[str, Any]) -> str:
    """Deterministic hash of canonical action parameters."""
    return hashlib.sha256(canonical_json_bytes(params)).hexdigest()


class ApprovalManager:
    """Manages creation, verification, and single-use consumption of approval tokens."""

    def __init__(self):
        self.approvals: dict[str, ApprovalRecord] = {}
        self.executed_actions: set[tuple[str, str, str]] = set()  # (action, target, params_hash) for idempotency

    def issue_approval(
        self,
        proposal: ActionProposal,
        evidence_snapshot_hash: str,
        approver_id: str,
        approver_role: str,
        clinical_approver_id: str | None = None,
        validity_seconds: int = 3600,
    ) -> ApprovalRecord:
        """Create a cryptographically bound one-time approval record."""
        now = utc_now()
        expires = now + timedelta(seconds=validity_seconds)
        params_hash = hash_params(proposal.canonical_parameters)

        # Generate unique one-time token bound to all critical context
        token_payload = f"{proposal.action}:{proposal.target}:{params_hash}:{evidence_snapshot_hash}:{POLICY_VERSION}:{approver_id}:{now.isoformat()}:{uuid.uuid4().hex}"
        token = "APPR-" + hashlib.sha256(token_payload.encode()).hexdigest()[:24].upper()

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
        self.approvals[token] = record
        return record

    def validate_and_consume(
        self,
        approval_token: str,
        proposal: ActionProposal,
        current_evidence_hash: str,
    ) -> tuple[bool, str, ApprovalRecord | None]:
        """Revalidate approval token immediately before execution (Section 14)."""
        record = self.approvals.get(approval_token)
        if not record:
            return False, "Approval token not found", None

        if record.is_consumed:
            return False, "Approval token has already been consumed (replay prevention)", record

        if utc_now() > record.expires_at:
            return False, "Approval token has expired", record

        if record.action != proposal.action:
            return False, f"Action mismatch: approved '{record.action}', executing '{proposal.action}'", record

        if record.target != proposal.target:
            return False, f"Target mismatch: approved '{record.target}', executing '{proposal.target}'", record

        current_params_hash = hash_params(proposal.canonical_parameters)
        if record.canonical_parameters_hash != current_params_hash:
            return False, "Canonical parameters have been modified after approval was granted", record

        if record.evidence_snapshot_hash != current_evidence_hash:
            return False, "Evidence snapshot has changed since approval was granted", record

        if record.policy_version != POLICY_VERSION:
            return False, "System policy version changed after approval was granted", record

        # Mark consumed
        record.is_consumed = True
        return True, "Valid and consumed", record


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

        # 1. Check if action requires approval
        if proposal.is_disruptive:
            if not approval:
                return ActionExecution(
                    execution_id=exec_id,
                    proposal_id=proposal.proposal_id,
                    action=proposal.action,
                    target=proposal.target,
                    state="AWAITING_APPROVAL",
                    outcome_details={"reason": "Disruptive action requires signed approval record"},
                    error_message="Missing approval token",
                    provenance=self.provenance,
                )

            # Revalidate token
            valid, reason, rec = self.approval_manager.validate_and_consume(
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
                    outcome_details={"validation_failure": reason},
                    error_message=reason,
                    provenance=self.provenance,
                )

        # 2. Check idempotency: avoid duplicate executions
        idempotency_key = (proposal.action, proposal.target, hash_params(proposal.canonical_parameters))
        if idempotency_key in self.approval_manager.executed_actions:
            return ActionExecution(
                execution_id=exec_id,
                proposal_id=proposal.proposal_id,
                approval_token=approval.approval_token if approval else None,
                action=proposal.action,
                target=proposal.target,
                state="SUCCEEDED",
                executed_at=now,
                connector_name=self.name,
                outcome_details={"idempotent_skip": True, "message": "Action was previously executed"},
                provenance=self.provenance,
            )

        # 3. Simulate timeout preservation: Section 14 rule:
        # "A timeout must not be reported as success. Do not blindly retry a disruptive operation with an unknown result."
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
                outcome_details={"timeout": True, "details": "Connector timed out waiting for device ACK"},
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
                outcome_details={"failed": True},
                error_message="Simulated endpoint rejection",
                provenance=self.provenance,
            )
            self.execution_history.append(record)
            return record

        # 4. Successful dry-run execution
        self.approval_manager.executed_actions.add(idempotency_key)
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
                "dry_run": True,
                "action": proposal.action,
                "target": proposal.target,
                "parameters": proposal.canonical_parameters,
                "execution_status": "simulated_success",
            },
            provenance=self.provenance,
        )
        self.execution_history.append(record)
        return record
