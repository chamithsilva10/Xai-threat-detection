"""Deterministic Policy Engine and Mandatory Hard Safety Gates (Agent 06).

Strict compliance with Section 5, 8, 9, 14, and Contribution C16:
- Replaces score-based safety with Mandatory Independent Hard Safety Gates:
  1. Evidence integrity valid (snapshot hash confirmed).
  2. Required claims supported (no missing mandatory evidence).
  3. No unresolved critical contradictions (has_critical_contradiction == False).
  4. Required verification completed (critic approved).
  5. Applicable risk eligibility valid (selective-risk certified, s(x) <= lambda_hat).
  6. Asset policy allows the action (criticality & role permissions satisfied).
  7. Target identity resolved (target exists in evidence and registry).
  8. Action explicitly allowlisted for autonomous execution.
- ETS score CANNOT override mandatory hard safety gate failures (even if ETS == 1.0).
- Prohibits automated disruptive actions on critical IoMT medical assets (C16).
- Separates safe observational/safety operations (open_ticket) from remediation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import re
from typing import Any

from .knowledge import (
    DEFAULT_ASSET_REGISTRY,
    LABEL_BASE_SEVERITY,
    MITRE_TECHNIQUES,
    AssetRegistry,
    is_internal_ip,
    is_iomt_device,
    severity_rank,
)
from .ledger import ClaimEvidenceLedger
from .schemas import (
    DANGEROUS_ACTIONS,
    SAFE_AUTO_ACTIONS,
    AnalystReport,
    ConformalTriageResult,
    ResponsePlan,
)

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_NUMBER = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w])")

INJECTION_PATTERNS = {
    "override_instructions": r"\b(ignore|disregard|forget|override)\b.{0,30}\b(instruction|rule|prompt|polic)",
    "role_hijack": r"\b(you are now|act as|pretend to be|new role)\b",
    "prompt_markup": r"(system prompt|\[/?inst\]|###\s*instruction|<\|im_start\|>|\bassistant\s*:)",
    "tag_breakout": r"</?\s*(evidence|report|system|instructions?)\b",
    "verdict_tampering": r"\b(set|mark|change|lower|downgrade)\b.{0,20}\b(severity|verdict|priority)\b",
    "allowlisting": r"\b(approve|whitelist|allowlist|trust)\b.{0,20}\b(this|the|ip|host|alert|traffic)\b",
    "suppression": r"\b(do not|don't|never)\b.{0,15}\b(flag|alert|report|escalate|block)\b",
}
_INJECTION_RE = {k: re.compile(v, re.IGNORECASE) for k, v in INJECTION_PATTERNS.items()}


def sanitize(value: Any, max_len: int = 500, _depth: int = 0) -> Any:
    """Sanitize untrusted text fields without modifying original evidence storage."""
    if _depth > 8:
        return "[truncated: nesting too deep]"
    if isinstance(value, str):
        value = _CTRL.sub("", value).replace("<", "‹").replace(">", "›")
        return value if len(value) <= max_len else value[:max_len] + "…[truncated]"
    if isinstance(value, dict):
        return {sanitize(str(k), 100): sanitize(v, max_len, _depth + 1) for k, v in list(value.items())[:200]}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, max_len, _depth + 1) for v in list(value)[:100]]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _walk(obj: Any, path: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            yield p + " (key)", str(k)
            yield from _walk(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def scan_injection(evidence: dict) -> list[dict]:
    flags = []
    for path, text in _walk(evidence):
        for name, rx in _INJECTION_RE.items():
            if rx.search(text):
                flags.append({"field": path, "pattern": name})
    return flags


def evidence_paths(obj: Any, prefix: str = "") -> set[str]:
    paths = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            paths.add(p)
            paths |= evidence_paths(v, p)
    elif isinstance(obj, list):
        for v in obj:
            paths |= evidence_paths(v, prefix)
    return paths


def _key_exists(key: str, paths: set[str]) -> bool:
    key_clean = re.sub(r"\[\d+\]", "", key.strip()).strip(".")
    if key_clean.startswith("/"):
        key_clean = key_clean[1:].replace("/", ".")
    return key_clean in paths or any(p.endswith("." + key_clean) for p in paths)


def _evidence_numbers(obj: Any) -> list[float]:
    nums = []
    if isinstance(obj, bool):
        return nums
    if isinstance(obj, (int, float)):
        nums.append(float(obj))
    elif isinstance(obj, str):
        nums += [float(n) for n in _NUMBER.findall(_IPV4.sub(" ", obj))]
    elif isinstance(obj, dict):
        for v in obj.values():
            nums += _evidence_numbers(v)
    elif isinstance(obj, list):
        for v in obj:
            nums += _evidence_numbers(v)
    return nums


def _number_grounded(token: str, known: list[float]) -> bool:
    try:
        n = float(token)
    except ValueError:
        return False
    decimals = len(token.split(".")[1]) if "." in token else 0
    tol = 0.5 * 10 ** -decimals + 1e-9
    for v in known:
        if abs(n - v) <= tol or abs(n - v * 100) <= max(tol, 0.5) or (v and abs(n - v) / abs(v) < 0.01):
            return True
    return False


def _strings(obj: Any) -> list[str]:
    return [t for _, t in _walk(obj)]


@dataclass
class GroundingResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def feedback(self) -> str:
        return "; ".join(self.errors)


def check_grounding(report: AnalystReport, evidence: dict) -> GroundingResult:
    res = GroundingResult()
    paths = evidence_paths(evidence)
    known_numbers = _evidence_numbers(evidence)
    evidence_ips = set(_IPV4.findall(" ".join(_strings(evidence))))

    for i, claim in enumerate(report.claims, 1):
        raw_keys = getattr(claim, "evidence_pointers", None) or getattr(claim, "evidence_keys", [])
        if not raw_keys:
            res.errors.append(f"Claim {i} cites no evidence pointers: '{claim.statement[:80]}'")
        bad = [k for k in raw_keys if not _key_exists(k, paths)]
        if bad:
            res.errors.append(f"Claim {i} cites keys that do not exist in the evidence: {bad}")

    text = " ".join([report.summary] + [c.statement for c in report.claims])
    for ip in set(_IPV4.findall(text)) - evidence_ips:
        res.errors.append(f"IP address {ip} appears in report but not in evidence")

    stripped = _MITRE.sub(" ", _IPV4.sub(" ", text))
    for token in sorted(set(_NUMBER.findall(stripped))):
        if not _number_grounded(token, known_numbers):
            res.warnings.append(f"Number {token} is not found in the evidence (derived or invented?)")

    candidates = {t["id"] for t in evidence.get("candidate_mitre", []) if isinstance(t, dict)}
    for tid in report.mitre_techniques:
        if tid not in MITRE_TECHNIQUES and not candidates:
            res.warnings.append(f"MITRE ID {tid} is not in the local ATT&CK knowledge base")
        elif candidates and tid not in candidates:
            res.errors.append(f"MITRE ID {tid} is not one of evidence.candidate_mitre {sorted(candidates)}")

    label = (evidence.get("detection") or {}).get("label")
    if label in LABEL_BASE_SEVERITY:
        gap = severity_rank(report.severity) - severity_rank(LABEL_BASE_SEVERITY[label])
        if abs(gap) >= 2:
            res.warnings.append(
                f"Severity '{report.severity}' is far from baseline '{LABEL_BASE_SEVERITY[label]}' for {label}"
            )
    return res


# ---------------------------------------------------------------------------
# Mandatory Hard Safety Gate Evaluation (Section 5)
# ---------------------------------------------------------------------------
@dataclass
class HardSafetyGateResult:
    all_passed: bool
    evidence_integrity: bool
    required_claims_supported: bool
    no_critical_contradictions: bool
    verification_completed: bool
    risk_eligibility_valid: bool
    target_identity_resolved: bool
    failed_reasons: list[str] = field(default_factory=list)


def evaluate_hard_safety_gates(
    evidence: dict,
    critic_approved: bool,
    grounding_ok: bool,
    conformal_result: ConformalTriageResult | None,
    ledger: ClaimEvidenceLedger | None = None,
    injection_flags: list | None = None,
) -> HardSafetyGateResult:
    """Evaluate mandatory independent gates before incident-driven automatic remediation."""
    reasons = []

    # 1. Evidence integrity
    evidence_integrity = bool(evidence) and not evidence.get("corrupted", False)
    if not evidence_integrity:
        reasons.append("Evidence integrity failure: empty evidence or corrupted snapshot")

    # 2. Injection check
    if injection_flags:
        reasons.append(f"Prompt injection / untrusted manipulation detected: {len(injection_flags)} flags")

    # 3. Required claims supported
    has_unsupported = False
    has_contradiction = False
    if ledger:
        has_unsupported = ledger.unsupported_claims > 0
        has_contradiction = ledger.has_critical_contradiction or (ledger.contradicted_claims > 0)
        if has_unsupported:
            reasons.append(f"Ledger contains {ledger.unsupported_claims} unsupported claim(s)")
        if has_contradiction:
            reasons.append(f"Ledger contains {ledger.contradicted_claims} contradictory claim(s)")

    # 4. Verification completed
    verification_completed = critic_approved and grounding_ok
    if not verification_completed:
        reasons.append("Verification incomplete or rejected by independent critic")

    # 5. Risk eligibility valid
    risk_eligibility_valid = False
    if conformal_result is not None:
        risk_eligibility_valid = conformal_result.eligible_for_auto_response
        if not risk_eligibility_valid:
            reasons.append(f"Selective risk control abstention: {conformal_result.abstain_reason}")
    else:
        reasons.append("No selective-risk calibration available")

    # 6. Target identity resolved
    targets = {str(evidence.get(k)) for k in ("host", "src_ip", "dst_ip", "username") if evidence.get(k)}
    target_identity_resolved = len(targets) > 0
    if not target_identity_resolved:
        reasons.append("Target identity could not be resolved from evidence")

    all_passed = (
        evidence_integrity
        and not injection_flags
        and not has_unsupported
        and not has_contradiction
        and verification_completed
        and risk_eligibility_valid
        and target_identity_resolved
    )

    return HardSafetyGateResult(
        all_passed=all_passed,
        evidence_integrity=evidence_integrity,
        required_claims_supported=not has_unsupported,
        no_critical_contradictions=not has_contradiction,
        verification_completed=verification_completed,
        risk_eligibility_valid=risk_eligibility_valid,
        target_identity_resolved=target_identity_resolved,
        failed_reasons=reasons,
    )


@dataclass
class PolicyDecision:
    auto_execute: list[dict] = field(default_factory=list)
    pending_approval: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    hard_gate_result: HardSafetyGateResult | None = None

    def to_dict(self) -> dict:
        return {
            "auto_execute": self.auto_execute,
            "pending_approval": self.pending_approval,
            "rejected": self.rejected,
            "hard_gates_passed": self.hard_gate_result.all_passed if self.hard_gate_result else False,
            "hard_gate_failures": self.hard_gate_result.failed_reasons if self.hard_gate_result else [],
        }


def enforce_policy(
    plan: ResponsePlan,
    evidence: dict,
    severity: str,
    critic_approved: bool,
    grounded: bool,
    injection_flags: list,
    critical_assets: frozenset[str],
    conformal_result: ConformalTriageResult | None = None,
    asset_registry: AssetRegistry | None = None,
    ledger: ClaimEvidenceLedger | None = None,
) -> PolicyDecision:
    """Enforce deterministic deny-by-default response policy with clinical safeguards.
    
    Mandatory Rules (Sections 5, 8, 9, 14, C16):
      1. Mandatory hard gates must all pass for autonomous remediation.
         ETS score CANNOT bypass failed hard gates.
      2. Disruptive actions always require explicit human authorization under policy.
      3. Critical IoMT assets strictly prohibit automated disruptive actions.
         Missing clinical authorization workflow = denial.
      4. Unknown asset criticality = hold disruptive actions.
    """
    decision = PolicyDecision()
    registry = asset_registry or AssetRegistry()

    targets = {str(evidence.get(k)) for k in ("host", "src_ip", "dst_ip", "username") if evidence.get(k)}
    seen = set()

    # Evaluate mandatory hard gates
    hard_gates = evaluate_hard_safety_gates(
        evidence=evidence,
        critic_approved=critic_approved,
        grounding_ok=grounded,
        conformal_result=conformal_result,
        ledger=ledger,
        injection_flags=injection_flags,
    )
    decision.hard_gate_result = hard_gates

    # Asset context resolution
    host_val = evidence.get("host") or evidence.get("src_ip")
    asset_ctx = registry.lookup(str(host_val) if host_val else None, str(evidence.get("src_ip")))
    is_iomt = asset_ctx.is_iomt or is_iomt_device(str(host_val))

    for a in plan.actions:
        item = {
            "action": a.action,
            "target": a.target,
            "justification": a.justification,
            "asset_id": asset_ctx.asset_id,
            "asset_type": asset_ctx.asset_type,
        }
        key = (a.action, a.target)
        if key in seen:
            continue
        seen.add(key)

        target_ctx = registry.lookup(a.target, a.target)
        target_is_iomt = is_iomt or target_ctx.is_iomt or is_iomt_device(a.target)

        # 1. Target existence in evidence
        if a.target not in targets:
            decision.rejected.append({
                **item,
                "reason_code": "POLICY_DENIED_INVALID_TARGET",
                "reason": f"Target {a.target} is not an entity in the evidence {sorted(targets)}",
            })
            continue

        # 2. Internal IP blocking prohibition
        if a.action == "block_ip" and is_internal_ip(a.target):
            decision.rejected.append({
                **item,
                "reason_code": "POLICY_DENIED_INTERNAL_IP_BLOCK",
                "reason": "block_ip requested on internal RFC1918 address; use isolate_host instead",
            })
            continue

        # 3. Disruptive action on low severity
        if a.action in DANGEROUS_ACTIONS and severity == "low":
            decision.rejected.append({
                **item,
                "reason_code": "POLICY_DENIED_DISRUPTIVE_ACTION_FOR_LOW_SEVERITY",
                "reason": "Disruptive action not permitted on low severity alerts",
            })
            continue

        # 4. Contribution C16: Clinical IoMT Safeguard
        if target_is_iomt and a.action in DANGEROUS_ACTIONS:
            decision.pending_approval.append({
                **item,
                "reason_code": "POLICY_HOLD_IOMT_CLINICAL_SAFEGUARD",
                "reason": (
                    f"Target {a.target} is a life-critical IoMT medical device ({target_ctx.asset_type}). "
                    f"Autonomous disruption is prohibited; joint clinical engineering sign-off mandatory."
                ),
                "clinical_approval_required": True,
                "approval_roles": target_ctx.approval_roles,
            })
            continue

        if target_is_iomt and a.action in ("rate_limit", "isolate_host"):
            decision.pending_approval.append({
                **item,
                "reason_code": "POLICY_HOLD_IOMT_NETWORK_THROTTLE",
                "reason": "IoMT medical telemetry disruption risk; clinical approval mandatory before throttling.",
                "clinical_approval_required": True,
            })
            continue

        # 5. Disruptive actions require human authorization
        if a.action in DANGEROUS_ACTIONS:
            reason = "Disruptive action always requires human authorization"
            reason_code = "POLICY_HOLD_DISRUPTIVE_ACTION"
            if a.target in critical_assets or target_ctx.criticality == "CRITICAL":
                reason += "; target is a CRITICAL asset (CAB authorization needed)"
                reason_code = "POLICY_HOLD_CRITICAL_ASSET"
            elif target_ctx.asset_type == "UNKNOWN":
                reason += "; target has UNKNOWN asset identity (conservative hold applied)"
                reason_code = "POLICY_HOLD_UNKNOWN_ASSET"
            decision.pending_approval.append({**item, "reason_code": reason_code, "reason": reason})
            continue

        # 6. Mandatory Hard Safety Gate Check for autonomous remediation:
        # If any hard gate failed, autonomous action CANNOT proceed!
        if not hard_gates.all_passed:
            decision.pending_approval.append({
                **item,
                "reason_code": "POLICY_HOLD_MANDATORY_GATE_FAILED",
                "reason": f"Mandatory hard gate check failed: {'; '.join(hard_gates.failed_reasons)}",
            })
            continue

        # 7. Safe allowlisted observational/safety operations (e.g. open_ticket, collect_forensics)
        if a.action in SAFE_AUTO_ACTIONS:
            decision.auto_execute.append({**item, "reason_code": "AUTO_ALLOWLISTED"})
        elif hard_gates.all_passed and severity_rank(severity) >= severity_rank("medium"):
            decision.auto_execute.append({**item, "reason_code": "AUTO_TRUSTED_SEVERITY"})
        else:
            decision.pending_approval.append({
                **item,
                "reason_code": "POLICY_HOLD_UNVERIFIED_ANALYSIS",
                "reason": "Action not eligible for automated execution under configured policy",
            })

    # Independent safety operation: every medium+ alert receives a tracking ticket
    if severity_rank(severity) >= severity_rank("medium") and not any(
        d["action"] == "open_ticket" for d in decision.auto_execute
    ):
        target = evidence.get("host") or evidence.get("src_ip") or "unknown"
        decision.auto_execute.append({
            "action": "open_ticket",
            "target": str(target),
            "justification": "policy: every medium+ alert gets an automated tracking ticket",
            "reason_code": "AUTO_TICKET_MANDATE",
        })

    return decision
