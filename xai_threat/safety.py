"""Deterministic guardrails and Policy Engine (Agent 06: Response Policy Gate).

Enforces Sections 5, 8, 14, and Contribution C16:
1. sanitize()          - strip control chars, neutralize tag-like text, cap lengths.
2. scan_injection()    - flag prompt-injection markers in untrusted telemetry fields.
3. check_grounding()   - verify numbers, IPs, and MITRE IDs against evidence.
4. enforce_policy()    - deterministic deny-by-default policy with structured reason codes:
   - Separate decisions for classification risk, claim verification, and action policy.
   - Prohibits automatic disruptive actions on critical IoMT medical devices (C16).
   - Holds disruptive actions for unknown asset criticality.
   - No LLM, high ETS, or classifier confidence can bypass clinical safeguards.
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


# ---------------------------------------------------------------------------
# 1. Sanitisation (Section 5)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# 2. Prompt-injection scanning (Section 5)
# ---------------------------------------------------------------------------
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
    """Pattern matching flags suspicious text; does not claim complete injection prevention."""
    flags = []
    for path, text in _walk(evidence):
        for name, rx in _INJECTION_RE.items():
            if rx.search(text):
                flags.append({"field": path, "pattern": name})
    return flags


# ---------------------------------------------------------------------------
# 3. Grounding / hallucination checks
# ---------------------------------------------------------------------------
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
    """Validate report grounding against evidence before any response authorization."""
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
# 4. Response policy gate (Section 14)
# ---------------------------------------------------------------------------
@dataclass
class PolicyDecision:
    auto_execute: list[dict] = field(default_factory=list)
    pending_approval: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "auto_execute": self.auto_execute,
            "pending_approval": self.pending_approval,
            "rejected": self.rejected,
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
) -> PolicyDecision:
    """Enforce deterministic deny-by-default response policy with clinical safeguards.
    
    Section 14 & C16 Rules:
      1. Low-impact actions auto-execute only when allowlisted.
      2. Disruptive actions always require approval under policy.
      3. Critical IoMT assets strictly prohibit automated disruptive actions.
         Missing clinical authorization workflow = denial.
      4. Unknown asset criticality = hold disruptive actions.
      5. Conformal risk abstention (C9) blocks automated mitigation.
    """
    decision = PolicyDecision()
    registry = asset_registry or AssetRegistry()

    targets = {str(evidence.get(k)) for k in ("host", "src_ip", "dst_ip", "username") if evidence.get(k)}
    
    conformal_ok = conformal_result.eligible_for_auto_response if conformal_result is not None else False
    trusted = critic_approved and grounded and not injection_flags and conformal_ok
    seen = set()

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

        # Policy checks
        if a.target not in targets:
            decision.rejected.append({
                **item,
                "reason_code": "POLICY_DENIED_INVALID_TARGET",
                "reason": f"Target {a.target} is not an entity in the evidence {sorted(targets)}",
            })
        elif a.action == "block_ip" and is_internal_ip(a.target):
            decision.rejected.append({
                **item,
                "reason_code": "POLICY_DENIED_INTERNAL_IP_BLOCK",
                "reason": "block_ip requested on internal RFC1918 address; use isolate_host instead",
            })
        elif a.action in DANGEROUS_ACTIONS and severity == "low":
            decision.rejected.append({
                **item,
                "reason_code": "POLICY_DENIED_DISRUPTIVE_ACTION_FOR_LOW_SEVERITY",
                "reason": "Disruptive action not permitted on low severity alerts",
            })
        elif target_is_iomt and a.action in DANGEROUS_ACTIONS:
            # Contribution C16: Clinical IoMT Safeguard
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
        elif target_is_iomt and a.action in ("rate_limit", "isolate_host"):
            decision.pending_approval.append({
                **item,
                "reason_code": "POLICY_HOLD_IOMT_NETWORK_THROTTLE",
                "reason": "IoMT medical telemetry disruption risk; clinical approval mandatory before throttling.",
                "clinical_approval_required": True,
            })
        elif a.action in DANGEROUS_ACTIONS:
            reason = "Disruptive action always requires human authorization"
            reason_code = "POLICY_HOLD_DISRUPTIVE_ACTION"
            if a.target in critical_assets or target_ctx.criticality == "CRITICAL":
                reason += "; target is a CRITICAL asset (CAB authorization needed)"
                reason_code = "POLICY_HOLD_CRITICAL_ASSET"
            elif target_ctx.asset_type == "UNKNOWN":
                reason += "; target has UNKNOWN asset identity (conservative hold applied)"
                reason_code = "POLICY_HOLD_UNKNOWN_ASSET"
            decision.pending_approval.append({**item, "reason_code": reason_code, "reason": reason})
        elif not conformal_ok and a.action not in SAFE_AUTO_ACTIONS:
            # Contribution C9: Conformal Risk Abstention
            reason = (
                conformal_result.abstain_reason
                if conformal_result
                else "Conformal risk control abstention: classification error cannot be certified <= target alpha"
            )
            decision.pending_approval.append({
                **item,
                "reason_code": "POLICY_HOLD_CONFORMAL_UNBOUNDED_RISK",
                "reason": reason,
            })
        elif a.action in SAFE_AUTO_ACTIONS:
            decision.auto_execute.append({**item, "reason_code": "AUTO_ALLOWLISTED"})
        elif trusted and severity_rank(severity) >= severity_rank("medium"):
            decision.auto_execute.append({**item, "reason_code": "AUTO_TRUSTED_SEVERITY"})
        else:
            why = "Alert verdict not fully trusted (critic rejection, grounding errors, injection, or conformal abstention)"
            decision.pending_approval.append({**item, "reason_code": "POLICY_HOLD_UNVERIFIED_ANALYSIS", "reason": why})

    # Ensure every medium+ alert opens a ticket if not already present
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
