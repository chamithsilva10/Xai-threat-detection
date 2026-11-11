"""Strict output contracts and typed schemas for the Multi-Agent Explainable AI Framework.

Validated with Pydantic v2. Supports all 9 agents, three operating modes
(REPLAY, LIVE_MONITOR, LIVE_RESPONSE), explicit provenance tracking, RFC 6901
JSON Pointer evidence grounding, and finite-sample selective risk certification.
"""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Enums and Literal Types
# ---------------------------------------------------------------------------
Severity = Literal["low", "medium", "high", "critical"]

ActionType = Literal[
    "monitor",
    "open_ticket",
    "collect_forensics",
    "rate_limit",
    "block_ip",
    "isolate_host",
    "reset_credentials",
]

ActionState = Literal[
    "PROPOSED",
    "POLICY_DENIED",
    "AWAITING_APPROVAL",
    "APPROVED",
    "EXECUTING",
    "SUCCEEDED",
    "FAILED",
    "EXPIRED",
    "CANCELLED",
    "OUTCOME_UNKNOWN",
]

OperatingMode = Literal["REPLAY", "LIVE_MONITOR", "LIVE_RESPONSE"]

ProvenanceType = Literal["REAL", "SIMULATED", "UNAVAILABLE"]

ClaimType = Literal[
    "MEASUREMENT",
    "PREDICTION",
    "ATTRIBUTION",
    "THREAT_INTEL",
    "HYPOTHESIS",
    "RECOMMENDATION",
]

VerificationStatus = Literal["SUPPORTED", "UNSUPPORTED", "CONTRADICTED"]

AssetType = Literal[
    "WORKSTATION",
    "SERVER",
    "NETWORK_INFRASTRUCTURE",
    "IOMT_MEDICAL",
    "SCADA_OT",
    "UNKNOWN",
]

AssetCriticality = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

DANGEROUS_ACTIONS: frozenset[str] = frozenset({"block_ip", "isolate_host", "reset_credentials"})
SAFE_AUTO_ACTIONS: frozenset[str] = frozenset({"monitor", "open_ticket", "collect_forensics"})


def _lower(v: Any) -> Any:
    return v.strip().lower() if isinstance(v, str) else v


def _as_list(v: Any) -> Any:
    if v is None:
        return []
    return [v] if isinstance(v, (str, dict)) else v


def utc_now() -> datetime:
    """Always return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Section 4: Typed Schemas with Full Provenance
# ---------------------------------------------------------------------------

class RawEvent(BaseModel):
    """Raw incoming network or host event before feature extraction."""
    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    trace_id: str = Field(default_factory=lambda: f"trc-{uuid.uuid4().hex[:12]}")
    event_time: datetime = Field(default_factory=utc_now)
    ingestion_time: datetime = Field(default_factory=utc_now)
    source: str = Field(description="Sensor or log source, e.g. 'zeek_conn', 'ssh_auth', 'suricata_eve'")
    sensor_identity: str = Field(default="sensor-default")
    schema_version: str = Field(default="1.0.0")
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    provenance: ProvenanceType = Field(default="REAL")

    @field_validator("event_time", "ingestion_time", mode="before")
    @classmethod
    def _ensure_utc(cls, v: Any) -> datetime:
        if isinstance(v, str):
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return utc_now()


class NormalizedEvent(BaseModel):
    """Structured network/host event with validated IP addresses and protocol."""
    event_id: str
    trace_id: str
    event_time: datetime = Field(default_factory=utc_now)
    ingestion_time: datetime = Field(default_factory=utc_now)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = Field(default="tcp")
    host: str | None = None
    user: str | None = None
    raw_text: str | None = None
    provenance: ProvenanceType = Field(default="REAL")


class FeatureVector(BaseModel):
    """Extracted numeric feature vector distinguishing genuine 0 from missing (None)."""
    event_id: str
    feature_pipeline_version: str = Field(default="1.0.0")
    features: dict[str, float | None] = Field(
        description="Feature mapping; None represents missing/unobserved, distinct from 0.0"
    )
    feature_origins: dict[str, str] = Field(
        default_factory=dict,
        description="Documentation of feature source, e.g. {'failed_logins': 'ssh_auth.failed_attempts'}"
    )
    aggregation_windows: dict[str, str] = Field(
        default_factory=dict,
        description="Time windows, e.g. {'conn_rate': '60s_sliding'}"
    )

    @field_validator("features")
    @classmethod
    def _validate_finite(cls, v: dict[str, float | None]) -> dict[str, float | None]:
        for name, val in v.items():
            if val is not None and not math.isfinite(val):
                raise ValueError(f"Feature '{name}' contains non-finite value: {val}")
        return v


class DetectionResult(BaseModel):
    """ML multi-class prediction and unsupervised anomaly percentile."""
    event_id: str
    incident_id: str
    predicted_label: str
    class_probabilities: dict[str, float] = Field(
        description="Probability vector with explicit class ordering"
    )
    anomaly_score: float = Field(ge=0.0, le=1.0, description="IsolationForest anomaly percentile")
    anomaly_is_escalated: bool = Field(default=False)
    model_version: str = Field(default="xgboost-v1.0.0")
    feature_pipeline_version: str = Field(default="1.0.0")
    inference_latency_ms: float = Field(ge=0.0)
    compatibility_status: Literal["COMPATIBLE", "INCOMPATIBLE", "DEGRADED"] = "COMPATIBLE"
    provenance: ProvenanceType = Field(default="REAL")

    @field_validator("class_probabilities")
    @classmethod
    def _validate_probs(cls, v: dict[str, float]) -> dict[str, float]:
        for c, p in v.items():
            if not (0.0 <= p <= 1.0) or not math.isfinite(p):
                raise ValueError(f"Invalid probability for class {c}: {p}")
        return v


class ExplanationResult(BaseModel):
    """Detailed XAI result containing TreeSHAP, LIME, and counterfactuals."""
    explained_class: str
    shap_attributions: list[dict[str, Any]] = Field(default_factory=list)
    lime_attributions: list[dict[str, Any]] = Field(default_factory=list)
    shap_baseline: float = 0.0
    shap_reconstruction_error: float = Field(default=0.0, description="|baseline + sum(phi) - f(x)|")
    lime_local_fidelity: float = Field(default=1.0, description="R^2 local surrogate score")
    agreement_score: float = Field(ge=0.0, le=1.0, default=1.0)
    faithfulness_score: float = Field(ge=0.0, le=1.0, default=1.0)
    counterfactual: ContrastiveExplanation | None = None
    background_data_version: str = "v1.0-synthetic-ref"


class ThreatIntelResult(BaseModel):
    """Enriched threat intelligence and ATT&CK mappings."""
    target: str
    observed_behavior: str
    candidate_mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)
    feed_matches: list[dict[str, Any]] = Field(default_factory=list)
    feed_provenance: ProvenanceType = Field(default="SIMULATED")
    lookup_status: Literal["HIT", "MISS", "UNAVAILABLE", "ERROR"] = "HIT"
    retrieval_time: datetime = Field(default_factory=utc_now)


class AssetContext(BaseModel):
    """Maintained asset registry entry ensuring clinical and operational safety."""
    asset_id: str
    host: str
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    asset_type: AssetType = "UNKNOWN"
    criticality: AssetCriticality = "MEDIUM"
    is_iomt: bool = False
    clinical_restrictions: list[str] = Field(default_factory=list)
    owner: str = "Unassigned"
    approval_roles: list[str] = Field(default_factory=lambda: ["soc_analyst"])


class RiskDecision(BaseModel):
    """Finite-sample selective risk certification result."""
    nonconformity_score: float = Field(description="s(x) = 1 - max P(c|x)")
    calibrated_threshold: float = Field(description="Selected lambda threshold")
    target_risk_alpha: float = Field(default=0.05, description="Target selective error rate alpha")
    delta_failure_probability: float = Field(default=0.01, description="Statistical failure bound delta")
    upper_confidence_bound: float = Field(description="Exact one-sided Binomial UCB (Clopper-Pearson)")
    coverage: float = Field(ge=0.0, le=1.0, description="Accepted calibration coverage")
    is_certified: bool = Field(description="True only if UCB <= alpha with Bonferroni correction")
    decision: Literal["AUTO_ELIGIBLE", "ABSTAIN_AND_ESCALATE"]
    abstain_reason: str = ""
    calibration_version: str = "v1.0"


class AtomicClaim(BaseModel):
    """Machine-checkable structured claim adhering to Section 10."""
    claim_id: str = Field(description="Unique claim ID, e.g. CLM-01-01")
    claim_type: ClaimType = Field(default="MEASUREMENT")
    subject: str = Field(description="Subject entity, e.g. '10.0.2.15' or 'failed_logins'")
    predicate: str = Field(description="Predicate or operator, e.g. 'equals', 'exceeds_baseline', 'classified_as'")
    asserted_value: Any = Field(description="Asserted value or string")
    unit: str | None = Field(default=None, description="Optional unit, e.g. 'attempts', 'MB', 'pps'")
    scope_time_window: str | None = Field(default=None, description="Scope or aggregation window")
    evidence_pointers: list[str] = Field(
        default_factory=list,
        description="RFC 6901 JSON Pointers, e.g. ['/features/failed_logins', '/detection/label']"
    )
    statement: str = Field(description="Natural language sentence for the report")


class ClaimVerification(BaseModel):
    """Deterministic validation outcome for an individual AtomicClaim."""
    claim_id: str
    verification_status: VerificationStatus
    verification_method: Literal["DETERMINISTIC_POINTER", "NUMERIC_TOLERANCE", "LLM_CRITIC", "RULE_BASED"]
    resolved_value: Any = None
    evidence_snapshot_hash: str = ""
    reason_codes: list[str] = Field(default_factory=list)
    contradiction_details: str | None = None


class IncidentReport(BaseModel):
    """Structured report produced by the LLM Analyst (Agent 08)."""
    incident_id: str
    severity: Severity
    summary: str
    claims: list[AtomicClaim] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    alternative_hypotheses: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    analyst_model: str = "mock-analyst"
    prompt_version: str = "v1.0"
    latency_ms: float = 0.0
    is_fallback: bool = False

    _sev = field_validator("severity", mode="before")(_lower)
    _lists = field_validator("claims", "mitre_techniques", "alternative_hypotheses", "limitations", mode="before")(_as_list)


class ActionProposal(BaseModel):
    """Proposed remediation action with canonical parameters."""
    proposal_id: str = Field(default_factory=lambda: f"act-{uuid.uuid4().hex[:8]}")
    incident_id: str
    action: ActionType
    target: str
    canonical_parameters: dict[str, Any] = Field(default_factory=dict)
    justification: str
    is_disruptive: bool = False
    requires_clinical_authorization: bool = False


class ApprovalRecord(BaseModel):
    """Cryptographically bound one-time approval record."""
    approval_token: str
    proposal_id: str
    action: ActionType
    target: str
    canonical_parameters_hash: str
    evidence_snapshot_hash: str
    policy_version: str = "v1.0"
    approver_id: str
    approver_role: str
    clinical_approver_id: str | None = None
    granted_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    is_consumed: bool = False


class ActionExecution(BaseModel):
    """Complete execution record of a remediation action."""
    execution_id: str = Field(default_factory=lambda: f"exec-{uuid.uuid4().hex[:8]}")
    proposal_id: str
    approval_token: str | None = None
    action: ActionType
    target: str
    state: ActionState
    executed_at: datetime | None = None
    connector_name: str = "dry_run"
    outcome_details: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    provenance: ProvenanceType = Field(default="SIMULATED")


class AuditEvent(BaseModel):
    """Tamper-evident audit log record."""
    event_id: str = Field(default_factory=lambda: f"aud-{uuid.uuid4().hex[:12]}")
    trace_id: str
    incident_id: str
    stage: str
    timestamp: datetime = Field(default_factory=utc_now)
    record_payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    entry_hash: str


class AnalystFeedback(BaseModel):
    """Human analyst evaluation and override record."""
    feedback_id: str = Field(default_factory=lambda: f"fb-{uuid.uuid4().hex[:8]}")
    incident_id: str
    analyst_id: str
    true_label: str | None = None
    perceived_trust: float = Field(ge=1.0, le=5.0)
    clarity_rating: float = Field(ge=1.0, le=5.0)
    verdict_agreed: bool
    action_overridden: bool = False
    time_to_triage_sec: float = Field(ge=0.0)
    notes: str = ""
    recorded_at: datetime = Field(default_factory=utc_now)


# ---------------------------------------------------------------------------
# Backwards-Compatible Models for Existing Pipeline
# ---------------------------------------------------------------------------

class Claim(BaseModel):
    statement: str = Field(description="One factual sentence about the alert.")
    evidence_keys: list[str] = Field(description="Evidence keys (JSON pointers or dotted paths).")
    contradicts: bool = Field(default=False, description="Whether claim contradicts known ground truth evidence")
    contradiction_detail: str = Field(default="", description="Reasoning for contradiction")

    _list = field_validator("evidence_keys", mode="before")(_as_list)


class LedgerClaimRecord(BaseModel):
    claim_id: str = Field(description="Unique claim identifier, e.g. CLM-001")
    statement: str = Field(description="Atomic claim statement")
    evidence_keys: list[str] = Field(default_factory=list, description="Evidence keys cited")
    resolved_values: dict[str, Any] = Field(default_factory=dict, description="Values resolved from evidence")
    grounded: bool = Field(default=True, description="Whether claim is syntactically and semantically grounded")
    verification_status: Literal["SUPPORTED", "UNSUPPORTED", "CONTRADICTED"] = Field(
        default="SUPPORTED", description="Status verified by independent verifier"
    )
    verifier_family: str = Field(default="independent", description="Model family of the verifier")
    verifier_notes: str = Field(default="", description="Detailed verification reasoning")


class ClaimEvidenceLedgerSchema(BaseModel):
    alert_id: str
    claims: list[LedgerClaimRecord] = Field(default_factory=list)
    total_claims: int = 0
    supported_claims: int = 0
    unsupported_claims: int = 0
    contradicted_claims: int = 0
    supported_ratio: float = 0.0
    unsupported_rate: float = 0.0
    mandatory_verification_passed: bool = False
    has_critical_contradiction: bool = False
    disagreements: list[str] = Field(default_factory=list)
    hash_digest: str = ""


class ConformalTriageResult(BaseModel):
    nonconformity_score: float = Field(description="Uncertainty / nonconformity metric s(x)")
    calibrated_threshold: float = Field(description="Conformal threshold lambda_hat bounding expected loss <= alpha")
    target_risk: float = Field(default=0.05, description="Target loss / error level alpha (e.g. 5%)")
    empirical_calibration_risk: float = Field(default=0.0, description="Observed risk on calibration set")
    eligible_for_auto_response: bool = Field(description="True if s(x) <= lambda_hat and certified")
    decision: Literal["AUTO_ELIGIBLE", "ABSTAIN_AND_ESCALATE"] = Field(
        description="Autonomous handling eligibility or mandatory escalation"
    )
    abstain_reason: str = Field(default="", description="Explanation if system abstained from auto-action")
    risk_band: Severity = Field(default="medium", description="Risk priority band")


class ExplanationTrustScoreBreakdown(BaseModel):
    composite_score: float = Field(ge=0.0, le=1.0, description="Overall Explanation Trust Score ETS in [0, 1]")
    faithfulness: float = Field(ge=0.0, le=1.0, description="Top-feature perturbation / deletion drop F(x)")
    cross_explainer_agreement: float = Field(ge=0.0, le=1.0, description="SHAP vs LIME attribution overlap/consistency")
    grounding_ratio: float = Field(ge=0.0, le=1.0, description="Fraction of narrative claims supported by evidence")
    model_certainty: float = Field(ge=0.0, le=1.0, description="Calibrated classifier margin / confidence")
    penalty: float = Field(default=0.0, description="Deductions for prompt-injection or distribution drift")
    weights: dict[str, float] = Field(default_factory=dict, description="Component weights in composite score")


class ContrastiveExplanation(BaseModel):
    target_class: str = Field(description="Baseline or target class, e.g. 'benign'")
    feature: str = Field(description="Key feature required to change")
    current_value: float = Field(description="Observed feature value")
    counterfactual_value: float = Field(description="Value that would alter prediction to target class")
    description: str = Field(description="Human-readable contrastive description")


class AnalystFeedbackRecord(BaseModel):
    alert_id: str
    analyst_id: str
    perceived_trust: float = Field(ge=1.0, le=5.0, description="Likert score 1-5")
    clarity_rating: float = Field(ge=1.0, le=5.0, description="Clarity rating 1-5")
    verdict_agreed: bool = Field(description="Did analyst agree with the system verdict?")
    action_overridden: bool = Field(default=False, description="Did analyst modify proposed actions?")
    time_to_triage_sec: float = Field(ge=0.0, description="Time spent by analyst reviewing alert")
    notes: str = Field(default="", description="Analyst qualitative feedback")


class AnalystReport(BaseModel):
    severity: Severity
    summary: str
    claims: list[Claim] = Field(description="Ordered attack narrative; every claim cites evidence keys.")
    mitre_techniques: list[str] = Field(description="ATT&CK IDs chosen from evidence.candidate_mitre only.")
    alternative_hypotheses: list[str] = Field(
        description="Benign or alternative explanations considered, and why they are less likely.")
    confidence: float = Field(ge=0, le=1)

    _sev = field_validator("severity", mode="before")(_lower)
    _lists = field_validator("claims", "mitre_techniques", "alternative_hypotheses", mode="before")(_as_list)

    @field_validator("mitre_techniques")
    @classmethod
    def _upper_ids(cls, v: list[str]) -> list[str]:
        return [t.strip().upper() for t in v]


class CriticVerdict(BaseModel):
    approved: bool
    unsupported_claims: list[str]
    corrected_severity: Severity
    feedback_for_analyst: str = Field(description="Concrete fixes the analyst must make; empty if approved.")
    reasoning: str

    _sev = field_validator("corrected_severity", mode="before")(_lower)
    _lists = field_validator("unsupported_claims", mode="before")(_as_list)


class ProposedAction(BaseModel):
    action: ActionType
    target: str = Field(description="Exact host or IP value copied from the evidence.")
    justification: str

    _act = field_validator("action", mode="before")(_lower)


class ResponsePlan(BaseModel):
    actions: list[ProposedAction]
    reasoning: str

    _lists = field_validator("actions", mode="before")(_as_list)
