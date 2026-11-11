"""Nine-Agent Pipeline Orchestration:

  01 Data Ingestion Agent       (sanitize + injection scan + schema provenance)
         │
  02 Detection Agent            (XGBoost classifier + IsolationForest anomaly)
         │
  03 Explainability Agent       (SHAP + LIME attributions + C10 contrastive)
         │
  04 Threat Intelligence Agent  (rule-grounded ATT&CK mapping + IOC enrichment)
         │
  05 Risk Scoring & Triage Agent(C9 Conformal Risk-Controlled Abstention)
         │
  08 LLM Analyst Agent ◄──────► 09 Independent LLM Verifier Agent (Debate loop + C1 Ledger)
         │
  06 Response Orchestrator Agent(policy gate + C16 IoMT safeguards + SOAR playbooks)
         │
  07 Audit & Feedback Agent     (hash-chained ledger log + C4 feedback + C13 Trust Score)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import audit
from .agents import (
    AgentTeam,
    DataIngestionAgent,
    DetectionAgent,
    ExplainabilityAgent,
    ResponseOrchestratorAgent,
    RiskScoringAndTriageAgent,
    ThreatIntelligenceAgent,
)
from .config import Settings
from .connectors import ApprovalManager, DryRunResponseConnector
from .detection import Detection, ThreatDetector
from .evidence import build_evidence, is_flow_record, normalize_prebuilt
from .knowledge import AssetRegistry, LABEL_BASE_SEVERITY, SEVERITY_ORDER, ThreatIntel, severity_rank
from .ledger import ClaimEvidenceLedger
from .safety import (
    GroundingResult,
    PolicyDecision,
    check_grounding,
    enforce_policy,
    sanitize,
    scan_injection,
)
from .schemas import (
    ActionProposal,
    AnalystFeedbackRecord,
    AnalystReport,
    ConformalTriageResult,
    CriticVerdict,
    ExplanationTrustScoreBreakdown,
    OperatingMode,
    ProvenanceType,
    ResponsePlan,
)
from .trust_score import calculate_explanation_trust_score


@dataclass
class Investigation:
    alert_id: str
    evidence: dict
    detection: Detection | None
    conformal: ConformalTriageResult
    ledger: ClaimEvidenceLedger
    trust_breakdown: ExplanationTrustScoreBreakdown
    report: AnalystReport
    verdict: CriticVerdict
    grounding: GroundingResult
    plan: ResponsePlan
    decision: PolicyDecision
    final_severity: str
    trust_score: float
    status: str
    rounds: list[dict] = field(default_factory=list)
    injection_flags: list[dict] = field(default_factory=list)
    telemetry: list[dict] = field(default_factory=list)
    backend: str = ""
    operating_mode: OperatingMode = "REPLAY"
    telemetry_provenance: ProvenanceType = "SIMULATED"
    intel_provenance: ProvenanceType = "SIMULATED"
    action_provenance: ProvenanceType = "SIMULATED"

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "status": self.status,
            "backend": self.backend,
            "operating_mode": self.operating_mode,
            "provenance": {
                "telemetry": self.telemetry_provenance,
                "intel": self.intel_provenance,
                "action": self.action_provenance,
            },
            "final_severity": self.final_severity,
            "trust_score": self.trust_score,
            "trust_breakdown": self.trust_breakdown.model_dump(),
            "conformal_triage": self.conformal.model_dump(),
            "claim_evidence_ledger": self.ledger.to_dict(),
            "evidence": self.evidence,
            "report": self.report.model_dump(),
            "verdict": self.verdict.model_dump(),
            "grounding": {"errors": self.grounding.errors, "warnings": self.grounding.warnings},
            "plan": self.plan.model_dump(),
            "policy": self.decision.to_dict(),
            "debate_rounds": self.rounds,
            "injection_flags": self.injection_flags,
            "telemetry": self.telemetry,
        }


def final_severity(
    verdict: CriticVerdict,
    detection: Detection | None,
    evidence: dict,
    threshold: float,
) -> str:
    """Critic's severity, with deterministic floors preventing injection from talking down alerts."""
    sev = severity_rank(verdict.corrected_severity)
    if detection and detection.label != "benign" and detection.confidence >= threshold:
        sev = max(sev, severity_rank(LABEL_BASE_SEVERITY.get(detection.label, "medium")) - 1)
    asset = evidence.get("asset") or {}
    if (asset.get("host_is_critical") or asset.get("is_iomt")) and detection and detection.label != "benign":
        sev = max(sev, severity_rank("high"))
    if evidence.get("input_security_flags"):
        sev = max(sev, severity_rank("medium"))
    return SEVERITY_ORDER[sev]


class Orchestrator:
    """Executes the Nine-Agent Architecture across detection, explanation, risk control, and response."""

    def __init__(
        self,
        team: AgentTeam,
        settings: Settings,
        detector: ThreatDetector | None = None,
        intel: ThreatIntel | None = None,
        operating_mode: OperatingMode = "REPLAY",
    ):
        self.team = team
        self.settings = settings
        self.detector = detector
        self.intel = intel or ThreatIntel(settings.ioc_feed)
        self.operating_mode = operating_mode
        self.asset_registry = AssetRegistry()
        self.approval_manager = ApprovalManager()
        self.connector = DryRunResponseConnector(self.approval_manager)

        # Initialize explicit functional agents
        self.ingestion_agent = DataIngestionAgent(max_field_len=settings.max_field_len)
        self.intel_agent = ThreatIntelligenceAgent(self.intel, settings.critical_assets)
        self.triage_agent = RiskScoringAndTriageAgent(
            self.detector.calibrator if self.detector else ThreatDetector().calibrator
        )
        self.orchestration_agent = ResponseOrchestratorAgent(settings.critical_assets)

    def build_evidence(self, raw: dict) -> tuple[dict, Detection | None, list[dict]]:
        clean, flags = self.ingestion_agent.process(raw)
        if is_flow_record(clean):
            if self.detector is None:
                raise ValueError("A flow record needs the ML detector; none was loaded.")
            det = self.detector.detect(clean)
            evidence = self.intel_agent.enrich(clean, det)
        else:
            det = None
            evidence = self.intel_agent.enrich(clean, None)

        if flags:
            evidence["input_security_flags"] = flags
        return evidence, det, flags

    def investigate(self, raw: dict, log: callable = lambda *_: None) -> Investigation:
        self.team.telemetry = []
        evidence, det, flags = self.build_evidence(raw)
        aid = evidence["alert_id"]

        if det:
            log(f"[{aid}] XGBoost: {det.label} p={det.confidence:.2f} anomaly={det.anomaly_score:.2f} ({det.explainer})")
        if flags:
            log(f"[{aid}] ⚠ prompt-injection patterns in input: {sorted({f['pattern'] for f in flags})}")

        # Agent 05: Risk scoring & conformal abstention triage (C9)
        conformal_res = self.triage_agent.triage(det)
        log(
            f"[{aid}] Conformal triage: {conformal_res.decision} "
            f"(s={conformal_res.nonconformity_score:.3f}, limit={conformal_res.calibrated_threshold:.3f})"
        )

        # Agent 08 (Analyst) and Agent 09 (Verifier) debate loop with C1 Claim-Evidence Ledger
        ledger = ClaimEvidenceLedger(aid)
        rounds: list[dict] = []
        report = self.team.analyst(evidence)

        for r in range(self.settings.max_revision_rounds + 1):
            grounding = check_grounding(report, evidence)
            verdict = self.team.critic(evidence, report, grounding, ledger=ledger)
            ledger.register_claims(
                claims=report.claims,
                evidence=evidence,
                verdict=verdict,
                verifier_family=getattr(self.team.verifier_backend, "model_family", "independent_verifier"),
                round_no=r,
            )

            rounds.append({
                "round": r,
                "grounding_errors": grounding.errors,
                "critic_approved": verdict.approved,
                "unsupported_claims": verdict.unsupported_claims,
                "ledger_supported_ratio": ledger.supported_ratio,
            })
            log(
                f"[{aid}] round {r}: grounding errors={len(grounding.errors)} "
                f"critic={'APPROVED' if verdict.approved else 'REJECTED'} "
                f"ledger_grounding={ledger.supported_ratio * 100:.1f}%"
            )

            if (verdict.approved and grounding.ok) or r == self.settings.max_revision_rounds:
                break

            problems = grounding.errors + verdict.unsupported_claims + [verdict.feedback_for_analyst]
            report = self.team.analyst(
                evidence,
                previous=report,
                round_no=r + 1,
                feedback="; ".join(p for p in problems if p),
            )

        severity = final_severity(verdict, det, evidence, self.settings.alert_threshold)

        # Agent 06: Response Orchestrator Agent proposing plan and enforcing policy
        plan = self.team.responder(evidence, report, verdict)
        decision = self.orchestration_agent.enforce(
            plan=plan,
            evidence=evidence,
            severity=severity,
            critic_approved=verdict.approved,
            grounded=grounding.ok,
            flags=flags,
            conformal_result=conformal_res,
            ledger=ledger,
        )

        # C13: Composite Explanation Trust Score (ETS)
        shap_attr = det.attributions if det else []
        lime_attr = det.lime_attributions if det else []
        trust_breakdown = calculate_explanation_trust_score(
            detector=self.detector,
            raw_record=evidence,
            detection_label=det.label if det else "unknown",
            class_probabilities=det.class_probabilities if det else {},
            shap_attributions=shap_attr,
            lime_attributions=lime_attr,
            ledger=ledger,
            grounding_warnings=grounding.warnings,
            injection_flags=flags,
        )
        trust_score_val = trust_breakdown.composite_score

        # Status determination
        if not (verdict.approved and grounding.ok):
            status = "needs_analyst_review"
        elif not conformal_res.eligible_for_auto_response:
            status = "conformal_abstain_escalated"
        elif decision.pending_approval:
            status = "awaiting_human_approval"
        else:
            status = "auto_resolved"

        # Determine provenance
        telemetry_prov: ProvenanceType = "REAL" if "real" in str(raw.get("source", "")) else "SIMULATED"
        intel_prov: ProvenanceType = getattr(self.intel, "provenance", "SIMULATED")

        inv = Investigation(
            alert_id=aid,
            evidence=evidence,
            detection=det,
            conformal=conformal_res,
            ledger=ledger,
            trust_breakdown=trust_breakdown,
            report=report,
            verdict=verdict,
            grounding=grounding,
            plan=plan,
            decision=decision,
            final_severity=severity,
            trust_score=trust_score_val,
            status=status,
            rounds=rounds,
            injection_flags=flags,
            telemetry=list(self.team.telemetry),
            backend=getattr(self.team.backend, "name", "unknown"),
            operating_mode=self.operating_mode,
            telemetry_provenance=telemetry_prov,
            intel_provenance=intel_prov,
            action_provenance="SIMULATED",
        )
        self._persist(inv)
        return inv

    def _persist(self, inv: Investigation) -> None:
        """Agent 07: Cryptographic hash-chained audit logging."""
        audit.append(self.settings.audit_log, {"event": "investigation", **inv.to_dict()})
        if inv.decision.pending_approval:
            self.settings.pending_queue.parent.mkdir(parents=True, exist_ok=True)
            with open(self.settings.pending_queue, "a", encoding="utf-8") as f:
                for item in inv.decision.pending_approval:
                    f.write(
                        json.dumps({
                            "alert_id": inv.alert_id,
                            "severity": inv.final_severity,
                            "status": "pending",
                            **item,
                        })
                        + "\n"
                    )

    def record_feedback(self, feedback: AnalystFeedbackRecord) -> None:
        """C4: Records human analyst feedback, trust ratings, and response overrides."""
        audit.append(self.settings.audit_log, {"event": "analyst_feedback", **feedback.model_dump()})
