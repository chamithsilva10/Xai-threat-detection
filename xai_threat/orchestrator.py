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
import secrets
import time
from typing import Any

from . import audit
from .agents import (
    AgentTeam,
    AuditFeedbackAgent,
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
    AgentExecutionRecord,
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
    agent_traces: list[AgentExecutionRecord] = field(default_factory=list)

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
            "agent_traces": [t.model_dump() for t in self.agent_traces],
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
        self.detection_agent = DetectionAgent(self.detector) if self.detector else None
        self.explainability_agent = ExplainabilityAgent(self.detector) if self.detector else None
        self.intel_agent = ThreatIntelligenceAgent(self.intel, settings.critical_assets)
        self.triage_agent = RiskScoringAndTriageAgent(
            self.detector.calibrator if self.detector else ThreatDetector().calibrator
        )
        self.orchestration_agent = ResponseOrchestratorAgent(settings.critical_assets)
        self.audit_agent = AuditFeedbackAgent(settings.audit_log)

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
        trace_id = f"trace-{secrets.token_hex(6)}"

        # -------------------------------------------------------------------
        # Agent 01: Data Ingestion Agent
        # -------------------------------------------------------------------
        t0 = time.perf_counter()
        clean, flags = self.ingestion_agent.process(raw)
        dur01 = (time.perf_counter() - t0) * 1000.0

        # -------------------------------------------------------------------
        # Agent 02: Detection Agent & Agent 03: Explainability Agent
        # -------------------------------------------------------------------
        is_flow = is_flow_record(clean)
        t0 = time.perf_counter()
        if is_flow:
            if self.detector is None:
                raise ValueError("A flow record needs the ML detector; none was loaded.")
            det = self.detector.detect(clean)
            dur02 = (time.perf_counter() - t0) * 1000.0
            dur03 = det.inference_latency_ms
        else:
            det = None
            dur02 = 0.0
            dur03 = 0.0

        # -------------------------------------------------------------------
        # Agent 04: Threat Intelligence Agent
        # -------------------------------------------------------------------
        t0 = time.perf_counter()
        if det:
            evidence = self.intel_agent.enrich(clean, det)
        else:
            evidence = self.intel_agent.enrich(clean, None)
        if flags:
            evidence["input_security_flags"] = flags
        dur04 = (time.perf_counter() - t0) * 1000.0

        aid = evidence["alert_id"]

        if det:
            log(f"[{aid}] XGBoost: {det.label} p={det.confidence:.2f} anomaly={det.anomaly_score:.2f} ({det.explainer})")
        if flags:
            log(f"[{aid}] ⚠ prompt-injection patterns in input: {sorted({f['pattern'] for f in flags})}")

        # -------------------------------------------------------------------
        # Agent 05: Risk Scoring & Triage Agent
        # -------------------------------------------------------------------
        t0 = time.perf_counter()
        conformal_res = self.triage_agent.triage(det)
        dur05 = (time.perf_counter() - t0) * 1000.0
        log(
            f"[{aid}] Conformal triage: {conformal_res.decision} "
            f"(s={conformal_res.nonconformity_score:.3f}, limit={conformal_res.calibrated_threshold:.3f})"
        )

        # -------------------------------------------------------------------
        # Agent 08: LLM Analyst & Agent 09: Independent LLM Verifier (Debate Loop)
        # -------------------------------------------------------------------
        ledger = ClaimEvidenceLedger(aid)
        rounds: list[dict] = []
        dur08_total = 0.0
        dur09_total = 0.0

        t_analyst = time.perf_counter()
        report = self.team.analyst(evidence)
        dur08_total += (time.perf_counter() - t_analyst) * 1000.0

        for r in range(self.settings.max_revision_rounds + 1):
            grounding = check_grounding(report, evidence)

            t_critic = time.perf_counter()
            verdict = self.team.critic(evidence, report, grounding, ledger=ledger)
            dur09_total += (time.perf_counter() - t_critic) * 1000.0

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
            t_analyst = time.perf_counter()
            report = self.team.analyst(
                evidence,
                previous=report,
                round_no=r + 1,
                feedback="; ".join(p for p in problems if p),
            )
            dur08_total += (time.perf_counter() - t_analyst) * 1000.0

        severity = final_severity(verdict, det, evidence, self.settings.alert_threshold)

        # -------------------------------------------------------------------
        # Agent 06: Response Orchestration Agent
        # -------------------------------------------------------------------
        t0 = time.perf_counter()
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
        dur06 = (time.perf_counter() - t0) * 1000.0

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

        # -------------------------------------------------------------------
        # Assemble 9 Agent Execution Records
        # -------------------------------------------------------------------
        trace_01 = AgentExecutionRecord(
            agent_id=self.ingestion_agent.agent_id,
            agent_name=self.ingestion_agent.agent_name,
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=round(dur01, 2),
            input_summary={"raw_fields_count": len(raw)},
            output_summary={"injection_flags_count": len(flags)},
        )
        trace_02 = AgentExecutionRecord(
            agent_id="agent_02_detection",
            agent_name="Detection Agent",
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=round(dur02, 2),
            input_summary={"is_flow_record": is_flow},
            output_summary={"predicted_label": det.label if det else "none", "confidence": round(det.confidence, 4) if det else 0.0},
        )
        trace_03 = AgentExecutionRecord(
            agent_id="agent_03_explainability",
            agent_name="Explainability Agent",
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=round(dur03, 2),
            input_summary={"detection_label": det.label if det else "none"},
            output_summary={"xai_method": det.explainer if det else "none", "shap_features": len(shap_attr), "lime_features": len(lime_attr)},
        )
        trace_04 = AgentExecutionRecord(
            agent_id=self.intel_agent.agent_id,
            agent_name=self.intel_agent.agent_name,
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=round(dur04, 2),
            input_summary={"candidate_techniques": len(evidence.get("candidate_mitre", []))},
            output_summary={"host_critical": evidence.get("asset", {}).get("host_is_critical", False), "is_iomt": evidence.get("asset", {}).get("is_iomt", False)},
        )
        trace_05 = AgentExecutionRecord(
            agent_id=self.triage_agent.agent_id,
            agent_name=self.triage_agent.agent_name,
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=round(dur05, 2),
            input_summary={"nonconformity_score": round(conformal_res.nonconformity_score, 4)},
            output_summary={"decision": conformal_res.decision, "eligible_for_auto_response": conformal_res.eligible_for_auto_response},
        )
        trace_08 = AgentExecutionRecord(
            agent_id=self.team.analyst_agent_id,
            agent_name=self.team.analyst_agent_name,
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=round(dur08_total, 2),
            input_summary={"revision_rounds": len(rounds)},
            output_summary={"claims_generated": len(report.claims), "mitre_techniques": report.mitre_techniques},
        )
        trace_09 = AgentExecutionRecord(
            agent_id=self.team.verifier_agent_id,
            agent_name=self.team.verifier_agent_name,
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=round(dur09_total, 2),
            input_summary={"verifier_family": getattr(self.team.verifier_backend, "model_family", "independent_verifier")},
            output_summary={"approved": verdict.approved, "corrected_severity": verdict.corrected_severity, "unsupported_claims": len(verdict.unsupported_claims)},
        )
        trace_06 = AgentExecutionRecord(
            agent_id=self.orchestration_agent.agent_id,
            agent_name=self.orchestration_agent.agent_name,
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=round(dur06, 2),
            input_summary={"proposed_actions": len(plan.actions)},
            output_summary={
                "auto_execute": len(decision.auto_execute),
                "rejected": len(decision.rejected),
                "pending_approval": len(decision.pending_approval),
            },
        )
        trace_07 = AgentExecutionRecord(
            agent_id=self.audit_agent.agent_id,
            agent_name=self.audit_agent.agent_name,
            trace_id=trace_id,
            incident_id=aid,
            duration_ms=0.0,
            input_summary={"incident_id": aid},
            output_summary={"hash_chain_persisted": True},
        )

        all_traces = [trace_01, trace_02, trace_03, trace_04, trace_05, trace_08, trace_09, trace_06, trace_07]

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
            agent_traces=all_traces,
        )
        t_persist = time.perf_counter()
        self._persist(inv)
        trace_07.duration_ms = round((time.perf_counter() - t_persist) * 1000.0, 2)
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
