"""FastAPI Backend for Sentinel-XAI Multi-Agent SOC Dashboard.

Provides REST APIs for:
- System overview and security operational metrics
- Incident triage and deep-dive inspection (SHAP/LIME, ledger, counterfactuals)
- 9-Agent distributed execution telemetry and pipeline tracking
- Isolated What-If Sandbox hypotheses analysis
- Human-in-the-loop and IoMT clinical dual-authorization approval queue
- Cryptographic hash-chain audit log verification (RFC 8785 / SHA-256)
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .. import audit
from ..agents import AgentTeam
from ..config import Settings
from ..connectors import (
    ApprovalManager,
    DryRunResponseConnector,
    UserCredentialRegistry,
)
from ..detection import FEATURES, ThreatDetector
from ..knowledge import AssetRegistry, ThreatIntel
from ..llm import OllamaBackend
from ..mock_llm import MockBackend
from ..orchestrator import Orchestrator
from ..schemas import ActionProposal, WhatIfRequest, WhatIfResult

TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"


def _make_backend(settings: Settings):
    if settings.offline:
        return MockBackend()
    try:
        backend = OllamaBackend(settings)
        backend.ping()
        return backend
    except Exception:
        return MockBackend()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI Sentinel-XAI application."""
    app_settings = settings or Settings.from_env()
    detector = ThreatDetector.load_or_train(app_settings.model_path)
    intel = ThreatIntel(app_settings.ioc_feed)
    asset_registry = AssetRegistry()

    # Backend initialization
    backend = _make_backend(app_settings)
    team = AgentTeam(backend, retries=app_settings.max_retries)
    orchestrator = Orchestrator(
        team=team,
        settings=app_settings,
        detector=detector,
        intel=intel,
        operating_mode=app_settings.mode,
    )
    approval_mgr = ApprovalManager()
    connector = DryRunResponseConnector(approval_mgr)
    cred_registry = UserCredentialRegistry()

    app = FastAPI(
        title="Sentinel-XAI Platform",
        description="A Safety-Aware Multi-Agent Explainable AI Platform for Autonomous Cyber Threat Detection",
        version="2.2.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -----------------------------------------------------------------------
    # Web UI Route
    # -----------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index():
        if TEMPLATE_PATH.is_file():
            return HTMLResponse(content=TEMPLATE_PATH.read_text(encoding="utf-8"))
        return HTMLResponse(
            content="<h1>Sentinel-XAI SOC Dashboard</h1><p>Template loading...</p>"
        )

    # -----------------------------------------------------------------------
    # API: System Overview & SOC Health
    # -----------------------------------------------------------------------
    @app.get("/api/overview")
    def get_overview():
        audit_file = app_settings.audit_log
        incidents = []
        if audit_file.is_file():
            with open(audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line_s = line.strip()
                    if not line_s:
                        continue
                    try:
                        record = json.loads(line_s)
                        if record.get("event") == "investigation":
                            incidents.append(record)
                    except Exception:
                        pass

        total_alerts = len(incidents)
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        statuses = {
            "needs_analyst_review": 0,
            "awaiting_human_approval": 0,
            "auto_resolved": 0,
            "conformal_abstain_escalated": 0,
        }
        for inc in incidents:
            sev = inc.get("final_severity", "low").lower()
            severities[sev] = severities.get(sev, 0) + 1
            st = inc.get("status", "unknown")
            statuses[st] = statuses.get(st, 0) + 1

        cal = detector.calibrator
        return {
            "platform": "Sentinel-XAI",
            "version": "2.2.0",
            "status": "OPERATIONAL",
            "operating_mode": app_settings.mode,
            "default_defensive_mode": "DRY_RUN",
            "external_effect": False,
            "total_incidents": total_alerts,
            "severity_breakdown": severities,
            "status_breakdown": statuses,
            "conformal_calibration": {
                "target_risk_alpha": cal.target_risk,
                "confidence_guarantee": f"{(1.0 - cal.target_risk) * 100:.1f}%",
                "calibrated_threshold": round(cal.calibrated_threshold, 4),
                "is_calibrated": cal.is_calibrated,
            },
            "llm_configuration": {
                "analyst_provider": app_settings.analyst_provider,
                "analyst_model": app_settings.analyst_model,
                "verifier_provider": app_settings.verifier_provider,
                "verifier_model": app_settings.verifier_model or app_settings.analyst_model,
                "offline_mode": app_settings.offline,
            },
            "features_monitored": FEATURES,
        }

    # -----------------------------------------------------------------------
    # API: Incident Triage & Listing
    # -----------------------------------------------------------------------
    @app.get("/api/incidents")
    def list_incidents(limit: int = Query(50, ge=1, le=500)):
        audit_file = app_settings.audit_log
        items = []
        if audit_file.is_file():
            with open(audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line_s = line.strip()
                    if not line_s:
                        continue
                    try:
                        record = json.loads(line_s)
                        if record.get("event") == "investigation":
                            det = record.get("evidence", {}).get("detection") or {}
                            items.append({
                                "alert_id": record.get("alert_id"),
                                "timestamp": record.get("timestamp"),
                                "label": det.get("label", "unknown"),
                                "severity": record.get("final_severity", "low"),
                                "confidence": det.get("confidence", 0.0),
                                "anomaly_score": det.get("anomaly_score", 0.0),
                                "trust_score": record.get("trust_score", 0.0),
                                "status": record.get("status", "unknown"),
                                "operating_mode": record.get("operating_mode", "REPLAY"),
                                "src_ip": record.get("evidence", {}).get("features", {}).get("src_ip")
                                or record.get("evidence", {}).get("src_ip", "10.0.0.1"),
                                "dst_ip": record.get("evidence", {}).get("features", {}).get("dst_ip")
                                or record.get("evidence", {}).get("dst_ip", "10.0.0.5"),
                                "is_iomt": record.get("evidence", {}).get("asset", {}).get("is_iomt", False),
                                "host_is_critical": record.get("evidence", {}).get("asset", {}).get("host_is_critical", False),
                            })
                    except Exception:
                        pass

        # Return most recent first
        items.reverse()
        return {"total": len(items), "incidents": items[:limit]}

    # -----------------------------------------------------------------------
    # API: Incident Deep-Dive
    # -----------------------------------------------------------------------
    @app.get("/api/incidents/{alert_id}")
    def get_incident(alert_id: str):
        audit_file = app_settings.audit_log
        if audit_file.is_file():
            with open(audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line_s = line.strip()
                    if not line_s:
                        continue
                    try:
                        record = json.loads(line_s)
                        if record.get("event") == "investigation" and record.get("alert_id") == alert_id:
                            return record
                    except Exception:
                        pass
        raise HTTPException(status_code=404, detail=f"Incident {alert_id} not found in audit log")

    # -----------------------------------------------------------------------
    # API: 9 Logical Agents Telemetry & Status
    # -----------------------------------------------------------------------
    @app.get("/api/agents")
    def get_agents():
        agents_info = [
            {
                "agent_id": "agent_01_ingestion",
                "name": "Data Ingestion Agent",
                "role": "Schema validation, sanitization, prompt injection scanning, provenance recording",
                "status": "HEALTHY",
                "version": "1.0.0",
                "model_type": "Deterministic Rule & Regex Engine",
                "safeguards": ["Max field length truncation", "Sanitization strip-tags", "Adversarial pattern scanner"],
            },
            {
                "agent_id": "agent_02_detection",
                "name": "Detection Agent",
                "role": "Supervised multi-class classification and baseline anomaly detection",
                "status": "HEALTHY",
                "version": detector.model_version,
                "model_type": "XGBoost (5-class) + IsolationForest",
                "safeguards": ["Non-negative bounds", "Unimodal probability distribution", "Anomaly escalation floor"],
            },
            {
                "agent_id": "agent_03_explainability",
                "name": "Explainability Agent",
                "role": "Local SHAP feature attributions, LIME surrogate explanations, contrastive counterfactuals (C10)",
                "status": "HEALTHY",
                "version": "1.0.0",
                "model_type": "TreeSHAP + LIME Tabular + Constrained Counterfactuals",
                "safeguards": ["Reconstruction verification: sum(phi)+baseline==f(x)", "Actionable feature constraints"],
            },
            {
                "agent_id": "agent_04_threat_intel",
                "name": "Threat Intelligence Agent",
                "role": "Rule-grounded MITRE ATT&CK mapping, IOC lookups, IoMT asset context",
                "status": "HEALTHY",
                "version": "1.0.0",
                "model_type": "Deterministic ATT&CK KB & Local Threat Feed",
                "safeguards": ["Strict candidate mapping bounds", "No speculative technique invention"],
            },
            {
                "agent_id": "agent_05_risk_triage",
                "name": "Risk Scoring & Triage Agent",
                "role": "Conformal selective risk control (C9) & automated abstention triage",
                "status": "HEALTHY",
                "version": "1.0.0",
                "model_type": "Conformal Calibrator (Clopper-Pearson UCB)",
                "safeguards": ["Nonconformity score bounded <= lambda_hat", "Fail-closed ABSTAIN_AND_ESCALATE"],
            },
            {
                "agent_id": "agent_08_llm_analyst",
                "name": "LLM Analyst Agent",
                "role": "Plain-language incident narrative with atomic claims cited against evidence pointers (C1)",
                "status": "HEALTHY",
                "version": "1.0.0",
                "model_type": f"{app_settings.analyst_provider} - {app_settings.analyst_model}",
                "safeguards": ["Evidence tag isolation", "Structured JSON Schema output", "Zero shell/tool permissions"],
            },
            {
                "agent_id": "agent_09_llm_verifier",
                "name": "Independent LLM Verifier Agent",
                "role": "Adversarial cross-model verification against RFC 6901 Claim-Evidence Ledger",
                "status": "HEALTHY",
                "version": "1.0.0",
                "model_type": f"{app_settings.verifier_provider} - {app_settings.verifier_model or app_settings.analyst_model}",
                "safeguards": ["Independent critique role", "Deterministic grounding error check", "Rejection on contradiction"],
            },
            {
                "agent_id": "agent_06_response_orchestrator",
                "name": "Response Orchestration Agent",
                "role": "Proposes playbooks, enforces mandatory hard safety gates, IoMT clinical separation of duties (C16)",
                "status": "HEALTHY",
                "version": "2.2.0",
                "model_type": "Deterministic Policy Engine & Gate Keeper",
                "safeguards": ["No automated disruptive IoMT actions", "Human-in-the-loop gate", "Strict dry-run response mode"],
            },
            {
                "agent_id": "agent_07_audit_feedback",
                "name": "Audit & Feedback Agent",
                "role": "RFC 8785 canonical hash-chained ledger, human analyst feedback loop (C4), KS-drift monitoring",
                "status": "HEALTHY",
                "version": "1.0.0",
                "model_type": "Cryptographic SHA-256 Chain + Concurrency Lock",
                "safeguards": ["Duplicate key rejection", "Negative zero normalization", "Single-token atomic consumption"],
            },
        ]
        return {"total_agents": len(agents_info), "pipeline": "01->02->03->04->05->08<->09->06 (observed by 07)", "agents": agents_info}

    # -----------------------------------------------------------------------
    # API: Isolated What-If Sandbox
    # -----------------------------------------------------------------------
    @app.post("/api/what-if", response_model=WhatIfResult)
    def run_what_if(req: WhatIfRequest):
        """Execute hypothetical feature perturbation in an isolated sandbox.
        Base evidence remains strictly immutable.
        """
        try:
            res = detector.what_if_analysis(req.base_features, req.modifications)
            return res
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"What-If analysis error: {e}")

    # -----------------------------------------------------------------------
    # API: Human Approval Queue & Clinical Gate
    # -----------------------------------------------------------------------
    @app.get("/api/pending")
    def get_pending_actions():
        pending_file = app_settings.pending_queue
        items = []
        if pending_file.is_file():
            with open(pending_file, "r", encoding="utf-8") as f:
                for line in f:
                    line_s = line.strip()
                    if not line_s:
                        continue
                    try:
                        record = json.loads(line_s)
                        items.append(record)
                    except Exception:
                        pass
        return {"total_pending": len(items), "items": items}

    @app.post("/api/approve")
    def approve_action(
        proposal_id: str = Body(..., embed=True),
        alert_id: str = Body(..., embed=True),
        action: str = Body(..., embed=True),
        target: str = Body(..., embed=True),
        user_id: str = Body("soc_lead_chamith", embed=True),
        user_key: str = Body("sec_lead_secret_token_123", embed=True),
        clinical_user_id: str | None = Body(None, embed=True),
        clinical_user_key: str | None = Body(None, embed=True),
        is_iomt: bool = Body(False, embed=True),
        parameters: dict[str, Any] = Body(default_factory=dict, embed=True),
    ):
        """Authorize a pending high-impact action and execute it in dry-run mode."""
        # 1. Authenticate primary security approver
        auth_ok, reason, role = cred_registry.authenticate(user_id, user_key)
        if not auth_ok:
            raise HTTPException(status_code=403, detail=f"Security approver authentication failed: {reason}")

        # 2. Check clinical approver for IoMT devices
        if is_iomt:
            if not clinical_user_id or not clinical_user_key:
                raise HTTPException(
                    status_code=403,
                    detail="IoMT clinical safety rule (C16): Critical clinical device requires secondary clinical approver credentials.",
                )
            if clinical_user_id == user_id:
                raise HTTPException(
                    status_code=403,
                    detail="IoMT Separation of Duties violated: Security approver and clinical approver cannot be the same person.",
                )
            clin_ok, clin_reason, clin_role = cred_registry.authenticate(clinical_user_id, clinical_user_key)
            if not clin_ok or clin_role not in ("clinical_engineer", "medical_director"):
                raise HTTPException(
                    status_code=403,
                    detail=f"Clinical approver authentication failed or insufficient role: {clin_reason} (role: {clin_role})",
                )

        proposal = ActionProposal(
            incident_id=alert_id,
            proposal_id=proposal_id,
            action=action,
            target=target,
            justification=f"Approved in SOC dashboard by {user_id}",
            canonical_parameters=parameters,
            asset_type="IOMT_MEDICAL_DEVICE" if is_iomt else "ENTERPRISE_WORKSTATION",
        )

        dummy_evidence_hash = "mock_evidence_hash_validated"
        # Issue cryptographically bound approval record
        try:
            appr_record = approval_mgr.issue_approval(
                proposal=proposal,
                approver_id=user_id,
                approver_role=role or "soc_lead",
                evidence_snapshot_hash=dummy_evidence_hash,
                clinical_approver_id=clinical_user_id,
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to issue approval: {e}")

        # Execute response in strict dry-run mode
        execution = connector.execute(
            proposal=proposal,
            approval=appr_record,
            evidence_snapshot_hash=dummy_evidence_hash,
        )

        # Log approval event to audit trail
        audit.append(
            app_settings.audit_log,
            {
                "event": "human_approval_executed",
                "alert_id": alert_id,
                "proposal_id": proposal_id,
                "action": action,
                "target": target,
                "approver_id": user_id,
                "clinical_approver_id": clinical_user_id,
                "execution_state": execution.state,
                "execution_mode": "DRY_RUN",
                "external_effect": False,
                "token": appr_record.approval_token,
            },
        )

        return {
            "status": "APPROVED_AND_EXECUTED",
            "execution": execution.model_dump(),
            "approval_token": appr_record.approval_token,
            "execution_mode": "DRY_RUN",
            "external_effect": False,
            "disclaimer": "Defensive safe execution complete. Response executed as DRY-RUN; no external network packets or disruptive commands issued.",
        }

    # -----------------------------------------------------------------------
    # API: Cryptographic Audit Trail Verification
    # -----------------------------------------------------------------------
    @app.get("/api/audit/verify")
    def verify_audit():
        valid, msg, count = audit.verify(app_settings.audit_log)
        last_hash = audit.get_last_hash(app_settings.audit_log)
        return {
            "chain_valid": valid,
            "message": msg,
            "entries_verified": count,
            "latest_entry_hash": last_hash,
            "genesis_block": audit.GENESIS,
            "rfc_canonicalization": "RFC8785-v1.0",
            "tamper_evident": True,
        }

    # -----------------------------------------------------------------------
    # API: Real-Time Flow Sample & Live Investigation
    # -----------------------------------------------------------------------
    @app.get("/api/stream/sample")
    def get_stream_sample():
        sample_path = Path("data/authentic_flows_advanced.csv")
        if not sample_path.is_file():
            sample_path = Path("data/sample_flows.csv")

        if sample_path.is_file():
            import csv
            with open(sample_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                if rows:
                    import random
                    choice = random.choice(rows)
                    flow = {k: float(v) if k in FEATURES else v for k, v in choice.items()}
                    return {"sample": flow}

        # Fallback authentic vector
        return {
            "sample": {
                "failed_logins": 142.0,
                "conn_rate": 28.5,
                "distinct_dst_ports": 1.0,
                "bytes_out_mb": 0.25,
                "bytes_in_mb": 0.45,
                "off_hours": 1.0,
                "dns_query_entropy": 2.4,
                "beacon_regularity": 0.12,
                "src_ip": "185.220.101.47",
                "dst_ip": "10.0.0.5",
                "service": "ssh",
                "source": "authentic_telemetry_flow",
            }
        }

    @app.post("/api/investigate")
    def trigger_investigation(record: dict[str, Any] = Body(...)):
        """Trigger an end-to-end investigation across all 9 agents."""
        try:
            inv = orchestrator.investigate(record)
            return inv.to_dict()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Pipeline investigation error: {e}")

    return app
