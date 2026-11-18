"""Comprehensive Verification Tests for Sentinel-XAI Platform.

Covers:
- Section 6 & 8: Nine named functional agents execution traces
- Section 12: Dual-LLM independent configuration and epistemic roles
- Section 16: Isolated What-If Sandbox analysis with strict bounds and immutability
- Section 15: Statistical drift monitoring via Kolmogorov-Smirnov test
- Section 10: Claim-Evidence Ledger (C1) with claim types and expected value checks
- Section 16: FastAPI SOC Dashboard endpoints and IoMT clinical approval gating
- Section 17: 6-Configuration Comparative Evaluation ablation suite
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from xai_threat.agents import (
    AgentTeam,
    AuditFeedbackAgent,
    DataIngestionAgent,
    DetectionAgent,
    ExplainabilityAgent,
    ResponseOrchestratorAgent,
    RiskScoringAndTriageAgent,
    ThreatIntelligenceAgent,
)
from xai_threat.config import Settings
from xai_threat.detection import FEATURES, ThreatDetector, generate_synthetic
from xai_threat.eval import evaluate_comparative_configurations
from xai_threat.mock_llm import MockBackend
from xai_threat.orchestrator import Orchestrator
from xai_threat.schemas import Claim, WhatIfRequest
from xai_threat.web.app import create_app


@pytest.fixture
def test_settings(tmp_path):
    return Settings.from_env(
        audit_log=tmp_path / "test_audit.jsonl",
        pending_queue=tmp_path / "test_pending.jsonl",
        model_path=tmp_path / "test_model.joblib",
        offline=True,
    )


@pytest.fixture
def trained_detector(tmp_path):
    det = ThreatDetector()
    X, y = generate_synthetic(n_per_class=100)
    det.fit(X, y)
    return det


def test_nine_named_agents_traces_recorded(test_settings, trained_detector):
    """Verify that all nine functional agents record typed execution traces in every investigation."""
    team = AgentTeam(MockBackend())
    orch = Orchestrator(team, test_settings, trained_detector)

    flow = {
        "flow_id": "test-trace-01",
        "features": {
            "failed_logins": 140.0,
            "conn_rate": 30.0,
            "distinct_dst_ports": 2.0,
            "bytes_out_mb": 0.5,
            "bytes_in_mb": 0.5,
            "off_hours": 1.0,
            "dns_query_entropy": 2.5,
            "beacon_regularity": 0.1,
        },
    }

    inv = orch.investigate(flow)
    assert len(inv.agent_traces) == 9

    agent_ids = [t.agent_id for t in inv.agent_traces]
    expected_agents = [
        "agent_01_ingestion",
        "agent_02_detection",
        "agent_03_explainability",
        "agent_04_threat_intel",
        "agent_05_risk_triage",
        "agent_08_llm_analyst",
        "agent_09_llm_verifier",
        "agent_06_response_orchestrator",
        "agent_07_audit_feedback",
    ]
    assert agent_ids == expected_agents

    for trace in inv.agent_traces:
        assert trace.status == "SUCCESS"
        assert trace.incident_id == inv.alert_id
        assert trace.duration_ms >= 0.0
        assert isinstance(trace.input_summary, dict)
        assert isinstance(trace.output_summary, dict)

    # Check serialization includes traces
    inv_dict = inv.to_dict()
    assert "agent_traces" in inv_dict
    assert len(inv_dict["agent_traces"]) == 9


def test_dual_llm_independent_configuration():
    """Verify Section 12: Dual-LLM roles are independently configured."""
    settings = Settings.from_env()
    assert hasattr(settings, "analyst_provider")
    assert hasattr(settings, "analyst_model")
    assert hasattr(settings, "verifier_provider")
    assert hasattr(settings, "verifier_model")

    team = AgentTeam(
        backend=MockBackend(model_family="family_analyst"),
        verifier_backend=MockBackend(model_family="family_verifier"),
    )
    assert team.analyst_agent_id == "agent_08_llm_analyst"
    assert team.verifier_agent_id == "agent_09_llm_verifier"
    assert team.backend.model_family == "family_analyst"
    assert team.verifier_backend.model_family == "family_verifier"


def test_what_if_sandbox_immutability_and_bounds(trained_detector):
    """Verify Section 16: Isolated What-If Sandbox evaluates hypothetical shifts
    without mutating base evidence and enforces strict domain bounds.
    """
    base_features = {
        "failed_logins": 150.0,
        "conn_rate": 35.0,
        "distinct_dst_ports": 2.0,
        "bytes_out_mb": 0.8,
        "bytes_in_mb": 0.5,
        "off_hours": 1.0,
        "dns_query_entropy": 2.5,
        "beacon_regularity": 0.15,
    }
    base_copy = dict(base_features)

    # Test perturbation flipping brute force to benign
    res = trained_detector.what_if_analysis(
        base_features=base_features,
        modifications={"failed_logins": 0.0, "conn_rate": 2.0},
    )

    # Immutability: base_features dict must not have been mutated
    assert base_features == base_copy
    assert res.original_label == "ssh_bruteforce"
    assert res.new_label == "benign"
    assert res.decision_changed is True
    assert "HYPOTHETICAL_SANDBOX_ANALYSIS" in res.disclaimer
    assert len(res.top_attribution_changes) > 0

    # Bounds check: beacon_regularity bounded in [0, 1]
    res_bounds = trained_detector.what_if_analysis(
        base_features=base_features,
        modifications={"beacon_regularity": 5.0, "failed_logins": -20.0},
    )
    assert res_bounds.modified_features["beacon_regularity"]["modified"] == 1.0
    assert res_bounds.modified_features["failed_logins"]["modified"] == 0.0


def test_statistical_drift_monitoring(trained_detector):
    """Verify Section 15: Statistical drift monitor detects feature shifts via KS test."""
    # 1. Normal batch matching baseline distribution
    ref_samples = trained_detector._training_sample_X[:30]
    normal_flows = [
        {feat: float(ref_samples[i, j]) for j, feat in enumerate(FEATURES)}
        for i in range(len(ref_samples))
    ]
    normal_drift = trained_detector.compute_drift(normal_flows)
    assert normal_drift.sample_size == 30
    assert normal_drift.status in ("NORMAL", "DRIFT_WARNING")

    # 2. Heavily drifted batch (e.g. massive data exfiltration shift)
    drifted_flows = [
        {
            "failed_logins": 0.0,
            "conn_rate": 100.0,
            "distinct_dst_ports": 500.0,
            "bytes_out_mb": 999.0,
            "bytes_in_mb": 1.0,
            "off_hours": 1.0,
            "dns_query_entropy": 5.8,
            "beacon_regularity": 0.95,
        }
        for _ in range(50)
    ]
    heavy_drift = trained_detector.compute_drift(drifted_flows)
    assert heavy_drift.sample_size == 50
    assert heavy_drift.drift_detected is True
    assert heavy_drift.status in ("DRIFT_WARNING", "CALIBRATION_INVALIDATED")


def test_claim_evidence_ledger_types_and_expected_values(test_settings, trained_detector):
    """Verify Section 10: Claim-Evidence Ledger (C1) validates claim_type and flags expected value mismatches."""
    from xai_threat.ledger import ClaimEvidenceLedger

    ledger = ClaimEvidenceLedger("ALRT-TEST-C1")
    evidence = {
        "alert_id": "ALRT-TEST-C1",
        "features": {"failed_logins": 140, "conn_rate": 28.5},
        "detection": {"label": "ssh_bruteforce", "confidence": 0.98},
    }

    # Claim with expected value matching
    c_valid = Claim(
        claim_id="CLM-01",
        claim_type="observed_fact",
        statement="Failed authentication count is 140",
        evidence_pointers=["/features/failed_logins"],
        expected_values=[140],
    )

    # Claim with expected value mismatching resolved evidence
    c_mismatch = Claim(
        claim_id="CLM-02",
        claim_type="observed_fact",
        statement="Failed authentication count was only 5",
        evidence_pointers=["/features/failed_logins"],
        expected_values=[5],
    )

    ledger.register_claims([c_valid, c_mismatch], evidence)
    assert ledger.total_claims == 2
    assert ledger.claims[0].verification_status == "SUPPORTED"
    assert ledger.claims[0].claim_type == "observed_fact"

    assert ledger.claims[1].verification_status == "CONTRADICTED"
    assert "Expected value mismatch" in ledger.claims[1].verifier_notes
    assert ledger.has_critical_contradiction is True


def test_soc_dashboard_fastapi_endpoints(test_settings):
    """Verify Section 16: SOC dashboard API endpoints operate properly."""
    app = create_app(test_settings)
    client = TestClient(app)

    # 1. UI Root
    r_ui = client.get("/")
    assert r_ui.status_code == 200
    assert "SENTINEL-XAI" in r_ui.text

    # 2. Overview
    r_ov = client.get("/api/overview")
    assert r_ov.status_code == 200
    ov_data = r_ov.json()
    assert ov_data["platform"] == "Sentinel-XAI"
    assert ov_data["status"] == "OPERATIONAL"

    # 3. Agents Map
    r_ag = client.get("/api/agents")
    assert r_ag.status_code == 200
    ag_data = r_ag.json()
    assert ag_data["total_agents"] == 9

    # 4. What-If Sandbox
    r_wi = client.post("/api/what-if", json={
        "flow_id": "test-wi",
        "base_features": {
            "failed_logins": 140, "conn_rate": 30, "distinct_dst_ports": 2,
            "bytes_out_mb": 0.5, "bytes_in_mb": 0.5, "off_hours": 1,
            "dns_query_entropy": 2.5, "beacon_regularity": 0.1,
        },
        "modifications": {"failed_logins": 0},
    })
    assert r_wi.status_code == 200
    assert r_wi.json()["original_label"] == "ssh_bruteforce"
    assert r_wi.json()["new_label"] == "benign"

    # 5. Audit Hash Chain Verification
    r_aud = client.get("/api/audit/verify")
    assert r_aud.status_code == 200
    assert "chain_valid" in r_aud.json()


def test_iomt_dual_role_clinical_approval_gate(test_settings):
    """Verify Section 8, 9, 14, and C16: IoMT clinical assets strictly enforce dual-role separation of duties."""
    app = create_app(test_settings)
    client = TestClient(app)

    # 1. Attempt IoMT authorization without clinical approver -> Must Fail 403
    r_fail = client.post("/api/approve", json={
        "proposal_id": "PROP-IOMT-01",
        "alert_id": "ALRT-IOMT-01",
        "action": "isolate_host",
        "target": "10.0.0.10",
        "user_id": "soc_lead_chamith",
        "user_key": "sec_lead_secret_token_123",
        "is_iomt": True,
    })
    assert r_fail.status_code == 403
    assert "requires secondary clinical approver" in r_fail.json()["detail"]

    # 2. Attempt IoMT authorization where security and clinical approver are identical -> Must Fail 403 (Separation of Duties)
    r_same = client.post("/api/approve", json={
        "proposal_id": "PROP-IOMT-02",
        "alert_id": "ALRT-IOMT-02",
        "action": "isolate_host",
        "target": "10.0.0.10",
        "user_id": "soc_lead_chamith",
        "user_key": "sec_lead_secret_token_123",
        "clinical_user_id": "soc_lead_chamith",
        "clinical_user_key": "sec_lead_secret_token_123",
        "is_iomt": True,
    })
    assert r_same.status_code == 403
    assert "Separation of Duties violated" in r_same.json()["detail"]

    # 3. Legitimate dual authorization with independent clinical engineer -> Succeeded
    r_ok = client.post("/api/approve", json={
        "proposal_id": "PROP-IOMT-03",
        "alert_id": "ALRT-IOMT-03",
        "action": "isolate_host",
        "target": "10.0.0.10",
        "user_id": "soc_lead_chamith",
        "user_key": "sec_lead_secret_token_123",
        "clinical_user_id": "dr_sarah_clinical",
        "clinical_user_key": "clin_eng_secret_token_789",
        "is_iomt": True,
    })
    assert r_ok.status_code == 200
    res = r_ok.json()
    assert res["status"] == "APPROVED_AND_EXECUTED"
    assert res["execution_mode"] == "DRY_RUN"
    assert res["external_effect"] is False
    assert res["approval_token"].startswith("APPR-HMAC-")


def test_six_configuration_comparative_ablation(test_settings):
    """Verify Section 17: Evaluates 6 comparative configurations across latency, hallucinations, and risk guarantees."""
    report = evaluate_comparative_configurations(test_settings, n_samples=6)
    expected_configs = [
        "config_1_detection_only",
        "config_2_detection_xai",
        "config_3_single_llm",
        "config_4_dual_llm_no_ledger",
        "config_5_full_with_ledger",
        "config_6_full_safety_gated",
    ]
    for c in expected_configs:
        assert c in report
        assert "latency_ms" in report[c]
        assert "hallucination_rate" in report[c]
        assert "selective_risk_bounded" in report[c]

    # Verify key hypotheses:
    # 1. Config 3 (Single LLM) has non-zero hallucination rate
    assert report["config_3_single_llm"]["hallucination_rate"] > 0.0

    # 2. Config 5 & 6 (With Ledger) eliminate ungrounded claims
    assert report["config_5_full_with_ledger"]["hallucination_rate"] == 0.0
    assert report["config_6_full_safety_gated"]["hallucination_rate"] == 0.0

    # 3. Only Config 6 guarantees selective risk bounding and clinical safeguards
    assert report["config_1_detection_only"]["selective_risk_bounded"] is False
    assert report["config_6_full_safety_gated"]["selective_risk_bounded"] is True
    assert report["config_6_full_safety_gated"]["iomt_disruptive_actions_auto_executed"] == 0
    assert report["config_6_full_safety_gated"]["all_9_agents_active"] is True
