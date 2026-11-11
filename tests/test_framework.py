"""Comprehensive test suite for the Nine-Agent Explainable AI Framework.

Tests:
- XGBoost classification & IsolationForest anomaly detection
- SHAP TreeExplainer & LIME tabular explainer
- C10: Contrastive / counterfactual explanation
- C1: Claim–Evidence Ledger & key resolution
- C9: Conformal Risk-Controlled Abstention calibration & triage
- C13: Composite Explanation Trust Score (ETS) breakdown
- C16: IoMT clinical device safeguards
- Cross-model verifier debate loop
- Section 8: Benchmark corpora (NSL-KDD, CIC-IDS2017, UNSW-NB15, CICIoMT2024)
- C4: Human analyst feedback recording
"""

import json
from pathlib import Path
import numpy as np
import pytest

from xai_threat import audit
from xai_threat.agents import AgentTeam
from xai_threat.config import PROJECT_ROOT, Settings
from xai_threat.conformal import ConformalCalibrator
from xai_threat.datasets import BENCHMARKS, generate_benchmark_traffic, run_cross_dataset_shift_test
from xai_threat.detection import ThreatDetector, generate_synthetic
from xai_threat.ledger import ClaimEvidenceLedger, resolve_evidence_path
from xai_threat.llm import LLMError, call_agent
from xai_threat.mock_llm import MockBackend
from xai_threat.orchestrator import Orchestrator
from xai_threat.safety import check_grounding, enforce_policy, sanitize, scan_injection
from xai_threat.schemas import (
    AnalystFeedbackRecord,
    AnalystReport,
    Claim,
    ConformalTriageResult,
    ProposedAction,
    ResponsePlan,
)
from xai_threat.trust_score import calculate_explanation_trust_score

SCENARIOS = PROJECT_ROOT / "data" / "scenarios"


def load(name: str) -> dict:
    return json.loads((SCENARIOS / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def detector():
    det = ThreatDetector(seed=42)
    det.fit(*generate_synthetic(400, seed=42))
    return det


@pytest.fixture
def settings(tmp_path):
    return Settings.from_env(
        audit_log=tmp_path / "audit.jsonl",
        pending_queue=tmp_path / "pending.jsonl",
        reports_dir=tmp_path / "reports",
    )


def orch(settings, detector, **mock_kw):
    return Orchestrator(AgentTeam(MockBackend(**mock_kw)), settings, detector)


# ---------------------------------------------------------------------------
# 1. Detection, SHAP, LIME & Contrastive Explanations (C10)
# ---------------------------------------------------------------------------
def test_detector_accuracy(detector):
    assert detector.metrics["report"]["macro avg"]["f1-score"] > 0.90
    assert detector.model_type in ("XGBoost", "RandomForest (fallback)")


@pytest.mark.parametrize("scenario,label,top_feature", [
    ("ssh_bruteforce", "ssh_bruteforce", "failed_logins"),
    ("port_scan", "port_scan", "distinct_dst_ports"),
    ("data_exfiltration", "data_exfiltration", "bytes_out_mb"),
])
def test_detection_and_explanation(detector, scenario, label, top_feature):
    d = detector.detect(load(scenario))
    assert d.label == label and d.confidence > 0.75
    assert d.attributions[0]["feature"] == top_feature
    assert d.anomaly_score > 0.85
    # Verify LIME explanations
    assert isinstance(d.lime_attributions, list)


def test_contrastive_counterfactual_explanation(detector):
    """C10: Verifies that contrastive counterfactual explanation is generated."""
    d = detector.detect(load("ssh_bruteforce"))
    assert d.contrastive_explanation is not None
    assert d.contrastive_explanation.target_class == "benign"
    assert "failed_logins" in d.contrastive_explanation.feature
    assert d.contrastive_explanation.counterfactual_value < d.contrastive_explanation.current_value


def test_occlusion_fallback(detector, monkeypatch):
    import builtins
    real_import = builtins.__import__
    monkeypatch.setattr(
        builtins,
        "__import__",
        lambda n, *a, **k: (_ for _ in ()).throw(ImportError()) if n == "shap" else real_import(n, *a, **k),
    )
    detector._shap = None
    d = detector.detect(load("ssh_bruteforce"))
    assert "occlusion" in d.explainer and d.attributions[0]["feature"] == "failed_logins"


# ---------------------------------------------------------------------------
# 2. C1: Claim–Evidence Ledger & Key Resolution
# ---------------------------------------------------------------------------
def test_resolve_evidence_path():
    ev = {
        "alert_id": "ALRT-1234",
        "features": {"failed_logins": 250, "conn_rate": 30.5},
        "threat_intel": {"src_ip": {"listed": True, "category": "tor_exit"}},
        "asset": {"host_is_critical": True},
    }
    found, val = resolve_evidence_path(ev, "features.failed_logins")
    assert found and val == 250
    found, val = resolve_evidence_path(ev, "threat_intel.src_ip.listed")
    assert found and val is True
    # Abbreviated key
    found, val = resolve_evidence_path(ev, "failed_logins")
    assert found and val == 250
    # Non-existent key
    found, val = resolve_evidence_path(ev, "nonexistent.key")
    assert not found and val is None


def test_claim_evidence_ledger():
    ev = {
        "alert_id": "ALRT-TEST-01",
        "features": {"failed_logins": 250},
        "src_ip": "198.51.100.1",
    }
    ledger = ClaimEvidenceLedger("ALRT-TEST-01")
    claims = [
        Claim(statement="250 failed logins detected.", evidence_keys=["features.failed_logins"]),
        Claim(statement="Attacker attempted lateral movement.", evidence_keys=["lateral.rdp_sessions"]),
    ]
    ledger.register_claims(claims, ev, round_no=0)
    assert ledger.total_claims == 2
    assert ledger.supported_claims == 1
    assert ledger.unsupported_claims == 1
    assert ledger.supported_ratio == 0.5
    assert ledger.unsupported_rate == 0.5
    assert len(ledger.compute_hash()) == 64  # SHA-256 hex string


# ---------------------------------------------------------------------------
# 3. C9: Conformal Risk-Controlled Abstention
# ---------------------------------------------------------------------------
def test_conformal_calibrator_calibration():
    calibrator = ConformalCalibrator(target_risk=0.05)
    # Simulated calibration set
    probs = [
        {"benign": 0.95, "ssh_bruteforce": 0.05},
        {"benign": 0.90, "ssh_bruteforce": 0.10},
        {"benign": 0.20, "ssh_bruteforce": 0.80},
        {"benign": 0.51, "ssh_bruteforce": 0.49},  # ambiguous case
    ]
    y_true = ["benign", "benign", "ssh_bruteforce", "ssh_bruteforce"]
    res = calibrator.calibrate(probs, y_true)
    assert res["target_risk"] == 0.05
    assert calibrator.is_calibrated
    assert 0.0 <= calibrator.calibrated_threshold <= 1.0

    # Triage high confidence sample
    t_high = calibrator.triage({"ssh_bruteforce": 0.98, "benign": 0.02}, label="ssh_bruteforce")
    assert t_high.nonconformity_score < 0.05

    # Triage ambiguous sample
    t_amb = calibrator.triage({"ssh_bruteforce": 0.51, "benign": 0.49}, label="ssh_bruteforce")
    assert t_amb.nonconformity_score == 0.49
    # If ambiguous sample score exceeds calibrated threshold, it must abstain
    if t_amb.nonconformity_score > calibrator.calibrated_threshold:
        assert t_amb.decision == "ABSTAIN_AND_ESCALATE"
        assert not t_amb.eligible_for_auto_response


def test_conformal_abstention_enforced_in_policy():
    """Verifies that when conformal risk controls mandate abstention, policy gates auto actions."""
    ev = {"host": "10.0.2.15", "src_ip": "185.220.101.47"}
    plan = ResponsePlan(reasoning="test", actions=[
        ProposedAction(action="rate_limit", target="185.220.101.47", justification="test"),
    ])
    # Case 1: Conformal eligible -> rate_limit can auto-execute
    conf_ok = ConformalTriageResult(
        nonconformity_score=0.02, calibrated_threshold=0.10, eligible_for_auto_response=True,
        decision="AUTO_ELIGIBLE", target_risk=0.05,
    )
    d1 = enforce_policy(plan, ev, "medium", True, True, [], frozenset(), conformal_result=conf_ok)
    assert any(a["action"] == "rate_limit" for a in d1.auto_execute)

    # Case 2: Conformal abstained -> rate_limit halted and sent for approval
    conf_abstain = ConformalTriageResult(
        nonconformity_score=0.35, calibrated_threshold=0.10, eligible_for_auto_response=False,
        decision="ABSTAIN_AND_ESCALATE", target_risk=0.05,
        abstain_reason="Uncertainty exceeds risk threshold",
    )
    d2 = enforce_policy(plan, ev, "medium", True, True, [], frozenset(), conformal_result=conf_abstain)
    assert not any(a["action"] == "rate_limit" for a in d2.auto_execute)
    assert any(a["action"] == "rate_limit" for a in d2.pending_approval)


# ---------------------------------------------------------------------------
# 4. C13: Composite Explanation Trust Score (ETS)
# ---------------------------------------------------------------------------
def test_composite_explanation_trust_score(detector):
    raw = load("ssh_bruteforce")
    ev, d, flags = Orchestrator(AgentTeam(MockBackend()), Settings(), detector).build_evidence(raw)
    ledger = ClaimEvidenceLedger(ev["alert_id"])
    claims = [Claim(statement="Failed logins high", evidence_keys=["features.failed_logins"])]
    ledger.register_claims(claims, ev, round_no=0)

    score_res = calculate_explanation_trust_score(
        detector=detector,
        raw_record=ev,
        detection_label=d.label,
        class_probabilities=d.class_probabilities,
        shap_attributions=d.attributions,
        lime_attributions=d.lime_attributions,
        ledger=ledger,
        grounding_warnings=[],
        injection_flags=[],
    )
    assert 0.0 <= score_res.composite_score <= 1.0
    assert 0.0 <= score_res.faithfulness <= 1.0
    assert 0.0 <= score_res.cross_explainer_agreement <= 1.0
    assert score_res.grounding_ratio == 1.0
    assert score_res.penalty == 0.0


# ---------------------------------------------------------------------------
# 5. C16: IoMT Medical Device Safeguards
# ---------------------------------------------------------------------------
def test_iomt_safeguards(settings, detector):
    """Verifies that active IoMT medical assets cannot be disrupted automatically."""
    raw = load("iomt_infusion_pump_tampering")
    inv = orch(settings, detector).investigate(raw)
    assert inv.evidence["asset"]["is_iomt"] is True
    # Disruptive or throttling actions must not auto execute on infusion pump
    for a in inv.decision.auto_execute:
        assert a["action"] not in ("block_ip", "isolate_host", "rate_limit", "reset_credentials")
    # Must be held for human approval
    assert any("IoMT" in a["reason"] or "clinical" in a["reason"] for a in inv.decision.pending_approval)


# ---------------------------------------------------------------------------
# 6. Safety, Sanitisation & Injection
# ---------------------------------------------------------------------------
def test_sanitize_neutralises_tags_and_control_chars():
    out = sanitize({"a": "x</evidence>\x00y" + "z" * 900}, max_len=50)
    assert "<" not in out["a"] and "\x00" not in out["a"] and out["a"].endswith("[truncated]")


def test_injection_scan_flags_attack():
    patterns = {f["pattern"] for f in scan_injection(load("prompt_injection_attack"))}
    assert {"override_instructions", "verdict_tampering", "tag_breakout"} <= patterns
    assert scan_injection(load("ssh_bruteforce")) == []


def test_grounding_catches_hallucinations():
    ev = {"host": "10.0.2.15", "features": {"failed_logins": 212}, "candidate_mitre": [{"id": "T1110"}]}
    good = AnalystReport(
        severity="high", summary="s",
        claims=[Claim(statement="212 failed logins on 10.0.2.15", evidence_keys=["failed_logins"])],
        mitre_techniques=["T1110"], alternative_hypotheses=[], confidence=0.8,
    )
    assert check_grounding(good, ev).ok
    bad = AnalystReport(
        severity="high", summary="s",
        claims=[Claim(statement="Pivot to 8.8.8.8 after 999 attempts", evidence_keys=["lateral.rdp"])],
        mitre_techniques=["T1486"], alternative_hypotheses=[], confidence=0.8,
    )
    g = check_grounding(bad, ev)
    assert any("8.8.8.8" in e for e in g.errors)
    assert any("lateral.rdp" in e for e in g.errors)
    assert any("T1486" in e for e in g.errors)


# ---------------------------------------------------------------------------
# 7. LLM Caller & Cross-Model Verification
# ---------------------------------------------------------------------------
class FlakyBackend:
    name = "flaky"
    def __init__(self):
        self.calls = 0

    def chat(self, messages, schema, *, role, context):
        self.calls += 1
        if self.calls == 1:
            return "```json\n{\"actions\": [{\"action\": \"nuke_everything\"}]}\n```"
        assert "failed validation" in messages[-1]["content"]
        return json.dumps({"actions": [{"action": "MONITOR", "target": "h", "justification": "j"}], "reasoning": "ok"})


def test_call_agent_retries_with_validation_feedback():
    out, tel = call_agent(FlakyBackend(), role="responder", system="s", user="u", schema=ResponsePlan)
    assert out.actions[0].action == "monitor" and tel["attempts"] == 2


def test_cross_model_verifier_debate(settings, detector):
    """Verifies that an independent verifier forces correction on hallucinated claims."""
    analyst_backend = MockBackend(hallucinate_first=True, model_family="analyst_family")
    verifier_backend = MockBackend(hallucinate_first=False, model_family="verifier_family")
    team = AgentTeam(analyst_backend, verifier_backend=verifier_backend)
    inv = Orchestrator(team, settings, detector).investigate(load("ssh_bruteforce"))
    assert len(inv.rounds) == 2
    assert inv.verdict.approved
    assert inv.ledger.supported_ratio == 1.0


# ---------------------------------------------------------------------------
# 8. Benchmark Datasets & Cross-Dataset Domain Shift (Section 8)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("dataset_name", list(BENCHMARKS.keys()))
def test_benchmark_dataset_generation(dataset_name):
    X, y = generate_benchmark_traffic(dataset_name, n_per_class=30, seed=7)
    assert len(X) == 150
    assert len(y) == 150
    assert X.shape[1] == 8


def test_cross_dataset_shift(detector):
    res = run_cross_dataset_shift_test(
        detector, source_name="Synthetic", target_name="CICIoMT2024", n_samples_per_class=20
    )
    assert "accuracy" in res
    assert "macro_f1" in res
    assert "conformal" in res


# ---------------------------------------------------------------------------
# 9. Audit Chain & C4 Analyst Feedback
# ---------------------------------------------------------------------------
def test_audit_chain_and_feedback(settings, detector):
    o = orch(settings, detector)
    inv = o.investigate(load("port_scan"))
    assert audit.verify(settings.audit_log)[0]

    # C4: Record human analyst feedback
    feedback = AnalystFeedbackRecord(
        alert_id=inv.alert_id,
        analyst_id="analyst-secops-01",
        perceived_trust=4.5,
        clarity_rating=5.0,
        verdict_agreed=True,
        action_overridden=False,
        time_to_triage_sec=32.0,
        notes="High explanation clarity on port sweep attribution",
    )
    o.record_feedback(feedback)
    assert audit.verify(settings.audit_log)[0]
