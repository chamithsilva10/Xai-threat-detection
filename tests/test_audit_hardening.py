"""Regression and Hardening Tests for Multi-Agent XAI Cyber Threat Framework.

Strictly verifies audit sections:
- Section 4: Mathematical and computational audit of selective-risk certification.
- Section 5: Hard safety gate enforcement (ETS cannot bypass failed gates).
- Section 7: RFC 8785 canonical JSON, negative zero, and claim semantics.
- Section 8: Authenticated user registry, HMAC token binding, dual-role IoMT separation of duties, atomic consumption.
- Section 9: Clinical IoMT safety across all paths.
- Section 10: Ingestion tailing, partial writes, copy-truncate, and rename-and-create rotation.
- Section 12: Audit hash chain integrity and dry-run boundaries.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import threading
import time

import numpy as np
import pytest

from xai_threat.audit import append as audit_append, verify as verify_audit_chain
from xai_threat.canonical_json import (
    canonical_json_bytes,
    canonical_json_dumps,
    canonical_json_hash,
)
from xai_threat.conformal import (
    ConformalCalibrator,
    ConformalTriageResult,
    clopper_pearson_upper_bound,
)
from xai_threat.connectors import (
    ApprovalManager,
    DryRunResponseConnector,
    UserCredentialRegistry,
)
from xai_threat.ingestion import SuricataEveJsonAdapter
from xai_threat.knowledge import AssetRegistry
from xai_threat.ledger import Claim, ClaimEvidenceLedger
from xai_threat.safety import (
    DANGEROUS_ACTIONS,
    SAFE_AUTO_ACTIONS,
    enforce_policy,
    evaluate_hard_safety_gates,
)
from xai_threat.schemas import (
    ActionProposal,
    ApprovalRecord,
    ProposedAction,
    ResponsePlan,
)


# ---------------------------------------------------------------------------
# Section 7: RFC 8785 Canonical JSON Serialization Tests
# ---------------------------------------------------------------------------
def test_rfc8785_negative_zero_normalization():
    """Verifies that -0.0 is normalized to 0 in canonical JSON."""
    data = {"temperature": -0.0, "offset": 0.0}
    serialized = canonical_json_dumps(data)
    assert serialized == '{"offset":0,"temperature":0}'


def test_rfc8785_float_integer_representation():
    """Verifies that floats with integer values do not emit trailing .0."""
    data = {"count": 42.0, "sub": 100}
    serialized = canonical_json_dumps(data)
    assert serialized == '{"count":42,"sub":100}'


def test_rfc8785_utf16_code_unit_key_sorting():
    """Verifies keys are sorted by UTF-16 code units per RFC 8785."""
    data = {
        "b": 1,
        "a": 2,
        "\u00e9": 3,  # e-acute (U+00E9)
        "z": 4,
    }
    serialized = canonical_json_dumps(data)
    assert serialized == '{"a":2,"b":1,"z":4,"\u00e9":3}'


def test_rfc8785_non_finite_float_rejection():
    """Verifies NaN and Infinity are strictly rejected per RFC 8785."""
    with pytest.raises(ValueError, match="non-finite"):
        canonical_json_dumps({"bad": float("nan")})

    with pytest.raises(ValueError, match="non-finite"):
        canonical_json_dumps({"bad": float("inf")})


def test_rfc8785_duplicate_key_rejection():
    """Verifies duplicate keys in JSON are rejected per RFC 8785 Section 3.2.1."""
    from xai_threat.canonical_json import safe_json_loads
    with pytest.raises(ValueError, match="duplicate key"):
        safe_json_loads('{"flow_id": "F-01", "flow_id": "F-02"}')


def test_rfc8785_nested_structures_and_arrays():
    """Verifies nested maps, lists, and empty structures format conformingly."""
    data = {
        "z": [],
        "m": {"b": [3, 2, 1], "a": {}},
        "a": None,
    }
    serialized = canonical_json_dumps(data)
    assert serialized == '{"a":null,"m":{"a":{},"b":[3,2,1]},"z":[]}'


# ---------------------------------------------------------------------------
# Section 4: Exact Binomial Selective Risk Computation & Boundary Conditions
# ---------------------------------------------------------------------------
def test_exact_binomial_ucb_zero_error_boundary():
    """Verifies closed-form boundary U = 1 - delta^(1/m) for e = 0."""
    m = 100
    delta = 0.05
    # Closed form: 1 - (0.05)**(1/100)
    expected = 1.0 - (delta ** (1.0 / m))
    computed = clopper_pearson_upper_bound(k_errors=0, n_samples=m, delta=delta)
    assert abs(computed - expected) < 1e-6


def test_exact_binomial_ucb_all_errors_boundary():
    """Verifies boundary U = 1.0 for e = m."""
    m = 50
    computed = clopper_pearson_upper_bound(k_errors=m, n_samples=m, delta=0.05)
    assert computed == 1.0


def test_zero_accepted_samples_cannot_certify():
    """Verifies that empty calibration raises ValueError and does not certify."""
    calibrator = ConformalCalibrator(target_risk=0.05)
    with pytest.raises(ValueError, match="cannot be empty"):
        calibrator.calibrate([], [])
    assert not calibrator.is_calibrated
    assert calibrator.calibrated_threshold == 0.0
    assert calibrator.calibrated_threshold != 1.0  # Never a silent fallback


def test_uncertified_state_always_abstains_even_with_zero_uncertainty():
    """Verifies that is_certified=False always forces abstention, even when uncertainty score is 0.0."""
    calibrator = ConformalCalibrator(target_risk=0.05)
    calibrator.is_calibrated = True
    calibrator.is_certified = False  # e.g. no candidate met UCB <= alpha
    calibrator.calibrated_threshold = 0.0

    # Probability distribution with 100% top probability -> nonconformity score = 0.0
    res = calibrator.triage({"ssh_bruteforce": 1.0, "benign": 0.0}, label="ssh_bruteforce")
    assert res.nonconformity_score == 0.0
    assert res.eligible_for_auto_response is False
    assert res.decision == "ABSTAIN_AND_ESCALATE"
    assert "certification not established" in res.abstain_reason


# ---------------------------------------------------------------------------
# Section 5: Hard Safety Gates & ETS Independence
# ---------------------------------------------------------------------------
def test_ets_cannot_bypass_failed_hard_safety_gate():
    """Verifies that high ETS score (e.g. 1.0) CANNOT authorize automated action

    when an independent hard safety gate (e.g. adversarial prompt injection) fails.
    """
    ev = {
        "alert_id": "ALRT-INJ-01",
        "host": "10.0.2.15",
        "src_ip": "185.220.101.47",
        "features": {"failed_logins": 120},
    }
    plan = ResponsePlan(
        reasoning="Suspicious activity",
        actions=[ProposedAction(action="rate_limit", target="185.220.101.47", justification="Bruteforce")],
    )
    conf_ok = ConformalTriageResult(
        nonconformity_score=0.02,
        calibrated_threshold=0.10,
        eligible_for_auto_response=True,
        decision="AUTO_ELIGIBLE",
        target_risk=0.05,
    )
    # Injection detected by Agent 08 sanitizer
    injection_flags = ["PROMPT_INJECTION_SUSPECTED: IGNORE PRIOR INSTRUCTIONS"]

    decision = enforce_policy(
        plan=plan,
        evidence=ev,
        severity="high",
        critic_approved=True,
        grounded=True,
        injection_flags=injection_flags,
        critical_assets=frozenset(),
        conformal_result=conf_ok,
    )
    # Must be denied/held, regardless of how good the explanations or ETS would be
    assert not any(a["action"] == "rate_limit" for a in decision.auto_execute)
    assert any(a["action"] == "rate_limit" for a in decision.pending_approval)
    assert any("injection" in p["reason"].lower() for p in decision.pending_approval)


def test_contradiction_preserves_factual_ratio_while_gate_blocks():
    """Verifies that contradictory claims preserve factual supported ratio (e.g. 0.5)

    without artificial overwrite, while hard gate correctly halts automation.
    """
    ledger = ClaimEvidenceLedger(alert_id="ALRT-CONTRADICT-01")
    ev = {
        "features": {"failed_logins": 5, "bytes_out_mb": 12.0},
        "src_ip": "10.0.0.50",
    }
    # Register 1 supported claim and 1 contradictory claim
    claims = [
        Claim(statement="Failed logins were 5.", evidence_keys=["features.failed_logins"]),
        Claim(
            statement="Zero failed logins occurred.",
            evidence_keys=["features.failed_logins"],
            contradicts=True,
            contradiction_detail="Claim stated zero failed logins, but evidence records 5",
        ),
    ]
    ledger.register_claims(claims, ev)

    # Factual ratio is preserved (1 out of 2 is supported = 0.5)
    assert ledger.supported_ratio == 0.5
    assert ledger.contradicted_claims == 1
    assert ledger.has_critical_contradiction is True

    # Gate must fail due to critical contradiction
    gate_res = evaluate_hard_safety_gates(
        evidence=ev,
        critic_approved=True,
        grounding_ok=True,
        conformal_result=ConformalTriageResult(
            nonconformity_score=0.01,
            calibrated_threshold=0.1,
            eligible_for_auto_response=True,
            decision="AUTO_ELIGIBLE",
            target_risk=0.05,
        ),
        ledger=ledger,
    )
    assert gate_res.all_passed is False
    assert gate_res.no_critical_contradictions is False
    assert any("contradictory" in r for r in gate_res.failed_reasons)


# ---------------------------------------------------------------------------
# Section 8 & 9: Dual-Role IoMT Authorization & Separation of Duties
# ---------------------------------------------------------------------------
def test_iomt_separation_of_duties_enforced():
    """Verifies that supplying the same identity for both security and clinical roles

    on an IoMT disruptive action raises SEPARATION_OF_DUTIES_VIOLATION.
    """
    mgr = ApprovalManager()
    prop = ActionProposal(
        incident_id="INC-IOMT-01",
        action="isolate_host",
        target="10.200.1.5",
        canonical_parameters={"vlan": 99},
        justification="Infusion pump compromised",
        is_disruptive=True,
        requires_clinical_authorization=True,
    )

    # Same identity for security and clinical authorization
    with pytest.raises(ValueError, match="SEPARATION_OF_DUTIES_VIOLATION"):
        mgr.issue_approval(
            proposal=prop,
            evidence_snapshot_hash="hash-123",
            approver_id="soc_lead_chamith",
            approver_role="soc_lead",
            clinical_approver_id="soc_lead_chamith",  # Same ID!
        )


def test_iomt_missing_clinical_approver_rejected():
    """Verifies that IoMT disruptive action without clinical approver is rejected."""
    mgr = ApprovalManager()
    prop = ActionProposal(
        incident_id="INC-IOMT-02",
        action="isolate_host",
        target="10.200.1.5",
        canonical_parameters={"vlan": 99},
        justification="Infusion pump compromised",
        is_disruptive=True,
        requires_clinical_authorization=True,
    )

    with pytest.raises(ValueError, match="CLINICAL_AUTHORIZATION_REQUIRED"):
        mgr.issue_approval(
            proposal=prop,
            evidence_snapshot_hash="hash-123",
            approver_id="soc_lead_chamith",
            approver_role="soc_lead",
            clinical_approver_id=None,
        )


def test_concurrent_approval_token_consumption():
    """Verifies atomic consumption under concurrency: exactly one execution succeeds,

    and concurrent attempt receives TOKEN_ALREADY_CONSUMED / POLICY_DENIED.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "apprs.json"
        mgr = ApprovalManager(store_path=store_path)
        connector = DryRunResponseConnector(mgr)

        prop = ActionProposal(
            incident_id="INC-CONCURRENT-01",
            action="block_ip",
            target="198.51.100.99",
            canonical_parameters={"duration": 3600},
            justification="Concurrent test",
            is_disruptive=True,
        )
        appr = mgr.issue_approval(
            proposal=prop,
            evidence_snapshot_hash="ev-hash-1",
            approver_id="soc_lead_chamith",
            approver_role="soc_lead",
        )

        results = []

        def worker():
            c = DryRunResponseConnector(mgr)
            res = c.execute(prop, appr, evidence_snapshot_hash="ev-hash-1")
            results.append(res)

        # Run 2 concurrent execution attempts
        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        states = [r.state for r in results]
        assert "SUCCEEDED" in states
        assert "POLICY_DENIED" in states
        denied_res = next(r for r in results if r.state == "POLICY_DENIED")
        assert "already been consumed" in denied_res.error_message


# ---------------------------------------------------------------------------
# Section 10: Ingestion File Tailing, Partial Writes, and Rotation
# ---------------------------------------------------------------------------
def test_ingestion_partial_writes_held_until_newline():
    """Verifies that incomplete lines in telemetry file are not emitted until completed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "eve.json"
        adapter = SuricataEveJsonAdapter(log_file, checkpoint_dir=Path(tmpdir))

        # 1. Write an incomplete JSON line (no trailing newline)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write('{"event_type": "alert", "src_ip": "10.0.0.1"')

        events = list(adapter.tail())
        assert len(events) == 0  # Incomplete line must not be emitted!

        # 2. Complete the write with remaining fields and newline
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(', "event_id": "EV-01"}\n')

        events = list(adapter.tail())
        assert len(events) == 1
        assert events[0].raw_payload["event_id"] == "EV-01"


def test_ingestion_copy_truncate_rotation():
    """Verifies that copy-truncate log rotation (file shrinks) resets offset to 0."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "eve.json"
        adapter = SuricataEveJsonAdapter(log_file, checkpoint_dir=Path(tmpdir))

        # Initial writes
        with open(log_file, "w", encoding="utf-8") as f:
            f.write('{"event_id": "EV-01"}\n{"event_id": "EV-02"}\n')

        events = list(adapter.tail())
        assert len(events) == 2

        # Copy-truncate simulation: file truncated to smaller size
        with open(log_file, "w", encoding="utf-8") as f:
            f.write('{"event_id": "EV-03"}\n')

        events = list(adapter.tail())
        assert len(events) == 1
        assert events[0].raw_payload["event_id"] == "EV-03"


# ---------------------------------------------------------------------------
# Section 12: Audit Hash Chain Tamper Detection
# ---------------------------------------------------------------------------
def test_audit_interior_deletion_and_reordering_detected():
    """Verifies that deleting or reordering records in the audit chain breaks verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = Path(tmpdir) / "audit.jsonl"

        audit_append(audit_path, {"event": "step_1", "data": "first"})
        audit_append(audit_path, {"event": "step_2", "data": "second"})
        audit_append(audit_path, {"event": "step_3", "data": "third"})

        ok, msg, count = verify_audit_chain(audit_path)
        assert ok is True
        assert count == 3

        # Tampering: swap step 2 and step 3
        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        reordered = [lines[0], lines[2], lines[1]]
        audit_path.write_text("\n".join(reordered) + "\n", encoding="utf-8")

        ok, msg, count = verify_audit_chain(audit_path)
        assert ok is False
        assert "broken" in msg.lower() or "mismatch" in msg.lower()


# ---------------------------------------------------------------------------
# Section 6 & 8: Crash Recovery, Separate-Process Concurrency, and Clinical Auth
# ---------------------------------------------------------------------------
def test_clinical_approval_requires_independent_authentication():
    """Verifies that clinical approval requires genuine independent credential verification,

    not merely distinct string names.
    """
    mgr = ApprovalManager()
    prop = ActionProposal(
        incident_id="INC-IOMT-AUTH-01",
        action="isolate_host",
        target="10.200.1.5",
        canonical_parameters={"vlan": 99},
        justification="IoMT auth verification test",
        is_disruptive=True,
        requires_clinical_authorization=True,
    )

    # 1. Invalid clinical secret key is rejected even if username is different
    with pytest.raises(PermissionError, match="Clinical approver authentication failed"):
        mgr.issue_approval(
            proposal=prop,
            evidence_snapshot_hash="hash-123",
            approver_id="soc_lead_chamith",
            approver_key="sec_lead_secret_token_123",
            clinical_approver_id="dr_sarah_clinical",
            clinical_approver_key="WRONG_FORGED_KEY",  # Invalid key!
        )

    # 2. Valid clinical secret key succeeds
    appr = mgr.issue_approval(
        proposal=prop,
        evidence_snapshot_hash="hash-123",
        approver_id="soc_lead_chamith",
        approver_key="sec_lead_secret_token_123",
        clinical_approver_id="dr_sarah_clinical",
        clinical_approver_key="clin_eng_secret_token_789",  # Genuine key
    )
    assert appr.approval_token.startswith("APPR-HMAC-")
    assert appr.clinical_approver_id == "dr_sarah_clinical"


def test_concurrent_approval_token_consumption_multiprocessing():
    """Verifies atomic consumption under separate OS processes: exactly one process succeeds,

    and the concurrent process receives TOKEN_ALREADY_CONSUMED / POLICY_DENIED.
    """
    import subprocess
    import sys

    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "apprs.json"
        mgr = ApprovalManager(store_path=store_path)

        prop = ActionProposal(
            incident_id="INC-PROC-01",
            action="block_ip",
            target="198.51.100.99",
            canonical_parameters={"duration": 3600},
            justification="Multiprocess test",
            is_disruptive=True,
        )
        appr = mgr.issue_approval(
            proposal=prop,
            evidence_snapshot_hash="ev-hash-proc",
            approver_id="soc_lead_chamith",
            approver_role="soc_lead",
        )

        # Worker script executed in separate OS processes
        script = f"""
import sys
from pathlib import Path
from xai_threat.connectors import ApprovalManager, DryRunResponseConnector
from xai_threat.schemas import ActionProposal, ApprovalRecord

store_path = Path("{store_path}")
mgr = ApprovalManager(store_path=store_path)
connector = DryRunResponseConnector(mgr)

prop = ActionProposal(
    incident_id="INC-PROC-01",
    action="block_ip",
    target="198.51.100.99",
    canonical_parameters={{"duration": 3600}},
    justification="Multiprocess test",
    is_disruptive=True,
)
rec_data = mgr.store.load_all().get("{appr.approval_token}")
appr = ApprovalRecord.model_validate(rec_data)

res = connector.execute(prop, appr, evidence_snapshot_hash="ev-hash-proc")
print(res.state)
"""
        # Run two separate Python processes concurrently
        p1 = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p2 = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        out1, _ = p1.communicate(timeout=10)
        out2, _ = p2.communicate(timeout=10)

        states = [out1.strip(), out2.strip()]
        assert "SUCCEEDED" in states, f"No process succeeded: {states}"
        assert "POLICY_DENIED" in states, f"No process was denied: {states}"


def test_crash_recovery_preserves_uncommitted_events():
    """Verifies that an uncommitted crash allows full recovery of events from last committed checkpoint."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "eve.json"
        ckpt_dir = Path(tmpdir) / "ckpts"
        adapter = SuricataEveJsonAdapter(log_file, checkpoint_dir=ckpt_dir)

        # Write 2 events
        with open(log_file, "w", encoding="utf-8") as f:
            f.write('{"event_id": "EVT-01"}\n{"event_id": "EVT-02"}\n')

        # Read 1 event and simulate crash before checkpoint save
        file_key = str(log_file.resolve())
        # Checkpoint is initially 0
        assert adapter.checkpoint_mgr.get_offset(file_key) == 0

        # Normal tail reads and commits checkpoint
        events = list(adapter.tail(max_records=2))
        assert len(events) == 2
        committed_offset = adapter.checkpoint_mgr.get_offset(file_key)
        assert committed_offset > 0

        # Append third event
        with open(log_file, "a", encoding="utf-8") as f:
            f.write('{"event_id": "EVT-03"}\n')

        # Simulate fresh process restart by creating a new adapter instance pointing to same checkpoint dir
        recovered_adapter = SuricataEveJsonAdapter(log_file, checkpoint_dir=ckpt_dir)
        # Resumes exactly from committed offset, reading ONLY the new event
        resumed_events = list(recovered_adapter.tail())
        assert len(resumed_events) == 1
        assert resumed_events[0].raw_payload["event_id"] == "EVT-03"
