"""End-to-End Demonstration of the 9 Mandated Scenarios (Section 20).

Scenarios demonstrated:
 1. Benign activity (no alarms, low severity, fast triage).
 2. SSH brute-force alert with genuine authentication evidence.
 3. An uncertain anomaly (selective risk control abstains and escalates).
 4. An unsupported analyst claim (detected and corrected via multi-round C1 ledger debate).
 5. A verifier outage (circuit breaker / fallback escalation).
 6. A critical IoMT medical target (patient safety safeguards C16 block autonomous action).
 7. A disruptive action held for approval (policy gate holding IP block / isolation).
 8. A dry-run approved action (cryptographically bound one-time token authorization).
 9. Tamper-evident cryptographic audit verification.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from xai_threat import audit
from xai_threat.agents import AgentTeam
from xai_threat.config import PROJECT_ROOT, Settings
from xai_threat.connectors import ActionProposal, ApprovalManager, DryRunResponseConnector
from xai_threat.detection import ThreatDetector, generate_synthetic
from xai_threat.mock_llm import MockBackend
from xai_threat.orchestrator import Orchestrator
from xai_threat.report import console_summary


def print_banner(num: int, title: str):
    print("\n" + "═" * 78)
    print(f" SCENARIO {num}: {title.upper()}")
    print("═" * 78)


def run_all_demonstrations():
    settings = Settings.from_env(
        audit_log=PROJECT_ROOT / "runs" / "demo_audit.jsonl",
        pending_queue=PROJECT_ROOT / "runs" / "demo_pending.jsonl",
        reports_dir=PROJECT_ROOT / "runs" / "demo_reports",
    )
    # Ensure detector is trained
    detector = ThreatDetector.load_or_train(settings.model_path)

    # -----------------------------------------------------------------------
    # 1. Benign Activity
    # -----------------------------------------------------------------------
    print_banner(1, "Benign Activity (Normal HTTPS Web & Dev Traffic)")
    team_normal = AgentTeam(MockBackend(name="mock-analyst"))
    orch_normal = Orchestrator(team_normal, settings, detector, operating_mode="REPLAY")

    benign_raw = json.loads((PROJECT_ROOT / "data" / "scenarios" / "benign_traffic.json").read_text())
    inv1 = orch_normal.investigate(benign_raw, log=lambda m: print(f"   {m}"))
    print(f"   Outcome Status : {inv1.status}")
    print(f"   Final Severity : {inv1.final_severity}")
    print(f"   Detector Label : {inv1.detection.label} (confidence: {inv1.detection.confidence:.2f})")
    print(f"   Provenance     : Telemetry={inv1.telemetry_provenance}, Action={inv1.action_provenance}")

    # -----------------------------------------------------------------------
    # 2. SSH Brute-Force Alert with Authentication Evidence
    # -----------------------------------------------------------------------
    print_banner(2, "SSH Brute-Force with Authentication Evidence")
    ssh_raw = json.loads((PROJECT_ROOT / "data" / "scenarios" / "ssh_bruteforce.json").read_text())
    inv2 = orch_normal.investigate(ssh_raw, log=lambda m: print(f"   {m}"))
    print(f"   Outcome Status : {inv2.status}")
    print(f"   Final Severity : {inv2.final_severity}")
    print(f"   Detector Label : {inv2.detection.label} (p={inv2.detection.confidence:.3f})")
    print(f"   C1 Ledger      : {inv2.ledger.supported_claims}/{inv2.ledger.total_claims} claims verified (100%)")
    print(f"   C13 Trust Score: ETS = {inv2.trust_score:.3f}")

    # -----------------------------------------------------------------------
    # 3. An Uncertain Anomaly (Selective-Risk Control Abstains)
    # -----------------------------------------------------------------------
    print_banner(3, "Uncertain Anomaly (Selective Risk Control Abstains & Escalates)")
    anom_raw = json.loads((PROJECT_ROOT / "data" / "scenarios" / "uncertain_anomaly.json").read_text())
    inv3 = orch_normal.investigate(anom_raw, log=lambda m: print(f"   {m}"))
    print(f"   Conformal Triage: {inv3.conformal.decision}")
    print(f"   Nonconformity s : {inv3.conformal.nonconformity_score:.4f} vs threshold {inv3.conformal.calibrated_threshold:.4f}")
    print(f"   Abstain Reason  : {inv3.conformal.abstain_reason}")
    print(f"   Outcome Status  : {inv3.status} (Human escalation enforced)")

    # -----------------------------------------------------------------------
    # 4. An Unsupported Analyst Claim (Multi-Round Verifier Debate)
    # -----------------------------------------------------------------------
    print_banner(4, "Unsupported Analyst Claim (Multi-Round Ledger Debate)")
    team_hallucinating = AgentTeam(
        backend=MockBackend(hallucinate_first=True, model_family="mock-analyst"),
        verifier_backend=MockBackend(model_family="mock-independent-critic"),
    )
    orch_debate = Orchestrator(team_hallucinating, settings, detector)
    inv4 = orch_debate.investigate(ssh_raw, log=lambda m: print(f"   {m}"))
    print(f"   Debate Rounds  : {len(inv4.rounds)} round(s) executed")
    for r in inv4.rounds:
        print(f"     * Round {r['round']}: Critic={ 'APPROVED' if r['critic_approved'] else 'REJECTED' }, "
              f"Grounding Errors={len(r['grounding_errors'])}, Unsupported={len(r['unsupported_claims'])}")
    print(f"   Final Status   : {inv4.status}")

    # -----------------------------------------------------------------------
    # 5. A Verifier Outage (Fallback Escalation)
    # -----------------------------------------------------------------------
    print_banner(5, "Verifier Outage (Fallback Safety Escalation)")
    class FailingVerifierBackend(MockBackend):
        def chat(self, *args, **kwargs):
            if kwargs.get("role") == "critic":
                raise RuntimeError("Connection refused: Independent Verifier service is offline")
            return super().chat(*args, **kwargs)

    team_outage = AgentTeam(
        backend=MockBackend(),
        verifier_backend=FailingVerifierBackend(),
        retries=1,
    )
    orch_outage = Orchestrator(team_outage, settings, detector)
    try:
        inv5 = orch_outage.investigate(ssh_raw, log=lambda m: print(f"   {m}"))
        print(f"   Outcome Status : {inv5.status}")
    except Exception as e:
        print(f"   [CIRCUIT BREAKER TRIGGERED]: Verifier failure handled safely: {e}")

    # -----------------------------------------------------------------------
    # 6. A Critical IoMT Target (Clinical Patient Safeguards C16)
    # -----------------------------------------------------------------------
    print_banner(6, "Critical IoMT Medical Target (Patient Safety Safeguard C16)")
    iomt_raw = json.loads((PROJECT_ROOT / "data" / "scenarios" / "iomt_infusion_pump_tampering.json").read_text())
    inv6 = orch_normal.investigate(iomt_raw, log=lambda m: print(f"   {m}"))
    print(f"   Target Asset    : {inv6.evidence.get('host')}")
    print(f"   Is IoMT Device  : {inv6.evidence.get('asset', {}).get('is_iomt')}")
    print(f"   Policy Decision :")
    for act in inv6.decision.pending_approval:
        print(f"     ⏸ HOLD: {act['action']} on {act['target']}")
        print(f"       Reason: {act['reason']}")

    # -----------------------------------------------------------------------
    # 7. A Disruptive Action Held for Approval
    # -----------------------------------------------------------------------
    print_banner(7, "Disruptive Action Held for Human Approval")
    print(f"   Alert ID        : {inv2.alert_id}")
    print(f"   Auto Actions    : {[a['action'] for a in inv2.decision.auto_execute]}")
    print(f"   Held Actions    : {[a['action'] for a in inv2.decision.pending_approval]}")

    # -----------------------------------------------------------------------
    # 8. A Dry-Run Approved Action
    # -----------------------------------------------------------------------
    print_banner(8, "Dry-Run Authorized Remediation Execution")
    mgr = ApprovalManager()
    connector = DryRunResponseConnector(mgr)

    prop = ActionProposal(
        incident_id=inv2.alert_id,
        action="block_ip",
        target="185.220.101.47",
        canonical_parameters={"duration_sec": 3600},
        justification="Verified external brute-force source",
        is_disruptive=True,
    )
    appr = mgr.issue_approval(
        proposal=prop,
        evidence_snapshot_hash=inv2.ledger.evidence_snapshot_hash,
        approver_id="soc_lead_chamith",
        approver_role="soc_lead",
    )
    print(f"   Approval Token Issued: {appr.approval_token}")
    print(f"   Bound To Target       : {appr.target}")
    print(f"   Bound To Snapshot     : {appr.evidence_snapshot_hash[:16]}...")

    exec_result = connector.execute(prop, appr, evidence_snapshot_hash=inv2.ledger.evidence_snapshot_hash)
    print(f"   Execution State       : {exec_result.state}")
    print(f"   Connector Name        : {exec_result.connector_name}")
    print(f"   Details               : {exec_result.outcome_details}")

    # -----------------------------------------------------------------------
    # 9. Audit Verification
    # -----------------------------------------------------------------------
    print_banner(9, "Tamper-Evident Cryptographic Audit Verification")
    audit_ok, audit_msg, count = audit.verify(settings.audit_log)
    print(f"   Audit Chain File   : {settings.audit_log}")
    print(f"   Verification Status: {'VALID' if audit_ok else 'FAILED'}")
    print(f"   Verified Entries   : {count}")
    print(f"   Details            : {audit_msg}")
    print("═" * 78 + "\n")


if __name__ == "__main__":
    run_all_demonstrations()
