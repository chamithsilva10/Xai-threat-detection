"""Command-line interface.

  python threat_agents.py check                       # test the Ollama connection / API key
  python threat_agents.py train [--csv data.csv]      # train XGBoost detector, calibrate conformal risk
  python threat_agents.py demo [--scenario all]       # run bundled attack & IoMT scenarios
  python threat_agents.py investigate --evidence alert.json
  python threat_agents.py detect --flows data/sample_flows.csv --top 5
  python threat_agents.py verify-audit                # check the cryptographic audit hash chain
  python threat_agents.py eval-rq1                    # evaluate C1 Claim-Evidence Ledger & verifier ablation
  python threat_agents.py eval-rq2                    # evaluate C9 Conformal Risk Control & risk-coverage curves
  python threat_agents.py eval-rq3                    # evaluate C13 Explanation Trust Score vs constituents
  python threat_agents.py eval-benchmarks             # evaluate across NSL-KDD, CIC-IDS2017, UNSW-NB15, CICIoMT2024
  python threat_agents.py eval-all                    # run complete research evaluation suite
  python threat_agents.py feedback                    # record analyst feedback (C4)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from . import audit
from .agents import AgentTeam
from .config import PROJECT_ROOT, Settings
from .datasets import BENCHMARKS
from .detection import FEATURES, ThreatDetector, generate_synthetic, load_training_csv
from .eval import (
    evaluate_rq1_ledger,
    evaluate_rq2_conformal,
    evaluate_rq3_trust_score,
    evaluate_rq4_benchmarks,
)
from .llm import LLMError, OllamaBackend
from .mock_llm import MockBackend
from .orchestrator import Orchestrator
from .report import console_summary, write_markdown
from .schemas import AnalystFeedbackRecord

SCENARIO_DIR = PROJECT_ROOT / "data" / "scenarios"


def _settings(args) -> Settings:
    return Settings.from_env(
        model=getattr(args, "model", None),
        host=getattr(args, "host", None),
    )


def _backend(args, settings: Settings, model_override: str | None = None):
    if args.offline:
        family = "mock-verifier" if model_override else "mock-analyst"
        return MockBackend(
            hallucinate_first=getattr(args, "hallucinate", False),
            model_family=family,
        )
    return OllamaBackend(settings)


def _orchestrator(args) -> Orchestrator:
    settings = _settings(args)
    detector = ThreatDetector.load_or_train(settings.model_path)
    analyst_backend = _backend(args, settings)
    verifier_backend = (
        _backend(args, settings, model_override=getattr(args, "verifier_model", None))
        if getattr(args, "verifier_model", None) or args.offline
        else analyst_backend
    )
    team = AgentTeam(analyst_backend, verifier_backend=verifier_backend, retries=settings.max_retries)
    return Orchestrator(team, settings, detector)


def _run_one(orch: Orchestrator, raw: dict, as_json: bool) -> None:
    inv = orch.investigate(raw, log=lambda m: print(m, file=sys.stderr))
    path = write_markdown(inv, orch.settings.reports_dir)
    if as_json:
        print(json.dumps(inv.to_dict(), indent=2, default=str))
    else:
        print(console_summary(inv))
        print(f"\n   report: {path}")


# ---------------------------------------------------------------------------
def cmd_check(args):
    settings = _settings(args)
    print(OllamaBackend(settings).ping())


def cmd_train(args):
    settings = _settings(args)
    X, y = load_training_csv(Path(args.csv)) if args.csv else generate_synthetic(args.samples)
    det = ThreatDetector(target_risk=getattr(args, "target_risk", 0.05))
    metrics = det.fit(X, y)
    det.save(settings.model_path)
    print(f"Model Engine: {metrics['model_type']}")
    print(f"Trained on {metrics['n_train']} flows, calibrated on {metrics['n_cal']}, tested on {metrics['n_test']}.\n")
    print(metrics["report_text"])
    print("Confusion matrix (rows=true, cols=pred):", metrics["labels"])
    for label, row in zip(metrics["labels"], metrics["confusion_matrix"]):
        print(f"  {label:<18} {row}")

    print("\n--- Conformal Risk Calibration (C9) ---")
    conf = metrics["conformal"]
    print(f"Target Risk (alpha):         {conf['target_risk']:.2%}")
    print(f"Calibrated Threshold (lambda): {conf['calibrated_threshold']:.4f}")
    print(f"Empirical Calibration Risk:  {conf['empirical_calibration_risk']:.2%}")
    print(f"Operational Triage Coverage: {conf['calibration_coverage']:.2%}")
    print(f"\nSaved model artifact to {settings.model_path}")


def cmd_demo(args):
    orch = _orchestrator(args)
    files = (
        sorted(SCENARIO_DIR.glob("*.json"))
        if args.scenario == "all"
        else [SCENARIO_DIR / f"{args.scenario}.json"]
    )
    for f in files:
        if not f.is_file():
            sys.exit(
                f"Unknown scenario '{args.scenario}'. Options: "
                + ", ".join(p.stem for p in SCENARIO_DIR.glob("*.json"))
                + ", all"
            )
        print(f"\n### Scenario: {f.stem}", file=sys.stderr)
        _run_one(orch, json.loads(f.read_text(encoding="utf-8")), args.json)


def cmd_demo_scenarios(args):
    from scripts.demo_all_scenarios import run_all_demonstrations
    run_all_demonstrations()


def cmd_investigate(args):
    orch = _orchestrator(args)
    _run_one(orch, json.loads(Path(args.evidence).read_text(encoding="utf-8")), args.json)


def cmd_detect(args):
    orch = _orchestrator(args)
    with open(args.flows, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k in FEATURES:
            r[k] = float(r[k])
    scored = []
    for r in rows:
        d = orch.detector.detect(r)
        if d.label != "benign" and d.confidence >= orch.settings.alert_threshold:
            scored.append((d.confidence * 0.7 + d.anomaly_score * 0.3, r, d))
    scored.sort(key=lambda t: t[0], reverse=True)
    print(
        f"{len(rows)} flows scored, {len(scored)} alerts above threshold "
        f"{orch.settings.alert_threshold}; investigating top {min(args.top, len(scored))}.",
        file=sys.stderr,
    )
    for priority, r, d in scored[: args.top]:
        print(f"\n### flow {r.get('flow_id')} priority={priority:.2f} ({d.label})", file=sys.stderr)
        _run_one(orch, r, args.json)


def cmd_verify(args):
    ok, msg = audit.verify(_settings(args).audit_log)
    print(("OK: " if ok else "TAMPERING DETECTED: ") + msg)
    sys.exit(0 if ok else 1)


# ---------------------------------------------------------------------------
# Research Evaluation Commands (RQ1, RQ2, RQ3, RQ4)
# ---------------------------------------------------------------------------
def cmd_eval_rq1(args):
    settings = _settings(args)
    print("\n=== Evaluating RQ1: Claim–Evidence Ledger & Cross-Model Verification ===")
    res = evaluate_rq1_ledger(settings, n_scenarios=args.scenarios)
    print(json.dumps(res, indent=2))


def cmd_eval_rq2(args):
    settings = _settings(args)
    det = ThreatDetector.load_or_train(settings.model_path)
    print("\n=== Evaluating RQ2: Conformal Risk-Controlled Abstention ===")
    res = evaluate_rq2_conformal(det)
    print(json.dumps(res, indent=2))


def cmd_eval_rq3(args):
    orch = _orchestrator(args)
    print("\n=== Evaluating RQ3: Composite Explanation Trust Score (ETS) ===")
    res = evaluate_rq3_trust_score(orch, n_samples=args.samples)
    print(json.dumps(res, indent=2))


def cmd_eval_benchmarks(args):
    settings = _settings(args)
    det = ThreatDetector.load_or_train(settings.model_path)
    print("\n=== Evaluating RQ4: Benchmark Corpora (NSL-KDD, CIC-IDS2017, UNSW-NB15, CICIoMT2024) ===")
    res = evaluate_rq4_benchmarks(det)
    print(json.dumps(res, indent=2))


def cmd_eval_all(args):
    settings = _settings(args)
    det = ThreatDetector.load_or_train(settings.model_path)
    orch = _orchestrator(args)
    print("\n=======================================================")
    print("Multi-Agent Explainable AI Framework - Empirical Suite")
    print("=======================================================")

    print("\n[1/4] RQ1: Claim-Evidence Ledger (C1) & Cross-Model Verification:")
    r1 = evaluate_rq1_ledger(settings, n_scenarios=10)
    print(json.dumps(r1, indent=2))

    print("\n[2/4] RQ2: Conformal Risk-Controlled Abstention (C9):")
    r2 = evaluate_rq2_conformal(det)
    print(json.dumps(r2, indent=2))

    print("\n[3/4] RQ3: Explanation Trust Score (C13):")
    r3 = evaluate_rq3_trust_score(orch, n_samples=10)
    print(json.dumps(r3, indent=2))

    print("\n[4/4] RQ4: Benchmark Corpora & Cross-Dataset Domain Shift:")
    r4 = evaluate_rq4_benchmarks(det)
    print(json.dumps(r4, indent=2))


def cmd_feedback(args):
    settings = _settings(args)
    record = AnalystFeedbackRecord(
        alert_id=args.alert_id,
        analyst_id=args.analyst_id,
        perceived_trust=args.trust,
        clarity_rating=args.clarity,
        verdict_agreed=not args.disagree,
        action_overridden=args.override,
        time_to_triage_sec=args.time_sec,
        notes=args.notes,
    )
    audit.append(settings.audit_log, {"event": "analyst_feedback", **record.model_dump()})
    print(f"Recorded feedback for {args.alert_id} in {settings.audit_log}")


def cmd_pending(args):
    settings = _settings(args)
    p_file = settings.pending_queue
    if not p_file.is_file():
        print("No pending actions awaiting approval.")
        return
    lines = [l for l in p_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        print("No pending actions awaiting approval.")
        return
    print(f"\n══ {len(lines)} Pending Remediation Action(s) Requiring Human Authorization ══\n")
    for i, line in enumerate(lines, 1):
        item = json.loads(line)
        print(f"[{i}] Alert: {item.get('alert_id')} | Severity: {item.get('severity', '').upper()}")
        print(f"    Action : {item.get('action', '').upper()} -> Target: {item.get('target')}")
        print(f"    Why    : {item.get('reason')}")
        print(f"    Fix    : {item.get('justification')}\n")


def cmd_approve(args):
    settings = _settings(args)
    p_file = settings.pending_queue
    if not p_file.is_file():
        print("No pending actions awaiting approval.")
        return
    lines = [l for l in p_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        print("No pending actions awaiting approval.")
        return
    remaining = []
    executed = []
    import time
    for line in lines:
        item = json.loads(line)
        match = (args.alert_id == "all" or item.get("alert_id") == args.alert_id)
        if match:
            item["status"] = "executed"
            item["approved_by"] = getattr(args, "analyst_id", "soc_tier2_lead")
            item["executed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            executed.append(item)
            audit.append(settings.audit_log, {"event": "action_executed", **item})
        else:
            remaining.append(line)
    p_file.write_text("\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8")
    if executed:
        print(f"\n✔ Successfully authorized and executed {len(executed)} remediation action(s):")
        for ex in executed:
            print(f"  [{ex['action'].upper()}] -> Target: {ex['target']} | Fix: {ex['justification']}")
        print(f"\nRemediation recorded in immutable audit log: {settings.audit_log}")
    else:
        print(f"No pending actions found for alert '{args.alert_id}'.")


# ---------------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(
        prog="threat_agents",
        description="Multi-Agent Explainable AI Framework for Autonomous Cyber Threat Detection",
    )
    p.add_argument("--model", help="Ollama model (default: $OLLAMA_MODEL or gpt-oss:120b)")
    p.add_argument("--verifier-model", help="Independent Ollama model for Agent 09 Verifier")
    p.add_argument("--host", help="Ollama host (default: $OLLAMA_HOST or https://ollama.com)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, helptext):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--offline", action="store_true", help="use deterministic mock backend")
        sp.add_argument("--json", action="store_true", help="print full JSON output")
        sp.set_defaults(fn=fn)
        return sp

    add("check", cmd_check, "test the Ollama connection and API key")

    t = add("train", cmd_train, "train XGBoost detector and calibrate conformal risk")
    t.add_argument("--csv", help="training CSV with feature columns + label")
    t.add_argument("--samples", type=int, default=1500, help="synthetic samples per class")
    t.add_argument("--target-risk", type=float, default=0.05, help="target conformal risk alpha")

    d = add("demo", cmd_demo, "run bundled scenarios")
    d.add_argument("--scenario", default="all")
    d.add_argument(
        "--hallucinate",
        action="store_true",
        help="(offline) make analyst draft hallucinate to test verifier debate loop",
    )

    add("demo-scenarios", cmd_demo_scenarios, "run the 9 end-to-end mandated scenarios (Section 20)")

    i = add("investigate", cmd_investigate, "investigate one alert / flow JSON file")
    i.add_argument("--evidence", required=True)

    s = add("detect", cmd_detect, "score a CSV of flows and investigate the top alerts")
    s.add_argument("--flows", required=True)
    s.add_argument("--top", type=int, default=3)

    add("verify-audit", cmd_verify, "verify the tamper-evident audit log")

    # Research Evaluation Suite
    e1 = add("eval-rq1", cmd_eval_rq1, "evaluate Claim-Evidence Ledger (C1) and verifier ablations")
    e1.add_argument("--scenarios", type=int, default=10)

    e2 = add("eval-rq2", cmd_eval_rq2, "evaluate Conformal Risk-Controlled Abstention (C9)")

    e3 = add("eval-rq3", cmd_eval_rq3, "evaluate Explanation Trust Score (C13) vs constituents")
    e3.add_argument("--samples", type=int, default=10)

    add("eval-benchmarks", cmd_eval_benchmarks, "evaluate across NSL-KDD, CIC-IDS2017, UNSW-NB15, CICIoMT2024")
    add("eval-all", cmd_eval_all, "run the complete experimental evaluation suite for RQ1-RQ4")

    # Remediation Action Approval & Execution Gate (Agent 06)
    add("pending", cmd_pending, "list pending remediation actions waiting for authorization")

    app = add("approve", cmd_approve, "authorize and execute remediation actions for an alert (or all)")
    app.add_argument("--alert-id", default="all", help="Alert ID to approve, or 'all'")
    app.add_argument("--analyst-id", default="soc_analyst_lead", help="Sign-off authority ID")

    # Analyst Feedback (C4)
    fb = add("feedback", cmd_feedback, "record human analyst feedback on an alert")
    fb.add_argument("--alert-id", required=True)
    fb.add_argument("--analyst-id", default="analyst-1")
    fb.add_argument("--trust", type=float, default=4.0, help="1-5 Likert trust rating")
    fb.add_argument("--clarity", type=float, default=4.5, help="1-5 clarity rating")
    fb.add_argument("--disagree", action="store_true", help="flag disagreement with system verdict")
    fb.add_argument("--override", action="store_true", help="flag that proposed actions were modified")
    fb.add_argument("--time-sec", type=float, default=45.0, help="time taken to triage")
    fb.add_argument("--notes", default="", help="qualitative analyst notes")

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except LLMError as e:
        sys.exit(f"LLM error: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
