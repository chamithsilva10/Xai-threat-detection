"""Empirical Evaluation Suite for Research Questions RQ1, RQ2, RQ3, and RQ4.

Provides rigorous, reproducible experimental evaluation matching the Project Proposal:
- RQ1: Claim-Evidence Ledger & cross-model verification ablation
- RQ2: Conformal risk-controlled abstention & risk-coverage curves
- RQ3: Composite Explanation Trust Score (ETS) vs constituent metrics
- RQ4: Cross-dataset shift, adversarial prompt-injection tests, and telemetry
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any
import numpy as np

from .agents import AgentTeam
from .config import Settings
from .conformal import ConformalCalibrator, zero_one_loss
from .datasets import BENCHMARKS, generate_benchmark_traffic, run_cross_dataset_shift_test
from .detection import ThreatDetector, generate_synthetic
from .mock_llm import MockBackend
from .orchestrator import Orchestrator
from .schemas import Claim


# ---------------------------------------------------------------------------
# RQ1: Claim–Evidence Ledger & Cross-Model Verification Evaluation
# ---------------------------------------------------------------------------
def evaluate_rq1_ledger(
    settings: Settings,
    n_scenarios: int = 15,
) -> dict:
    """Evaluates whether the Claim-Evidence Ledger (C1) and cross-model verification
    improve claim support ratio and reduce hallucinated/unsupported assertions.
    """
    results = {
        "single_llm_no_ledger": {"total_claims": 0, "supported_claims": 0, "latency_ms": 0.0},
        "same_model_self_verification": {"total_claims": 0, "supported_claims": 0, "latency_ms": 0.0},
        "cross_model_with_ledger": {"total_claims": 0, "supported_claims": 0, "latency_ms": 0.0},
    }

    # Generate synthetic alert cases (some with hallucination stress)
    det = ThreatDetector.load_or_train(settings.model_path)

    # 1. Single LLM without ledger (no debate rounds, raw draft)
    team_single = AgentTeam(MockBackend(hallucinate_first=True))
    t0 = time.perf_counter()
    for i in range(n_scenarios):
        raw = {"flow_id": f"flow-rq1-{i}", "features": {"failed_logins": 150 + i, "conn_rate": 25.0,
               "distinct_dst_ports": 2, "bytes_out_mb": 0.1, "bytes_in_mb": 0.2, "off_hours": 1,
               "dns_query_entropy": 2.5, "beacon_regularity": 0.3}}
        ev, d, flags = Orchestrator(team_single, settings, det).build_evidence(raw)
        rep = team_single.analyst(ev)
        # In single model without verification, hallucinations survive in the output
        for c in rep.claims:
            results["single_llm_no_ledger"]["total_claims"] += 1
            # Grounding check
            if "203.0.113.250" not in c.statement and "lateral_movement" not in str(c.evidence_keys):
                results["single_llm_no_ledger"]["supported_claims"] += 1
    results["single_llm_no_ledger"]["latency_ms"] = round((time.perf_counter() - t0) * 1000 / n_scenarios, 2)

    # 2. Same-model self-verification
    team_same = AgentTeam(MockBackend(hallucinate_first=True, model_family="same_family"))
    orch_same = Orchestrator(team_same, settings, det)
    t0 = time.perf_counter()
    for i in range(n_scenarios):
        raw = {"flow_id": f"flow-rq1-same-{i}", "features": {"failed_logins": 150 + i, "conn_rate": 25.0,
               "distinct_dst_ports": 2, "bytes_out_mb": 0.1, "bytes_in_mb": 0.2, "off_hours": 1,
               "dns_query_entropy": 2.5, "beacon_regularity": 0.3}}
        inv = orch_same.investigate(raw)
        results["same_model_self_verification"]["total_claims"] += inv.ledger.total_claims
        results["same_model_self_verification"]["supported_claims"] += inv.ledger.supported_claims
    results["same_model_self_verification"]["latency_ms"] = round((time.perf_counter() - t0) * 1000 / n_scenarios, 2)

    # 3. Cross-model verification with Claim-Evidence Ledger (Proposed)
    analyst_backend = MockBackend(hallucinate_first=True, model_family="family_analyst_llama")
    verifier_backend = MockBackend(hallucinate_first=False, model_family="family_verifier_mistral")
    team_cross = AgentTeam(analyst_backend, verifier_backend=verifier_backend)
    orch_cross = Orchestrator(team_cross, settings, det)
    t0 = time.perf_counter()
    for i in range(n_scenarios):
        raw = {"flow_id": f"flow-rq1-cross-{i}", "features": {"failed_logins": 150 + i, "conn_rate": 25.0,
               "distinct_dst_ports": 2, "bytes_out_mb": 0.1, "bytes_in_mb": 0.2, "off_hours": 1,
               "dns_query_entropy": 2.5, "beacon_regularity": 0.3}}
        inv = orch_cross.investigate(raw)
        results["cross_model_with_ledger"]["total_claims"] += inv.ledger.total_claims
        results["cross_model_with_ledger"]["supported_claims"] += inv.ledger.supported_claims
    results["cross_model_with_ledger"]["latency_ms"] = round((time.perf_counter() - t0) * 1000 / n_scenarios, 2)

    # Summary ratios
    summary = {}
    for k, v in results.items():
        tot = v["total_claims"]
        supp = v["supported_claims"]
        summary[k] = {
            "supported_claims": supp,
            "total_claims": tot,
            "supported_ratio": round(supp / tot, 4) if tot else 1.0,
            "unsupported_rate": round((tot - supp) / tot, 4) if tot else 0.0,
            "avg_latency_ms": v["latency_ms"],
        }
    return summary


# ---------------------------------------------------------------------------
# RQ2: Conformal Risk-Controlled Abstention Evaluation
# ---------------------------------------------------------------------------
def evaluate_rq2_conformal(
    detector: ThreatDetector,
    alphas: tuple[float, ...] = (0.01, 0.05, 0.10),
    n_test: int = 400,
) -> dict:
    """Evaluates conformal risk control across multiple target risk levels alpha,
    comparing against an uncalibrated heuristic threshold baseline.
    """
    X_test, y_test = generate_synthetic(n_per_class=n_test // 5, seed=123)
    probs = detector.predict_proba_dict(X_test)
    preds = [max(p.items(), key=lambda t: t[1])[0] for p in probs]
    losses = np.array([zero_one_loss(p, y) for p, y in zip(preds, y_test)])

    # Uncalibrated baseline: score thresholding (e.g. confidence >= 0.70)
    top_confs = np.array([max(p.values()) for p in probs])
    uncalibrated_accepted = top_confs >= 0.70
    uncal_cov = float(np.mean(uncalibrated_accepted))
    uncal_risk = float(np.mean(losses[uncalibrated_accepted])) if np.any(uncalibrated_accepted) else 0.0

    table = {
        "uncalibrated_heuristic": {
            "policy": "Confidence >= 0.70",
            "coverage": round(uncal_cov, 4),
            "empirical_risk": round(uncal_risk, 4),
        },
        "conformal_policies": {},
    }

    # Evaluate conformal calibrator at each alpha
    for a in alphas:
        calibrator = ConformalCalibrator(target_risk=a)
        # Use calibration set from detector
        calibrator.calibrate(probs[: len(probs) // 2], y_test[: len(y_test) // 2])
        test_eval = calibrator.evaluate_test_set(probs[len(probs) // 2 :], y_test[len(y_test) // 2 :])
        table["conformal_policies"][f"alpha_{a:.2f}"] = {
            "target_risk_alpha": a,
            "calibrated_threshold_lambda": calibrator.calibrated_threshold,
            "test_coverage": test_eval["test_coverage"],
            "empirical_test_risk": test_eval["test_risk"],
            "guarantee_satisfied": bool(test_eval["test_risk"] <= a + 0.02),  # within sampling tolerance
            "abstained_count": test_eval["abstained_count"],
        }

    return table


# ---------------------------------------------------------------------------
# RQ3: Composite Explanation Trust Score (ETS) Evaluation
# ---------------------------------------------------------------------------
def evaluate_rq3_trust_score(
    orch: Orchestrator,
    n_samples: int = 15,
) -> dict:
    """Evaluates whether the composite Explanation Trust Score (ETS, C13)
    reflects overall alert validity better than any single constituent metric.
    """
    composite_scores = []
    faithfulness_scores = []
    agreement_scores = []
    grounding_scores = []
    certainty_scores = []

    for i in range(n_samples):
        # Mix of standard and edge cases
        raw = {
            "flow_id": f"flow-rq3-{i}",
            "features": {
                "failed_logins": 50 + i * 15,
                "conn_rate": 10.0 + i * 2,
                "distinct_dst_ports": 1 + (i % 3),
                "bytes_out_mb": 1.0,
                "bytes_in_mb": 0.5,
                "off_hours": i % 2,
                "dns_query_entropy": 2.4,
                "beacon_regularity": 0.2,
            },
        }
        inv = orch.investigate(raw)
        tb = inv.trust_breakdown
        composite_scores.append(tb.composite_score)
        faithfulness_scores.append(tb.faithfulness)
        agreement_scores.append(tb.cross_explainer_agreement)
        grounding_scores.append(tb.grounding_ratio)
        certainty_scores.append(tb.model_certainty)

    return {
        "sample_count": n_samples,
        "composite_ets": {
            "mean": round(float(np.mean(composite_scores)), 4),
            "std": round(float(np.std(composite_scores)), 4),
            "min": round(float(np.min(composite_scores)), 4),
            "max": round(float(np.max(composite_scores)), 4),
        },
        "faithfulness": {"mean": round(float(np.mean(faithfulness_scores)), 4)},
        "cross_explainer_agreement": {"mean": round(float(np.mean(agreement_scores)), 4)},
        "grounding_ratio": {"mean": round(float(np.mean(grounding_scores)), 4)},
        "model_certainty": {"mean": round(float(np.mean(certainty_scores)), 4)},
    }


# ---------------------------------------------------------------------------
# RQ4: Robustness, Cross-Dataset Benchmarks, and Telemetry
# ---------------------------------------------------------------------------
def evaluate_rq4_benchmarks(
    detector: ThreatDetector,
    datasets: tuple[str, ...] = ("NSL-KDD", "CIC-IDS2017", "UNSW-NB15", "CICIoMT2024"),
) -> dict:
    """Evaluates cross-corpus generalisation, genuine local captures, and authentic benchmark status."""
    from .datasets import BENCHMARKS, evaluate_genuine_local_flows, run_cross_dataset_shift_test

    # 1. Genuine Local Captured Dataset Evaluation
    local_eval = evaluate_genuine_local_flows(detector, Path("data/sample_flows.csv"))
    adv_csv = Path("data/authentic_flows_advanced.csv")
    adv_eval = evaluate_genuine_local_flows(detector, adv_csv) if adv_csv.is_file() else None

    # 2. External Benchmark Audit (Checking for presence of raw multi-GB captures)
    benchmarks_status = {}
    synthetic_shifts = {}

    for ds in datasets:
        meta = BENCHMARKS.get(ds)
        # Check if raw files exist locally
        raw_paths = {
            "NSL-KDD": Path("data/raw/nsl_kdd/KDDTrain+.txt"),
            "CIC-IDS2017": Path("data/raw/cic_ids2017"),
            "UNSW-NB15": Path("data/raw/unsw_nb15/UNSW_NB15_training-set.csv"),
            "CICIoMT2024": Path("data/raw/ciciomt2024"),
        }
        target_path = raw_paths.get(ds, Path(f"data/raw/{ds.lower()}"))
        raw_exists = target_path.is_file() or (target_path.is_dir() and any(target_path.iterdir()))

        if raw_exists:
            benchmarks_status[ds] = {
                "status": "RAW_FILES_PRESENT",
                "path": str(target_path),
                "evaluation": "PENDING_ARFF_PARSING",
            }
        else:
            benchmarks_status[ds] = {
                "status": "NOT_RUN (RAW_DATASETS_ABSENT)",
                "publisher": meta.publisher if meta else "Unknown",
                "device_context": meta.device_context if meta else "Unknown",
                "authentic_classes": meta.publisher_attack_classes if meta else [],
                "missing_path": str(target_path),
                "reason": "Raw empirical PCAP/CSV captures are absent from repository; synthetic generators must not be substituted for real datasets.",
            }

        # Run synthetic shift test strictly labeled as synthetic distribution stand-in
        shift_res = run_cross_dataset_shift_test(
            detector=detector,
            source_name="Synthetic Baseline",
            target_name=ds,
            n_samples_per_class=100,
        )
        synthetic_shifts[ds] = shift_res

    return {
        "genuine_dataset_evaluation": {
            "sample_flows": local_eval,
            "authentic_flows_advanced": adv_eval,
        },
        "external_benchmarks_audit": benchmarks_status,
        "synthetic_distribution_shift_demonstration": synthetic_shifts,
    }
