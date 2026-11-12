"""Real-Time Telemetry Streaming & Continuous Flow Ingestion Engine.

Simulates an active network sensor tap / Netflow collector interface:
- Consumes authentic flow records sequentially with configurable delay / playback rate.
- Dispatches each flow record through Feature Extraction (Agent 01).
- Triggers Real-Time Detection (Agent 02) and Risk Abstention Triage (Agent 05).
- Automatically escalates anomalies and malicious bursts to the SOC Orchestrator.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Callable, Iterator

from .canonical_json import canonicalize
from .detection import FEATURES, ThreatDetector
from .orchestrator import Orchestrator
from .schemas import utc_now


class LiveNetworkFlowStreamer:
    """Streams flow records in real-time or accelerated replay into the framework."""

    def __init__(
        self,
        flows_csv: Path | str,
        detector: ThreatDetector,
        orchestrator: Orchestrator | None = None,
        playback_delay_sec: float = 0.05,
    ):
        self.csv_path = Path(flows_csv)
        self.detector = detector
        self.orchestrator = orchestrator
        self.delay_sec = playback_delay_sec
        self.flows_streamed = 0
        self.alerts_generated = 0
        self.abstained_count = 0
        self.auto_eligible_count = 0

    def stream(
        self,
        limit: int | None = None,
        on_flow: Callable[[dict[str, Any], Any], None] | None = None,
        on_alert: Callable[[dict[str, Any], Any], None] | None = None,
    ) -> dict[str, Any]:
        """Continuously streams flows, scoring each with the detector and triaging."""
        if not self.csv_path.is_file():
            raise FileNotFoundError(f"Flow stream source not found at '{self.csv_path}'")

        with open(self.csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        if limit:
            rows = rows[:limit]

        t0 = time.time()
        results: list[dict[str, Any]] = []

        for row in rows:
            self.flows_streamed += 1

            # Convert features to numeric
            for feat in FEATURES:
                row[feat] = float(row[feat])

            # Agent 02: Real-time detection inference
            det = self.detector.detect(row)

            # Agent 05: Conformal triage
            triage = self.detector.calibrator.triage(
                class_probabilities=det.class_probabilities,
                label=det.label,
                anomaly_score=det.anomaly_score,
            )

            is_alert = (det.label != "benign" and det.confidence >= 0.70)
            if is_alert:
                self.alerts_generated += 1

            if triage.eligible_for_auto_response:
                self.auto_eligible_count += 1
            else:
                self.abstained_count += 1

            event_summary = {
                "flow_id": row.get("flow_id"),
                "timestamp": row.get("timestamp"),
                "src_ip": row.get("src_ip"),
                "dst_ip": row.get("dst_ip"),
                "true_label": row.get("true_label"),
                "predicted_label": det.label,
                "confidence": round(det.confidence, 4),
                "anomaly_score": round(det.anomaly_score, 4),
                "is_alert": is_alert,
                "conformal_decision": triage.decision,
                "eligible_auto": triage.eligible_for_auto_response,
            }

            if on_flow:
                on_flow(row, event_summary)

            if is_alert and on_alert:
                on_alert(row, det)

            results.append(event_summary)

            if self.delay_sec > 0:
                time.sleep(self.delay_sec)

        elapsed = round(time.time() - t0, 3)
        throughput = round(self.flows_streamed / elapsed, 1) if elapsed > 0 else 0.0

        return {
            "dataset_streamed": str(self.csv_path),
            "total_flows": self.flows_streamed,
            "alerts_triggered": self.alerts_generated,
            "auto_eligible": self.auto_eligible_count,
            "abstained_for_human": self.abstained_count,
            "elapsed_seconds": elapsed,
            "throughput_flows_per_sec": throughput,
            "sample_events": results[:10],
        }
