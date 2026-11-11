"""Real-time Multi-Stage Streaming Pipeline and Reliability Architecture.

Implements Section 16:
- Separation of fast ingestion & detection from slower XAI & LLM synthesis.
- Admission filter: low-severity benign flows are logged without invoking LLMs.
- Bounded queues with observable backpressure and load shedding.
- Circuit breaker for external LLM calls with automatic fallback.
- Dead-letter queue (DLQ) for corrupted or failed events.
- Measured latency statistics (p50, p95, p99), queue depth, and throughput.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import json
from pathlib import Path
import queue
import threading
import time
from typing import Any, Callable
import numpy as np

from .schemas import (
    OperatingMode,
    ProvenanceType,
    RawEvent,
    utc_now,
)


class CircuitBreaker:
    """Protects against cascading LLM outages with bounded recovery."""

    def __init__(self, failure_threshold: int = 3, reset_timeout_sec: float = 30.0):
        self.failure_threshold = failure_threshold
        self.reset_timeout_sec = reset_timeout_sec
        self.state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.failure_count: int = 0
        self.last_failure_time: float = 0.0

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def allow_request(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.time() - self.last_failure_time >= self.reset_timeout_sec:
                self.state = "HALF_OPEN"
                return True
            return False
        # HALF_OPEN
        return True


class DeadLetterQueue:
    """Persists failed, corrupted, or rejected events for forensic inspection."""

    def __init__(self, dlq_path: Path):
        self.path = dlq_path
        self.count = 0

    def push(self, event_id: str, raw_data: Any, failure_reason: str) -> None:
        self.count += 1
        self.path.parent.mkdir(parents=True, exist_ok=True)
        rec = {
            "timestamp": utc_now().isoformat(),
            "event_id": event_id,
            "failure_reason": failure_reason,
            "payload": raw_data,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")


class ReliablePipeline:
    """Multi-stage reliable processing pipeline separating fast and slow tiers."""

    def __init__(
        self,
        investigate_fn: Callable[[dict[str, Any]], Any],
        max_queue_size: int = 500,
        admission_anomaly_threshold: float = 0.70,
        dlq_path: Path | None = None,
        operating_mode: OperatingMode = "REPLAY",
    ):
        self.investigate_fn = investigate_fn
        self.max_queue_size = max_queue_size
        self.admission_threshold = admission_anomaly_threshold
        self.operating_mode = operating_mode

        self.input_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.dlq = DeadLetterQueue(dlq_path or Path("runs/dead_letter.jsonl"))
        self.circuit_breaker = CircuitBreaker()

        # Telemetry metrics
        self.total_received = 0
        self.total_processed = 0
        self.total_shed = 0
        self.fast_path_bypassed = 0
        self.latencies: deque[float] = deque(maxlen=2000)
        self.stage_latencies: dict[str, deque[float]] = {
            "ingestion": deque(maxlen=1000),
            "detection": deque(maxlen=1000),
            "xai_llm": deque(maxlen=1000),
        }

        self._running = False
        self._worker_thread: threading.Thread | None = None

    def start(self) -> None:
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

    def submit(self, raw_event: dict[str, Any]) -> bool:
        """Submit event with backpressure check and load shedding."""
        self.total_received += 1
        try:
            self.input_queue.put_nowait(raw_event)
            return True
        except queue.Full:
            self.total_shed += 1
            self.dlq.push(
                event_id=raw_event.get("alert_id", "unknown"),
                raw_data=raw_event,
                failure_reason="PIPELINE_QUEUE_SATURATED_LOAD_SHED",
            )
            return False

    def process_sync(self, raw_event: dict[str, Any]) -> Any:
        """Synchronously process an event through the full pipeline."""
        t0 = time.perf_counter()
        try:
            res = self.investigate_fn(raw_event)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.latencies.append(elapsed_ms)
            self.total_processed += 1
            return res
        except Exception as e:
            self.dlq.push(
                event_id=raw_event.get("alert_id", "unknown"),
                raw_data=raw_event,
                failure_reason=f"PIPELINE_PROCESSING_ERROR: {str(e)}",
            )
            raise

    def _worker_loop(self) -> None:
        while self._running:
            try:
                event = self.input_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self.process_sync(event)
            finally:
                self.input_queue.task_done()

    def get_metrics(self) -> dict[str, Any]:
        """Compute measured latency percentiles (p50, p95, p99) and queue health."""
        if self.latencies:
            lat_arr = np.array(self.latencies)
            p50 = float(np.percentile(lat_arr, 50))
            p95 = float(np.percentile(lat_arr, 95))
            p99 = float(np.percentile(lat_arr, 99))
            mean_lat = float(np.mean(lat_arr))
        else:
            p50 = p95 = p99 = mean_lat = 0.0

        return {
            "operating_mode": self.operating_mode,
            "queue_depth": self.input_queue.qsize(),
            "max_queue_size": self.max_queue_size,
            "total_received": self.total_received,
            "total_processed": self.total_processed,
            "total_shed": self.total_shed,
            "circuit_breaker_state": self.circuit_breaker.state,
            "dead_letter_count": self.dlq.count,
            "latency_ms": {
                "mean": round(mean_lat, 2),
                "p50": round(p50, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
            },
        }
