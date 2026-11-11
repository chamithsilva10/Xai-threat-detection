"""Agent 01: Real-Time Telemetry Ingestion and Log Adapters.

Implements Section 5:
- Telemetry Adapters:
  1. LiveSshAuthLogAdapter: Genuine parser for SSH authentication logs (/var/log/auth.log).
  2. SuricataEveJsonAdapter: Parser for Suricata EVE JSON event logs with rotation support.
  3. ReplayAdapter: Reproducible replay of recorded datasets with explicit provenance tags.
- Reliability & Edge-Case Handling:
  - Persistent byte offset checkpoints for file restart and rotation recovery.
  - Partial line buffering and malformed line quarantine.
  - Deduplication via event fingerprint cache.
  - Bounded memory queues with backpressure and observable overflow counters.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterator
import uuid

from .schemas import (
    NormalizedEvent,
    OperatingMode,
    ProvenanceType,
    RawEvent,
    utc_now,
)

SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port (?P<port>\d+)",
    re.IGNORECASE,
)


class CheckpointManager:
    """Manages persistent byte-offsets and line counters for resilient restart recovery."""

    def __init__(self, checkpoint_path: Path):
        self.path = checkpoint_path
        self.offsets: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        if self.path.is_file():
            try:
                self.offsets = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.offsets = {}

    def get_offset(self, file_key: str) -> int:
        return self.offsets.get(file_key, 0)

    def save_offset(self, file_key: str, offset: int) -> None:
        self.offsets[file_key] = offset
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.offsets, indent=2), encoding="utf-8")


class QuarantineLogger:
    """Isolates malformed or corrupted log records without crashing the pipeline."""

    def __init__(self, quarantine_file: Path):
        self.path = quarantine_file
        self.quarantine_count = 0

    def quarantine(self, raw_data: str, error_reason: str, source: str) -> None:
        self.quarantine_count += 1
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": utc_now().isoformat(),
            "source": source,
            "error_reason": error_reason,
            "raw_snippet": raw_data[:500],
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


class BaseAdapter:
    """Abstract base adapter with deduplication, quarantine, and backpressure."""

    def __init__(
        self,
        source_name: str,
        checkpoint_dir: Path | None = None,
        max_queue_size: int = 1000,
        quarantine_path: Path | None = None,
    ):
        self.source_name = source_name
        self.max_queue_size = max_queue_size
        self.buffer: deque[RawEvent] = deque(maxlen=max_queue_size)
        self.dropped_events = 0
        self.checkpoint_mgr = CheckpointManager(
            checkpoint_dir / f"{source_name}_checkpoint.json"
            if checkpoint_dir
            else Path(f"runs/{source_name}_checkpoint.json")
        )
        self.quarantine = QuarantineLogger(
            quarantine_path or Path(f"runs/quarantine_{source_name}.jsonl")
        )
        self._seen_fingerprints: deque[str] = deque(maxlen=10000)

    def is_duplicate(self, fingerprint: str) -> bool:
        if fingerprint in self._seen_fingerprints:
            return True
        self._seen_fingerprints.append(fingerprint)
        return False

    def enqueue(self, event: RawEvent) -> bool:
        """Enqueue event with observable backpressure handling."""
        if len(self.buffer) >= self.max_queue_size:
            self.dropped_events += 1
            return False  # Queue saturated
        self.buffer.append(event)
        return True


class LiveSshAuthLogAdapter(BaseAdapter):
    """Genuine adapter for parsing Linux/UNIX SSH authentication logs."""

    def __init__(self, log_path: Path, **kwargs):
        super().__init__(source_name="ssh_auth", **kwargs)
        self.log_path = Path(log_path)
        self.failed_login_window: deque[tuple[float, str]] = deque()  # (timestamp, ip)

    def tail(self, max_records: int = 100) -> Iterator[RawEvent]:
        """Read newly appended lines since last checkpoint."""
        if not self.log_path.is_file():
            return

        file_key = str(self.log_path.resolve())
        offset = self.checkpoint_mgr.get_offset(file_key)

        # Handle file truncation/rotation
        file_size = self.log_path.stat().st_size
        if file_size < offset:
            offset = 0  # File was rotated

        count = 0
        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            while count < max_records:
                line = f.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    # Partial line; rewind to start of line and wait
                    f.seek(offset)
                    break

                offset = f.tell()
                count += 1
                evt = self._parse_line(line)
                if evt:
                    yield evt

            self.checkpoint_mgr.save_offset(file_key, offset)

    def _parse_line(self, line: str) -> RawEvent | None:
        fail_m = SSH_FAILED_RE.search(line)
        succ_m = SSH_ACCEPTED_RE.search(line)

        now = utc_now()
        if fail_m:
            ip = fail_m.group("ip")
            user = fail_m.group("user")
            port = int(fail_m.group("port"))
            payload = {
                "auth_status": "FAILED",
                "src_ip": ip,
                "user": user,
                "dst_port": port,
                "raw_line": line.strip(),
            }
            fp = hashlib.sha256(f"ssh_fail:{ip}:{user}:{now.timestamp():.0f}".encode()).hexdigest()
            if self.is_duplicate(fp):
                return None
            return RawEvent(
                source="ssh_auth",
                sensor_identity="host-sshd",
                raw_payload=payload,
                provenance="REAL",
            )
        elif succ_m:
            ip = succ_m.group("ip")
            user = succ_m.group("user")
            port = int(succ_m.group("port"))
            payload = {
                "auth_status": "ACCEPTED",
                "src_ip": ip,
                "user": user,
                "dst_port": port,
                "raw_line": line.strip(),
            }
            return RawEvent(
                source="ssh_auth",
                sensor_identity="host-sshd",
                raw_payload=payload,
                provenance="REAL",
            )
        return None


class SuricataEveJsonAdapter(BaseAdapter):
    """Genuine adapter for parsing Suricata EVE JSON event logs."""

    def __init__(self, eve_path: Path, **kwargs):
        super().__init__(source_name="suricata_eve", **kwargs)
        self.eve_path = Path(eve_path)

    def tail(self, max_records: int = 100) -> Iterator[RawEvent]:
        if not self.eve_path.is_file():
            return

        file_key = str(self.eve_path.resolve())
        offset = self.checkpoint_mgr.get_offset(file_key)
        if self.eve_path.stat().st_size < offset:
            offset = 0

        count = 0
        with open(self.eve_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            while count < max_records:
                line = f.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    f.seek(offset)
                    break

                offset = f.tell()
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    payload = json.loads(line_str)
                    count += 1
                    yield RawEvent(
                        source="suricata_eve",
                        sensor_identity=payload.get("host", "suricata-sensor-01"),
                        raw_payload=payload,
                        provenance="REAL",
                    )
                except json.JSONDecodeError as err:
                    self.quarantine.quarantine(line_str, str(err), "suricata_eve")

            self.checkpoint_mgr.save_offset(file_key, offset)


class ReplayAdapter(BaseAdapter):
    """Reproducible replay adapter for benchmark datasets and saved scenarios."""

    def __init__(self, records: list[dict[str, Any]], provenance: ProvenanceType = "SIMULATED"):
        super().__init__(source_name="replay_adapter")
        self.records = records
        self.provenance = provenance
        self._index = 0

    def next_event(self) -> RawEvent | None:
        if self._index >= len(self.records):
            return None
        rec = self.records[self._index]
        self._index += 1
        return RawEvent(
            event_id=rec.get("alert_id") or f"replay-{self._index:04d}",
            source="replay_flow",
            sensor_identity="replay-harness",
            raw_payload=rec,
            provenance=self.provenance,
        )

    def reset(self) -> None:
        self._index = 0
