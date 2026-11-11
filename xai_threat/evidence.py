"""Turns a raw flow record + ML detection into the evidence bundle the agents reason over."""

from __future__ import annotations

import hashlib
import json

from .detection import FEATURES, Detection
from .knowledge import ThreatIntel, candidate_techniques, is_internal_ip, is_iomt_device

META_KEYS = ("flow_id", "timestamp", "host", "src_ip", "dst_ip", "dst_port", "protocol",
             "window_minutes", "username", "notes", "raw_log")


def is_flow_record(record: dict) -> bool:
    feats = record.get("features", record)
    return isinstance(feats, dict) and all(f in feats for f in FEATURES)


def flow_features(record: dict) -> dict:
    feats = record.get("features", record)
    return {f: feats[f] for f in FEATURES}


def alert_id(evidence: dict) -> str:
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest()
    return "ALRT-" + digest[:12].upper()


def build_evidence(record: dict, detection: Detection, intel: ThreatIntel,
                   critical_assets: frozenset[str]) -> dict:
    evidence: dict = {k: record[k] for k in META_KEYS if k in record}
    evidence["features"] = flow_features(record)
    evidence["detection"] = detection.to_dict()
    evidence["threat_intel"] = {
        role: intel.lookup(record.get(role)) for role in ("src_ip", "dst_ip") if record.get(role)
    }
    host = record.get("host")
    evidence["asset"] = {
        "host_is_critical": bool(host and host in critical_assets),
        "src_ip_is_internal": is_internal_ip(record.get("src_ip", "")),
        "is_iomt": bool(host and is_iomt_device(host)),
    }
    evidence["candidate_mitre"] = candidate_techniques(detection.label)
    evidence["alert_id"] = alert_id(evidence)
    return evidence


def normalize_prebuilt(evidence: dict, critical_assets: frozenset[str]) -> dict:
    """Accept hand-written evidence (e.g. from a SIEM export) and add the fields the pipeline expects."""
    ev = dict(evidence)
    label = (ev.get("detection") or {}).get("label") or _guess_label(ev)
    if "candidate_mitre" not in ev and label:
        ev["candidate_mitre"] = candidate_techniques(label)
    host = ev.get("host")
    if "asset" not in ev and host:
        ev["asset"] = {
            "host_is_critical": host in critical_assets,
            "is_iomt": is_iomt_device(host),
        }
    elif "asset" in ev and host and "is_iomt" not in ev["asset"]:
        ev["asset"]["is_iomt"] = is_iomt_device(host)
    ev.setdefault("alert_id", alert_id(ev))
    return ev


def _guess_label(ev: dict) -> str | None:
    text = json.dumps(ev).lower()
    for needle, label in (("brute", "ssh_bruteforce"), ("scan", "port_scan"),
                          ("exfil", "data_exfiltration"), ("beacon", "c2_beaconing")):
        if needle in text:
            return label
    return None
