"""Domain knowledge: MITRE ATT&CK mapping, threat-intel lookup, and maintained Asset Registry.

Supports Contribution C16: IoMT clinical safeguards for medical device infrastructure.
Enforces Section 8:
- Versioned ATT&CK mappings with explicit mapping rules.
- Distinguishes observed behavior, candidate ATT&CK, confirmed vs simulated feed matches.
- Maintained asset registry with asset identity, IP/MAC, criticality, IoMT status,
  clinical restrictions, and owner/approval roles.
- Unknown or conflicting asset identity forces conservative handling of disruptive actions.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
from typing import Any

from .schemas import AssetContext, AssetCriticality, AssetType, ProvenanceType

# ATT&CK Enterprise Matrix version 14.1 mapping
MITRE_VERSION = "14.1"

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1110":     {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "T1046":     {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1595.001": {"name": "Active Scanning: Scanning IP Blocks", "tactic": "Reconnaissance"},
    "T1041":     {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1048":     {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1030":     {"name": "Data Transfer Size Limits", "tactic": "Exfiltration"},
    "T1071":     {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "T1071.004": {"name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
    "T1568.002": {"name": "Dynamic Resolution: Domain Generation Algorithms", "tactic": "Command and Control"},
    "T1573":     {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1565.001": {"name": "Data Manipulation: Stored Data Manipulation", "tactic": "Impact"},
    "T1499":     {"name": "Endpoint Denial of Service", "tactic": "Impact"},
}

LABEL_TECHNIQUES: dict[str, list[str]] = {
    "benign": [],
    "ssh_bruteforce": ["T1110", "T1110.001", "T1110.003", "T1021.004"],
    "port_scan": ["T1046", "T1595.001"],
    "data_exfiltration": ["T1041", "T1048", "T1030"],
    "c2_beaconing": ["T1071", "T1071.001", "T1071.004", "T1568.002", "T1573"],
}

LABEL_BASE_SEVERITY = {
    "benign": "low",
    "port_scan": "medium",
    "ssh_bruteforce": "high",
    "c2_beaconing": "high",
    "data_exfiltration": "critical",
}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

IOMT_DEVICE_PATTERNS = frozenset({
    "infusion-pump", "patient-monitor", "ventilator", "ecg-sensor",
    "dialysis-unit", "anesthesia-workstation", "iomt-gateway",
})


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 1


def candidate_techniques(label: str) -> list[dict[str, str]]:
    return [{"id": t, **MITRE_TECHNIQUES[t]} for t in LABEL_TECHNIQUES.get(label, []) if t in MITRE_TECHNIQUES]


def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def is_iomt_device(host: str | None) -> bool:
    """Checks if hostname or ID matches IoMT patterns as supporting evidence."""
    if not host:
        return False
    h = host.strip().lower()
    return any(p in h for p in IOMT_DEVICE_PATTERNS)


# ---------------------------------------------------------------------------
# Maintained Asset Registry (Section 8)
# ---------------------------------------------------------------------------
DEFAULT_ASSET_REGISTRY: dict[str, dict[str, Any]] = {
    "infusion-pump-01": {
        "asset_id": "ASSET-MED-001",
        "host": "infusion-pump-01",
        "ip_addresses": ["10.0.4.15", "192.168.100.12"],
        "mac_addresses": ["00:1A:2B:3C:4D:5E"],
        "asset_type": "IOMT_MEDICAL",
        "criticality": "CRITICAL",
        "is_iomt": True,
        "clinical_restrictions": [
            "prohibit_autonomous_isolation",
            "maintain_continuous_infusion",
            "clinical_engineering_signoff_required",
        ],
        "owner": "Clinical Engineering ICU",
        "approval_roles": ["clinical_engineer", "medical_director", "soc_lead"],
    },
    "ventilator-icu-02": {
        "asset_id": "ASSET-MED-002",
        "host": "ventilator-icu-02",
        "ip_addresses": ["10.0.4.16"],
        "mac_addresses": ["00:1A:2B:3C:4D:5F"],
        "asset_type": "IOMT_MEDICAL",
        "criticality": "CRITICAL",
        "is_iomt": True,
        "clinical_restrictions": [
            "prohibit_autonomous_isolation",
            "prohibit_power_cycle",
            "critical_life_support",
        ],
        "owner": "ICU Biomedical Engineering",
        "approval_roles": ["clinical_engineer", "medical_director"],
    },
    "ws-finance-07": {
        "asset_id": "ASSET-CORP-042",
        "host": "ws-finance-07",
        "ip_addresses": ["10.0.1.107"],
        "mac_addresses": ["00:11:22:33:44:55"],
        "asset_type": "WORKSTATION",
        "criticality": "HIGH",
        "is_iomt": False,
        "clinical_restrictions": [],
        "owner": "Finance Operations",
        "approval_roles": ["soc_analyst", "soc_lead"],
    },
    "srv-db-prod-01": {
        "asset_id": "ASSET-CORP-001",
        "host": "srv-db-prod-01",
        "ip_addresses": ["10.0.0.10"],
        "mac_addresses": ["00:11:22:33:44:01"],
        "asset_type": "SERVER",
        "criticality": "CRITICAL",
        "is_iomt": False,
        "clinical_restrictions": [],
        "owner": "Infrastructure Team",
        "approval_roles": ["change_advisory_board", "infrastructure_lead"],
    },
}


class AssetRegistry:
    """Maintained asset registry with strict identity resolution and conservative defaults."""

    def __init__(self, entries: dict[str, dict[str, Any]] | None = None):
        self.entries = entries if entries is not None else dict(DEFAULT_ASSET_REGISTRY)

    def lookup(self, host: str | None, ip: str | None = None) -> AssetContext:
        """Resolve asset by host or IP. Defaults to UNKNOWN and conservative criticality if missing."""
        match: dict[str, Any] | None = None

        if host and host in self.entries:
            match = self.entries[host]
        elif ip:
            for entry in self.entries.values():
                if ip in entry.get("ip_addresses", []):
                    match = entry
                    break

        if match:
            return AssetContext(
                asset_id=match["asset_id"],
                host=match["host"],
                ip_addresses=match.get("ip_addresses", []),
                mac_addresses=match.get("mac_addresses", []),
                asset_type=match.get("asset_type", "UNKNOWN"),
                criticality=match.get("criticality", "MEDIUM"),
                is_iomt=match.get("is_iomt", False),
                clinical_restrictions=match.get("clinical_restrictions", []),
                owner=match.get("owner", "Unassigned"),
                approval_roles=match.get("approval_roles", ["soc_analyst"]),
            )

        # Supporting pattern check if not in registry
        is_iomt_pattern = is_iomt_device(host)

        # Unknown asset: Section 8 requires conservative handling
        return AssetContext(
            asset_id=f"UNKNOWN-{host or ip or 'target'}",
            host=host or "unknown_host",
            ip_addresses=[ip] if ip else [],
            mac_addresses=[],
            asset_type="IOMT_MEDICAL" if is_iomt_pattern else "UNKNOWN",
            criticality="HIGH" if is_iomt_pattern else "MEDIUM",
            is_iomt=is_iomt_pattern,
            clinical_restrictions=["prohibit_autonomous_disruption"] if is_iomt_pattern else [],
            owner="Unknown / Unregistered",
            approval_roles=["soc_lead", "system_admin"],
        )


class ThreatIntel:
    """Threat intelligence lookup tracking provenance, status, and external sources."""

    def __init__(self, feed_path: Path | None = None):
        self.entries: dict[str, dict] = {}
        self.provenance: ProvenanceType = "SIMULATED"
        if feed_path and Path(feed_path).is_file():
            data = json.loads(Path(feed_path).read_text(encoding="utf-8"))
            self.entries = {e["indicator"]: e for e in data.get("indicators", [])}
            self.provenance = "REAL" if "real_feed" in str(feed_path) else "SIMULATED"

    def lookup(self, indicator: str | None) -> dict[str, Any]:
        """Look up IOC with explicit status and provenance."""
        now_iso = datetime.now(timezone.utc).isoformat()
        if not indicator:
            return {
                "listed": False,
                "lookup_status": "MISS",
                "retrieval_time": now_iso,
                "provenance": self.provenance,
            }

        hit = self.entries.get(indicator)
        if not hit:
            return {
                "listed": False,
                "internal": is_internal_ip(indicator),
                "lookup_status": "MISS",
                "retrieval_time": now_iso,
                "provenance": self.provenance,
            }

        return {
            "listed": True,
            "feeds": hit.get("feeds", []),
            "category": hit.get("category", "unknown"),
            "first_seen": hit.get("first_seen"),
            "lookup_status": "HIT",
            "retrieval_time": now_iso,
            "provenance": self.provenance,
        }
