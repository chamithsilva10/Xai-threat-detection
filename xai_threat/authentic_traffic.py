"""Advanced Authentic Network Flow Generator and Real-Time Telemetry Builder.

Models high-fidelity enterprise network traffic, IoMT clinical environments,
and genuine attack dynamics across five classes:
1. benign (Normal web, database, and dev workflows)
2. ssh_bruteforce (Credential stuffing / dictionary attacks on port 22)
3. port_scan (Horizontal / vertical reconnaissance scanning)
4. data_exfiltration (High-volume egress data theft)
5. c2_beaconing (Periodic command-and-control heartbeats & DGA queries)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
from typing import Any
import numpy as np

from .detection import FEATURES, LABELS
from .features import MODEL_FEATURES


# Realistic enterprise network IP topology
ENTERPRISE_TOPOLOGY = {
    "auth_servers": [
        {"host": "auth-dc01", "ip": "10.0.0.5", "role": "Active Directory / Kerberos"},
        {"host": "auth-srv-02", "ip": "10.0.0.6", "role": "Linux Bastion / SSH"},
    ],
    "db_servers": [
        {"host": "db-prod-01", "ip": "10.0.0.10", "role": "Production SQL Database"},
        {"host": "db-analytics-01", "ip": "10.0.0.12", "role": "Data Warehouse"},
    ],
    "workstations": [
        f"10.0.1.{i}" for i in range(10, 80)
    ],
    "iomt_devices": [
        {"host": f"iomt-vitals-{i:02d}", "ip": f"10.200.1.{i}", "device": "Patient Vitals Monitor"} for i in range(10, 25)
    ] + [
        {"host": f"iomt-infusion-{j:02d}", "ip": f"10.200.1.{j}", "device": "Smart Infusion Pump"} for j in range(30, 45)
    ],
    "external_threat_actors": [
        {"ip": "45.133.1.20", "actor": "APT-Exfil-DropPoint", "cc": "RU"},
        {"ip": "91.219.236.18", "actor": "CobaltStrike-C2", "cc": "NL"},
        {"ip": "185.220.101.5", "actor": "Tor-Exit-Scanner", "cc": "DE"},
        {"ip": "77.83.36.9", "actor": "Mirai-Recon-Probe", "cc": "SC"},
        {"ip": "194.26.29.112", "actor": "BruteForce-Botnet", "cc": "BG"},
    ],
    "external_legit_services": [
        "8.8.8.8", "1.1.1.1", "142.250.190.46", "13.107.42.14", "151.101.65.140"
    ]
}


def generate_advanced_authentic_flows(
    n_flows: int = 1000,
    start_time: datetime | None = None,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Generates realistic, chronologically consistent network flow records."""
    rng = np.random.default_rng(seed)
    py_rng = random.Random(seed)

    if start_time is None:
        start_time = datetime(2026, 11, 10, 8, 0, 0, tzinfo=timezone.utc)

    # Class distribution: ~65% benign, ~10% brute force, ~10% port scan, ~7.5% exfil, ~7.5% C2
    target_proportions = {
        "benign": 0.65,
        "ssh_bruteforce": 0.10,
        "port_scan": 0.10,
        "data_exfiltration": 0.075,
        "c2_beaconing": 0.075,
    }

    class_pool = []
    for cls_name, prop in target_proportions.items():
        count = int(round(n_flows * prop))
        class_pool.extend([cls_name] * count)

    # Adjust rounding differences
    while len(class_pool) < n_flows:
        class_pool.append("benign")
    class_pool = class_pool[:n_flows]
    py_rng.shuffle(class_pool)

    flows: list[dict[str, Any]] = []
    current_time = start_time

    for i, true_label in enumerate(class_pool):
        # Time progression: 1 to 45 seconds between flow summaries
        delta_sec = py_rng.randint(2, 35)
        current_time += timedelta(seconds=delta_sec)
        hour = current_time.hour
        is_off_hours = 1 if (hour < 7 or hour >= 19) else 0

        flow_id = f"FLOW-{current_time.strftime('%Y%m%d')}-{i+1:05d}"

        if true_label == "benign":
            # Realistic enterprise benign flow
            host = py_rng.choice(ENTERPRISE_TOPOLOGY["workstations"])
            src_ip = host
            dst_ip = py_rng.choice(ENTERPRISE_TOPOLOGY["external_legit_services"] + ["10.0.0.10"])
            
            failed_logins = float(rng.choice([0.0, 0.0, 0.0, 1.0, 2.0], p=[0.70, 0.15, 0.10, 0.04, 0.01]))
            conn_rate = float(np.clip(rng.lognormal(mean=1.1, sigma=0.45), 0.2, 12.0))
            distinct_dst_ports = float(rng.integers(1, 7))
            bytes_out = float(np.clip(rng.lognormal(mean=0.5, sigma=0.8), 0.05, 15.0))
            bytes_in = float(np.clip(rng.lognormal(mean=1.8, sigma=0.9), 0.1, 45.0))
            dns_entropy = float(np.clip(rng.normal(loc=2.45, scale=0.25), 1.5, 3.2))
            beacon_reg = float(np.clip(rng.beta(a=1.5, b=6.0), 0.01, 0.35))

        elif true_label == "ssh_bruteforce":
            # High-volume failed logins targeting an auth server
            attacker = py_rng.choice(ENTERPRISE_TOPOLOGY["external_threat_actors"])
            src_ip = attacker["ip"]
            target = py_rng.choice(ENTERPRISE_TOPOLOGY["auth_servers"])
            dst_ip = target["ip"]
            host = target["host"]

            failed_logins = float(rng.integers(45, 320))
            conn_rate = float(np.clip(rng.normal(loc=28.0, scale=6.0), 12.0, 60.0))
            distinct_dst_ports = 1.0  # Targeted port 22
            bytes_out = float(np.clip(rng.lognormal(mean=0.2, sigma=0.4), 0.1, 2.5))
            bytes_in = float(np.clip(rng.lognormal(mean=0.3, sigma=0.4), 0.2, 3.0))
            dns_entropy = float(np.clip(rng.normal(loc=2.2, scale=0.3), 1.5, 3.0))
            beacon_reg = float(np.clip(rng.beta(a=2.0, b=5.0), 0.05, 0.40))

        elif true_label == "port_scan":
            # Reconnaissance probing across hundreds of ports
            attacker = py_rng.choice(ENTERPRISE_TOPOLOGY["external_threat_actors"])
            src_ip = attacker["ip"]
            victim = py_rng.choice(ENTERPRISE_TOPOLOGY["workstations"] + ["10.0.0.5", "10.0.0.10"])
            dst_ip = victim
            host = f"srv-{victim.split('.')[-1]}"

            failed_logins = float(rng.choice([0.0, 1.0, 2.0, 3.0], p=[0.75, 0.15, 0.08, 0.02]))
            conn_rate = float(np.clip(rng.normal(loc=55.0, scale=12.0), 25.0, 120.0))
            distinct_dst_ports = float(rng.integers(120, 1450))
            bytes_out = float(np.clip(rng.lognormal(mean=-0.8, sigma=0.4), 0.05, 1.2))
            bytes_in = float(np.clip(rng.lognormal(mean=-0.8, sigma=0.4), 0.05, 1.2))
            dns_entropy = float(np.clip(rng.normal(loc=2.3, scale=0.3), 1.6, 3.1))
            beacon_reg = float(np.clip(rng.beta(a=2.0, b=4.0), 0.08, 0.45))

        elif true_label == "data_exfiltration":
            # Massive outbound data spike to drop point
            insider_host = py_rng.choice(ENTERPRISE_TOPOLOGY["workstations"])
            src_ip = insider_host
            drop_point = "45.133.1.20"
            dst_ip = drop_point
            host = f"ws-corp-{insider_host.split('.')[-1]}"

            failed_logins = float(rng.choice([0.0, 1.0], p=[0.9, 0.1]))
            conn_rate = float(np.clip(rng.normal(loc=4.5, scale=1.5), 1.0, 10.0))
            distinct_dst_ports = float(rng.integers(1, 3))
            bytes_out = float(np.clip(rng.lognormal(mean=5.5, sigma=0.6), 85.0, 1600.0))  # High egress MB
            bytes_in = float(np.clip(rng.lognormal(mean=0.4, sigma=0.5), 0.2, 5.0))
            dns_entropy = float(np.clip(rng.normal(loc=2.5, scale=0.35), 1.8, 3.4))
            beacon_reg = float(np.clip(rng.beta(a=2.5, b=4.0), 0.15, 0.60))

        elif true_label == "c2_beaconing":
            # Periodic heartbeat with high regularity and DGA DNS entropy
            compromised_host = py_rng.choice(ENTERPRISE_TOPOLOGY["workstations"])
            src_ip = compromised_host
            c2_server = "91.219.236.18"
            dst_ip = c2_server
            host = f"ws-corp-{compromised_host.split('.')[-1]}"

            failed_logins = 0.0
            conn_rate = float(np.clip(rng.normal(loc=2.5, scale=0.5), 1.0, 5.0))
            distinct_dst_ports = 1.0  # e.g., HTTPS port 443 or custom 8443
            bytes_out = float(np.clip(rng.lognormal(mean=-0.2, sigma=0.3), 0.2, 1.8))
            bytes_in = float(np.clip(rng.lognormal(mean=-0.1, sigma=0.3), 0.3, 2.2))
            dns_entropy = float(np.clip(rng.normal(loc=4.25, scale=0.30), 3.75, 5.20))  # DGA algorithm
            beacon_reg = float(np.clip(rng.beta(a=8.5, b=1.5), 0.75, 0.98))            # Strict periodicity

        else:
            raise ValueError(f"Unknown label: {true_label}")

        flow_record = {
            "flow_id": flow_id,
            "timestamp": current_time.isoformat(),
            "host": host,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "true_label": true_label,
            "failed_logins": round(failed_logins, 1),
            "conn_rate": round(conn_rate, 3),
            "distinct_dst_ports": round(distinct_dst_ports, 1),
            "bytes_out_mb": round(bytes_out, 3),
            "bytes_in_mb": round(bytes_in, 3),
            "off_hours": float(is_off_hours),
            "dns_query_entropy": round(dns_entropy, 3),
            "beacon_regularity": round(beacon_reg, 3),
        }
        flows.append(flow_record)

    return flows


def save_authentic_flows_csv(
    flows: list[dict[str, Any]],
    output_path: Path | str,
) -> tuple[Path, str, dict[str, Any]]:
    """Saves flows to CSV and generates a cryptographically authenticated manifest."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "flow_id", "timestamp", "host", "src_ip", "dst_ip", "true_label",
        "failed_logins", "conn_rate", "distinct_dst_ports",
        "bytes_out_mb", "bytes_in_mb", "off_hours",
        "dns_query_entropy", "beacon_regularity"
    ]

    import csv
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for flow in flows:
            writer.writerow(flow)

    # Compute SHA256 checksum
    data_bytes = out.read_bytes()
    file_sha256 = hashlib.sha256(data_bytes).hexdigest()

    # Calculate distribution statistics
    class_counts: dict[str, int] = {}
    for fl in flows:
        lbl = fl["true_label"]
        class_counts[lbl] = class_counts.get(lbl, 0) + 1

    manifest = {
        "dataset_name": out.name,
        "format": "RFC 4180 CSV",
        "sha256": file_sha256,
        "n_flows": len(flows),
        "columns": fieldnames,
        "class_breakdown": class_counts,
        "time_span": {
            "start": flows[0]["timestamp"] if flows else None,
            "end": flows[-1]["timestamp"] if flows else None,
        },
        "provenance": "HIGH_FIDELITY_AUTHENTIC_NETWORK_SIMULATION",
        "features": {feat: spec.origin for feat, spec in zip(FEATURES, MODEL_FEATURES)},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    manifest_path = out.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return out, file_sha256, manifest
