"""Deterministic offline LLM stand-in.

Lets the full pipeline (debate loop, grounding, policy gate, audit, cross-model verification)
run in tests and without network.
"""

from __future__ import annotations

import json

from .knowledge import LABEL_BASE_SEVERITY, is_internal_ip
from .safety import check_grounding


class MockBackend:
    def __init__(
        self,
        hallucinate_first: bool = False,
        model_family: str = "mock-family-a",
        name: str = "mock (offline, deterministic)",
    ):
        self.hallucinate_first = hallucinate_first
        self.model_family = model_family
        self.name = name

    def chat(self, messages, schema, *, role, context):
        handler = {
            "analyst": self._analyst,
            "critic": self._critic,
            "responder": self._responder,
        }[role]
        return json.dumps(handler(context))

    # ------------------------------------------------------------------
    @staticmethod
    def _label(ev):
        return (ev.get("detection") or {}).get("label", "unknown")

    def _analyst(self, ctx):
        ev = ctx["evidence"]
        det = ev.get("detection", {})
        label = self._label(ev)
        claims = []
        if det:
            claims.append({
                "statement": f"The detector classified the flow as {label} with confidence "
                             f"{det.get('confidence')} and an anomaly percentile of {det.get('anomaly_score')}.",
                "evidence_keys": ["detection.label", "detection.confidence", "detection.anomaly_score"],
            })
            for a in det.get("top_attributions", [])[:3]:
                if a["contribution"] <= 0 or a["value"] == a["normal_baseline"]:
                    continue
                claims.append({
                    "statement": f"{a['feature']} = {a['value']} versus a normal baseline of "
                                 f"{a['normal_baseline']} pushed the model toward {label}.",
                    "evidence_keys": [f"features.{a['feature']}", "detection.top_attributions"],
                })
        else:
            for k, v in ev.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    claims.append({"statement": f"{k} is {v}.", "evidence_keys": [k]})

        src = (ev.get("threat_intel") or {}).get("src_ip") or {}
        if src.get("listed"):
            claims.append({
                "statement": f"Source {ev.get('src_ip')} appears in threat feeds "
                             f"{', '.join(src.get('feeds', []))} ({src.get('category')}).",
                "evidence_keys": ["src_ip", "threat_intel.src_ip.listed", "threat_intel.src_ip.feeds"],
            })

        if ev.get("input_security_flags"):
            claims.append({
                "statement": "The input contains text that tries to manipulate the analysis; "
                             "it was treated as data and is itself suspicious.",
                "evidence_keys": ["input_security_flags"],
            })

        if self.hallucinate_first and ctx.get("round", 0) == 0:
            claims.append({
                "statement": "The attacker then pivoted to 203.0.113.250 over RDP.",
                "evidence_keys": ["lateral_movement.rdp_sessions"],
            })

        mitre = [t["id"] for t in ev.get("candidate_mitre", [])][:2]
        conf = float(det.get("confidence", 0.6))
        return {
            "severity": LABEL_BASE_SEVERITY.get(label, "medium"),
            "summary": f"Activity on {ev.get('host', 'the host')} is consistent with "
                       f"{label.replace('_', ' ') if label != 'unknown' else 'the detected attack pattern'}.",
            "claims": claims,
            "mitre_techniques": mitre,
            "alternative_hypotheses": [
                "A misconfigured service or legitimate admin job; less likely given how far the top "
                "features deviate from their normal baselines."
            ],
            "confidence": round(min(conf, 0.95) * 0.9, 2),
        }

    def _critic(self, ctx):
        ev, report = ctx["evidence"], ctx["report"]
        g = check_grounding(report, ev)
        bad = [
            c.statement
            for c in report.claims
            if any(err.startswith("Claim") and c.statement[:40] in err for err in g.errors)
        ]
        bad += [e for e in g.errors if not e.startswith("Claim")]
        label = self._label(ev)
        severity = LABEL_BASE_SEVERITY.get(label, report.severity)
        if (ev.get("asset") or {}).get("host_is_critical") and severity == "high":
            severity = "critical"
        return {
            "approved": g.ok,
            "unsupported_claims": bad or ([] if g.ok else g.errors),
            "corrected_severity": severity,
            "feedback_for_analyst": "" if g.ok else "Remove or fix: " + "; ".join(g.errors),
            "reasoning": "All claims trace to evidence keys."
            if g.ok
            else "The report contains claims that the evidence does not support.",
        }

    def _responder(self, ctx):
        ev = ctx["evidence"]
        label, host, src, dst = self._label(ev), ev.get("host"), ev.get("src_ip"), ev.get("dst_ip")
        acts = [{"action": "collect_forensics", "target": host, "justification": "Preserve evidence."}] if host else []
        if label == "ssh_bruteforce" and src:
            if is_internal_ip(src):
                acts.append({"action": "isolate_host", "target": src, "justification": "Internal brute-force source."})
            else:
                acts.append({"action": "block_ip", "target": src, "justification": "External brute-force source."})
            if host:
                acts.append({
                    "action": "reset_credentials",
                    "target": host,
                    "justification": "Accounts on the target may be compromised.",
                })
        elif label == "port_scan" and src:
            acts.append({"action": "rate_limit", "target": src, "justification": "Slow the scanner down."})
        elif label in ("data_exfiltration", "c2_beaconing"):
            if host:
                acts.append({"action": "isolate_host", "target": host, "justification": "Contain the endpoint."})
            if dst and not is_internal_ip(dst):
                acts.append({"action": "block_ip", "target": dst, "justification": "Cut the external channel."})
        else:
            acts.append({"action": "monitor", "target": host or src or "unknown", "justification": "Low risk."})
        return {"actions": acts, "reasoning": f"Proportionate containment for {label}."}
