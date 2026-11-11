"""Human-readable outputs: console summary and Markdown incident report per alert.

Presents all headline contributions:
- C1: Typed Claim-Evidence Ledger & verification verdicts
- C9: Conformal Risk-Controlled Abstention decision and metrics
- C13: Composite Explanation Trust Score (ETS) breakdown
- C10: Contrastive / counterfactual explanation
- C16: IoMT clinical safeguards status
"""

from __future__ import annotations

from pathlib import Path

from .knowledge import MITRE_TECHNIQUES
from .orchestrator import Investigation


def _bar(value: float, scale: float, width: int = 20) -> str:
    n = int(round(min(abs(value) / scale, 1.0) * width)) if scale else 0
    return ("█" * n).ljust(width) + ("  ▲" if value > 0 else "  ▼")


def console_summary(inv: Investigation) -> str:
    r, v, d, led, conf, tb = (
        inv.report,
        inv.verdict,
        inv.decision,
        inv.ledger,
        inv.conformal,
        inv.trust_breakdown,
    )
    lines = [
        "",
        f"══ {inv.alert_id} ═══ severity={inv.final_severity.upper()}  "
        f"ETS={inv.trust_score:.3f}  conformal={conf.decision}  status={inv.status}",
        f"Backend : {inv.backend}",
    ]
    if inv.detection:
        det = inv.detection
        lines += [
            f"Detector: {det.label} (p={det.confidence:.2f}), anomaly percentile {det.anomaly_score:.2f}",
            f"XAI     : {det.explainer}",
        ]
        top = det.attributions[:5]
        scale = max(abs(a["contribution"]) for a in top) or 1
        for a in top:
            lines.append(
                f"   {a['feature']:<20} {a['value']:>10} (normal {a['normal_baseline']:>8})  "
                f"{_bar(a['contribution'], scale)}"
            )
        if det.contrastive_explanation:
            lines.append(f"   Contrastive (C10): {det.contrastive_explanation.description}")

    lines += [
        "",
        f"Conformal Triage (C9): {conf.decision} "
        f"[s(x)={conf.nonconformity_score:.3f}, limit={conf.calibrated_threshold:.3f}, target_risk={conf.target_risk:.2f}]",
    ]
    if conf.abstain_reason:
        lines.append(f"   Reason: {conf.abstain_reason}")

    lines += [
        "",
        f"Trust Score Breakdown (C13): ETS={tb.composite_score:.3f} "
        f"[Faithfulness={tb.faithfulness:.2f}, Agreement={tb.cross_explainer_agreement:.2f}, "
        f"Grounding={tb.grounding_ratio:.2f}, Certainty={tb.model_certainty:.2f}]",
    ]

    lines += [
        "",
        f"Claim-Evidence Ledger (C1): {led.supported_claims}/{led.total_claims} claims supported "
        f"({led.supported_ratio * 100:.1f}%)",
    ]
    for c in led.claims:
        status_mark = "✔" if c.verification_status == "SUPPORTED" else "✖"
        lines.append(f"   {status_mark} [{c.claim_id}] {c.statement}")
        lines.append(f"      keys: {', '.join(c.evidence_keys)}")

    lines += ["", f"Analyst : {r.summary}  [narrative confidence {r.confidence}]"]
    lines.append(
        "   MITRE: "
        + (
            ", ".join(
                f"{t} {MITRE_TECHNIQUES.get(t, {}).get('name', '')}"
                for t in r.mitre_techniques
            )
            or "none"
        )
    )
    lines += [
        "",
        f"Verifier: {'APPROVED' if v.approved else 'REJECTED'} after {len(inv.rounds)} round(s) — {v.reasoning}",
    ]
    if v.unsupported_claims:
        lines += [f"   unsupported: {c}" for c in v.unsupported_claims]
    for w in inv.grounding.warnings:
        lines.append(f"   grounding warning: {w}")

    lines += ["", "Response (policy gate):"]
    lines += [f"   ✔ AUTO     {a['action']:<18} {a['target']}" for a in d.auto_execute]
    lines += [
        f"   ⏸ APPROVE  {a['action']:<18} {a['target']}  — {a['reason']}"
        for a in d.pending_approval
    ]
    lines += [f"   ✖ REJECTED {a['action']:<18} {a['target']}  — {a['reason']}" for a in d.rejected]
    return "\n".join(lines)


def write_markdown(inv: Investigation, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    r, v, d, ev, led, conf, tb = (
        inv.report,
        inv.verdict,
        inv.decision,
        inv.evidence,
        inv.ledger,
        inv.conformal,
        inv.trust_breakdown,
    )
    md = [
        f"# Incident {inv.alert_id}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Final severity | **{inv.final_severity.upper()}** |",
        f"| Status | {inv.status} |",
        f"| Explanation Trust Score (ETS) | **{inv.trust_score:.4f}** |",
        f"| Conformal Decision (C9) | **{conf.decision}** |",
        f"| Host | {ev.get('host', '-')} |",
        f"| Source IP | {ev.get('src_ip', '-')} |",
        f"| Destination IP | {ev.get('dst_ip', '-')} |",
        f"| Asset Criticality | {'CRITICAL' if (ev.get('asset') or {}).get('host_is_critical') else 'Standard'} |",
        f"| IoMT Device (C16) | {'YES (Medical Safeguard Active)' if (ev.get('asset') or {}).get('is_iomt') else 'No'} |",
        f"| LLM Backend | {inv.backend} |",
        "",
    ]
    if inv.injection_flags:
        md += [
            "> **Security Warning:** The input contained prompt-injection patterns: "
            + ", ".join(sorted({f["pattern"] for f in inv.injection_flags})),
            "",
        ]

    # Section 1: Detection & XAI
    if inv.detection:
        det = inv.detection
        md += [
            "## 1. Detection and Model Explanation",
            "",
            f"The detector predicted **{det.label}** with probability {det.confidence:.3f}; "
            f"the IsolationForest anomaly score places this flow at the {det.anomaly_score * 100:.1f}th percentile "
            f"of normal baseline traffic. Explainer: `{det.explainer}`.",
            "",
            "### Feature Attributions (SHAP TreeExplainer)",
            "",
            "| Feature | Value | Normal Baseline | Contribution |",
            "|---|---:|---:|---:|",
        ]
        md += [
            f"| {a['feature']} | {a['value']} | {a['normal_baseline']} | {a['contribution']:+.4f} |"
            for a in det.attributions
        ]
        md.append("")
        if det.lime_attributions:
            md += [
                "### Feature Attributions (LIME Tabular Explainer)",
                "",
                "| Feature | Rule | Value | Contribution |",
                "|---|---|---:|---:|",
            ]
            md += [
                f"| {a.get('feature', '-')} | `{a.get('rule', '-')}` | {a.get('value', '-')} | {a.get('contribution', 0.0):+.4f} |"
                for a in det.lime_attributions[:5]
            ]
            md.append("")
        if det.contrastive_explanation:
            cf = det.contrastive_explanation
            md += [
                "### Contrastive / Counterfactual Evidence (C10)",
                "",
                f"> **Target Class:** `{cf.target_class}`  ",
                f"> **Required Change:** `{cf.feature}` from {cf.current_value:.2f} to {cf.counterfactual_value:.2f}  ",
                f"> **Analysis:** {cf.description}",
                "",
            ]

    # Section 2: Conformal Risk-Controlled Abstention
    md += [
        "## 2. Conformal Risk-Controlled Triage (C9)",
        "",
        "| Metric | Value | Interpretation |",
        "|---|---|---|",
        f"| Conformal Decision | **{conf.decision}** | {'Eligible for autonomous response' if conf.eligible_for_auto_response else 'Autonomous action halted; escalated to human'} |",
        f"| Nonconformity Score s(x) | {conf.nonconformity_score:.4f} | Uncertainty level derived from predictive distribution |",
        f"| Calibrated Threshold λ | {conf.calibrated_threshold:.4f} | Statistically calibrated boundary bounding expected loss <= target risk |",
        f"| Target Risk α | {conf.target_risk:.2f} | Allowable operational error bound (e.g. 5%) |",
        "",
    ]
    if conf.abstain_reason:
        md += [f"> **Abstention Rationale:** {conf.abstain_reason}", ""]

    # Section 3: Composite Explanation Trust Score (C13)
    md += [
        "## 3. Explanation Trust Score Breakdown (C13)",
        "",
        "| Constituent Metric | Score | Description |",
        "|---|---:|---|",
        f"| **Composite ETS** | **{tb.composite_score:.4f}** | Multi-dimensional calibrated trust metric |",
        f"| Faithfulness F(x) | {tb.faithfulness:.4f} | Sensitivity / probability drop upon top-feature deletion |",
        f"| Cross-Explainer Agreement A(x) | {tb.cross_explainer_agreement:.4f} | Consistency between SHAP and LIME attribution rankings |",
        f"| Narrative Grounding Ratio G(C) | {tb.grounding_ratio:.4f} | Proportion of claims verified as supported in evidence ledger |",
        f"| Model Certainty C(x) | {tb.model_certainty:.4f} | Calibrated class margin (top probability - runner-up) |",
        f"| Safety Penalty | -{tb.penalty:.4f} | Deductions for injection patterns, drift, or disagreements |",
        "",
    ]

    # Section 4: Claim-Evidence Ledger (C1)
    md += [
        "## 4. Claim–Evidence Ledger (C1)",
        "",
        f"**Ledger Summary:** {led.supported_claims}/{led.total_claims} claims verified supported "
        f"({led.supported_ratio * 100:.1f}%). Fingerprint: `{led.compute_hash()[:16]}...`",
        "",
        "| Claim ID | Statement | Cited Evidence Keys | Status | Verifier Notes |",
        "|---|---|---|---|---|",
    ]
    for c in led.claims:
        keys_str = ", ".join(f"`{k}`" for k in c.evidence_keys) or "None"
        md.append(
            f"| {c.claim_id} | {c.statement} | {keys_str} | **{c.verification_status}** | {c.verifier_notes} |"
        )
    md.append("")

    # Section 5: Narrative & Verification
    md += [
        "## 5. Analyst Narrative & Cross-Model Verification",
        "",
        r.summary,
        "",
        "**MITRE ATT&CK Mapping:** "
        + (
            ", ".join(
                f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/) "
                f"{MITRE_TECHNIQUES.get(t, {}).get('name', '')}"
                for t in r.mitre_techniques
            )
            or "none"
        ),
        "",
        "**Alternative Hypotheses Considered:**",
        "",
    ]
    md += [f"- {h}" for h in r.alternative_hypotheses] + [""]
    md += [
        f"**Independent Verifier Verdict:** **{'Approved' if v.approved else 'Rejected'}** "
        f"(Corrected Severity: {v.corrected_severity}). {v.reasoning}",
        "",
        "| Debate Round | Grounding Errors | Verifier Approved | Ledger Grounding |",
        "|---|---:|---|---:|",
    ]
    md += [
        f"| {x['round']} | {len(x['grounding_errors'])} | {x['critic_approved']} | {x.get('ledger_supported_ratio', 1.0)*100:.1f}% |"
        for x in inv.rounds
    ]
    if inv.grounding.warnings:
        md += ["", "Grounding Warnings:", ""] + [f"- {w}" for w in inv.grounding.warnings]

    # Section 6: Response Decisions
    md += [
        "",
        "## 6. Response Decision & Action Gate",
        "",
        "| Decision | Action | Target | Reason / Policy |",
        "|---|---|---|---|",
    ]
    md += [f"| auto | {a['action']} | {a['target']} | {a['justification']} |" for a in d.auto_execute]
    md += [f"| needs approval | {a['action']} | {a['target']} | {a['reason']} |" for a in d.pending_approval]
    md += [f"| rejected | {a['action']} | {a['target']} | {a['reason']} |" for a in d.rejected]
    md += [
        "",
        "_Generated by the Multi-Agent Explainable AI Framework. Disruptive actions on medical or critical "
        "infrastructure are strictly gated for human authorization._",
        "",
    ]
    path = out_dir / f"{inv.alert_id}.md"
    path.write_text("\n".join(md), encoding="utf-8")
    return path
