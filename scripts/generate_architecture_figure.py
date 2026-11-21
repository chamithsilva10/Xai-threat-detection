import matplotlib.pyplot as plt
import matplotlib.patches as patches
from pathlib import Path

def create_architecture_diagram():
    fig, ax = plt.subplots(figsize=(10, 8.2), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Background canvas styling
    bg = patches.Rectangle((0, 0), 100, 100, facecolor="#F8FAFC", edgecolor="none")
    ax.add_patch(bg)

    # Palette
    c_blue = "#1E3A8A"     # Dark Blue
    c_sky = "#0284C7"      # Accent Blue
    c_slate = "#334155"    # Dark Slate
    c_box = "#FFFFFF"      # Box white
    c_edge = "#CBD5E1"     # Box border
    c_green = "#059669"    # Verification green
    c_red = "#DC2626"      # Gate red
    c_gold = "#D97706"     # Risk amber
    c_purple = "#7C3AED"   # XAI purple

    def draw_box(x, y, w, h, title, subtitle, tag, color=c_blue, bg_c=c_box):
        rect = patches.FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.5,rounding_size=1.5",
            facecolor=bg_c, edgecolor=color, linewidth=1.6, zorder=2
        )
        ax.add_patch(rect)
        # Tag pill
        tag_w = len(tag) * 1.5 + 2
        tag_rect = patches.FancyBboxPatch(
            (x + w - tag_w - 1, y + h - 3.2), tag_w, 2.5, boxstyle="round,pad=0.2,rounding_size=0.6",
            facecolor=color, edgecolor="none", zorder=3
        )
        ax.add_patch(tag_rect)
        ax.text(x + w - tag_w / 2 - 1, y + h - 1.95, tag, color="#FFFFFF", fontsize=6.5,
                fontweight="bold", ha="center", va="center", zorder=4)

        # Title and subtitle
        ax.text(x + 2, y + h - 3.2, title, color=c_slate, fontsize=9.2, fontweight="bold", va="top", zorder=4)
        ax.text(x + 2, y + 2.5, subtitle, color="#64748B", fontsize=7.2, va="bottom", zorder=4)

    # 1. Telemetry Ingestion (Agent 01)
    draw_box(4, 86, 92, 10, "Agent 01: Ingestion & Input Sanitization", 
             "NetFlow / IPFIX Telemetry Validation • Control Token & Escape Stripping • Prompt Injection Filter", 
             "C6, C7", color=c_sky)

    # Arrow 1 down
    ax.annotate("", xy=(50, 80), xytext=(50, 86),
                arrowprops=dict(arrowstyle="->", color=c_slate, lw=1.8, mutation_scale=15), zorder=5)
    ax.text(50.8, 83, "Validated Clean Flow Vector x in R^d", color="#475569", fontsize=7.5, fontstyle="italic")

    # 2. Threat Detection (Agent 02)
    draw_box(4, 69, 43, 11, "Agent 02: Multi-Model Ensemble",
             "XGBoost Multiclass (5 Classes) + Isolation Forest\nComputes Class Probabilities P(Y=c|x) and Anomaly Margin",
             "C8", color=c_blue)

    # 3. Explainability Triad (Agent 03)
    draw_box(53, 69, 43, 11, "Agent 03: Explainability Triad",
             "TreeSHAP Additive Efficiency | LIME Local Surrogate\nActionable Contrastive Counterfactual Delta (L1 Bound)",
             "C10, C11", color=c_purple)

    # Arrow between 02 and 03
    ax.annotate("", xy=(53, 74.5), xytext=(47, 74.5),
                arrowprops=dict(arrowstyle="->", color=c_slate, lw=1.5, mutation_scale=12), zorder=5)

    # 4. Threat Intel (Agent 04)
    draw_box(4, 52, 43, 11, "Agent 04: Threat Intelligence Context",
             "MITRE ATT&CK TTP Pointer Resolution • IoC Feed Cross-Ref\nClinical Asset Registry Lookup & Device Criticality Tiers",
             "Intel", color="#475569")

    # 5. Conformal Risk Triage (Agent 05)
    draw_box(53, 52, 43, 11, "Agent 05: Conformal Selective Triage",
             "Exact Clopper-Pearson Binomial UCB (Beta-inv, alpha <= 0.05)\nCalibrated Threshold lambda-hat • Abstain / Escalate Circuit",
             "C9", color=c_gold)

    # Connection to Agent 05
    ax.annotate("", xy=(53, 57.5), xytext=(47, 57.5),
                arrowprops=dict(arrowstyle="->", color=c_slate, lw=1.5, mutation_scale=12), zorder=5)
    ax.annotate("", xy=(74.5, 63), xytext=(74.5, 69),
                arrowprops=dict(arrowstyle="->", color=c_slate, lw=1.5, mutation_scale=12), zorder=5)

    # Flow down to Epistemic Verification
    ax.annotate("", xy=(50, 46), xytext=(74.5, 52),
                arrowprops=dict(arrowstyle="->", color=c_slate, lw=1.8, mutation_scale=15), zorder=5)
    ax.text(64, 48.5, "Certified Safe s(x) <= lambda-hat", color=c_gold, fontsize=7.5, fontweight="bold")

    # Sub-container for Verification Debate
    debate_box = patches.FancyBboxPatch(
        (4, 25), 92, 21, boxstyle="round,pad=0.5,rounding_size=2.0",
        facecolor="#EFF6FF", edgecolor="#BFDBFE", linewidth=1.5, linestyle="--", zorder=1
    )
    ax.add_patch(debate_box)
    ax.text(6, 43.5, "Dual-LLM Epistemic Verification Protocol (RFC 6901 Claim-Evidence Ledger)", 
            color="#1E40AF", fontsize=8.5, fontweight="bold")

    # Agent 08 (Analyst)
    draw_box(6, 27, 40, 14, "Agent 08: LLM Analyst",
             "Synthesizes Incident Narrative\nEmits Atomic Telemetry Claims\nTagged JSON Pointers (RFC 6901)",
             "LLaMA-3.1-8B", color=c_blue)

    # Agent 09 (Critic Verifier)
    draw_box(54, 27, 40, 14, "Agent 09: Independent Critic",
             "Audits Claims Against RFC 8785 Digest\nContradiction / Unsupported Flagging\nMulti-Round Iterative Debate (M<=3)",
             "Mistral-7B", color=c_green)

    # Bidirectional arrow between 08 and 09
    ax.annotate("", xy=(54, 34), xytext=(46, 34),
                arrowprops=dict(arrowstyle="<->", color=c_blue, lw=2.0, mutation_scale=14), zorder=5)
    ax.text(50, 35.5, "Debate Loop\n(C1, C2)", color=c_blue, fontsize=7.2, fontweight="bold", ha="center")

    # Arrow down to Orchestration
    ax.annotate("", xy=(50, 19), xytext=(50, 25),
                arrowprops=dict(arrowstyle="->", color=c_slate, lw=1.8, mutation_scale=15), zorder=5)
    ax.text(50.8, 21.8, "Verified Verdict: Grounding G(C) = 1.0", color=c_green, fontsize=7.5, fontweight="bold")

    # 6. Response Orchestrator (Agent 06)
    draw_box(4, 9, 43, 10, "Agent 06: Response Orchestrator",
             "SOAR Playbooks • Safe Auto-Actions Allowlist\nIoMT Separation of Duties Gate (Halt Disruptive)",
             "C16 Gate", color=c_red)

    # 7. Audit Ledger (Agent 07)
    draw_box(53, 9, 43, 10, "Agent 07: Immutable Audit Ledger",
             "RFC 8785 Canonical JSON Serialization\nSHA-256 Hash Chaining • Trust Score (ETS)",
             "C4, C13", color="#0F172A")

    # Arrow 06 -> 07
    ax.annotate("", xy=(53, 14), xytext=(47, 14),
                arrowprops=dict(arrowstyle="->", color=c_slate, lw=1.5, mutation_scale=12), zorder=5)

    # Footnote
    ax.text(50, 2.5, "Fig. 1. Sentinel-XAI Nine-Agent Modular Architecture with Invariant Contracts (C1–C16) and Safety Safeguards.",
            color=c_slate, fontsize=8.5, fontweight="bold", ha="center")

    plt.tight_layout()
    plt.savefig("paper/figures/sentinel_architecture.png", dpi=300, bbox_inches="tight")
    plt.savefig("paper/figures/sentinel_architecture.pdf", bbox_inches="tight")
    plt.savefig("docs/figures/sentinel_architecture.png", dpi=300, bbox_inches="tight")
    plt.savefig("docs/figures/sentinel_architecture.pdf", bbox_inches="tight")
    plt.close()
    print("Architecture diagram created successfully!")

def create_author_photos():
    fig, axes = plt.subplots(1, 2, figsize=(3.2, 2.0), dpi=300)
    for ax, name in zip(axes, ["L. C. S. De Silva", "Dr. A. Aponso"]):
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 12)
        ax.axis("off")
        # Frame
        rect = patches.Rectangle((0.5, 0.5), 9, 11, facecolor="#F1F5F9", edgecolor="#94A3B8", linewidth=1.2)
        ax.add_patch(rect)
        # Silhouette Head
        head = patches.Circle((5, 7.8), 2.2, facecolor="#64748B", edgecolor="none")
        ax.add_patch(head)
        # Silhouette Shoulders
        shoulders = patches.Ellipse((5, 3.2), 6.5, 4.0, facecolor="#64748B", edgecolor="none")
        ax.add_patch(shoulders)
        # Name tag
        ax.text(5, 1.2, name, color="#1E293B", fontsize=7.2, fontweight="bold", ha="center")

    axes[0].figure.savefig("paper/figures/author1.png", dpi=300, bbox_inches="tight")
    axes[1].figure.savefig("paper/figures/author2.png", dpi=300, bbox_inches="tight")
    axes[0].figure.savefig("docs/figures/author1.png", dpi=300, bbox_inches="tight")
    axes[1].figure.savefig("docs/figures/author2.png", dpi=300, bbox_inches="tight")
    plt.close()
    print("Author photos created successfully!")

if __name__ == "__main__":
    create_architecture_diagram()
    create_author_photos()
