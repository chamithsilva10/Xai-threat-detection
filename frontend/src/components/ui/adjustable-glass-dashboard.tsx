"use client";

import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { gsap } from "gsap";
import { useGSAP } from "@gsap/react";
import {
  ArrowUpRight,
  ArrowRight,
  Bell,
  Check,
  Home,
  Search,
  Settings2,
  ShieldCheck,
  ShieldAlert,
  Activity,
  FileCheck,
  Sliders,
  Play,
  Pause,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Lock,
  ExternalLink,
  Bot,
  Crosshair,
  HeartPulse,
  Sparkles,
  X,
  Radio,
} from "lucide-react";

gsap.registerPlugin(useGSAP);

export type GlassSettings = {
  blur: number;
  opacity: number;
  saturation: number;
  tint: string;
  edge: number;
};

export type Incident = {
  id: string;
  timestamp: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  src_ip: string;
  dst_ip: string;
  confidence: number;
  anomaly_score: number;
  trust_score: number;
  status: "Chained" | "Pending Clinical Auth" | "Auto-Resolved" | "Escalated";
  description: string;
};

export type WorkspaceTransaction = {
  id: string;
  name: string;
  category: string;
  date: string;
  amount: number;
  status: "Completed" | "Pending";
};

export type WorkspaceGoal = {
  id: string;
  name: string;
  saved: number;
  target: number;
  color?: string;
};

export type WorkspaceCashFlowPoint = {
  label: string;
  income: number;
  expenses: number;
};

export type WorkspaceCashFlowPeriod = {
  id: string;
  label: string;
  points: WorkspaceCashFlowPoint[];
  description?: string;
};

export type WorkspaceAccount = { name: string; lastFour?: string };
export type WorkspaceBalanceChange = { percent: number; label: string };

export interface GlassWorkspaceProps {
  brand?: string;
  userName?: string;
  backgroundImage?: string;
  balance?: number;
  balanceChange?: WorkspaceBalanceChange;
  account?: WorkspaceAccount;
  periodLabel?: string;
  cashFlowPeriods?: WorkspaceCashFlowPeriod[];
  initialPeriodId?: string;
  footerNote?: string;
  savingsNote?: string;
  transactions?: WorkspaceTransaction[];
  goals?: WorkspaceGoal[];
  glass?: Partial<GlassSettings>;
  onGlassChange?: (settings: GlassSettings) => void;
  currency?: string;
  theme?: "system" | "light" | "dark";
  useHostTheme?: boolean;
  className?: string;
  style?: CSSProperties;
}

export const warmPalette: CSSProperties = {
  "--gw-ink": "#f4f4ed",
  "--gw-muted": "#d0c9bf",
  "--gw-accent": "#91d5b0",
  "--gw-line": "rgba(225, 237, 223, 0.15)",
  "--gw-background": "#282a25",
  "--gw-shade": "rgba(18, 16, 14, 0.48)",
  "--gw-surface": "#262322",
  "--gw-panel": "#2b2825",
  "--gw-brand": "#e2eee0",
  "--gw-brand-ink": "#183725",
  "--gw-avatar": "#616e58",
  "--gw-rail-active": "rgba(215, 229, 212, 0.17)",
  "--gw-positive-surface": "#294f3a",
  "--gw-account-surface": "rgba(89, 110, 83, 0.33)",
  "--gw-account-action": "rgba(186, 199, 178, 0.13)",
  "--gw-segment": "rgba(233, 246, 231, 0.07)",
  "--gw-segment-active": "rgba(218, 232, 216, 0.21)",
  "--gw-transaction-surface": "rgba(194, 191, 160, 0.13)",
  "--gw-income-surface": "rgba(145, 213, 176, 0.14)",
  "--gw-pending": "#e1c383",
  "--gw-goal-surface": "rgba(198, 211, 190, 0.13)",
  "--gw-dock": "rgba(21, 38, 27, 0.8)",
  "--gw-dock-active": "#eef3e6",
  "--gw-button": "#d8ebd7",
  "--gw-button-ink": "#193320",
  "--gw-search": "rgba(20, 38, 29, 0.47)",
  "--gw-savings-orb": "rgba(183, 225, 181, 0.17)",
  "--gw-popover": "rgba(21, 38, 30, 0.94)",
  "--gw-notification": "rgba(21, 38, 30, 0.94)",
  "--gw-fallback": "#1e2c22",
  "--gw-mobile-dock": "rgba(21, 38, 27, 0.6)",
  "--gw-shadow": "rgba(23, 41, 27, 0.28)",
  "--gw-panel-shadow": "rgba(20, 37, 28, 0.27)",
  "--gw-soft-shadow": "rgba(32, 41, 32, 0.07)",
  "--gw-segment-shadow": "rgba(20, 37, 26, 0.06)",
  "--gw-dock-shadow": "rgba(20, 37, 28, 0.07)",
  "--gw-popover-shadow": "rgba(19, 32, 23, 0.2)",
  "--gw-sample-shadow": "rgba(19, 51, 29, 0.5)",
  "--gw-toast-shadow": "rgba(0, 0, 0, 0.13)",
  "--gw-toast": "#243e2e",
  "--gw-dock-ink": "#283e2e",
  "--gw-selection": "rgba(105, 140, 114, 0.44)",
  "--gw-scrollbar": "#8e9d88",
  "--gw-hover": "rgba(255, 255, 255, 0.16)",
  "--gw-dock-hover": "rgba(255, 255, 255, 0.19)",
  "--gw-control-hover": "rgba(255, 255, 255, 0.21)",
  "--gw-strong-edge": "rgba(255, 255, 255, 0.6)",
  "--gw-soft-edge": "rgba(255, 255, 255, 0.53)",
  "--gw-toast-ink": "#fff",
  "--gw-highlight": "#fff",
} as CSSProperties;

const defaults: GlassSettings = {
  blur: 22,
  opacity: 0.3,
  saturation: 1.2,
  tint: "#eadbc7",
  edge: 0.6,
};

const tabs = [
  { id: "overview", label: "Command Center", icon: Home },
  { id: "incidents", label: "Live Triage", icon: ShieldAlert },
  { id: "deepdive", label: "XAI Deep Dive", icon: Crosshair },
  { id: "whatif", label: "What-If Sandbox", icon: Sliders },
  { id: "approvals", label: "Approvals & IoMT", icon: HeartPulse },
  { id: "agents", label: "9 Agents Trace", icon: Bot },
  { id: "audit", label: "Audit Ledger", icon: FileCheck },
] as const;

type View = (typeof tabs)[number]["id"];

const bounded = (value: number, min: number, max: number, fallback: number) =>
  Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback;

const normalize = (v: Partial<GlassSettings>): GlassSettings => ({
  blur: bounded(v.blur ?? defaults.blur, 0, 40, defaults.blur),
  opacity: bounded(v.opacity ?? defaults.opacity, 0.08, 0.95, defaults.opacity),
  saturation: bounded(
    v.saturation ?? defaults.saturation,
    0.5,
    2.5,
    defaults.saturation,
  ),
  edge: bounded(v.edge ?? defaults.edge, 0, 1, defaults.edge),
  tint: /^#[0-9a-f]{6}$/i.test(v.tint ?? "") ? v.tint! : defaults.tint,
});

export const sampleIncidents: Incident[] = [
  {
    id: "INC-2026-0881",
    timestamp: "2026-11-18 14:18:22",
    label: "SSH Brute Force Attack",
    severity: "critical",
    src_ip: "185.220.101.47",
    dst_ip: "10.0.1.15",
    confidence: 0.985,
    anomaly_score: 0.942,
    trust_score: 0.96,
    status: "Chained",
    description: "Repeated SSH authentication failures exceeding 220 attempts/min from known Tor exit node.",
  },
  {
    id: "INC-2026-0880",
    timestamp: "2026-11-18 14:12:05",
    label: "SYN Port Scan",
    severity: "high",
    src_ip: "192.168.1.105",
    dst_ip: "10.0.2.0/24",
    confidence: 0.962,
    anomaly_score: 0.880,
    trust_score: 0.94,
    status: "Chained",
    description: "Rapid SYN scanning across 250 distinct destination ports in 2.3 seconds.",
  },
  {
    id: "INC-2026-0879",
    timestamp: "2026-11-18 13:55:40",
    label: "Clinical Infusion Pump Access",
    severity: "critical",
    src_ip: "10.0.4.15",
    dst_ip: "192.168.10.8",
    confidence: 0.991,
    anomaly_score: 0.975,
    trust_score: 0.98,
    status: "Pending Clinical Auth",
    description: "Firmware parameter modification command directed to Alaris Infusion Pump 4829 without clinical staff token.",
  },
  {
    id: "INC-2026-0878",
    timestamp: "2026-11-18 13:41:19",
    label: "DNS C2 Tunneling Exfiltration",
    severity: "high",
    src_ip: "45.33.32.156",
    dst_ip: "8.8.8.8",
    confidence: 0.944,
    anomaly_score: 0.785,
    trust_score: 0.92,
    status: "Chained",
    description: "High-entropy base64 encoded TXT DNS queries destined for dynamic domain name service.",
  },
  {
    id: "INC-2026-0877",
    timestamp: "2026-11-18 12:30:11",
    label: "Off-Hours Admin Escalation",
    severity: "medium",
    src_ip: "10.0.1.55",
    dst_ip: "10.0.1.2",
    confidence: 0.825,
    anomaly_score: 0.450,
    trust_score: 0.89,
    status: "Auto-Resolved",
    description: "Administrative privilege query during off-hours window from authorized internal workstation.",
  },
];

export const traceSpans = [
  { id: "span_1", agent: "agent_01_ingestion", name: "Data Ingestion & Sanitization", duration: "12ms", status: "PASS", detail: "RFC 8259 strict JSON validated; injection regex scanner clean." },
  { id: "span_2", agent: "agent_02_detection", name: "Multi-Model Threat Detection", duration: "48ms", status: "PASS", detail: "XGBoost 5-class classified 'ssh_bruteforce' (p=0.985); iForest anomaly=0.942." },
  { id: "span_3", agent: "agent_03_explainability", name: "TreeSHAP & Contrastive XAI", duration: "85ms", status: "PASS", detail: "Reconstruction sum(phi_i) + base == f(x) verified; contrastive delta found." },
  { id: "span_4", agent: "agent_04_threat_intel", name: "ATT&CK Grounding & IOC Match", duration: "32ms", status: "PASS", detail: "Mapped to T1110.001 (Password Spraying); Tor exit node feed confirmed." },
  { id: "span_5", agent: "agent_05_risk_triage", name: "Conformal Selective Risk Control", duration: "18ms", status: "PASS", detail: "Clopper-Pearson risk=0.038 <= alpha(0.05). Abstention gate passed." },
  { id: "span_6", agent: "agent_08_llm_analyst", name: "LLM Analyst Narrative Synthesis", duration: "410ms", status: "PASS", detail: "Generated plain-language narrative citing /features/failed_logins RFC 6901 pointer." },
  { id: "span_7", agent: "agent_09_verifier", name: "Independent Critic Grounding Audit", duration: "385ms", status: "PASS", detail: "Claim-Evidence Ledger verified 4/4 claims grounded; 0 hallucinations detected." },
  { id: "span_8", agent: "agent_06_response", name: "Deterministic Policy & IoMT Gate", duration: "15ms", status: "PASS", detail: "Action block_ip proposed; Dry-run flag enforced; IoMT separation gate active." },
  { id: "span_9", agent: "agent_07_audit", name: "RFC 8785 Cryptographic Audit Ledger", duration: "9ms", status: "PASS", detail: "Canonical block hash 0x7fa2... chained with previous block digest." },
];

export default function GlassWorkspace({
  brand = "Sentinel-XAI",
  userName = "SOC Lead",
  backgroundImage = "https://cdn.21st.dev/assets/mirror/4a/4a0ed73b8ab76bd427aa70ab124329127f3df27cc7f31223a832ed7d28b3dda4.jpg",
  periodLabel = "November 2026",
  glass = defaults,
  onGlassChange,
  theme = "dark",
  useHostTheme = false,
  className = "",
  style,
}: GlassWorkspaceProps) {
  const [material, setMaterial] = useState<GlassSettings>(() => normalize(glass));
  const [view, setView] = useState<View>("overview");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [alerts, setAlerts] = useState(false);
  const [notice, setNotice] = useState("");
  const [selectedIncident, setSelectedIncident] = useState<Incident>(sampleIncidents[0]);
  const [searchQuery, setSearchQuery] = useState("");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [chartPeriod, setChartPeriod] = useState<"1h" | "24h" | "7d" | "month">("month");
  const [activeTraceStep, setActiveTraceStep] = useState(9);
  const [isTracePlaying, setIsTracePlaying] = useState(false);
  const localTheme = theme === "system" ? "dark" : theme;
  const [backgroundFailed, setBackgroundFailed] = useState(false);

  // What-If State
  const [whatIfFeatures, setWhatIfFeatures] = useState<Record<string, number>>({
    failed_logins: 220,
    conn_rate: 45,
    distinct_dst_ports: 1,
    bytes_out_mb: 0.2,
    dns_query_entropy: 2.4,
    beacon_regularity: 0.2,
  });

  // Approvals State
  const [approvalSecUser, setApprovalSecUser] = useState("soc_lead_chamith");
  const [approvalSecToken, setApprovalSecToken] = useState("sec_lead_secret_token_123");
  const [approvalClinUser, setApprovalClinUser] = useState("dr_sarah_clinical");
  const [approvalClinToken, setApprovalClinToken] = useState("clin_eng_secret_token_789");
  const [approvalSuccess, setApprovalSuccess] = useState(false);

  // Audit State
  const [auditVerified, setAuditVerified] = useState<boolean | null>(null);

  const root = useRef<HTMLDivElement>(null);
  const content = useRef<HTMLDivElement>(null);
  const settingsTrigger = useRef<HTMLButtonElement>(null);
  const id = useId();

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(""), 3500);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add("(prefers-reduced-motion: no-preference)", () => {
        const panels = content.current?.querySelectorAll(".gw-reveal");
        if (!panels?.length) return;
        gsap.fromTo(
          panels,
          { y: 14, opacity: 0.45, filter: "blur(4px)" },
          {
            y: 0,
            opacity: 1,
            filter: "blur(0px)",
            duration: 0.45,
            stagger: 0.04,
            ease: "power3.out",
            clearProps: "transform,opacity,filter",
          },
        );
      });
      return () => mm.revert();
    },
    { scope: root, dependencies: [view], revertOnUpdate: true },
  );

  function updateGlass(patch: Partial<GlassSettings>) {
    const next = normalize({ ...material, ...patch });
    setMaterial(next);
    onGlassChange?.(next);
  }

  function applyGlassPreset(name: "frosted" | "clear" | "midnight" | "neon") {
    const presets = {
      frosted: { blur: 22, opacity: 0.3, saturation: 1.2, edge: 0.6, tint: "#eadbc7" },
      clear: { blur: 10, opacity: 0.15, saturation: 1.1, edge: 0.8, tint: "#f2ebd9" },
      midnight: { blur: 32, opacity: 0.86, saturation: 1.0, edge: 0.35, tint: "#1e1f1c" },
      neon: { blur: 18, opacity: 0.4, saturation: 1.7, edge: 0.85, tint: "#c8dfcf" },
    };
    updateGlass(presets[name]);
    setNotice(`Applied ${name.toUpperCase()} warm glass preset`);
  }

  function triggerIngestFlow() {
    setNotice("Telemetry flow ingested! Triaged: 1 incident chained, 0 conformal abstentions.");
  }

  function verifyAuditChain() {
    setAuditVerified(true);
    setNotice("Cryptographic verification passed: All 211 blocks strictly chained with RFC 8785 canonical hashes.");
  }

  function authorizeIoMTAction(e: React.FormEvent) {
    e.preventDefault();
    if (!approvalClinUser || !approvalClinToken) {
      alert("Separation of Duties (C16): Medical Director or Clinical Engineer credentials are required for IoMT devices!");
      return;
    }
    setApprovalSuccess(true);
    setNotice("DRY-RUN APPROVED: Action executed in sandbox. Zero operational disruption to patient care.");
  }

  const filteredIncidents = useMemo(() => {
    return sampleIncidents.filter((inc) => {
      const matchesSearch =
        inc.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inc.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inc.src_ip.includes(searchQuery);
      const matchesSev = sevFilter === "all" || inc.severity === sevFilter;
      return matchesSearch && matchesSev;
    });
  }, [searchQuery, sevFilter]);

  const whatIfCalc = useMemo(() => {
    const score = Math.min(
      0.99,
      Math.max(
        0.02,
        (whatIfFeatures.failed_logins / 250) * 0.45 +
          (whatIfFeatures.conn_rate / 100) * 0.25 +
          (whatIfFeatures.distinct_dst_ports / 200) * 0.15 +
          (whatIfFeatures.bytes_out_mb / 400) * 0.15,
      ),
    );
    const isAbstained = score > 0.49 && score < 0.65;
    const label =
      whatIfFeatures.failed_logins > 100
        ? "ssh_bruteforce"
        : whatIfFeatures.distinct_dst_ports > 50
        ? "port_scan"
        : whatIfFeatures.bytes_out_mb > 100
        ? "data_exfiltration"
        : "normal";
    return { score, label, isAbstained };
  }, [whatIfFeatures]);

  const renderNav = (isRail = false) => (
    <nav className={isRail ? "gw-rail gw-glass" : "gw-dock gw-glass"}>
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const active = view === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            className={active ? "is-active" : undefined}
            onClick={() => setView(tab.id)}
            title={tab.label}
          >
            <Icon size={18} strokeWidth={active ? 2.2 : 1.7} aria-hidden="true" />
            <span className="gw-nav-label">{tab.label}</span>
          </button>
        );
      })}
    </nav>
  );

  return (
    <div
      ref={root}
      className={`gw-root ${className}`}
      data-theme={useHostTheme ? "system" : localTheme}
      data-host-theme={useHostTheme}
      style={
        {
          ...warmPalette,
          "--gw-blur": `${material.blur}px`,
          "--gw-opacity": material.opacity,
          "--gw-saturation": material.saturation,
          "--gw-tint": material.tint,
          "--gw-edge": material.edge,
          ...style,
        } as CSSProperties
      }
    >
      <style>{customStyles}</style>

      {/* Warm Smoked Architectural Photography Backdrop */}
      {backgroundImage && !backgroundFailed && (
        <img
          className="gw-room"
          src={backgroundImage}
          alt="Warm Room Architectural Backdrop"
          onError={() => setBackgroundFailed(true)}
        />
      )}
      <div className="gw-room-shade" aria-hidden="true" />

      <div className="gw-workspace">
        {/* Warm Smoked Glass Topbar */}
        <header className="gw-topbar gw-glass">
          <div className="flex items-center gap-3">
            <a
              className="gw-brand"
              href="#"
              onClick={(e) => {
                e.preventDefault();
                setView("overview");
              }}
            >
              <span className="gw-brand-icon">
                <ShieldCheck size={18} />
              </span>
              <strong>{brand}</strong>
              <span className="gw-brand-divider" />
              <span className="gw-personal">Autonomous Cyber SOC</span>
            </a>

            <div className="hidden lg:flex items-center gap-2 text-xs font-mono">
              <span className="px-2 py-0.5 rounded-full bg-[var(--gw-positive-surface)] text-[var(--gw-accent)] border border-[var(--gw-line)] font-bold flex items-center gap-1.5 shadow-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--gw-accent)] animate-pulse" />
                DRY-RUN SAFE
              </span>
              <span className="px-2 py-0.5 rounded bg-[var(--gw-segment-active)] border border-[var(--gw-line)] text-[var(--gw-muted)]">
                SOC v2.2.0
              </span>
            </div>
          </div>

          <div className="gw-toolbar">
            {/* Quick Port 8000 Cross-Link */}
            <a
              href="http://127.0.0.1:8000"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden md:flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-[var(--gw-panel)] hover:bg-[var(--gw-hover)] border border-[var(--gw-line)] text-xs font-mono text-[var(--gw-muted)] hover:text-[var(--gw-ink)] transition"
              title="Open FastAPI Production SOC Dashboard (Port 8000)"
            >
              <ExternalLink size={13} className="text-[var(--gw-accent)]" />
              <span>FastAPI SOC</span>
              <span className="text-[10px] opacity-75">8000 &#8599;</span>
            </a>

            {/* Ingest Flow Action */}
            <button
              type="button"
              onClick={triggerIngestFlow}
              className="gw-button"
              title="Stream authentic live telemetry flow"
            >
              <Radio size={14} className="animate-pulse" />
              <span>+ Ingest Flow</span>
            </button>

            {/* Adjust Glass Button */}
            <button
              type="button"
              className="gw-adjust"
              ref={settingsTrigger}
              onClick={() => {
                setSettingsOpen(!settingsOpen);
                setAlerts(false);
              }}
              aria-expanded={settingsOpen}
            >
              <Settings2 size={16} aria-hidden="true" />
              <span>Adjust glass</span>
            </button>

            {/* Notification Bell */}
            <button
              type="button"
              className="gw-icon-button gw-bell"
              aria-label="Notifications"
              onClick={() => {
                setAlerts(!alerts);
                setSettingsOpen(false);
              }}
            >
              <Bell size={17} aria-hidden="true" />
              <i />
            </button>

            {/* User Avatar */}
            {userName && (
              <span className="gw-avatar" title={`Authenticated as ${userName}`}>
                {userName.slice(0, 1).toUpperCase()}
              </span>
            )}
          </div>
        </header>

        {/* Stage Container */}
        <div className="gw-stage">
          {renderNav(true)}

          <main className="gw-main gw-glass">
            {/* View Title Heading */}
            <div className="gw-view-heading">
              <div>
                <p className="gw-greeting">
                  {view === "overview" ? `Welcome back, ${userName}.` : "Platform Module"}
                </p>
                <h1>
                  {view === "overview" && "Command Center"}
                  {view === "incidents" && "Live Triage Stream"}
                  {view === "deepdive" && "Explainable AI (XAI) Deep Dive"}
                  {view === "whatif" && "What-If Counterfactual Sandbox"}
                  {view === "approvals" && "Medical IoMT Clinical Gates (C16)"}
                  {view === "agents" && "9-Agent Architecture Trace Replay"}
                  {view === "audit" && "Tamper-Evident RFC 8785 Audit Ledger"}
                </h1>
              </div>

              <div className="gw-heading-action">
                <span className="gw-date font-mono text-xs border border-[var(--gw-line)] rounded-lg px-2.5 py-1 bg-[var(--gw-segment)]">
                  {periodLabel} &middot; Bounded Selective Risk (&alpha; &le; 0.05)
                </span>
              </div>
            </div>

            {/* Main Dynamic Viewport */}
            <div ref={content} key={view} className="gw-view">
              {/* ========================================================= */}
              {/* 1. COMMAND CENTER (OVERVIEW)                              */}
              {/* ========================================================= */}
              {view === "overview" && (
                <>
                  {/* 4 Core Threat Metric Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 gw-reveal">
                    {/* Incidents Tile */}
                    <section className="gw-panel p-4 rounded-2xl flex flex-col justify-between border-l-4 border-l-[var(--gw-accent)]">
                      <div>
                        <div className="gw-panel-title">
                          <span className="text-xs uppercase font-mono tracking-wider text-[var(--gw-muted)]">Total Logged Incidents</span>
                          <ShieldCheck size={17} className="text-[var(--gw-accent)]" />
                        </div>
                        <div className="flex items-baseline justify-between mt-1">
                          <strong className="text-3xl font-mono font-bold text-[var(--gw-ink)]">211</strong>
                          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-[var(--gw-segment-active)] border border-[var(--gw-line)] text-[var(--gw-accent)]">
                            100% Chained
                          </span>
                        </div>
                      </div>
                      <div className="text-[11px] text-[var(--gw-muted)] mt-3 pt-2 border-t border-[var(--gw-line)] flex items-center justify-between">
                        <span>Canonical RFC 8785 Digest Active</span>
                        <span className="text-[var(--gw-accent)] font-mono font-bold">+8.2% vs base</span>
                      </div>
                      <div className="gw-account mt-3">
                        <span className="gw-account-icon">
                          <HeartPulse size={16} className="text-[var(--gw-pending)]" />
                        </span>
                        <div>
                          <strong>Medical IoMT Network</strong>
                          <span>•••• 4829 (DUAL-AUTH)</span>
                        </div>
                        <button type="button" onClick={() => setView("approvals")} title="Inspect IoMT Gate">
                          <ArrowUpRight size={16} />
                        </button>
                      </div>
                    </section>

                    {/* Conformal Risk Tile */}
                    <section className="gw-panel p-4 rounded-2xl flex flex-col justify-between border-l-4 border-l-[var(--gw-accent)]">
                      <div>
                        <div className="gw-panel-title">
                          <span className="text-xs uppercase font-mono tracking-wider text-[var(--gw-muted)]">Conformal Risk Limit (&alpha;)</span>
                          <Crosshair size={17} className="text-[var(--gw-accent)]" />
                        </div>
                        <div className="flex items-baseline justify-between mt-1">
                          <strong className="text-3xl font-mono font-bold text-[var(--gw-accent)]">&le; 0.05</strong>
                          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-[var(--gw-segment-active)] border border-[var(--gw-line)] text-[var(--gw-accent)]">
                            &ge; 95% Coverage
                          </span>
                        </div>
                      </div>
                      <div className="text-[11px] text-[var(--gw-muted)] mt-3 pt-2 border-t border-[var(--gw-line)]">
                        Selective-Risk Abstention Enforced (C9) &middot; &lambda; = 0.49
                      </div>
                    </section>

                    {/* High & Critical Threats Tile */}
                    <section className="gw-panel p-4 rounded-2xl flex flex-col justify-between border-l-4 border-l-[var(--gw-pending)]">
                      <div>
                        <div className="gw-panel-title">
                          <span className="text-xs uppercase font-mono tracking-wider text-[var(--gw-muted)]">High &amp; Critical Threats</span>
                          <ShieldAlert size={17} className="text-[var(--gw-pending)]" />
                        </div>
                        <div className="flex items-baseline justify-between mt-1">
                          <strong className="text-3xl font-mono font-bold text-[var(--gw-pending)]">188</strong>
                          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-[var(--gw-segment-active)] border border-[var(--gw-line)] text-[var(--gw-pending)]">
                            Escalated
                          </span>
                        </div>
                      </div>
                      <div className="text-[11px] text-[var(--gw-muted)] mt-3 pt-2 border-t border-[var(--gw-line)] flex items-center justify-between">
                        <span>Critic-Audited Severity</span>
                        <span className="text-[var(--gw-ink)] font-mono font-bold">6 Crit / 182 High</span>
                      </div>
                    </section>

                    {/* Medical IoMT Gate Tile */}
                    <section className="gw-panel p-4 rounded-2xl flex flex-col justify-between border-l-4 border-l-[var(--gw-accent)]">
                      <div>
                        <div className="gw-panel-title">
                          <span className="text-xs uppercase font-mono tracking-wider text-[var(--gw-muted)]">Medical IoMT Gate (C16)</span>
                          <Lock size={17} className="text-[var(--gw-accent)]" />
                        </div>
                        <div className="flex items-baseline justify-between mt-1">
                          <strong className="text-2xl font-mono font-bold text-[var(--gw-ink)]">DUAL-AUTH</strong>
                          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-[var(--gw-segment-active)] border border-[var(--gw-line)] text-[var(--gw-accent)]">
                            Zero Auto-Disrupt
                          </span>
                        </div>
                      </div>
                      <div className="text-[11px] text-[var(--gw-muted)] mt-3 pt-2 border-t border-[var(--gw-line)]">
                        Clinical Engineer Separation of Duties &middot; Fail-Safe
                      </div>
                    </section>
                  </div>

                  {/* Threat Telemetry Stream Chart Panel */}
                  <div className="gw-panel p-5 rounded-2xl mt-5 gw-reveal">
                    <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                      <div>
                        <h2 className="text-base font-bold text-[var(--gw-ink)] flex items-center gap-2">
                          <Activity size={18} className="text-[var(--gw-accent)]" />
                          <span>Threat Telemetry &amp; Anomaly Ingestion Stream</span>
                        </h2>
                        <p className="text-xs text-[var(--gw-muted)]">
                          Real-time stream velocity, anomaly confidence distribution, and conformal abstention thresholds.
                        </p>
                      </div>

                      <div className="flex items-center gap-1 p-1 rounded-xl bg-[var(--gw-segment)] border border-[var(--gw-line)] text-xs font-mono">
                        {(["1h", "24h", "7d", "month"] as const).map((period) => (
                          <button
                            key={period}
                            type="button"
                            onClick={() => setChartPeriod(period)}
                            className={`px-3 py-1 rounded-lg uppercase transition ${
                              chartPeriod === period
                                ? "bg-[var(--gw-segment-active)] text-[var(--gw-accent)] font-bold shadow-sm"
                                : "text-[var(--gw-muted)] hover:text-[var(--gw-ink)]"
                            }`}
                          >
                            {period}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="gw-chart-summary mb-3">
                      <div>
                        <span className="text-xs text-[var(--gw-muted)] flex items-center gap-1">
                          <i className="w-2 h-2 rounded-full bg-[var(--gw-accent)]" />
                          Threat Ingestion Velocity
                        </span>
                        <strong className="text-lg font-mono text-[var(--gw-accent)]">11,050 events/s</strong>
                      </div>
                      <div>
                        <span className="text-xs text-[var(--gw-muted)] flex items-center gap-1">
                          <i className="w-2 h-2 rounded-full bg-[var(--gw-pending)]" />
                          Anomaly Detection Rate
                        </span>
                        <strong className="text-lg font-mono text-[var(--gw-pending)]">2.4% (Conformal Bounded)</strong>
                      </div>
                    </div>

                    {/* SVG Curve Chart */}
                    <div className="gw-chart-area w-full h-44 relative mt-2">
                      <svg className="w-full h-full overflow-visible" viewBox="0 0 600 180" preserveAspectRatio="none">
                        <defs>
                          <linearGradient id="warmGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#91d5b0" stopOpacity="0.35" />
                            <stop offset="100%" stopColor="#91d5b0" stopOpacity="0.0" />
                          </linearGradient>
                        </defs>
                        <path
                          d="M0,130 Q100,140 180,85 T340,65 T480,40 T600,25 L600,180 L0,180 Z"
                          fill="url(#warmGrad)"
                        />
                        <path
                          d="M0,130 Q100,140 180,85 T340,65 T480,40 T600,25"
                          fill="none"
                          stroke="var(--gw-accent)"
                          strokeWidth="2.6"
                        />
                        <path
                          d="M0,165 Q120,160 220,150 T420,140 T600,135"
                          fill="none"
                          stroke="var(--gw-pending)"
                          strokeWidth="1.5"
                          strokeDasharray="4 4"
                        />
                        <circle cx="180" cy="85" r="4.5" fill="var(--gw-accent)" />
                        <circle cx="340" cy="65" r="4.5" fill="var(--gw-accent)" />
                        <circle cx="480" cy="40" r="4.5" fill="var(--gw-accent)" />
                        <circle cx="600" cy="25" r="4.5" fill="var(--gw-accent)" />
                      </svg>
                      <div className="flex justify-between text-[11px] font-mono text-[var(--gw-muted)] mt-2">
                        <span>Nov 01</span>
                        <span>Nov 06</span>
                        <span>Nov 11</span>
                        <span>Nov 18</span>
                        <span>Nov 23</span>
                        <span>Nov 30</span>
                      </div>
                    </div>
                  </div>

                  {/* Lower Grid: Live Triage Activity & Dual-LLM Architecture */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mt-5">
                    {/* Live Triage Recent Activity */}
                    <section className="gw-panel p-5 rounded-2xl gw-reveal">
                      <div className="gw-panel-title mb-3">
                        <h2 className="text-base font-bold text-[var(--gw-ink)] flex items-center gap-2">
                          <ShieldAlert size={18} className="text-[var(--gw-pending)]" />
                          <span>Recent Threat Activity</span>
                        </h2>
                        <button
                          type="button"
                          className="gw-text-button flex items-center gap-1 text-xs text-[var(--gw-accent)] hover:underline font-mono"
                          onClick={() => setView("incidents")}
                        >
                          View all 211
                          <ArrowRight size={14} />
                        </button>
                      </div>

                      <div className="gw-transactions space-y-2">
                        {sampleIncidents.slice(0, 4).map((inc) => (
                          <div
                            key={inc.id}
                            className="gw-transaction p-3 rounded-xl flex items-center justify-between cursor-pointer hover:bg-[var(--gw-hover)] transition"
                            onClick={() => {
                              setSelectedIncident(inc);
                              setView("deepdive");
                            }}
                          >
                            <div className="flex items-center gap-3">
                              <span
                                className={`w-2.5 h-2.5 rounded-full ${
                                  inc.severity === "critical"
                                    ? "bg-[#d97768] animate-pulse"
                                    : inc.severity === "high"
                                    ? "bg-[var(--gw-pending)]"
                                    : "bg-[var(--gw-accent)]"
                                }`}
                              />
                              <div>
                                <strong className="text-sm text-[var(--gw-ink)] block">{inc.label}</strong>
                                <span className="text-xs text-[var(--gw-muted)] font-mono">
                                  {inc.src_ip} &rarr; {inc.dst_ip} &middot; {inc.timestamp.slice(11)}
                                </span>
                              </div>
                            </div>

                            <div className="text-right font-mono text-xs">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border border-[var(--gw-line)] ${
                                  inc.severity === "critical"
                                    ? "bg-[#3d231e] text-[#f2a296]"
                                    : "bg-[var(--gw-account-surface)] text-[var(--gw-pending)]"
                                }`}
                              >
                                {inc.severity}
                              </span>
                              <div className="text-[11px] text-[var(--gw-accent)] mt-1">
                                {(inc.confidence * 100).toFixed(1)}% conf
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </section>

                    {/* Dual-LLM Epistemic Verification Architecture (Section 12) */}
                    <section className="gw-panel p-5 rounded-2xl gw-reveal border-l-4 border-l-[var(--gw-accent)]">
                      <div className="gw-panel-title mb-2">
                        <div className="flex items-center gap-2">
                          <Bot size={18} className="text-[var(--gw-accent)]" />
                          <h2 className="text-base font-bold text-[var(--gw-ink)]">
                            Dual-LLM Epistemic Verification (Sec 12)
                          </h2>
                        </div>
                        <span className="px-2 py-0.5 rounded-full bg-[var(--gw-segment-active)] border border-[var(--gw-line)] text-[var(--gw-accent)] text-[10px] font-mono font-bold">
                          Debate Loop Active
                        </span>
                      </div>

                      <p className="text-xs text-[var(--gw-muted)] mb-4">
                        Independent model configurations with isolated reasoning and adversarial verification roles.
                      </p>

                      <div className="space-y-3">
                        {/* Agent 08: Analyst */}
                        <div className="p-3.5 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)]">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-bold font-mono text-[var(--gw-accent)]">
                              Agent 08: LLM Analyst
                            </span>
                            <span className="text-[11px] font-mono text-[var(--gw-muted)] bg-[var(--gw-segment)] px-2 py-0.5 rounded">
                              llama3.1:8b
                            </span>
                          </div>
                          <p className="text-xs text-[var(--gw-ink)] leading-relaxed">
                            Synthesizes plain-language attack narrative. Every factual claim must cite valid RFC 6901 evidence pointers.
                          </p>
                          <div className="text-[10px] font-mono text-[var(--gw-accent)] mt-2 flex items-center gap-1">
                            <CheckCircle2 size={12} />
                            <span>Zero tool/shell permissions &middot; Read-only evidence citation</span>
                          </div>
                        </div>

                        {/* Agent 09: Critic */}
                        <div className="p-3.5 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)]">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-bold font-mono text-[var(--gw-pending)]">
                              Agent 09: Independent Critic
                            </span>
                            <span className="text-[11px] font-mono text-[var(--gw-muted)] bg-[var(--gw-segment)] px-2 py-0.5 rounded">
                              llama3.1:8b (Independent)
                            </span>
                          </div>
                          <p className="text-xs text-[var(--gw-ink)] leading-relaxed">
                            Adversarial verification against Claim-Evidence Ledger (C1). Corrects exaggerated severity and flags ungrounded assertions.
                          </p>
                          <div className="text-[10px] font-mono text-[var(--gw-pending)] mt-2 flex items-center gap-1">
                            <ShieldCheck size={12} />
                            <span>Mandatory Grounding Gate &middot; Reject &amp; Revise protocol active</span>
                          </div>
                        </div>

                        {/* Conformal Abstention Floor */}
                        <div className="p-2.5 rounded-xl bg-[var(--gw-segment)] border border-[var(--gw-line)] flex items-center justify-between text-xs font-mono">
                          <span className="text-[var(--gw-muted)]">Conformal Abstention Floor:</span>
                          <span className="text-[var(--gw-accent)] font-bold">Active &middot; Fail-closed if s(x) &gt; &lambda;</span>
                        </div>
                      </div>
                    </section>
                  </div>
                </>
              )}

              {/* ========================================================= */}
              {/* 2. LIVE TRIAGE STREAM                                     */}
              {/* ========================================================= */}
              {view === "incidents" && (
                <section className="gw-panel p-6 rounded-2xl gw-reveal space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <h2 className="text-lg font-bold text-[var(--gw-ink)]">Live Incident Telemetry</h2>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-[var(--gw-segment-active)] text-[var(--gw-accent)] border border-[var(--gw-line)]">
                        {filteredIncidents.length} Filtered / 211 Total
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <label className="gw-search flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[var(--gw-search)] border border-[var(--gw-line)] text-xs">
                        <Search size={14} className="text-[var(--gw-muted)]" />
                        <input
                          placeholder="Search IP, alert ID, or attack..."
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="bg-transparent text-[var(--gw-ink)] outline-none font-mono"
                        />
                      </label>

                      <div className="flex items-center gap-1 text-xs font-mono">
                        {["all", "critical", "high", "medium", "low"].map((sev) => (
                          <button
                            key={sev}
                            type="button"
                            onClick={() => setSevFilter(sev)}
                            className={`px-2.5 py-1 rounded-lg uppercase ${
                              sevFilter === sev
                                ? "bg-[var(--gw-button)] text-[var(--gw-button-ink)] font-bold"
                                : "bg-[var(--gw-segment)] text-[var(--gw-muted)] hover:text-[var(--gw-ink)] border border-[var(--gw-line)]"
                            }`}
                          >
                            {sev}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Incident Table */}
                  <div className="overflow-x-auto">
                    <table className="w-full text-left font-mono text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-[var(--gw-line)] text-[var(--gw-muted)] text-[11px] uppercase">
                          <th className="py-2.5 px-3">Alert ID</th>
                          <th className="py-2.5 px-3">Timestamp</th>
                          <th className="py-2.5 px-3">Label</th>
                          <th className="py-2.5 px-3">Severity</th>
                          <th className="py-2.5 px-3">Source &rarr; Target</th>
                          <th className="py-2.5 px-3">Confidence</th>
                          <th className="py-2.5 px-3">Anomaly</th>
                          <th className="py-2.5 px-3">Trust</th>
                          <th className="py-2.5 px-3">Status</th>
                          <th className="py-2.5 px-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[var(--gw-line)] text-[var(--gw-ink)]">
                        {filteredIncidents.map((inc) => (
                          <tr key={inc.id} className="hover:bg-[var(--gw-hover)] transition">
                            <td className="py-3 px-3 text-[var(--gw-accent)] font-bold">{inc.id}</td>
                            <td className="py-3 px-3 text-[var(--gw-muted)]">{inc.timestamp.slice(11)}</td>
                            <td className="py-3 px-3 font-semibold text-[var(--gw-ink)]">{inc.label}</td>
                            <td className="py-3 px-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border border-[var(--gw-line)] ${
                                  inc.severity === "critical"
                                    ? "bg-[#3d231e] text-[#f2a296]"
                                    : "bg-[var(--gw-account-surface)] text-[var(--gw-pending)]"
                                }`}
                              >
                                {inc.severity}
                              </span>
                            </td>
                            <td className="py-3 px-3 text-[var(--gw-muted)]">
                              {inc.src_ip} &rarr; {inc.dst_ip}
                            </td>
                            <td className="py-3 px-3 text-[var(--gw-accent)]">{(inc.confidence * 100).toFixed(1)}%</td>
                            <td className="py-3 px-3 text-[var(--gw-pending)]">{(inc.anomaly_score * 100).toFixed(1)}%</td>
                            <td className="py-3 px-3 text-[var(--gw-accent)] font-bold">{inc.trust_score.toFixed(2)}</td>
                            <td className="py-3 px-3 text-[var(--gw-muted)]">{inc.status}</td>
                            <td className="py-3 px-3 text-right">
                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedIncident(inc);
                                  setView("deepdive");
                                }}
                                className="px-2.5 py-1 rounded bg-[var(--gw-segment-active)] hover:bg-[var(--gw-hover)] border border-[var(--gw-line)] text-[var(--gw-accent)] font-mono text-[11px] transition"
                              >
                                Deep Dive &rarr;
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}

              {/* ========================================================= */}
              {/* 3. XAI DEEP DIVE                                          */}
              {/* ========================================================= */}
              {view === "deepdive" && (
                <section className="gw-panel p-6 rounded-2xl gw-reveal space-y-6">
                  <div className="flex flex-wrap items-center justify-between border-b border-[var(--gw-line)] pb-4">
                    <div>
                      <span className="text-xs font-mono text-[var(--gw-accent)]">INVESTIGATION TARGET: {selectedIncident.id}</span>
                      <h2 className="text-xl font-bold text-[var(--gw-ink)] mt-1">{selectedIncident.label}</h2>
                      <p className="text-xs text-[var(--gw-muted)] mt-1">{selectedIncident.description}</p>
                    </div>

                    <div className="flex items-center gap-3 font-mono text-xs">
                      <div className="p-2 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)]">
                        <span className="text-[var(--gw-muted)] block text-[10px]">EXPLANATION TRUST</span>
                        <strong className="text-[var(--gw-accent)] text-base">{selectedIncident.trust_score.toFixed(2)} / 1.00</strong>
                      </div>
                      <div className="p-2 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)]">
                        <span className="text-[var(--gw-muted)] block text-[10px]">VERIFIER GROUNDING</span>
                        <strong className="text-[var(--gw-accent)] text-base">100% (4/4 CITED)</strong>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* TreeSHAP Local Attribution Bars */}
                    <div className="p-4 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)] space-y-3 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-[var(--gw-ink)] flex items-center gap-2">
                          <Cpu size={16} className="text-[var(--gw-accent)]" />
                          <span>TreeSHAP Feature Attributions (&phi;)</span>
                        </h3>
                        <span className="text-[10px] text-[var(--gw-accent)]">&sum;&phi; + base = f(x) verified</span>
                      </div>

                      <div className="space-y-2.5 pt-2">
                        {[
                          { feat: "failed_logins", phi: 0.42, val: "220 attempts" },
                          { feat: "conn_rate", phi: 0.28, val: "45 conn/s" },
                          { feat: "off_hours", phi: 0.12, val: "1 (active)" },
                          { feat: "bytes_out_mb", phi: -0.06, val: "0.2 MB" },
                          { feat: "distinct_dst_ports", phi: -0.08, val: "1 port" },
                        ].map((row) => (
                          <div key={row.feat} className="space-y-1">
                            <div className="flex justify-between text-[11px]">
                              <span className="text-[var(--gw-muted)]">{row.feat} ({row.val})</span>
                              <span className={row.phi >= 0 ? "text-[var(--gw-accent)] font-bold" : "text-[var(--gw-pending)] font-bold"}>
                                {row.phi >= 0 ? "+" : ""}{row.phi.toFixed(2)}
                              </span>
                            </div>
                            <div className="w-full h-2 rounded-full bg-[var(--gw-line)] overflow-hidden relative">
                              <div
                                className={`h-full rounded-full ${row.phi >= 0 ? "bg-[var(--gw-accent)]" : "bg-[var(--gw-pending)]"}`}
                                style={{ width: `${Math.abs(row.phi) * 100}%` }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Contrastive Counterfactual Explanation (C10) */}
                    <div className="p-4 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)] space-y-3 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-[var(--gw-ink)] flex items-center gap-2">
                          <Sparkles size={16} className="text-[var(--gw-pending)]" />
                          <span>Contrastive Counterfactual (C10)</span>
                        </h3>
                        <span className="text-[10px] text-[var(--gw-pending)]">Min Perturbation &rarr; Normal</span>
                      </div>

                      <p className="text-xs text-[var(--gw-muted)] leading-relaxed font-sans">
                        Minimum feature adjustments required to flip prediction from <span className="text-[var(--gw-pending)] font-bold">ssh_bruteforce</span> to <span className="text-[var(--gw-accent)] font-bold">normal</span>:
                      </p>

                      <div className="p-3 rounded-lg bg-[var(--gw-panel)] border border-[var(--gw-line)] space-y-1.5 text-xs">
                        <div className="flex justify-between">
                          <span className="text-[var(--gw-muted)]">failed_logins:</span>
                          <span className="text-[var(--gw-ink)] font-bold">220 &rarr; &le; 3 attempts</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--gw-muted)]">conn_rate:</span>
                          <span className="text-[var(--gw-ink)] font-bold">45.0 &rarr; &le; 8.5 conn/s</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--gw-muted)]">L1 Perturbation Distance:</span>
                          <span className="text-[var(--gw-accent)] font-bold">0.312 (Optimal Feasible)</span>
                        </div>
                      </div>

                      {/* Claim-Evidence Ledger */}
                      <div className="pt-2 border-t border-[var(--gw-line)]">
                        <h4 className="text-xs font-bold text-[var(--gw-muted)] mb-2">Critic-Audited Claim-Evidence Ledger (C1):</h4>
                        <div className="space-y-1.5 text-[11px]">
                          <div className="p-2 rounded bg-[var(--gw-positive-surface)] border border-[var(--gw-line)] text-[var(--gw-accent)] flex items-center justify-between">
                            <span>&quot;Failed logins count reached 220 attempts&quot;</span>
                            <span className="font-bold">&check; /features/failed_logins</span>
                          </div>
                          <div className="p-2 rounded bg-[var(--gw-positive-surface)] border border-[var(--gw-line)] text-[var(--gw-accent)] flex items-center justify-between">
                            <span>&quot;Target host is 10.0.1.15&quot;</span>
                            <span className="font-bold">&check; /context/dst_ip</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </section>
              )}

              {/* ========================================================= */}
              {/* 4. WHAT-IF SANDBOX                                        */}
              {/* ========================================================= */}
              {view === "whatif" && (
                <section className="gw-panel p-6 rounded-2xl gw-reveal space-y-6">
                  <div className="flex flex-wrap items-center justify-between border-b border-[var(--gw-line)] pb-4">
                    <div>
                      <h2 className="text-xl font-bold text-[var(--gw-ink)] flex items-center gap-2">
                        <Sliders size={20} className="text-[var(--gw-accent)]" />
                        <span>Interactive Feature Perturbation Sandbox</span>
                      </h2>
                      <p className="text-xs text-[var(--gw-muted)] mt-1">
                        Perturb network flow attributes to observe real-time model inferences and conformal abstention thresholds.
                      </p>
                    </div>

                    {/* Presets */}
                    <div className="flex items-center gap-1.5 font-mono text-xs">
                      <button
                        type="button"
                        onClick={() =>
                          setWhatIfFeatures({
                            failed_logins: 0,
                            conn_rate: 2,
                            distinct_dst_ports: 3,
                            bytes_out_mb: 0.5,
                            dns_query_entropy: 2.6,
                            beacon_regularity: 0.1,
                          })
                        }
                        className="px-2.5 py-1 rounded bg-[var(--gw-segment)] hover:bg-[var(--gw-hover)] text-[var(--gw-muted)] border border-[var(--gw-line)]"
                      >
                        Normal
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setWhatIfFeatures({
                            failed_logins: 220,
                            conn_rate: 45,
                            distinct_dst_ports: 1,
                            bytes_out_mb: 0.2,
                            dns_query_entropy: 2.4,
                            beacon_regularity: 0.2,
                          })
                        }
                        className="px-2.5 py-1 rounded bg-[var(--gw-segment)] hover:bg-[var(--gw-hover)] text-[var(--gw-pending)] border border-[var(--gw-line)]"
                      >
                        SSH Brute Force
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setWhatIfFeatures({
                            failed_logins: 2,
                            conn_rate: 90,
                            distinct_dst_ports: 250,
                            bytes_out_mb: 0.1,
                            dns_query_entropy: 2.5,
                            beacon_regularity: 0.3,
                          })
                        }
                        className="px-2.5 py-1 rounded bg-[var(--gw-segment)] hover:bg-[var(--gw-hover)] text-[var(--gw-pending)] border border-[var(--gw-line)]"
                      >
                        Port Scan
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setWhatIfFeatures({
                            failed_logins: 1,
                            conn_rate: 15,
                            distinct_dst_ports: 2,
                            bytes_out_mb: 350.0,
                            dns_query_entropy: 2.9,
                            beacon_regularity: 0.25,
                          })
                        }
                        className="px-2.5 py-1 rounded bg-[var(--gw-segment)] hover:bg-[var(--gw-hover)] text-[var(--gw-accent)] border border-[var(--gw-line)]"
                      >
                        Exfiltration
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Sliders */}
                    <div className="space-y-4 font-mono text-xs">
                      {[
                        { key: "failed_logins", label: "Failed Authentication Attempts", min: 0, max: 400, step: 1, unit: "attempts" },
                        { key: "conn_rate", label: "Connection Flow Rate", min: 0, max: 150, step: 1, unit: "conn/s" },
                        { key: "distinct_dst_ports", label: "Distinct Destination Ports", min: 1, max: 300, step: 1, unit: "ports" },
                        { key: "bytes_out_mb", label: "Egress Data Volume", min: 0, max: 500, step: 0.5, unit: "MB" },
                      ].map((feat) => (
                        <div key={feat.key} className="space-y-1.5 p-3 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)]">
                          <div className="flex justify-between">
                            <span className="text-[var(--gw-muted)]">{feat.label}</span>
                            <span className="text-[var(--gw-accent)] font-bold">
                              {whatIfFeatures[feat.key]} {feat.unit}
                            </span>
                          </div>
                          <input
                            type="range"
                            min={feat.min}
                            max={feat.max}
                            step={feat.step}
                            value={whatIfFeatures[feat.key]}
                            onChange={(e) =>
                              setWhatIfFeatures({
                                ...whatIfFeatures,
                                [feat.key]: parseFloat(e.target.value),
                              })
                            }
                            className="w-full accent-[var(--gw-accent)] cursor-pointer"
                          />
                        </div>
                      ))}
                    </div>

                    {/* Real-Time Prediction Output */}
                    <div className="p-5 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)] space-y-4 font-mono text-xs flex flex-col justify-between">
                      <div>
                        <span className="text-xs uppercase font-mono tracking-wider text-[var(--gw-muted)] block mb-1">
                          Simulated Prediction Outcome
                        </span>
                        <div className="flex items-center gap-2">
                          <strong className="text-2xl font-bold text-[var(--gw-ink)] uppercase">{whatIfCalc.label}</strong>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border border-[var(--gw-line)] ${
                              whatIfCalc.label === "normal"
                                ? "bg-[var(--gw-positive-surface)] text-[var(--gw-accent)]"
                                : "bg-[var(--gw-account-surface)] text-[var(--gw-pending)]"
                            }`}
                          >
                            {(whatIfCalc.score * 100).toFixed(1)}% score
                          </span>
                        </div>
                      </div>

                      <div className="p-3.5 rounded-xl bg-[var(--gw-panel)] border border-[var(--gw-line)] space-y-2">
                        <div className="flex justify-between">
                          <span className="text-[var(--gw-muted)]">Conformal Risk Status:</span>
                          <span className={whatIfCalc.isAbstained ? "text-[var(--gw-pending)] font-bold" : "text-[var(--gw-accent)] font-bold"}>
                            {whatIfCalc.isAbstained ? "ABSTAIN (Fail-Closed Escalation)" : "CERTIFIED (Risk <= 0.05)"}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--gw-muted)]">Calibrated Cutoff (&lambda;):</span>
                          <span className="text-[var(--gw-ink)]">0.4900</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--gw-muted)]">Policy Action:</span>
                          <span className="text-[var(--gw-accent)] font-bold">
                            {whatIfCalc.label === "normal" ? "allow_traffic" : "propose_defensive_mitigation"}
                          </span>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => setNotice("Sandbox scenario pushed to Live Triage queue")}
                        className="gw-button w-full justify-center py-2.5 font-bold"
                      >
                        Push Scenario to Telemetry Engine &rarr;
                      </button>
                    </div>
                  </div>
                </section>
              )}

              {/* ========================================================= */}
              {/* 5. APPROVALS & IoMT GATES                                 */}
              {/* ========================================================= */}
              {view === "approvals" && (
                <section className="gw-panel p-6 rounded-2xl gw-reveal space-y-6">
                  <div className="flex items-center justify-between border-b border-[var(--gw-line)] pb-4">
                    <div>
                      <h2 className="text-xl font-bold text-[var(--gw-ink)] flex items-center gap-2">
                        <HeartPulse size={20} className="text-[var(--gw-pending)]" />
                        <span>Medical IoMT Clinical Approval Gate (C16)</span>
                      </h2>
                      <p className="text-xs text-[var(--gw-muted)] mt-1">
                        Hard safety invariants: Separation of duties requires dual authentication for critical life-support medical assets.
                      </p>
                    </div>

                    <span className="px-3 py-1 rounded-full bg-[var(--gw-segment-active)] border border-[var(--gw-line)] text-[var(--gw-pending)] font-mono text-xs font-bold">
                      Zero Auto-Disrupt Active
                    </span>
                  </div>

                  <form onSubmit={authorizeIoMTAction} className="max-w-xl mx-auto space-y-4 font-mono text-xs">
                    <div className="p-4 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)] space-y-2">
                      <div className="text-[var(--gw-muted)]">Target Asset: <strong className="text-[var(--gw-ink)]">Alaris Infusion Pump 4829 (10.0.4.15)</strong></div>
                      <div className="text-[var(--gw-muted)]">Proposed Action: <strong className="text-[var(--gw-pending)]">isolate_host</strong></div>
                      <div className="text-[var(--gw-muted)]">Asset Classification: <strong className="text-[var(--gw-pending)]">CRITICAL_MEDICAL_IOMT</strong></div>
                    </div>

                    <div className="space-y-3">
                      <div>
                        <label className="block text-[var(--gw-muted)] mb-1">Primary Security Approver (soc_lead):</label>
                        <div className="grid grid-cols-2 gap-2">
                          <input
                            type="text"
                            value={approvalSecUser}
                            onChange={(e) => setApprovalSecUser(e.target.value)}
                            className="px-3 py-2 rounded-lg bg-[var(--gw-panel)] border border-[var(--gw-line)] text-[var(--gw-ink)]"
                          />
                          <input
                            type="password"
                            value={approvalSecToken}
                            onChange={(e) => setApprovalSecToken(e.target.value)}
                            className="px-3 py-2 rounded-lg bg-[var(--gw-panel)] border border-[var(--gw-line)] text-[var(--gw-ink)]"
                          />
                        </div>
                      </div>

                      <div className="p-3.5 rounded-xl bg-[var(--gw-account-surface)] border border-[var(--gw-line)] space-y-2">
                        <div className="text-[var(--gw-pending)] font-bold flex items-center gap-1.5">
                          <AlertTriangle size={15} />
                          <span>Secondary Clinical Approver Required (C16)</span>
                        </div>
                        <div className="text-[11px] text-[var(--gw-muted)]">
                          Clinical Director or Biomedical Engineering credentials required:
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          <input
                            type="text"
                            value={approvalClinUser}
                            onChange={(e) => setApprovalClinUser(e.target.value)}
                            placeholder="Clinical Approver ID"
                            className="px-3 py-2 rounded-lg bg-[var(--gw-panel)] border border-[var(--gw-line)] text-[var(--gw-ink)]"
                          />
                          <input
                            type="password"
                            value={approvalClinToken}
                            onChange={(e) => setApprovalClinToken(e.target.value)}
                            placeholder="Clinical Secret Token"
                            className="px-3 py-2 rounded-lg bg-[var(--gw-panel)] border border-[var(--gw-line)] text-[var(--gw-ink)]"
                          />
                        </div>
                      </div>

                      <button
                        type="submit"
                        className="gw-button w-full justify-center py-3 font-bold mt-3"
                      >
                        Authorize Defensive Action (DRY-RUN ENFORCED) &rarr;
                      </button>

                      {approvalSuccess && (
                        <div className="p-3 rounded-xl bg-[var(--gw-positive-surface)] border border-[var(--gw-line)] text-[var(--gw-accent)] text-center font-bold">
                          &check; Action approved with dual signatures! Dry-run simulated successfully without patient impact.
                        </div>
                      )}
                    </div>
                  </form>
                </section>
              )}

              {/* ========================================================= */}
              {/* 6. 9-AGENT TRACE REPLAY                                   */}
              {/* ========================================================= */}
              {view === "agents" && (
                <section className="gw-panel p-6 rounded-2xl gw-reveal space-y-5">
                  <div className="flex flex-wrap items-center justify-between border-b border-[var(--gw-line)] pb-4">
                    <div>
                      <h2 className="text-xl font-bold text-[var(--gw-ink)] flex items-center gap-2">
                        <Bot size={20} className="text-[var(--gw-accent)]" />
                        <span>Interactive 9-Agent Pipeline Trace Replay</span>
                      </h2>
                      <p className="text-xs text-[var(--gw-muted)] mt-1">
                        Timeline execution graph showing sequential telemetry from Ingestion to RFC 8785 Cryptographic Audit.
                      </p>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-xs">
                      <button
                        type="button"
                        onClick={() => {
                          setIsTracePlaying(!isTracePlaying);
                          if (!isTracePlaying) {
                            setActiveTraceStep(1);
                            const interval = setInterval(() => {
                              setActiveTraceStep((prev) => {
                                if (prev >= 9) {
                                  clearInterval(interval);
                                  setIsTracePlaying(false);
                                  return 9;
                                }
                                return prev + 1;
                              });
                            }, 500);
                          }
                        }}
                        className="gw-button"
                      >
                        {isTracePlaying ? <Pause size={14} /> : <Play size={14} />}
                        <span>{isTracePlaying ? "Pause" : "Replay Pipeline"}</span>
                      </button>
                    </div>
                  </div>

                  {/* Agent Spans Timeline */}
                  <div className="space-y-2.5 font-mono text-xs">
                    {traceSpans.slice(0, activeTraceStep).map((span, idx) => (
                      <div
                        key={span.id}
                        className="p-3.5 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)] flex items-center justify-between hover:bg-[var(--gw-hover)] transition"
                      >
                        <div className="flex items-center gap-3">
                          <span className="w-6 h-6 rounded-full bg-[var(--gw-brand)] text-[var(--gw-brand-ink)] font-bold flex items-center justify-center text-[10px]">
                            0{idx + 1}
                          </span>
                          <div>
                            <strong className="text-[var(--gw-ink)] block">{span.name}</strong>
                            <span className="text-[11px] text-[var(--gw-muted)]">{span.detail}</span>
                          </div>
                        </div>

                        <div className="text-right">
                          <span className="px-2 py-0.5 rounded bg-[var(--gw-positive-surface)] text-[var(--gw-accent)] font-bold text-[10px] border border-[var(--gw-line)]">
                            {span.status}
                          </span>
                          <span className="text-[11px] text-[var(--gw-muted)] block mt-1">{span.duration}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* ========================================================= */}
              {/* 7. AUDIT LEDGER                                           */}
              {/* ========================================================= */}
              {view === "audit" && (
                <section className="gw-panel p-6 rounded-2xl gw-reveal space-y-6">
                  <div className="flex flex-wrap items-center justify-between border-b border-[var(--gw-line)] pb-4">
                    <div>
                      <h2 className="text-xl font-bold text-[var(--gw-ink)] flex items-center gap-2">
                        <FileCheck size={20} className="text-[var(--gw-accent)]" />
                        <span>Tamper-Evident RFC 8785 Audit Ledger</span>
                      </h2>
                      <p className="text-xs text-[var(--gw-muted)] mt-1">
                        Cryptographic SHA-256 hash chaining under Canonical JSON RFC 8785 guarantees immutable forensics.
                      </p>
                    </div>

                    <button
                      type="button"
                      onClick={verifyAuditChain}
                      className="gw-button"
                    >
                      Verify Hash Chain Integrity
                    </button>
                  </div>

                  {auditVerified && (
                    <div className="p-4 rounded-xl bg-[var(--gw-positive-surface)] border border-[var(--gw-line)] text-xs font-mono space-y-1">
                      <div className="flex items-center gap-2 text-[var(--gw-accent)] font-bold text-sm">
                        <CheckCircle2 size={16} />
                        <span>Chain Status: Intact &amp; Cryptographically Certified</span>
                      </div>
                      <div className="text-[var(--gw-muted)]">
                        Verified 211 consecutive block entries &middot; 0 hash mismatches &middot; RFC 8785 Compliant
                      </div>
                    </div>
                  )}

                  <div className="space-y-2 font-mono text-xs">
                    {[
                      { index: 211, time: "2026-11-18 14:18:22", agent: "agent_07_audit", action: "append_ledger_entry", hash: "9f8a3c8e47b2c019d45e6f...", prev: "e10a4b7f..." },
                      { index: 210, time: "2026-11-18 14:18:21", agent: "agent_06_response", action: "propose_block_ip", hash: "e10a4b7f92c10a48d88e...", prev: "7fa2018c..." },
                      { index: 209, time: "2026-11-18 14:18:20", agent: "agent_09_verifier", action: "certify_grounding", hash: "7fa2018c44b910e53a29...", prev: "11c9408b..." },
                    ].map((blk) => (
                      <div key={blk.index} className="p-3 rounded-xl bg-[var(--gw-surface)] border border-[var(--gw-line)] flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-3">
                          <span className="text-[var(--gw-accent)] font-bold">#{blk.index}</span>
                          <span className="text-[var(--gw-muted)]">{blk.time}</span>
                          <span className="text-[var(--gw-ink)] font-semibold">{blk.agent}</span>
                          <span className="text-[var(--gw-muted)] text-[11px] bg-[var(--gw-segment)] px-2 py-0.5 rounded">{blk.action}</span>
                        </div>
                        <div className="text-[var(--gw-muted)] text-[11px]">
                          Hash: <span className="text-[var(--gw-accent)] font-bold">{blk.hash}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              )}
            </div>

            {/* Bottom Dock Navigation */}
            <div className="gw-desktop-dock">{renderNav()}</div>
          </main>
        </div>

        {/* Notifications Drawer */}
        {alerts && (
          <aside className="gw-notifications gw-glass" aria-label="Notifications">
            <div className="flex items-center justify-between border-b border-[var(--gw-line)] pb-2 mb-3">
              <h2 className="text-sm font-bold text-[var(--gw-ink)]">Live Threat Telemetry Feed</h2>
              <button type="button" onClick={() => setAlerts(false)} className="text-[var(--gw-muted)] hover:text-[var(--gw-ink)]">
                <X size={16} />
              </button>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="p-2 rounded bg-[var(--gw-surface)] border border-[var(--gw-line)] text-[var(--gw-pending)]">
                &bull; SSH Brute Force logged from 185.220.101.47 (14:18)
              </div>
              <div className="p-2 rounded bg-[var(--gw-surface)] border border-[var(--gw-line)] text-[var(--gw-accent)]">
                &bull; SYN Port scan detected on 192.168.1.105 (14:12)
              </div>
              <div className="p-2 rounded bg-[var(--gw-surface)] border border-[var(--gw-line)] text-[var(--gw-accent)]">
                &bull; Conformal calibration verified with risk &le; 0.05
              </div>
            </div>
          </aside>
        )}

        {/* Real-Time Warm Glass Controls Drawer */}
        {settingsOpen && (
          <aside className="gw-material gw-glass" id={`${id}-material`} aria-label="Glass appearance">
            <div className="gw-material-header">
              <div className="flex items-center gap-2">
                <Sliders size={16} className="text-[var(--gw-accent)]" />
                <h2 className="text-[var(--gw-ink)] font-bold text-sm">Adjust Glass Controls</h2>
              </div>
              <button
                type="button"
                className="gw-icon-button"
                aria-label="Close settings"
                onClick={() => setSettingsOpen(false)}
              >
                <X size={17} aria-hidden="true" />
              </button>
            </div>

            {/* Quick Presets */}
            <div className="gw-presets mb-3">
              <span className="text-[10px] uppercase font-mono tracking-wider text-[var(--gw-muted)] block mb-1">
                Glass Presets
              </span>
              <div className="grid grid-cols-2 gap-1.5 font-mono text-xs">
                <button
                  type="button"
                  onClick={() => applyGlassPreset("frosted")}
                  className="px-2 py-1.5 rounded bg-[var(--gw-surface)] hover:bg-[var(--gw-hover)] text-[var(--gw-accent)] border border-[var(--gw-line)] text-left"
                >
                  &#10052; Frosted Warm
                </button>
                <button
                  type="button"
                  onClick={() => applyGlassPreset("clear")}
                  className="px-2 py-1.5 rounded bg-[var(--gw-surface)] hover:bg-[var(--gw-hover)] text-[var(--gw-muted)] border border-[var(--gw-line)] text-left"
                >
                  &#9670; Minimal Glass
                </button>
                <button
                  type="button"
                  onClick={() => applyGlassPreset("midnight")}
                  className="px-2 py-1.5 rounded bg-[var(--gw-surface)] hover:bg-[var(--gw-hover)] text-[var(--gw-muted)] border border-[var(--gw-line)] text-left"
                >
                  &#9672; Midnight Solid
                </button>
                <button
                  type="button"
                  onClick={() => applyGlassPreset("neon")}
                  className="px-2 py-1.5 rounded bg-[var(--gw-surface)] hover:bg-[var(--gw-hover)] text-[var(--gw-accent)] border border-[var(--gw-line)] text-left"
                >
                  &#9889; High Contrast
                </button>
              </div>
            </div>

            {/* Optical Sliders */}
            <div className="gw-sliders space-y-3 font-mono text-xs">
              <label>
                <span className="flex justify-between text-[var(--gw-muted)] mb-1">
                  <span>Backdrop Blur</span>
                  <span className="text-[var(--gw-accent)]">{material.blur}px</span>
                </span>
                <input
                  type="range"
                  min="0"
                  max="40"
                  value={material.blur}
                  onChange={(e) => updateGlass({ blur: Number(e.target.value) })}
                  className="w-full accent-[var(--gw-accent)]"
                />
              </label>

              <label>
                <span className="flex justify-between text-[var(--gw-muted)] mb-1">
                  <span>Glass Opacity</span>
                  <span className="text-[var(--gw-accent)]">{Math.round(material.opacity * 100)}%</span>
                </span>
                <input
                  type="range"
                  min="8"
                  max="95"
                  value={Math.round(material.opacity * 100)}
                  onChange={(e) => updateGlass({ opacity: Number(e.target.value) / 100 })}
                  className="w-full accent-[var(--gw-accent)]"
                />
              </label>

              <label>
                <span className="flex justify-between text-[var(--gw-muted)] mb-1">
                  <span>Color Saturation</span>
                  <span className="text-[var(--gw-accent)]">{Math.round(material.saturation * 100)}%</span>
                </span>
                <input
                  type="range"
                  min="50"
                  max="250"
                  value={Math.round(material.saturation * 100)}
                  onChange={(e) => updateGlass({ saturation: Number(e.target.value) / 100 })}
                  className="w-full accent-[var(--gw-accent)]"
                />
              </label>

              <label>
                <span className="flex justify-between text-[var(--gw-muted)] mb-1">
                  <span>Edge Rim Light</span>
                  <span className="text-[var(--gw-accent)]">{Math.round(material.edge * 100)}%</span>
                </span>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={Math.round(material.edge * 100)}
                  onChange={(e) => updateGlass({ edge: Number(e.target.value) / 100 })}
                  className="w-full accent-[var(--gw-accent)]"
                />
              </label>

              <label>
                <span className="flex justify-between text-[var(--gw-muted)] mb-1">
                  <span>Tint Color</span>
                  <span className="text-[var(--gw-accent)]">{material.tint}</span>
                </span>
                <div className="flex items-center gap-2">
                  <input
                    type="color"
                    value={material.tint}
                    onChange={(e) => updateGlass({ tint: e.target.value })}
                    className="w-8 h-8 rounded border border-[var(--gw-line)] bg-transparent cursor-pointer"
                  />
                  <input
                    type="text"
                    value={material.tint}
                    onChange={(e) => updateGlass({ tint: e.target.value })}
                    className="flex-1 px-2.5 py-1 rounded bg-[var(--gw-surface)] border border-[var(--gw-line)] text-[var(--gw-ink)] font-mono text-xs"
                  />
                </div>
              </label>
            </div>

            <button
              className="gw-reset mt-4 w-full py-2 rounded-xl bg-[var(--gw-surface)] hover:bg-[var(--gw-hover)] text-[var(--gw-muted)] border border-[var(--gw-line)] font-mono text-xs font-bold transition"
              type="button"
              onClick={() => updateGlass(normalize(glass))}
            >
              Reset Appearance Defaults
            </button>
          </aside>
        )}
      </div>

      {/* Toast Feedback Notification */}
      {notice && (
        <div className="gw-toast" role="status">
          <Check size={16} aria-hidden="true" />
          <span>{notice}</span>
        </div>
      )}
    </div>
  );
}

const customStyles = `
.gw-root {
  position: relative;
  isolation: isolate;
  min-height: 100vh;
  overflow-x: hidden;
  padding: 24px 20px;
  background: var(--gw-background, #282a25);
  color: var(--gw-ink, #f4f4ed);
  font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  letter-spacing: -0.01em;
  box-sizing: border-box;
}
.gw-room {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  z-index: -2;
  filter: brightness(0.72) contrast(1.05);
}
.gw-room-shade {
  position: fixed;
  inset: 0;
  background: radial-gradient(circle at 15% 15%, rgba(234, 219, 199, 0.12) 0%, transparent 50%),
              radial-gradient(circle at 85% 85%, rgba(145, 213, 176, 0.08) 0%, transparent 50%),
              var(--gw-shade, rgba(18, 16, 14, 0.48));
  z-index: -1;
}
.gw-workspace {
  max-width: 1380px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.gw-glass {
  background: color-mix(in srgb, var(--gw-tint, #eadbc7) calc(var(--gw-opacity, 0.3) * 100%), var(--gw-surface, #262322));
  backdrop-filter: blur(var(--gw-blur, 22px)) saturate(var(--gw-saturation, 1.2));
  -webkit-backdrop-filter: blur(var(--gw-blur, 22px)) saturate(var(--gw-saturation, 1.2));
  border: 1px solid var(--gw-line, rgba(225, 237, 223, 0.15));
  box-shadow: 0 16px 36px -12px var(--gw-shadow, rgba(23, 41, 27, 0.28)), inset 0 1px 0 rgba(255, 255, 255, calc(var(--gw-edge, 0.6) * 0.15));
}
.gw-topbar {
  padding: 12px 20px;
  border-radius: 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.gw-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  text-decoration: none;
  color: inherit;
}
.gw-brand-icon {
  width: 32px;
  height: 32px;
  border-radius: 10px;
  background: var(--gw-brand, #e2eee0);
  color: var(--gw-brand-ink, #183725);
  display: flex;
  align-items: center;
  justify-content: center;
}
.gw-brand strong {
  font-size: 16px;
  font-weight: 800;
  letter-spacing: -0.02em;
  color: var(--gw-ink, #f4f4ed);
}
.gw-brand-divider {
  width: 1px;
  height: 16px;
  background: var(--gw-line, rgba(225, 237, 223, 0.15));
}
.gw-personal {
  font-size: 12px;
  color: var(--gw-muted, #d0c9bf);
}
.gw-toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
}
.gw-adjust {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 12px;
  background: var(--gw-segment, rgba(233, 246, 231, 0.07));
  border: 1px solid var(--gw-line, rgba(225, 237, 223, 0.15));
  color: var(--gw-ink, #f4f4ed);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}
.gw-adjust:hover {
  background: var(--gw-hover, rgba(255, 255, 255, 0.16));
}
.gw-button {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 12px;
  background: var(--gw-button, #d8ebd7);
  color: var(--gw-button-ink, #193320);
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  border: none;
  transition: filter 0.15s ease;
}
.gw-button:hover {
  filter: brightness(1.08);
}
.gw-icon-button {
  width: 34px;
  height: 34px;
  border-radius: 12px;
  background: var(--gw-segment, rgba(233, 246, 231, 0.07));
  border: 1px solid var(--gw-line, rgba(225, 237, 223, 0.15));
  color: var(--gw-muted, #d0c9bf);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  position: relative;
}
.gw-bell i {
  position: absolute;
  top: 7px;
  right: 7px;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--gw-accent, #91d5b0);
  box-shadow: 0 0 8px var(--gw-accent, #91d5b0);
}
.gw-avatar {
  width: 34px;
  height: 34px;
  border-radius: 12px;
  background: var(--gw-avatar, #616e58);
  color: var(--gw-ink, #f4f4ed);
  font-weight: 800;
  font-size: 13px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.gw-stage {
  display: flex;
  gap: 16px;
  align-items: stretch;
}
.gw-rail {
  width: 64px;
  padding: 16px 8px;
  border-radius: 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}
@media (max-width: 768px) {
  .gw-rail {
    display: none;
  }
}
.gw-rail button, .gw-dock button {
  width: 44px;
  height: 44px;
  border-radius: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--gw-muted, #d0c9bf);
  border: 1px solid transparent;
  background: transparent;
  cursor: pointer;
  transition: all 0.2s ease;
  position: relative;
}
.gw-rail button:hover, .gw-dock button:hover {
  color: var(--gw-ink, #f4f4ed);
  background: var(--gw-hover, rgba(255, 255, 255, 0.16));
}
.gw-rail button.is-active, .gw-dock button.is-active {
  color: var(--gw-accent, #91d5b0);
  background: var(--gw-rail-active, rgba(215, 229, 212, 0.17));
  border-color: var(--gw-line, rgba(225, 237, 223, 0.15));
  box-shadow: 0 0 16px -2px rgba(145, 213, 176, 0.25);
}
.gw-nav-label {
  display: none;
}
.gw-main {
  flex: 1;
  min-width: 0;
  border-radius: 28px;
  padding: 28px;
  display: flex;
  flex-direction: column;
}
.gw-view-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 24px;
}
.gw-greeting {
  font-size: 13px;
  color: var(--gw-muted, #d0c9bf);
  margin-bottom: 4px;
}
.gw-view-heading h1 {
  font-size: 26px;
  font-weight: 800;
  letter-spacing: -0.025em;
  color: var(--gw-ink, #f4f4ed);
}
.gw-panel {
  background: color-mix(in srgb, var(--gw-panel, #2b2825) 75%, transparent);
  border: 1px solid var(--gw-line, rgba(225, 237, 223, 0.15));
  border-radius: 20px;
}
.gw-panel-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
.gw-account {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: 14px;
  background: var(--gw-account-surface, rgba(89, 110, 83, 0.33));
  border: 1px solid var(--gw-line, rgba(225, 237, 223, 0.15));
  font-size: 12px;
}
.gw-account-icon {
  width: 28px;
  height: 28px;
  border-radius: 8px;
  background: rgba(225, 195, 131, 0.15);
  display: flex;
  align-items: center;
  justify-content: center;
}
.gw-account strong {
  display: block;
  font-size: 12px;
  color: var(--gw-ink, #f4f4ed);
}
.gw-account span {
  font-size: 11px;
  color: var(--gw-muted, #d0c9bf);
}
.gw-account button {
  margin-left: auto;
  color: var(--gw-accent, #91d5b0);
  background: none;
  border: none;
  cursor: pointer;
}
.gw-chart-summary {
  display: flex;
  gap: 24px;
}
.gw-desktop-dock {
  display: none;
}
@media (max-width: 768px) {
  .gw-desktop-dock {
    display: flex;
    justify-content: center;
    position: fixed;
    bottom: 16px;
    left: 16px;
    right: 16px;
    z-index: 40;
  }
}
.gw-dock {
  padding: 8px 16px;
  border-radius: 24px;
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--gw-dock, rgba(21, 38, 27, 0.8));
  box-shadow: 0 20px 40px -10px rgba(0,0,0,0.8);
}
.gw-material {
  position: fixed;
  top: 80px;
  right: 28px;
  width: 320px;
  border-radius: 24px;
  padding: 20px;
  z-index: 50;
  background: var(--gw-popover, rgba(21, 38, 30, 0.94));
  box-shadow: 0 24px 48px -12px rgba(0,0,0,0.8);
}
.gw-material-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.gw-notifications {
  position: fixed;
  top: 80px;
  right: 28px;
  width: 320px;
  border-radius: 24px;
  padding: 20px;
  z-index: 50;
  background: var(--gw-notification, rgba(21, 38, 30, 0.94));
}
.gw-toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  padding: 10px 18px;
  border-radius: 14px;
  background: var(--gw-toast, #243e2e);
  color: var(--gw-toast-ink, #fff);
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  font-weight: 600;
  z-index: 100;
  box-shadow: 0 12px 24px -4px var(--gw-toast-shadow, rgba(0, 0, 0, 0.13));
}
`;
