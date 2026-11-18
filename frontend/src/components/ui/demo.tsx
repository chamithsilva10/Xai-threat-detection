"use client"

import * as React from "react"
import { motion, useReducedMotion } from "motion/react"
import { AgentTrace, type TraceSpan } from "@/components/ui/agent-trace"
import { Shield } from "lucide-react"

// Sentinel-XAI Nine-Agent Telemetry Spans (Tokens removed, real security telemetry added)
const SENTINEL_SSH_RUN: TraceSpan[] = [
  { id: "agent_01", label: "01 Ingestion Agent", kind: "agent", start: 0, end: 450, detail: "Schema validated & sanitized" },
  { id: "sanitizer", label: "regex_sanitizer", kind: "tool", parentId: "agent_01", start: 50, end: 220, detail: "0 prompt injection patterns" },
  { id: "normalize", label: "feature_extractor", kind: "io", parentId: "agent_01", start: 240, end: 430, detail: "6 normalized numerical features" },

  { id: "agent_02", label: "02 Detection Agent", kind: "agent", start: 460, end: 1850, detail: "SSH_Bruteforce (p=0.982)" },
  { id: "xgboost", label: "xgboost_5class", kind: "model", parentId: "agent_02", start: 480, end: 1120, detail: "Confidence: 98.2%" },
  { id: "isoforest", label: "isolation_forest", kind: "model", parentId: "agent_02", start: 1140, end: 1820, detail: "Anomaly score: -0.684 (Outlier)" },

  { id: "agent_03", label: "03 Explainability Agent", kind: "agent", start: 1880, end: 3420, detail: "TreeSHAP reconstruction verified" },
  { id: "shap", label: "treeshap_attribution", kind: "tool", parentId: "agent_03", start: 1910, end: 2750, detail: "failed_logins: +0.642 phi" },
  { id: "cf", label: "counterfactual_engine", kind: "tool", parentId: "agent_03", start: 2780, end: 3380, detail: "Target: Benign (delta: -14 logins)" },

  { id: "agent_04", label: "04 Threat Intel Agent", kind: "agent", start: 3440, end: 4300, detail: "T1110.001 Brute Force" },
  { id: "ioc", label: "ioc_feed_lookup", kind: "io", parentId: "agent_04", start: 3470, end: 3880, status: "cached", detail: "Local IOC cache match" },
  { id: "mitre", label: "mitre_mapper", kind: "tool", parentId: "agent_04", start: 3900, end: 4280, detail: "Technique: Credential Stuffing" },

  { id: "agent_05", label: "05 Risk & Triage Agent", kind: "agent", start: 4320, end: 5100, detail: "Certified (s(x) <= lambda_hat)" },
  { id: "ucb", label: "clopper_pearson_ucb", kind: "tool", parentId: "agent_05", start: 4350, end: 4720, detail: "UCB: 0.041 <= alpha: 0.05" },
  { id: "abstain", label: "conformal_gate", kind: "tool", parentId: "agent_05", start: 4740, end: 5080, detail: "Coverage: 95.0% (PASS)" },

  { id: "agent_08", label: "08 LLM Analyst", kind: "model", start: 5120, end: 7200, detail: "Structured RFC 6901 narrative" },
  { id: "claims", label: "claim_ledger_writer", kind: "tool", parentId: "agent_08", start: 5150, end: 5850, detail: "6 claims -> /features/failed_logins" },
  { id: "narrative", label: "llama3.1:8b", kind: "model", parentId: "agent_08", start: 5880, end: 7150, detail: "Evidence grounded" },

  { id: "agent_09", label: "09 LLM Verifier", kind: "model", start: 7220, end: 8900, detail: "Adversarial audit PASSED" },
  { id: "pointer_chk", label: "pointer_resolver", kind: "tool", parentId: "agent_09", start: 7250, end: 7780, detail: "100% pointers verified against C1" },
  { id: "debate", label: "mistral:7b", kind: "model", parentId: "agent_09", start: 7800, end: 8850, detail: "Cross-model consensus" },

  { id: "agent_06", label: "06 Response Orchestrator", kind: "agent", start: 8920, end: 9800, detail: "Playbook: ISOLATE_HOST" },
  { id: "safety", label: "iomt_clinical_gate", kind: "tool", parentId: "agent_06", start: 8950, end: 9380, detail: "C16 dual-auth check: PASS" },
  { id: "dryrun", label: "dry_run_connector", kind: "io", parentId: "agent_06", start: 9400, end: 9780, detail: "external_effect: false (DRY_RUN)" },

  { id: "agent_07", label: "07 Audit & Feedback Agent", kind: "agent", start: 9820, end: 10450, detail: "RFC 8785 hash-chain VALID" },
  { id: "canon", label: "rfc8785_canonical_json", kind: "tool", parentId: "agent_07", start: 9850, end: 10150, detail: "SHA-256 e8f142... linked" },
  { id: "drift", label: "ks_drift_monitor", kind: "tool", parentId: "agent_07", start: 10180, end: 10420, detail: "KS stat: 0.12 (p=0.48, Normal)" },
]

const SENTINEL_TOTAL_MS = 10450

export function SentinelAgentTraceDemo() {
  const reduce = useReducedMotion()
  const [speed, setSpeed] = React.useState(1)
  const [selectedIncident, setSelectedIncident] = React.useState("INC-2026-892")

  const enter = (delay: number) =>
    reduce
      ? {}
      : {
          initial: { opacity: 0, y: 14, filter: "blur(6px)" },
          animate: { opacity: 1, y: 0, filter: "blur(0px)" },
          transition: { duration: 0.5, delay, ease: [0.22, 1, 0.36, 1] as const },
        }

  return (
    <div className="w-full flex flex-col items-center">
      {/* Incident Subheader & Controls */}
      <motion.div {...enter(0.05)} className="w-full flex flex-wrap items-center justify-between gap-4 mb-4 pb-3 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <select
                value={selectedIncident}
                onChange={(e) => setSelectedIncident(e.target.value)}
                className="bg-card border border-border rounded px-2 py-0.5 text-xs font-mono font-bold text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="INC-2026-892">INC-2026-892 (SSH_Bruteforce)</option>
                <option value="INC-2026-893">INC-2026-893 (Data_Exfiltration)</option>
                <option value="INC-2026-894">INC-2026-894 (Port_Scan)</option>
              </select>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/40">
                CRITICAL
              </span>
            </div>
            <span className="text-xs text-muted-foreground font-mono">Target: 192.168.1.105 (IoMT Infusion Pump)</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground font-mono">Speed:</span>
          {[0.5, 1, 2].map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSpeed(s)}
              className={`px-2 py-1 rounded text-xs font-mono transition-colors ${
                speed === s
                  ? "bg-cyan-500 text-black font-semibold"
                  : "bg-muted text-muted-foreground hover:text-foreground"
              }`}
            >
              {s}x
            </button>
          ))}
        </div>
      </motion.div>

      {/* Main AgentTrace Component (tokens removed, showTokens=false) */}
      <motion.div {...enter(0.12)} className="w-full">
        <AgentTrace
          id="sentinel-agent-trace"
          spans={SENTINEL_SSH_RUN}
          duration={SENTINEL_TOTAL_MS}
          runId={`${selectedIncident} · 9-Agent Pipeline`}
          model="Dual-LLM (llama3.1:8b / mistral:7b)"
          defaultTime={SENTINEL_TOTAL_MS}
          autoPlay={false}
          loop={true}
          speed={speed}
          rowHeight={34}
          labelWidth={220}
          showRuler={true}
          showTransport={true}
          showTokens={false} // Tokens removed per request; displays real incident telemetry
        />
      </motion.div>

      {/* Telemetry Footer Callouts */}
      <motion.div {...enter(0.2)} className="w-full mt-4 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
        <div className="p-3 rounded-lg bg-card border border-border flex items-center justify-between">
          <span className="text-muted-foreground">Calibration Gate:</span>
          <span className="text-emerald-400 font-semibold">CERTIFIED (Risk &le; 0.05)</span>
        </div>
        <div className="p-3 rounded-lg bg-card border border-border flex items-center justify-between">
          <span className="text-muted-foreground">Dual-LLM Grounding:</span>
          <span className="text-cyan-400 font-semibold">100% VERIFIED (C1 Ledger)</span>
        </div>
        <div className="p-3 rounded-lg bg-card border border-border flex items-center justify-between">
          <span className="text-muted-foreground">Audit Hash Chain:</span>
          <span className="text-emerald-400 font-semibold">RFC 8785 VALID</span>
        </div>
      </motion.div>
    </div>
  )
}

export default SentinelAgentTraceDemo
