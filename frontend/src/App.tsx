import { SentinelAgentTraceDemo } from './components/ui/demo'
import { Activity, ShieldCheck } from 'lucide-react'

export function App() {
  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col items-center justify-start p-4 sm:p-8">
      {/* Top Banner */}
      <header className="w-full max-w-5xl flex items-center justify-between pb-6 mb-8 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-black shadow-lg shadow-cyan-950/50">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              SENTINEL-XAI <span className="text-xs px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/40 font-mono">TRACE-REPLAY</span>
            </h1>
            <p className="text-xs text-muted-foreground font-mono">
              Nine-Agent Explainable Execution Timeline &scrub; Zero-Token Security Telemetry
            </p>
          </div>
        </div>

        <div className="hidden sm:flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-card border border-border">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-muted-foreground">SOC Status:</span>
            <span className="text-emerald-400 font-semibold">ACTIVE</span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="w-full max-w-5xl flex flex-col items-center">
        <div className="w-full mb-6">
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
            <Activity className="w-3.5 h-3.5" />
            <span>INCIDENT EXECUTION GRAPH & TIMELINE</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight">Agent Pipeline Timeline Replay</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Drag the timeline or press Play to replay the 9-agent detection, explainability, debate, and response cycle.
            Token metrics are replaced with actual execution latencies, accuracy scores, and verification outcomes.
          </p>
        </div>

        {/* The Scrubbable Agent Trace Component */}
        <div className="w-full">
          <SentinelAgentTraceDemo />
        </div>
      </main>

      {/* Footer */}
      <footer className="w-full max-w-5xl mt-12 pt-6 border-t border-border flex items-center justify-between text-xs text-muted-foreground font-mono">
        <div>Sentinel-XAI Platform v2.2.0 · University of Westminster / IIT</div>
        <div>All 9 Agents Operational · RFC 8785 Verified</div>
      </footer>
    </div>
  )
}

export default App
