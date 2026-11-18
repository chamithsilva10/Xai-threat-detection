import { useState } from 'react'
import { SentinelAgentTraceDemo } from './components/ui/demo'
import GlassWorkspaceDemo from './components/ui/glass-demo'
import { Activity, Layers, ShieldCheck } from 'lucide-react'

export function App() {
  const [activeTab, setActiveTab] = useState<'glass' | 'trace'>('glass')

  return (
    <div className="min-h-screen bg-[#070b12] text-slate-100 flex flex-col items-center">
      {/* Universal Top Switcher Bar */}
      <nav className="w-full bg-[#0d131f]/90 backdrop-blur-md border-b border-[#1b263b] px-6 py-3 flex items-center justify-between z-30 sticky top-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <span className="font-mono text-sm font-bold text-white tracking-wide">
              SENTINEL-XAI <span className="text-cyan-400">STUDIO</span>
            </span>
            <span className="ml-2 text-[10px] font-mono text-slate-400 border border-slate-700/60 rounded px-1.5 py-0.5">
              v2.2.0
            </span>
          </div>
        </div>

        {/* View Switcher Pills */}
        <div className="flex items-center p-1 rounded-xl bg-[#070b12] border border-[#1b263b] text-xs font-mono">
          <button
            type="button"
            onClick={() => setActiveTab('glass')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'glass'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Adjustable Glass Workspace</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('trace')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'trace'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>9-Agent Trace Replay</span>
          </button>
        </div>

        <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Localhost: 5173 / 8000</span>
        </div>
      </nav>

      {/* Main View Display */}
      {activeTab === 'glass' ? (
        <div className="w-full">
          <GlassWorkspaceDemo />
        </div>
      ) : (
        <main className="w-full max-w-5xl flex flex-col items-center p-6 sm:p-10">
          <div className="w-full mb-6">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
              <Activity className="w-3.5 h-3.5" />
              <span>INCIDENT EXECUTION GRAPH & TIMELINE</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight">Agent Pipeline Timeline Replay</h2>
            <p className="text-sm text-slate-400 mt-1">
              Drag the timeline or press Play to replay the 9-agent detection, explainability, debate, and response cycle.
              Token metrics are replaced with actual execution latencies, accuracy scores, and verification outcomes.
            </p>
          </div>

          <div className="w-full">
            <SentinelAgentTraceDemo />
          </div>
        </main>
      )}
    </div>
  )
}

export default App
