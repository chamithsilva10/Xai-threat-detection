import { useState } from 'react'
import { SentinelAgentTraceDemo } from './components/ui/demo'
import GlassWorkspaceDemo from './components/ui/glass-demo'
import { Activity, Layers, ShieldCheck } from 'lucide-react'

export function App() {
  const [activeTab, setActiveTab] = useState<'glass' | 'trace'>('glass')

  return (
    <div className="min-h-screen bg-[#282a25] text-[#f4f4ed] flex flex-col items-center">
      {/* Universal Top Switcher Bar with Warm Smoked Glass Aesthetic */}
      <nav className="w-full bg-[#262322]/90 backdrop-blur-md border-b border-[rgba(225,237,223,0.15)] px-6 py-3 flex items-center justify-between z-30 sticky top-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#e2eee0] text-[#183725] flex items-center justify-center font-bold">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <span className="font-mono text-sm font-bold text-[#f4f4ed] tracking-wide">
              SENTINEL-XAI <span className="text-[#91d5b0]">STUDIO</span>
            </span>
            <span className="ml-2 text-[10px] font-mono text-[#d0c9bf] border border-[rgba(225,237,223,0.2)] rounded px-1.5 py-0.5">
              v2.2.0
            </span>
          </div>
        </div>

        {/* View Switcher Pills */}
        <div className="flex items-center p-1 rounded-xl bg-[#282a25] border border-[rgba(225,237,223,0.15)] text-xs font-mono">
          <button
            type="button"
            onClick={() => setActiveTab('glass')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'glass'
                ? 'bg-[rgba(215,229,212,0.2)] text-[#91d5b0] border border-[rgba(225,237,223,0.25)] font-semibold shadow-sm'
                : 'text-[#d0c9bf] hover:text-[#f4f4ed]'
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
                ? 'bg-[rgba(215,229,212,0.2)] text-[#91d5b0] border border-[rgba(225,237,223,0.25)] font-semibold shadow-sm'
                : 'text-[#d0c9bf] hover:text-[#f4f4ed]'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>9-Agent Trace Replay</span>
          </button>
        </div>

        <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-[#d0c9bf]">
          <span className="w-2 h-2 rounded-full bg-[#91d5b0] animate-pulse" />
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
            <div className="flex items-center gap-2 text-xs font-mono text-[#91d5b0] mb-1">
              <Activity className="w-3.5 h-3.5" />
              <span>INCIDENT EXECUTION GRAPH & TIMELINE</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-[#f4f4ed]">Agent Pipeline Timeline Replay</h2>
            <p className="text-sm text-[#d0c9bf] mt-1">
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
