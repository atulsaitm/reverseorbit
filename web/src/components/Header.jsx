import { Activity, Binary, Boxes, FileSearch, GitBranch, SearchCheck, Workflow } from 'lucide-react';
import { useStore } from '../store';

const tabs = [
  { id: 'overview', label: 'Overview', icon: Binary },
  { id: 'timeline', label: 'Timeline', icon: Activity },
  { id: 'graphs', label: 'Graphs', icon: GitBranch },
  { id: 'findings', label: 'Findings', icon: SearchCheck },
  { id: 'artifacts', label: 'Artifacts', icon: FileSearch },
  { id: 'exports', label: 'Exports', icon: Boxes },
];

export default function Header() {
  const activeTab = useStore((state) => state.activeTab);
  const setActiveTab = useStore((state) => state.setActiveTab);
  const runStatus = useStore((state) => state.runStatus);
  const currentCase = useStore((state) => state.currentCase);
  const guidedModeEnabled = useStore((state) => state.guidedModeEnabled);
  const autopilotEnabled = useStore((state) => state.autopilotEnabled);
  const autopilotInFlightActionId = useStore((state) => state.autopilotInFlightActionId);

  return (
    <header className="glass border-b border-white/[0.04] px-6 py-3 relative z-10">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-accent-warm/20 to-accent-ice/5 border border-accent-warm/20 flex items-center justify-center shadow-glow-warm">
            <Workflow className="w-5 h-5 text-accent-warm" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-[0.15em] text-white/90">REVERSEORBIT</h1>
            <p className="text-[10px] text-white/25 -mt-0.5 tracking-wider uppercase">
              Deterministic Reverse-Engineering Workbench
            </p>
          </div>
        </div>

        <nav className="flex items-center gap-1.5 overflow-x-auto scrollbar-hide">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`key-btn flex items-center gap-2 px-4 py-2 text-sm font-medium whitespace-nowrap ${
                activeTab === id ? 'key-active' : 'text-white/40 hover:text-white/70'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-2.5 min-w-[200px] justify-end">
          <div className="metal-badge px-3 py-1.5">
            <span className="text-[11px] text-white/40 uppercase tracking-wide">
              {guidedModeEnabled ? 'guided' : 'manual'}
            </span>
          </div>
          {autopilotEnabled && (
            <div className="metal-badge px-3 py-1.5">
              <span className="text-[11px] text-white/40 uppercase tracking-wide">
                {autopilotInFlightActionId ? 'autopilot running' : 'autopilot armed'}
              </span>
            </div>
          )}
          <div className="flex items-center gap-2 metal-badge px-3 py-1.5">
            <div className={`w-1.5 h-1.5 rounded-full ${
              runStatus === 'running' ? 'bg-accent-amber animate-pulse shadow-[0_0_6px_rgba(245,158,11,0.5)]' :
              runStatus === 'complete' ? 'bg-accent-sage shadow-[0_0_6px_rgba(156,175,136,0.4)]' :
              runStatus === 'error' ? 'bg-threat-critical shadow-[0_0_6px_rgba(239,68,68,0.4)]' :
              'bg-white/20'
            }`} />
            <span className="text-[11px] text-white/40 capitalize tracking-wide">{runStatus}</span>
          </div>
          {currentCase?.manifest?.label && (
            <div className="metal-badge px-3 py-1.5 text-[11px] text-white/35 max-w-[220px] truncate">
              {currentCase.manifest.label}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

