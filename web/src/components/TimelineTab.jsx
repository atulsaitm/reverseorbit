import { Clock3 } from 'lucide-react';
import { useStore } from '../store';

export default function TimelineTab() {
  const timeline = useStore((state) => state.timeline);
  const selectedStep = useStore((state) => state.selectedStep);
  const selectStep = useStore((state) => state.selectStep);

  return (
    <div className="h-full overflow-auto p-6 dot-pattern">
      <div className="flex items-center gap-3 mb-5">
        <div className="w-8 h-8 rounded-xl bg-accent-ice/10 border border-accent-ice/20 flex items-center justify-center">
          <Clock3 className="w-4 h-4 text-accent-ice/70" />
        </div>
        <h2 className="text-base font-semibold text-white/85">Reverse Engineering Timeline</h2>
      </div>

      <div className="space-y-3">
        {timeline.map((step, index) => (
          <button
            key={step.id}
            onClick={() => selectStep(step)}
            className={`w-full text-left glass-card p-4 ${selectedStep?.id === step.id ? 'border-accent-warm/25 bg-accent-warm/[0.03]' : ''}`}
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-[11px] text-accent-warm/60 uppercase tracking-wide mb-1">Step {index + 1}</p>
                <h3 className="text-sm text-white/85 font-medium">{step.title}</h3>
                <p className="text-[12px] text-white/35 mt-2">{step.result_summary}</p>
              </div>
              <span className="metal-badge px-2.5 py-1 text-[10px] text-white/30 uppercase">{step.tool}</span>
            </div>
          </button>
        ))}
        {timeline.length === 0 && <p className="text-sm text-white/25">Run a case to populate the timeline.</p>}
      </div>
    </div>
  );
}

