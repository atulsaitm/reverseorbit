import { AlertTriangle } from 'lucide-react';
import { useStore } from '../store';

const severityTone = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
  info: 'text-white/40',
};

export default function FindingsTab() {
  const findings = useStore((state) => state.findings);
  const selectedFinding = useStore((state) => state.selectedFinding);
  const selectFinding = useStore((state) => state.selectFinding);

  return (
    <div className="h-full overflow-auto p-6 dot-pattern">
      <div className="flex items-center gap-3 mb-5">
        <div className="w-8 h-8 rounded-xl bg-accent-rose/10 border border-accent-rose/20 flex items-center justify-center">
          <AlertTriangle className="w-4 h-4 text-accent-rose/70" />
        </div>
        <h2 className="text-base font-semibold text-white/85">Deterministic Findings</h2>
      </div>

      <div className="glass-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-[#0d0f12]/95 backdrop-blur-sm">
            <tr className="border-b border-white/[0.04]">
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider">Severity</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider">Category</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider">Title</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider">Confidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr
                key={finding.id}
                onClick={() => selectFinding(finding)}
                className={`border-b border-white/[0.03] cursor-pointer ${selectedFinding?.id === finding.id ? 'bg-accent-warm/[0.04]' : 'hover:bg-white/[0.02]'}`}
              >
                <td className={`py-3 px-4 text-[11px] uppercase font-medium ${severityTone[finding.severity] || 'text-white/40'}`}>{finding.severity}</td>
                <td className="py-3 px-4 text-[11px] text-white/40 mono">{finding.category}</td>
                <td className="py-3 px-4 text-[12px] text-white/75">{finding.title}</td>
                <td className="py-3 px-4 text-[11px] text-white/35 mono">{Math.round((finding.confidence || 0) * 100)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
        {findings.length === 0 && <div className="p-5 text-sm text-white/25">No findings yet.</div>}
      </div>
    </div>
  );
}

