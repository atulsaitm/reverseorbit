import { useState } from 'react';
import { Database } from 'lucide-react';
import { getArtifact } from '../api';
import { useStore } from '../store';

export default function ArtifactsTab() {
  const artifacts = useStore((state) => state.artifacts);
  const currentCaseId = useStore((state) => state.currentCaseId);
  const selectedArtifact = useStore((state) => state.selectedArtifact);
  const selectArtifact = useStore((state) => state.selectArtifact);
  const [loadingId, setLoadingId] = useState(null);

  const handleSelect = async (artifact) => {
    selectArtifact(artifact, null);
    if (!currentCaseId) return;
    setLoadingId(artifact.id);
    try {
      const { data } = await getArtifact(currentCaseId, artifact.id);
      selectArtifact(artifact, data);
    } finally {
      setLoadingId(null);
    }
  };

  return (
    <div className="h-full overflow-auto p-6 dot-pattern">
      <div className="flex items-center gap-3 mb-5">
        <div className="w-8 h-8 rounded-xl bg-accent-sage/10 border border-accent-sage/20 flex items-center justify-center">
          <Database className="w-4 h-4 text-accent-sage/70" />
        </div>
        <h2 className="text-base font-semibold text-white/85">Stored Artifacts</h2>
      </div>

      <div className="space-y-3">
        {artifacts.map((artifact) => (
          <button
            key={artifact.id}
            onClick={() => handleSelect(artifact)}
            className={`w-full text-left glass-card p-4 ${selectedArtifact?.id === artifact.id ? 'border-accent-warm/25 bg-accent-warm/[0.03]' : ''}`}
          >
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm text-white/80 font-medium">{artifact.label}</p>
                <p className="text-[11px] text-white/25 mt-1">{artifact.summary}</p>
              </div>
              <span className="metal-badge px-2.5 py-1 text-[10px] text-white/35 uppercase">
                {loadingId === artifact.id ? 'Loading' : artifact.kind}
              </span>
            </div>
          </button>
        ))}
        {artifacts.length === 0 && <p className="text-sm text-white/25">No artifacts yet.</p>}
      </div>
    </div>
  );
}

