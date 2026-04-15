import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import {
  ChevronLeft,
  ChevronRight,
  Code2,
  Database,
  FileWarning,
  GitBranch,
  Play,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import { buildApiNotice, explainFinding, getArtifact, runAction } from "../api";
import { useStore } from "../store";

export default function InspectorPanel({ collapsed, onToggle }) {
  const currentCaseId = useStore((state) => state.currentCaseId);
  const currentCase = useStore((state) => state.currentCase);
  const actions = useStore((state) => state.actions);
  const selectedStep = useStore((state) => state.selectedStep);
  const selectedFinding = useStore((state) => state.selectedFinding);
  const selectedArtifact = useStore((state) => state.selectedArtifact);
  const selectedArtifactPayload = useStore(
    (state) => state.selectedArtifactPayload,
  );
  const selectedGraphNode = useStore((state) => state.selectedGraphNode);
  const selectedGraphEdge = useStore((state) => state.selectedGraphEdge);
  const guidedModeEnabled = useStore((state) => state.guidedModeEnabled);
  const selectArtifact = useStore((state) => state.selectArtifact);
  const setSystemNotice = useStore((state) => state.setSystemNotice);
  const clearSystemNotice = useStore((state) => state.clearSystemNotice);
  const [runningActionId, setRunningActionId] = useState(null);
  const [findingExplanation, setFindingExplanation] = useState(null);
  const [explanationLoading, setExplanationLoading] = useState(false);

  useEffect(() => {
    if (!currentCaseId || !selectedFinding?.id) {
      setFindingExplanation(null);
      return;
    }

    let cancelled = false;
    setExplanationLoading(true);
    explainFinding(currentCaseId, selectedFinding.id)
      .then(({ data }) => {
        if (cancelled) {
          return;
        }
        setFindingExplanation(data || null);
        clearSystemNotice("api");
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setFindingExplanation(null);
        const notice = buildApiNotice(
          error,
          `Failed to explain finding ${selectedFinding.title}`,
        );
        setSystemNotice({
          source: "api",
          ...notice,
        });
      })
      .finally(() => {
        if (!cancelled) {
          setExplanationLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [clearSystemNotice, currentCaseId, selectedFinding, setSystemNotice]);

  const runPendingAction = async (actionId) => {
    if (!currentCaseId) return;
    setRunningActionId(actionId);
    try {
      await runAction(currentCaseId, actionId);
    } finally {
      setRunningActionId(null);
    }
  };

  const openArtifact = async (artifactId) => {
    if (!currentCaseId) return;
    const { data } = await getArtifact(currentCaseId, artifactId);
    selectArtifact(data.artifact, data);
  };

  const content = (() => {
    if (selectedFinding) {
      const relatedActions =
        findingExplanation?.related_actions ||
        actions.filter((action) =>
          selectedFinding.next_action_ids?.includes(action.id),
        );

      return (
        <Panel
          title={selectedFinding.title}
          icon={<ShieldAlert className="w-4 h-4 text-accent-warm" />}
        >
          <Meta label="Severity" value={selectedFinding.severity} />
          <Meta label="Category" value={selectedFinding.category} />
          <Meta
            label="Confidence"
            value={`${Math.round((selectedFinding.confidence || 0) * 100)}%`}
          />
          <MarkdownBlock label="Summary" text={selectedFinding.summary} />
          <MarkdownBlock label="Rationale" text={selectedFinding.rationale} />
          {guidedModeEnabled && (
            <MarkdownBlock
              label="Teaching Summary"
              text={
                findingExplanation?.teaching_summary || selectedFinding.summary
              }
            />
          )}
          {guidedModeEnabled && explanationLoading && (
            <p className="text-[11px] text-white/30">
              Building explanation context...
            </p>
          )}
          {guidedModeEnabled && selectedFinding.inference_chain?.length > 0 && (
            <div className="space-y-2">
              <p className="text-[11px] uppercase tracking-wide text-white/25">
                Inference Chain
              </p>
              {selectedFinding.inference_chain.map((item, index) => (
                <div
                  key={`${selectedFinding.id}-inference-${index}`}
                  className="glass-sm p-3 rounded-xl border border-white/[0.04]"
                >
                  <p className="text-[11px] text-white/35">
                    Premise: {item.premise}
                  </p>
                  <p className="text-[12px] text-white/65 mt-1">
                    Conclusion: {item.conclusion}
                  </p>
                  <p className="text-[10px] text-white/30 mt-1">
                    Confidence contribution:{" "}
                    {Math.round((item.confidence_contribution || 0) * 100)}%
                  </p>
                </div>
              ))}
            </div>
          )}
          {guidedModeEnabled &&
            selectedFinding.counter_evidence?.length > 0 && (
              <div className="space-y-2">
                <p className="text-[11px] uppercase tracking-wide text-white/25">
                  Counter Evidence
                </p>
                {selectedFinding.counter_evidence.map((item, index) => (
                  <div
                    key={`${selectedFinding.id}-counter-${index}`}
                    className="glass-sm p-3 rounded-xl border border-white/[0.04]"
                  >
                    <p className="text-[12px] text-white/55">{item}</p>
                  </div>
                ))}
              </div>
            )}
          {selectedFinding.evidence?.map((item, index) => (
            <div
              key={index}
              className="glass-sm p-3 rounded-xl border border-white/[0.04]"
            >
              <p className="text-[11px] uppercase tracking-wide text-white/25 mb-1">
                {item.label}
              </p>
              <p className="text-[12px] text-white/55 break-all">
                {item.snippet || item.entity_id || "No snippet"}
              </p>
            </div>
          ))}
          {relatedActions.length > 0 && (
            <div className="space-y-2">
              <p className="text-[11px] uppercase tracking-wide text-white/25">
                Next Actions
              </p>
              {relatedActions.map((action) => (
                <button
                  key={action.id}
                  onClick={() => runPendingAction(action.id)}
                  className="w-full text-left glass-card p-3"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-[12px] text-white/75 font-medium">
                        {action.title}
                      </p>
                      <p className="text-[11px] text-white/25 mt-1">
                        {action.why}
                      </p>
                    </div>
                    <span className="metal-badge px-2 py-1 text-[10px] text-white/35">
                      {runningActionId === action.id
                        ? "Running"
                        : action.status}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </Panel>
      );
    }

    if (selectedStep) {
      return (
        <Panel
          title={selectedStep.title}
          icon={<Workflow className="w-4 h-4 text-accent-ice" />}
        >
          <MarkdownBlock label="Why" text={selectedStep.why} />
          <MarkdownBlock label="How" text={selectedStep.how} />
          <MarkdownBlock label="Result" text={selectedStep.result_summary} />
          {selectedStep.artifact_ids?.length > 0 && (
            <div className="space-y-2">
              <p className="text-[11px] uppercase tracking-wide text-white/25">
                Artifacts
              </p>
              {selectedStep.artifact_ids.map((artifactId) => (
                <button
                  key={artifactId}
                  onClick={() => openArtifact(artifactId)}
                  className="key-btn px-3 py-2 text-left text-[12px] text-white/55 w-full"
                >
                  {artifactId}
                </button>
              ))}
            </div>
          )}
        </Panel>
      );
    }

    if (selectedArtifact && selectedArtifactPayload) {
      return (
        <Panel
          title={selectedArtifact.label}
          icon={<Database className="w-4 h-4 text-accent-sage" />}
        >
          <Meta label="Kind" value={selectedArtifact.kind} />
          <Meta label="Summary" value={selectedArtifact.summary} />
          <JsonBlock
            label="Normalized"
            value={selectedArtifactPayload.normalized}
          />
          {selectedArtifactPayload.raw && (
            <JsonBlock label="Raw" value={selectedArtifactPayload.raw} />
          )}
        </Panel>
      );
    }

    if (selectedGraphNode) {
      return (
        <Panel
          title={selectedGraphNode.label}
          icon={<GitBranch className="w-4 h-4 text-accent-rose" />}
        >
          <Meta label="Kind" value={selectedGraphNode.kind} />
          <Meta label="Group" value={selectedGraphNode.group} />
          <MarkdownBlock label="Summary" text={selectedGraphNode.summary} />
          <JsonBlock label="Metadata" value={selectedGraphNode.metadata} />
        </Panel>
      );
    }

    if (selectedGraphEdge) {
      return (
        <Panel
          title={selectedGraphEdge.label}
          icon={<Code2 className="w-4 h-4 text-accent-amber" />}
        >
          <Meta label="Source" value={selectedGraphEdge.source} />
          <Meta label="Target" value={selectedGraphEdge.target} />
          <Meta label="Kind" value={selectedGraphEdge.kind} />
        </Panel>
      );
    }

    return (
      <Panel
        title="Analyst Inspector"
        icon={<FileWarning className="w-4 h-4 text-white/50" />}
      >
        {currentCase?.manifest ? (
          <>
            <Meta label="Case" value={currentCase.manifest.label} />
            <Meta
              label="Target"
              value={currentCase.manifest.target_path}
              mono
            />
            <Meta label="Status" value={currentCase.manifest.status} />
            <Meta
              label="Architecture"
              value={currentCase.manifest.architecture || "Unknown"}
            />
            <Meta
              label="Format"
              value={currentCase.manifest.binary_format || "Unknown"}
            />
            <div className="warm-divider" />
            <p className="text-[11px] uppercase tracking-wide text-white/25">
              Pending Actions
            </p>
            <div className="space-y-2">
              {actions
                .filter((action) => action.status === "pending")
                .slice(0, 6)
                .map((action) => (
                  <button
                    key={action.id}
                    onClick={() => runPendingAction(action.id)}
                    className="w-full text-left glass-card p-3"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <p className="text-[12px] text-white/75 font-medium">
                          {action.title}
                        </p>
                        <p className="text-[11px] text-white/25 mt-1">
                          {action.why}
                        </p>
                      </div>
                      <Play className="w-4 h-4 text-accent-warm/70" />
                    </div>
                  </button>
                ))}
            </div>
          </>
        ) : (
          <p className="text-sm text-white/25">
            Select a case and click a timeline step, finding, artifact, or graph
            node.
          </p>
        )}
      </Panel>
    );
  })();

  if (collapsed) {
    return (
      <aside className="w-9 flex-shrink-0 border-l border-white/[0.04] glass flex flex-col items-center py-3 gap-2">
        <button
          onClick={onToggle}
          title="Expand inspector"
          className="w-7 h-7 rounded-lg glass-sm border border-white/[0.06] flex items-center justify-center text-white/35 hover:text-white/70 hover:border-white/[0.12] transition-all duration-150"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </button>
        <div
          className="flex-1 flex items-center justify-center"
          style={{ writingMode: "vertical-rl", textOrientation: "mixed" }}
        >
          <span className="text-[10px] text-white/20 uppercase tracking-widest select-none rotate-180">
            Inspector
          </span>
        </div>
      </aside>
    );
  }

  return (
    <aside className="w-[380px] flex-shrink-0 border-l border-white/[0.04] glass overflow-y-auto min-h-0 relative">
      {/* collapse button */}
      <button
        onClick={onToggle}
        title="Collapse inspector"
        className="absolute top-3 right-3 z-10 w-6 h-6 rounded-md glass-sm border border-white/[0.06] flex items-center justify-center text-white/30 hover:text-white/65 hover:border-white/[0.12] transition-all duration-150"
      >
        <ChevronRight className="w-3 h-3" />
      </button>
      {content}
    </aside>
  );
}

function Panel({ title, icon, children }) {
  return (
    <div className="p-5 space-y-4">
      <div className="flex items-center gap-2">
        <div className="w-7 h-7 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center">
          {icon}
        </div>
        <h3 className="text-sm font-semibold text-white/80">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function Meta({ label, value, mono = false }) {
  return (
    <div>
      <p className="text-[10px] text-white/25 uppercase tracking-wide mb-1">
        {label}
      </p>
      <p
        className={`text-[12px] text-white/60 ${mono ? "mono break-all" : ""}`}
      >
        {value}
      </p>
    </div>
  );
}

function MarkdownBlock({ label, text }) {
  return (
    <div>
      <p className="text-[10px] text-white/25 uppercase tracking-wide mb-1">
        {label}
      </p>
      <div className="prose prose-invert prose-sm max-w-none prose-p:text-white/55 prose-p:my-1 prose-strong:text-accent-warm/80 prose-code:text-accent-warm/70 prose-code:bg-black/30 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-pre:bg-black/40 prose-pre:border prose-pre:border-white/[0.06] prose-pre:rounded-lg prose-pre:text-[11px] prose-pre:p-3">
        <ReactMarkdown>{text || ""}</ReactMarkdown>
      </div>
    </div>
  );
}

function JsonBlock({ label, value }) {
  return (
    <div>
      <p className="text-[10px] text-white/25 uppercase tracking-wide mb-1">
        {label}
      </p>
      <pre className="text-[11px] text-white/60 mono bg-black/30 p-3 rounded-xl border border-white/[0.04] overflow-auto max-h-[280px]">
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  );
}
