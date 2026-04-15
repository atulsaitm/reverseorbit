import { useMemo, useState } from "react";
import {
  Binary,
  Bot,
  GraduationCap,
  Play,
  RefreshCcw,
  Rocket,
  ScrollText,
} from "lucide-react";
import { analyzeCase, buildApiNotice, createCase, deleteCase } from "../api";
import { useStore } from "../store";

export default function OverviewTab({ onRefresh }) {
  const cases = useStore((state) => state.cases);
  const currentCaseId = useStore((state) => state.currentCaseId);
  const setCurrentCaseId = useStore((state) => state.setCurrentCaseId);
  const setActiveTab = useStore((state) => state.setActiveTab);
  const currentCase = useStore((state) => state.currentCase);
  const findings = useStore((state) => state.findings);
  const actions = useStore((state) => state.actions);
  const guidedModeEnabled = useStore((state) => state.guidedModeEnabled);
  const setGuidedModeEnabled = useStore((state) => state.setGuidedModeEnabled);
  const autopilotEnabled = useStore((state) => state.autopilotEnabled);
  const setAutopilotEnabled = useStore((state) => state.setAutopilotEnabled);
  const autopilotInFlightActionId = useStore(
    (state) => state.autopilotInFlightActionId,
  );
  const narrativeByCase = useStore((state) => state.narrativeByCase);
  const clearNarrativeForCase = useStore(
    (state) => state.clearNarrativeForCase,
  );
  const setSystemNotice = useStore((state) => state.setSystemNotice);
  const clearSystemNotice = useStore((state) => state.clearSystemNotice);

  const [targetPath, setTargetPath] = useState("/bin/ls");
  const [label, setLabel] = useState("");
  const [profile, setProfile] = useState("quick");
  const [loading, setLoading] = useState(false);

  const pendingActions = useMemo(
    () => actions.filter((action) => action.status === "pending"),
    [actions],
  );
  const liveNarrative = useMemo(() => {
    if (!currentCaseId) {
      return [];
    }
    return narrativeByCase[currentCaseId] || [];
  }, [currentCaseId, narrativeByCase]);

  const handleCreateAndAnalyze = async () => {
    if (!targetPath.trim()) return;
    setLoading(true);
    try {
      const { data } = await createCase({
        target_path: targetPath.trim(),
        label: label.trim() || null,
        profile,
      });
      const caseId = data.case?.manifest?.id || data.manifest?.id;
      if (!caseId) {
        throw new Error("Case creation response did not include a case id");
      }
      setCurrentCaseId(caseId);
      await analyzeCase(caseId, { profile });
      await onRefresh?.();
      clearSystemNotice("api");
    } catch (error) {
      console.error(error);
      const notice = buildApiNotice(error, "Failed to create and analyze case");
      setSystemNotice({
        source: "api",
        ...notice,
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-full overflow-auto p-6 dot-pattern">
      <div className="grid grid-cols-1 xl:grid-cols-[1.3fr_0.9fr] gap-6">
        <div className="space-y-6">
          <div className="glass-card p-5">
            <h2 className="text-base font-semibold text-white/85 flex items-center gap-2.5 mb-5">
              <div className="w-8 h-8 rounded-xl bg-accent-warm/10 border border-accent-warm/20 flex items-center justify-center">
                <Rocket className="w-4 h-4 text-accent-warm" />
              </div>
              Start ReverseOrbit Case
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-[1fr_200px_130px] gap-3">
              <input
                value={targetPath}
                onChange={(event) => setTargetPath(event.target.value)}
                placeholder="/path/to/binary"
                className="metal-input px-4 py-3 text-white/90 placeholder-white/20 mono text-sm"
              />
              <input
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                placeholder="Optional label"
                className="metal-input px-4 py-3 text-white/90 placeholder-white/20 text-sm"
              />
              <select
                value={profile}
                onChange={(event) => setProfile(event.target.value)}
                className="metal-input px-4 py-3 text-white/90 bg-transparent text-sm"
              >
                <option value="quick">Quick</option>
                <option value="full">Full</option>
              </select>
            </div>

            <div className="flex items-center gap-3 mt-4">
              <button
                onClick={handleCreateAndAnalyze}
                disabled={loading}
                className="btn-primary flex items-center gap-2 px-5 py-2.5 text-sm disabled:opacity-50"
              >
                {loading ? (
                  <RefreshCcw className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                {loading ? "Starting..." : "Create And Analyze"}
              </button>
              <p className="text-[11px] text-white/25">
                Uses radare2 baseline collection and builds timeline, findings,
                actions, and graphs.
              </p>
            </div>
          </div>

          <div className="glass-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-[13px] font-semibold text-white/75 flex items-center gap-2">
                <Binary className="w-4 h-4 text-accent-ice/60" />
                Local Cases
              </h3>
              <button
                onClick={() => onRefresh?.()}
                className="key-btn px-3 py-2 text-white/40 hover:text-white/70 text-xs"
              >
                Refresh
              </button>
            </div>
            <div className="space-y-2">
              {cases.map((entry) => (
                <CaseRow
                  key={entry.manifest.id}
                  entry={entry}
                  active={currentCaseId === entry.manifest.id}
                  onSelect={() => setCurrentCaseId(entry.manifest.id)}
                  onDelete={async () => {
                    if (
                      !window.confirm(
                        `Delete case "${entry.manifest.label}"? This cannot be undone.`,
                      )
                    )
                      return;
                    try {
                      await deleteCase(entry.manifest.id);
                      if (currentCaseId === entry.manifest.id)
                        setCurrentCaseId(null);
                      await onRefresh?.();
                    } catch (err) {
                      console.error("Delete failed:", err);
                      const notice = buildApiNotice(
                        err,
                        "Failed to delete case",
                      );
                      setSystemNotice({ source: "api", ...notice });
                    }
                  }}
                />
              ))}
              {cases.length === 0 && (
                <p className="text-sm text-white/25">No cases yet.</p>
              )}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="glass-card p-5">
            <h3 className="text-[13px] font-semibold text-white/75 mb-4">
              Current Case Snapshot
            </h3>
            {currentCase?.manifest ? (
              <div className="space-y-3 text-sm text-white/50">
                <p>
                  <span className="text-white/80">Label:</span>{" "}
                  {currentCase.manifest.label}
                </p>
                <p>
                  <span className="text-white/80">Target:</span>{" "}
                  <span className="mono break-all">
                    {currentCase.manifest.target_path}
                  </span>
                </p>
                <p>
                  <span className="text-white/80">Architecture:</span>{" "}
                  {currentCase.manifest.architecture || "Unknown"}
                </p>
                <p>
                  <span className="text-white/80">Format:</span>{" "}
                  {currentCase.manifest.binary_format || "Unknown"}
                </p>
                <div className="flex items-center gap-2 pt-2">
                  <button
                    onClick={() => setActiveTab("graphs")}
                    className="key-btn px-3 py-2 text-xs text-white/55 hover:text-accent-warm"
                  >
                    Open Graphs
                  </button>
                  <button
                    onClick={() => setActiveTab("timeline")}
                    className="key-btn px-3 py-2 text-xs text-white/55 hover:text-accent-warm"
                  >
                    Open Timeline
                  </button>
                </div>
              </div>
            ) : (
              <p className="text-sm text-white/25">
                Select a case to inspect it.
              </p>
            )}
          </div>

          <div className="glass-card p-5">
            <h3 className="text-[13px] font-semibold text-white/75 flex items-center gap-2 mb-4">
              <GraduationCap className="w-4 h-4 text-accent-ice/60" />
              Guided Session Controls
            </h3>
            <div className="space-y-2.5">
              <ToggleRow
                label="Guided mode"
                description="Shows a live reverse-engineering narrative and teaching context for each finding."
                enabled={guidedModeEnabled}
                onChange={setGuidedModeEnabled}
              />
              <ToggleRow
                label="Autopilot"
                description="Automatically executes the next pending action when analysis is complete."
                enabled={autopilotEnabled}
                onChange={setAutopilotEnabled}
                disabled={!currentCaseId}
              />
            </div>
            {(autopilotEnabled || autopilotInFlightActionId) && (
              <p className="text-[11px] text-white/35 mt-3">
                {autopilotInFlightActionId
                  ? `Autopilot running action: ${autopilotInFlightActionId}`
                  : pendingActions.length > 0
                    ? `Autopilot armed with ${pendingActions.length} pending actions.`
                    : "Autopilot is enabled and waiting for pending actions."}
              </p>
            )}
            {currentCaseId && (
              <button
                type="button"
                onClick={() => clearNarrativeForCase(currentCaseId)}
                className="key-btn px-3 py-2 text-white/45 hover:text-white/70 text-xs mt-3"
              >
                Clear Story Feed
              </button>
            )}
          </div>

          <div className="glass-card p-5">
            <h3 className="text-[13px] font-semibold text-white/75 flex items-center gap-2 mb-4">
              <ScrollText className="w-4 h-4 text-accent-warm/70" />
              Live Story Feed
            </h3>
            {guidedModeEnabled ? (
              <div className="space-y-2 max-h-[260px] overflow-auto pr-1">
                {liveNarrative.slice(0, 10).map((entry) => (
                  <div
                    key={entry.id}
                    className={`glass-sm p-3 rounded-xl border ${storyToneClass(entry)}`}
                  >
                    <p className="text-[11px] text-white/75 uppercase tracking-wide">
                      {storyTitle(entry)}
                    </p>
                    <p className="text-[11px] text-white/40 mt-1">
                      {storyDetail(entry)}
                    </p>
                    {entry.teachingSummary && (
                      <p className="text-[11px] text-accent-ice/70 mt-2">
                        {entry.teachingSummary}
                      </p>
                    )}
                  </div>
                ))}
                {liveNarrative.length === 0 && (
                  <p className="text-sm text-white/25">
                    Run analysis or actions to build a live reverse-engineering
                    story.
                  </p>
                )}
              </div>
            ) : (
              <p className="text-sm text-white/25">
                Enable guided mode to see live teaching events and reasoning
                context.
              </p>
            )}
          </div>

          <div className="glass-card p-5">
            <h3 className="text-[13px] font-semibold text-white/75 flex items-center gap-2 mb-4">
              <Bot className="w-4 h-4 text-accent-rose/60" />
              Findings & Pivots
            </h3>
            <div className="grid grid-cols-2 gap-4 mb-4">
              <Stat value={findings.length} label="Findings" />
              <Stat value={pendingActions.length} label="Pending Actions" />
            </div>
            <div className="space-y-2">
              {pendingActions.slice(0, 5).map((action) => (
                <div
                  key={action.id}
                  className="glass-sm p-3 rounded-xl border border-white/[0.04]"
                >
                  <p className="text-[12px] text-white/75 font-medium">
                    {action.title}
                  </p>
                  <p className="text-[11px] text-white/30 mt-1">{action.why}</p>
                </div>
              ))}
              {pendingActions.length === 0 && (
                <p className="text-sm text-white/25">No pending pivots yet.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Stat({ value, label }) {
  return (
    <div className="glass-sm rounded-xl p-4 border border-white/[0.04]">
      <p className="text-2xl font-bold text-white/85 mono">{value}</p>
      <p className="text-[11px] text-white/25 mt-1 uppercase tracking-wide">
        {label}
      </p>
    </div>
  );
}

function ToggleRow({
  label,
  description,
  enabled,
  onChange,
  disabled = false,
}) {
  return (
    <label
      className={`flex items-start justify-between gap-3 rounded-xl border border-white/[0.04] bg-white/[0.01] px-3 py-2 ${disabled ? "opacity-60" : "cursor-pointer"}`}
    >
      <div>
        <p className="text-[12px] text-white/75 font-medium">{label}</p>
        <p className="text-[11px] text-white/30 mt-0.5">{description}</p>
      </div>
      <input
        type="checkbox"
        checked={enabled}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-1 h-4 w-4 accent-[#f0a13f]"
      />
    </label>
  );
}

function storyTitle(entry) {
  if (entry.event === "status_changed") {
    return "Status";
  }
  if (entry.event === "step_complete") {
    return "Step Complete";
  }
  if (entry.event === "finding_created") {
    return "Finding Created";
  }
  if (entry.event === "graph_updated") {
    return "Graph Updated";
  }
  if (entry.event === "action_recommended") {
    return "Action Running";
  }
  return entry.event || "Event";
}

function storyDetail(entry) {
  const fragments = [];
  if (entry.message) {
    fragments.push(entry.message);
  }
  if (entry.error) {
    fragments.push(entry.error);
  }
  if (typeof entry.progress === "number") {
    fragments.push(`${Math.round(entry.progress * 100)}%`);
  }
  if (entry.nextActionIds?.length > 0) {
    fragments.push(`${entry.nextActionIds.length} suggested actions`);
  }
  if (fragments.length === 0) {
    return "Live event received";
  }
  return fragments.join(" | ");
}

function storyToneClass(entry) {
  if (entry.status === "failed" || entry.error) {
    return "border-red-400/25";
  }
  if (entry.event === "finding_created") {
    return "border-accent-rose/25";
  }
  if (entry.event === "step_complete") {
    return "border-accent-sage/25";
  }
  return "border-white/[0.04]";
}

function CaseRow({ entry, active, onSelect, onDelete }) {
  return (
    <div
      className={`glass-card flex items-stretch ${active ? "border-accent-warm/25 bg-accent-warm/[0.03]" : ""}`}
    >
      {/* main clickable area */}
      <button onClick={onSelect} className="flex-1 text-left p-3 min-w-0">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="text-sm text-white/80 font-medium truncate">
              {entry.manifest.label}
            </p>
            <p className="text-[11px] text-white/25 truncate mono">
              {entry.manifest.target_path}
            </p>
          </div>
          <span className="metal-badge px-2.5 py-1 text-[10px] text-white/35 uppercase flex-shrink-0">
            {entry.manifest.status}
          </span>
        </div>
        <div className="flex items-center gap-3 mt-2 text-[11px] text-white/25">
          <span>{entry.findings_count} findings</span>
          <span>{entry.actions_count} actions</span>
          <span>{entry.timeline_count} steps</span>
        </div>
      </button>

      {/* delete button — sits on the right, only visible on hover */}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onDelete();
        }}
        title="Delete case"
        className="flex-shrink-0 w-9 flex items-center justify-center border-l border-white/[0.04] text-white/20 hover:text-red-400/80 hover:bg-red-500/[0.05] rounded-r-2xl transition-colors duration-150"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="3 6 5 6 21 6" />
          <path d="M19 6l-1 14H6L5 6" />
          <path d="M10 11v6M14 11v6" />
          <path d="M9 6V4h6v2" />
        </svg>
      </button>
    </div>
  );
}
