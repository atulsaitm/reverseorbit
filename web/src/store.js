import { create } from "zustand";

const NOTICE_KINDS = new Set([
  "bad_request",
  "not_found",
  "timeout",
  "internal",
  "network",
]);
const NOTICE_DEDUPE_WINDOW_MS = 4000;
const NARRATIVE_MAX_EVENTS = 120;

function normalizeNoticeKind(kind) {
  if (typeof kind !== "string") {
    return null;
  }
  const normalized = kind.trim().toLowerCase();
  return NOTICE_KINDS.has(normalized) ? normalized : null;
}

function normalizeNoticeLevel(level, kind) {
  if (level === "warn" || level === "error") {
    return level;
  }
  if (kind === "bad_request" || kind === "not_found") {
    return "warn";
  }
  return "error";
}

function normalizeNarrativeEvent(event) {
  if (!event || typeof event !== "object") {
    return null;
  }

  const caseId = typeof event.case_id === "string" ? event.case_id : null;
  if (!caseId) {
    return null;
  }

  const payload =
    event.payload && typeof event.payload === "object" ? event.payload : {};
  const timestamp = Date.now();
  const eventName = typeof event.event === "string" ? event.event : "progress";
  const message = typeof event.message === "string" ? event.message : "";
  const status = typeof payload.status === "string" ? payload.status : null;
  const error = typeof payload.error === "string" ? payload.error : null;
  const errorKind = normalizeNoticeKind(payload.error_kind);
  const teachingSummary =
    typeof event.teaching_summary === "string"
      ? event.teaching_summary
      : typeof payload.teaching_summary === "string"
        ? payload.teaching_summary
        : null;
  const nextActionIds = Array.isArray(payload.next_action_ids)
    ? payload.next_action_ids.filter((value) => typeof value === "string")
    : [];

  return {
    id: `${caseId}:${eventName}:${timestamp}:${Math.random().toString(16).slice(2, 8)}`,
    caseId,
    event: eventName,
    message,
    status,
    progress: typeof event.progress === "number" ? event.progress : null,
    timestamp,
    teachingSummary,
    nextActionIds,
    error,
    errorKind,
  };
}

export const useStore = create((set, get) => ({
  activeTab: "overview",
  setActiveTab: (tab) => set({ activeTab: tab }),

  cases: [],
  currentCaseId: null,
  currentCase: null,
  timeline: [],
  findings: [],
  actions: [],
  artifacts: [],
  exports: [],
  graphs: {},
  currentGraphView: "provenance",

  runStatus: "idle",
  runProgress: 0,
  runMessage: "",
  runEvent: "",
  wsConnectionState: "connecting",
  systemNotice: null,
  refreshSignal: 0,
  guidedModeEnabled: true,
  autopilotEnabled: false,
  autopilotInFlightActionId: null,
  narrativeByCase: {},

  selectedStep: null,
  selectedFinding: null,
  selectedArtifact: null,
  selectedArtifactPayload: null,
  selectedGraphNode: null,
  selectedGraphEdge: null,

  setCases: (cases) => set({ cases }),
  setCurrentCase: (payload) => {
    const caseEnvelope = payload?.case || null;
    const currentCase = caseEnvelope
      ? {
          manifest: caseEnvelope.manifest,
          counts: caseEnvelope.counts || null,
        }
      : payload.summary || payload.manifest || payload;

    set({
      currentCase,
      findings: caseEnvelope?.findings || payload.findings || get().findings,
      actions: caseEnvelope?.actions || payload.actions || get().actions,
      artifacts:
        caseEnvelope?.artifacts || payload.artifacts || get().artifacts,
    });
  },
  setCurrentCaseId: (caseId) => set({ currentCaseId: caseId }),
  setTimeline: (timeline) => set({ timeline }),
  setFindings: (findings) => set({ findings }),

  setExports: (exports) => set({ exports }),
  setGraph: (view, graph) =>
    set((state) => ({
      graphs: { ...state.graphs, [view]: graph },
    })),
  setCurrentGraphView: (view) => set({ currentGraphView: view }),
  setWsConnectionState: (connectionState) =>
    set({ wsConnectionState: connectionState }),
  requestDataRefresh: () =>
    set((state) => ({ refreshSignal: state.refreshSignal + 1 })),
  setGuidedModeEnabled: (enabled) => set({ guidedModeEnabled: !!enabled }),
  setAutopilotEnabled: (enabled) => set({ autopilotEnabled: !!enabled }),
  setAutopilotInFlightActionId: (actionId) =>
    set({ autopilotInFlightActionId: actionId || null }),
  appendNarrativeEvent: (event) => {
    const normalized = normalizeNarrativeEvent(event);
    if (!normalized) {
      return;
    }

    set((state) => {
      const current = state.narrativeByCase[normalized.caseId] || [];
      const previous = current[0];
      if (
        previous &&
        previous.event === normalized.event &&
        previous.message === normalized.message &&
        normalized.timestamp - previous.timestamp < 1200
      ) {
        return {};
      }

      return {
        narrativeByCase: {
          ...state.narrativeByCase,
          [normalized.caseId]: [normalized, ...current].slice(
            0,
            NARRATIVE_MAX_EVENTS,
          ),
        },
      };
    });
  },
  clearNarrativeForCase: (caseId) =>
    set((state) => {
      if (!caseId || !state.narrativeByCase[caseId]) {
        return {};
      }
      const next = { ...state.narrativeByCase };
      delete next[caseId];
      return { narrativeByCase: next };
    }),
  setSystemNotice: (notice) => {
    if (!notice || !notice.message) {
      return;
    }
    const normalizedKind = normalizeNoticeKind(notice.kind);
    const source = notice.source || "app";
    const level = normalizeNoticeLevel(notice.level, normalizedKind);
    const message = notice.message;

    set((state) => {
      const existing = state.systemNotice;
      const now = Date.now();
      if (
        existing &&
        existing.source === source &&
        existing.level === level &&
        existing.kind === normalizedKind &&
        existing.message === message &&
        now - existing.timestamp < NOTICE_DEDUPE_WINDOW_MS
      ) {
        return {};
      }

      return {
        systemNotice: {
          source,
          level,
          kind: normalizedKind,
          message,
          timestamp: now,
        },
      };
    });
  },
  clearSystemNotice: (source) =>
    set((state) => {
      if (!state.systemNotice) {
        return {};
      }
      if (source && state.systemNotice.source !== source) {
        return {};
      }
      return { systemNotice: null };
    }),

  selectStep: (step) =>
    set({
      selectedStep: step,
      selectedFinding: null,
      selectedArtifact: null,
      selectedArtifactPayload: null,
      selectedGraphNode: null,
      selectedGraphEdge: null,
    }),
  selectFinding: (finding) =>
    set({
      selectedFinding: finding,
      selectedStep: null,
      selectedArtifact: null,
      selectedArtifactPayload: null,
      selectedGraphNode: null,
      selectedGraphEdge: null,
    }),
  selectArtifact: (artifact, payload = null) =>
    set({
      selectedArtifact: artifact,
      selectedArtifactPayload: payload,
      selectedStep: null,
      selectedFinding: null,
      selectedGraphNode: null,
      selectedGraphEdge: null,
    }),
  selectGraphNode: (node) =>
    set({
      selectedGraphNode: node,
      selectedGraphEdge: null,
      selectedStep: null,
      selectedFinding: null,
    }),
  selectGraphEdge: (edge) =>
    set({
      selectedGraphEdge: edge,
      selectedGraphNode: null,
      selectedStep: null,
      selectedFinding: null,
    }),

  updateRunState: (event) => {
    const currentCaseId = get().currentCaseId;
    if (currentCaseId && event.case_id && event.case_id !== currentCaseId) {
      return;
    }

    let runStatus = get().runStatus;
    if (event?.payload?.status === "failed") {
      runStatus = "error";
    } else if (event.event === "status_changed") {
      const reportedStatus = event.payload?.status;
      if (reportedStatus === "complete") {
        runStatus = "complete";
      } else if (reportedStatus === "failed") {
        runStatus = "error";
      } else {
        runStatus = "running";
      }
    } else if (event.event) {
      runStatus = "running";
    }

    set({
      runStatus,
      runProgress: event.progress || 0,
      runMessage: event.message || "",
      runEvent: event.event || "",
    });
  },
  resetSelections: () =>
    set({
      selectedStep: null,
      selectedFinding: null,
      selectedArtifact: null,
      selectedArtifactPayload: null,
      selectedGraphNode: null,
      selectedGraphEdge: null,
    }),
}));
