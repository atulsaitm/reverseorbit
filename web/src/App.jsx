import { useEffect, useState } from "react";
import {
  buildApiNotice,
  connectWebSocket,
  getCase,
  getFindings,
  getGraph,
  getTimeline,
  listCases,
  runAction,
} from "./api";
import { useStore } from "./store";
import Header from "./components/Header.jsx";
import OverviewTab from "./components/OverviewTab.jsx";
import TimelineTab from "./components/TimelineTab.jsx";
import GraphsTab from "./components/GraphsTab.jsx";
import FindingsTab from "./components/FindingsTab.jsx";
import ArtifactsTab from "./components/ArtifactsTab.jsx";
import ExportsTab from "./components/ExportsTab.jsx";
import InspectorPanel from "./components/InspectorPanel.jsx";
import StatusBar from "./components/StatusBar.jsx";

export default function App() {
  const activeTab = useStore((state) => state.activeTab);
  const currentCaseId = useStore((state) => state.currentCaseId);
  const currentCase = useStore((state) => state.currentCase);
  const currentGraphView = useStore((state) => state.currentGraphView);
  const actions = useStore((state) => state.actions);
  const setCases = useStore((state) => state.setCases);
  const setCurrentCase = useStore((state) => state.setCurrentCase);
  const setTimeline = useStore((state) => state.setTimeline);
  const setFindings = useStore((state) => state.setFindings);
  const setGraph = useStore((state) => state.setGraph);
  const refreshSignal = useStore((state) => state.refreshSignal);
  const requestDataRefresh = useStore((state) => state.requestDataRefresh);
  const autopilotEnabled = useStore((state) => state.autopilotEnabled);
  const autopilotInFlightActionId = useStore(
    (state) => state.autopilotInFlightActionId,
  );
  const setAutopilotInFlightActionId = useStore(
    (state) => state.setAutopilotInFlightActionId,
  );
  const updateRunState = useStore((state) => state.updateRunState);
  const setSystemNotice = useStore((state) => state.setSystemNotice);
  const clearSystemNotice = useStore((state) => state.clearSystemNotice);
  const setWsConnectionState = useStore((state) => state.setWsConnectionState);
  const [inspectorCollapsed, setInspectorCollapsed] = useState(false);

  useEffect(() => {
    refreshCases(setCases, { setSystemNotice, clearSystemNotice });
    const ws = connectWebSocket(
      async (event) => {
        updateRunState(event);
        const storeState = useStore.getState();
        if (storeState.guidedModeEnabled) {
          storeState.appendNarrativeEvent(event);
        }
        const failureNotice = buildWsFailureNotice(event);
        if (failureNotice) {
          setSystemNotice(failureNotice);
        }
        if (!event.case_id) return;
        if (
          event.event === "step_complete" ||
          event.event === "finding_created" ||
          event.event === "graph_updated" ||
          event.event === "status_changed"
        ) {
          const latestGraphView = useStore.getState().currentGraphView;
          await refreshCase(
            event.case_id,
            { setCurrentCase, setTimeline, setFindings, setGraph },
            latestGraphView,
            { setSystemNotice, clearSystemNotice },
          );
          await refreshCases(setCases, { setSystemNotice, clearSystemNotice });
        }
      },
      {
        onStatus: (status, details) => {
          setWsConnectionState(status);
          if (status === "open" || status === "closed") {
            clearSystemNotice("ws");
            return;
          }
          if (status === "reconnecting") {
            setSystemNotice({
              source: "ws",
              level: "warn",
              message: `Realtime updates disconnected. Reconnecting (${details.retryAttempt}/${details.maxRetries})...`,
            });
            return;
          }
          if (status === "failed") {
            setSystemNotice({
              source: "ws",
              level: "error",
              message:
                "Realtime updates are unavailable after repeated reconnect attempts.",
            });
          }
        },
        onError: (error) => {
          setSystemNotice({
            source: "ws",
            level: "error",
            message:
              error?.message || "Realtime connection encountered an error.",
          });
        },
      },
    );
    return () => {
      ws?.close();
      setWsConnectionState("closed");
    };
  }, []);

  // Full reload when the active case changes.
  useEffect(() => {
    if (!currentCaseId) return;
    refreshCase(
      currentCaseId,
      { setCurrentCase, setTimeline, setFindings, setGraph },
      currentGraphView,
      { setSystemNotice, clearSystemNotice },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentCaseId]);

  // Graph-only reload when the view tab changes — no need to re-fetch the
  // full case / timeline / findings again.
  useEffect(() => {
    if (!currentCaseId) return;
    refreshGraph(currentCaseId, currentGraphView, setGraph);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentGraphView]);

  useEffect(() => {
    if (refreshSignal < 1) {
      return;
    }

    refreshCases(setCases, { setSystemNotice, clearSystemNotice });
    if (currentCaseId) {
      const latestGraphView = useStore.getState().currentGraphView;
      refreshCase(
        currentCaseId,
        { setCurrentCase, setTimeline, setFindings, setGraph },
        latestGraphView,
        { setSystemNotice, clearSystemNotice },
      );
    }
  }, [refreshSignal]);

  useEffect(() => {
    if (!autopilotEnabled || !currentCaseId || autopilotInFlightActionId) {
      return;
    }
    if (currentCase?.manifest?.status !== "complete") {
      return;
    }

    const pendingAction = actions.find((action) => action.status === "pending");
    if (!pendingAction) {
      return;
    }

    setAutopilotInFlightActionId(pendingAction.id);

    runAction(currentCaseId, pendingAction.id)
      .then(() => {
        clearSystemNotice("autopilot");
      })
      .catch((error) => {
        console.error(error);
        const notice = buildApiNotice(
          error,
          `Autopilot failed while running ${pendingAction.title}`,
        );
        setSystemNotice({
          source: "autopilot",
          ...notice,
        });
      })
      .finally(() => {
        setAutopilotInFlightActionId(null);
        requestDataRefresh();
      });
  }, [
    actions,
    autopilotEnabled,
    autopilotInFlightActionId,
    clearSystemNotice,
    currentCase?.manifest?.status,
    currentCaseId,
    requestDataRefresh,
    setAutopilotInFlightActionId,
    setSystemNotice,
  ]);

  return (
    <div className="h-screen bg-[#0a0a0c] flex flex-col overflow-hidden">
      <Header />
      <StatusBar />
      <div className="flex-1 flex overflow-hidden">
        <main className="flex-1 overflow-hidden relative">
          {activeTab === "overview" && (
            <OverviewTab
              onRefresh={() =>
                refreshCases(setCases, { setSystemNotice, clearSystemNotice })
              }
            />
          )}
          {activeTab === "timeline" && <TimelineTab />}
          {activeTab === "graphs" && <GraphsTab />}
          {activeTab === "findings" && <FindingsTab />}
          {activeTab === "artifacts" && <ArtifactsTab />}
          {activeTab === "exports" && <ExportsTab />}
        </main>
        <InspectorPanel
          collapsed={inspectorCollapsed}
          onToggle={() => setInspectorCollapsed((v) => !v)}
        />
      </div>
    </div>
  );
}

async function refreshCases(setCases, noticeHandlers = {}) {
  const { setSystemNotice, clearSystemNotice } = noticeHandlers;
  try {
    const { data } = await listCases();
    setCases(data.cases || []);
    clearSystemNotice?.("api");
  } catch (error) {
    console.error(error);
    const notice = buildApiNotice(error, "Failed to load case list");
    setSystemNotice?.({
      source: "api",
      ...notice,
    });
  }
}

async function refreshCase(caseId, setters, graphView, noticeHandlers = {}) {
  const { setSystemNotice, clearSystemNotice } = noticeHandlers;

  // Core case data — fetched together; failure surfaces as a notice.
  try {
    const [{ data: caseData }, { data: timelineData }, { data: findingsData }] =
      await Promise.all([
        getCase(caseId),
        getTimeline(caseId),
        getFindings(caseId),
      ]);
    setters.setCurrentCase(caseData);
    setters.setTimeline(timelineData.timeline || []);
    setters.setFindings(findingsData.findings || []);
    clearSystemNotice?.("api");
  } catch (error) {
    console.error(error);
    const notice = buildApiNotice(error, `Failed to refresh case ${caseId}`);
    setSystemNotice?.({ source: "api", ...notice });
  }

  // Graph data — fetched independently so a missing graph view (e.g. CFG not
  // yet expanded) never blocks the case / timeline / findings from loading.
  if (graphView) {
    await refreshGraph(caseId, graphView, setters.setGraph);
  }
}

async function refreshGraph(caseId, graphView, setGraph) {
  try {
    const { data } = await getGraph(caseId, graphView);
    setGraph(graphView, data.graph || null);
  } catch {
    // Graph for this view may not exist yet (CFG / Xref populate only after
    // running expand_cfg / inspect_xrefs actions).  Set null silently so the
    // canvas shows the "no graph loaded" placeholder instead of an error.
    setGraph(graphView, null);
  }
}

function buildWsFailureNotice(event) {
  const payloadStatus = event?.payload?.status;
  const error = event?.payload?.error;
  if (
    payloadStatus !== "failed" ||
    typeof error !== "string" ||
    error.trim().length === 0
  ) {
    return null;
  }

  const kind = normalizeWsErrorKind(event?.payload?.error_kind);
  return {
    source: "ws",
    kind,
    level: kind === "bad_request" || kind === "not_found" ? "warn" : "error",
    message: `${event.message || "Operation failed"}: ${error}`,
  };
}

function normalizeWsErrorKind(kind) {
  if (typeof kind !== "string") {
    return null;
  }
  const normalized = kind.trim().toLowerCase();
  if (
    normalized === "bad_request" ||
    normalized === "not_found" ||
    normalized === "timeout" ||
    normalized === "internal"
  ) {
    return normalized;
  }
  return null;
}
