import { useEffect, useMemo, useRef, useState } from "react";
import { GitBranch, Layers, Maximize2, ZoomIn, ZoomOut } from "lucide-react";
import { useStore } from "../store";

// ── view catalogue ────────────────────────────────────────────────────────────

const VIEWS = [
  { id: "provenance", label: "Provenance", hint: "Case provenance chain" },
  {
    id: "call_graph",
    label: "Call Graph",
    hint: "Function call relationships",
  },
  { id: "cfg", label: "CFG", hint: "Control-flow graph" },
  { id: "xref_view", label: "Xref View", hint: "Cross-reference map" },
  {
    id: "string_relation_view",
    label: "String Relations",
    hint: "String reference map",
  },
];

// ── per-view layout strategy ──────────────────────────────────────────────────
//
// Each view specifies a PRIMARY layout and a FALLBACK chain.
// If dagre crashes or times out we try the next algorithm so the screen
// never goes blank.
//
// Layout key:
//   "breadthfirst" – hierarchical tree from roots (good for provenance / call)
//   "dagre"        – ranked directed layout (good for CFG, tight graphs)
//   "concentric"   – star / radial (good for xref / string hub-and-spoke)
//   "grid"         – last-resort, always works

// cose (Compound Spring Embedder) is Cytoscape's built-in force-directed layout.
// Unlike dagre/breadthfirst it handles cycles, disconnected components, and
// complex topologies naturally — producing organic, readable graphs without
// the "all nodes in one column" problem that plagued dagre on these graphs.
const COSE_BASE = {
  name: "cose",
  animate: false,
  padding: 60,
  nodeRepulsion: () => 8000,
  idealEdgeLength: () => 90,
  edgeElasticity: () => 45,
  gravity: 80,
  numIter: 1000,
  nodeDimensionsIncludeLabels: true,
  fit: true,
};

const VIEW_STRATEGY = {
  // Provenance: tree with one root — cose produces a nice spread
  provenance: {
    primary: "cose",
    primaryOpts: {
      ...COSE_BASE,
      nodeRepulsion: () => 10000,
      idealEdgeLength: () => 110,
    },
    fallback: "breadthfirst",
    fallbackOpts: { directed: true, spacingFactor: 1.5, padding: 55 },
  },
  // Call graph: functions calling other functions — cose clusters callers nicely
  call_graph: {
    primary: "cose",
    primaryOpts: {
      ...COSE_BASE,
      nodeRepulsion: () => 7000,
      idealEdgeLength: () => 100,
    },
    fallback: "dagre",
    fallbackOpts: {
      rankDir: "LR",
      nodeSep: 55,
      rankSep: 130,
      ranker: "network-simplex",
      acyclicer: "greedy",
      padding: 55,
    },
  },
  // CFG: keep dagre TB as primary since control-flow is naturally top-down code
  cfg: {
    primary: "dagre",
    primaryOpts: {
      rankDir: "TB",
      nodeSep: 42,
      rankSep: 80,
      ranker: "network-simplex",
      acyclicer: "greedy",
      padding: 55,
    },
    fallback: "cose",
    fallbackOpts: {
      ...COSE_BASE,
      nodeRepulsion: () => 5000,
      idealEdgeLength: () => 70,
    },
  },
  // Xref: hub-and-spoke — cose pulls targets to centre naturally
  xref_view: {
    primary: "cose",
    primaryOpts: {
      ...COSE_BASE,
      nodeRepulsion: () => 9000,
      idealEdgeLength: () => 120,
    },
    fallback: "grid",
    fallbackOpts: { padding: 55 },
  },
  // String relations: strings + referencing functions — cose handles zero-edge graphs too
  string_relation_view: {
    primary: "cose",
    primaryOpts: {
      ...COSE_BASE,
      nodeRepulsion: () => 9000,
      idealEdgeLength: () => 120,
    },
    fallback: "grid",
    fallbackOpts: { padding: 55 },
  },
};

const DEFAULT_STRATEGY = {
  primary: "cose",
  primaryOpts: { ...COSE_BASE },
  fallback: "grid",
  fallbackOpts: { padding: 55 },
};

// ── cytoscape bootstrap ───────────────────────────────────────────────────────

let cyExtensionsReady = false;

async function getCytoscape() {
  const cytoscape = (await import("cytoscape")).default;
  if (!cyExtensionsReady) {
    const dagre = (await import("cytoscape-dagre")).default;
    cytoscape.use(dagre);
    cyExtensionsReady = true;
  }
  return cytoscape;
}

// ── node appearance helpers ───────────────────────────────────────────────────
// Covers ALL groups emitted by graph.rs: provenance groups AND
// call_graph / cfg / xref_view / string_relation_view groups.

const NODE_BG = {
  // provenance view
  case: "#0b1628",
  timeline: "#1a1205",
  finding: "#1e0707",
  artifact: "#071626",
  action: "#091505",
  evidence: "#160c16",
  entity: "#071a1a",
  string: "#10071e",
  // call_graph / cfg / xref views
  function: "#0d1a0a", // dark green
  function: "#0d1a0a",
  import: "#1a0d1a", // dark purple
  callee: "#101a0a", // lighter green
  cfg: "#0a1a1a", // dark teal – basic blocks
  basic_block: "#0a1a1a",
  xref_target: "#1a180a", // dark amber
};

const NODE_BORDER = {
  // provenance view
  case: "#2e5eaa",
  timeline: "#9a6020",
  finding: "#aa2e2e",
  artifact: "#2e6eaa",
  action: "#3e7a2e",
  evidence: "#7a3e7a",
  entity: "#2e8a8a",
  string: "#6a3eaa",
  // call_graph / cfg / xref views
  function: "#3a8a2a", // green
  import: "#8a3a8a", // purple
  callee: "#4a9a3a", // lighter green
  cfg: "#2a8a8a", // teal
  basic_block: "#2a8a8a",
  xref_target: "#8a7a2a", // amber
};

const GROUP_LABEL = {
  case: "CASE",
  timeline: "STEP",
  finding: "FINDING",
  artifact: "ARTIFACT",
  action: "ACTION",
  evidence: "EVIDENCE",
  entity: "ENTITY",
  string: "STRING",
  function: "FUNCTION",
  import: "IMPORT",
  callee: "CALLEE",
  cfg: "BLOCK",
  basic_block: "BLOCK",
  xref_target: "XREF TARGET",
};

function nodeBg(group) {
  return NODE_BG[group] ?? "#0e0e12";
}
function nodeBorder(group) {
  return NODE_BORDER[group] ?? "rgba(255,255,255,0.12)";
}

// ── cytoscape stylesheet ──────────────────────────────────────────────────────

function buildStyle() {
  return [
    // ── base node ──
    {
      selector: "node",
      style: {
        label: "data(label)",
        "text-wrap": "ellipsis",
        "text-max-width": "120px",
        "text-valign": "center",
        "text-halign": "center",
        "font-size": "10px",
        "font-family": "'JetBrains Mono', 'Fira Code', monospace",
        color: "#dde6f0",
        "text-outline-color": "#050508",
        "text-outline-width": 2.5,
        width: 120,
        height: 44,
        shape: "roundrectangle",
        "background-color": (ele) => nodeBg(ele.data("group")),
        "border-width": 1.5,
        "border-color": (ele) => nodeBorder(ele.data("group")),
        "border-opacity": 0.75,
        padding: "8px",
        "transition-property":
          "border-color, border-width, shadow-blur, background-color",
        "transition-duration": "0.15s",
      },
    },

    // ── node hover ──
    {
      selector: "node:hover",
      style: {
        "border-color": "#d4a574",
        "border-width": 2.5,
        "border-opacity": 1,
        "shadow-blur": 14,
        "shadow-color": "rgba(212,165,116,0.55)",
        "shadow-offset-x": 0,
        "shadow-offset-y": 0,
        "shadow-opacity": 1,
        cursor: "pointer",
      },
    },

    // ── selected node ──
    {
      selector: "node:selected",
      style: {
        "border-color": "#f0b84a",
        "border-width": 2.5,
        "border-opacity": 1,
        "overlay-color": "#d4a574",
        "overlay-opacity": 0.12,
        "shadow-blur": 18,
        "shadow-color": "rgba(212,165,116,0.7)",
        "shadow-offset-x": 0,
        "shadow-offset-y": 0,
        "shadow-opacity": 1,
      },
    },

    // ── case node (top of hierarchy – slightly taller) ──
    {
      selector: "node[group='case']",
      style: {
        height: 52,
        "font-size": "11px",
        "font-weight": "bold",
        "border-width": 2,
      },
    },

    // ── finding node ──
    {
      selector: "node[group='finding']",
      style: {
        "border-width": 2,
        "border-opacity": 0.85,
      },
    },

    // ── base edge ──
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": "rgba(180,150,100,0.22)",
        "target-arrow-color": "rgba(212,165,116,0.45)",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.85,
        "curve-style": "bezier",
        label: "data(label)",
        "font-size": "8.5px",
        "font-family": "Inter, system-ui, sans-serif",
        color: "rgba(212,165,116,0.5)",
        "text-rotation": "autorotate",
        "text-margin-y": -9,
        "text-outline-color": "#050508",
        "text-outline-width": 2,
        "transition-property": "line-color, width",
        "transition-duration": "0.12s",
      },
    },

    // ── edge hover ──
    {
      selector: "edge:hover",
      style: {
        "line-color": "rgba(212,165,116,0.55)",
        "target-arrow-color": "rgba(212,165,116,0.8)",
        width: 2.5,
      },
    },

    // ── selected edge ──
    {
      selector: "edge:selected",
      style: {
        "line-color": "#d4a574",
        "target-arrow-color": "#d4a574",
        width: 2.5,
        "overlay-color": "#d4a574",
        "overlay-opacity": 0.12,
      },
    },

    // ── dim: applied to all elements NOT in the focused neighbourhood ──
    {
      selector: ".dim",
      style: {
        opacity: 0.12,
        "overlay-opacity": 0,
        events: "yes",
      },
    },
    // ── neighbour highlight ──
    {
      selector: ".neighbour",
      style: {
        opacity: 1,
        "border-color": "rgba(212,165,116,0.45)",
        "border-width": 2,
      },
    },
    // ── focused (the clicked node) ──
    {
      selector: ".focus-root",
      style: {
        opacity: 1,
        "border-color": "#f0b84a",
        "border-width": 3.5,
        "border-opacity": 1,
        "shadow-blur": 22,
        "shadow-color": "rgba(240,184,74,0.85)",
        "shadow-offset-x": 0,
        "shadow-offset-y": 0,
        "shadow-opacity": 1,
        "z-index": 9999,
      },
    },
  ];
}

// ── component ─────────────────────────────────────────────────────────────────

export default function GraphsTab() {
  const currentGraphView = useStore((s) => s.currentGraphView);
  const setCurrentGraphView = useStore((s) => s.setCurrentGraphView);
  const graph = useStore((s) => s.graphs[currentGraphView]);
  const selectGraphNode = useStore((s) => s.selectGraphNode);
  const selectGraphEdge = useStore((s) => s.selectGraphEdge);
  // Subscribe so GraphsTab re-renders when a node is selected — drives the
  // inline overlay and confirms selectGraphNode() is actually working.
  const selectedGraphNode = useStore((s) => s.selectedGraphNode);
  const selectedGraphEdge = useStore((s) => s.selectedGraphEdge);

  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [cyError, setCyError] = useState(null);
  const [ready, setReady] = useState(false);
  const [focusMode, setFocusMode] = useState(false);

  const activeView = VIEWS.find((v) => v.id === currentGraphView) ?? VIEWS[0];

  // Only produce graphData when there is at least one node.
  // ALSO filter dangling edges here in the frontend: if an edge's source or
  // target node doesn't exist, Cytoscape throws "Cannot create edge with
  // nonexistent target" and the whole graph fails to render.  This covers
  // cases where old on-disk data predates the backend fix.
  const graphData = useMemo(() => {
    if (!graph?.nodes?.length) return null;
    const nodeIds = new Set(graph.nodes.map((n) => n.id));
    return {
      nodes: graph.nodes.map((n) => ({ data: { ...n } })),
      edges: (graph.edges ?? [])
        .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
        .map((e) => ({ data: { ...e } })),
    };
  }, [graph]);

  useEffect(() => {
    // Container is always mounted now (display toggled via CSS).
    // Re-run whenever graphData or the active view changes.
    if (!graphData || !containerRef.current) return;

    let cancelled = false;

    const init = async () => {
      try {
        const cytoscape = await getCytoscape();
        if (cancelled) return;

        // Tear down any previous instance cleanly
        if (cyRef.current) {
          cyRef.current.destroy();
          cyRef.current = null;
        }
        setReady(false);
        setCyError(null);

        // Create cytoscape WITHOUT a layout so we can run it manually
        // with a proper fallback chain and error handling.
        const cy = cytoscape({
          container: containerRef.current,
          elements: [...graphData.nodes, ...graphData.edges],
          layout: { name: "preset" }, // positions set by layout below
          style: buildStyle(),
          minZoom: 0.05,
          maxZoom: 5,
          wheelSensitivity: 0.22,
          boxSelectionEnabled: false,
          autoungrabify: false,
        });

        if (cancelled) {
          cy.destroy();
          return;
        }

        // ── Layout with fallback chain ────────────────────────────────────
        // runLayout returns a Promise that resolves when layoutstop fires,
        // or rejects on error / timeout. We try primary → fallback → grid.

        const runLayout = (name, opts = {}) =>
          new Promise((resolve, reject) => {
            let timer;
            try {
              const layout = cy.layout({ name, animate: false, ...opts });
              timer = setTimeout(() => {
                reject(new Error(`${name} layout timeout`));
              }, 7000);
              layout.one("layoutstop", () => {
                clearTimeout(timer);
                resolve();
              });
              layout.run();
            } catch (err) {
              clearTimeout(timer);
              reject(err);
            }
          });

        const strategy = VIEW_STRATEGY[currentGraphView] ?? DEFAULT_STRATEGY;

        try {
          await runLayout(strategy.primary, strategy.primaryOpts);
        } catch (e1) {
          console.warn(
            `[GraphsTab] ${strategy.primary} failed (${e1?.message}), trying ${strategy.fallback}`,
          );
          try {
            await runLayout(strategy.fallback, strategy.fallbackOpts);
          } catch (e2) {
            console.warn(
              `[GraphsTab] ${strategy.fallback} failed (${e2?.message}), using grid`,
            );
            try {
              await runLayout("grid", { padding: 55 });
            } catch {
              // grid always works — if it somehow fails just continue
            }
          }
        }

        if (cancelled) {
          cy.destroy();
          return;
        }

        // cy.resize() forces Cytoscape to recalculate the canvas dimensions.
        // Official fix for "blank graph after tab switch": when the container
        // was hidden (display:none), its measured size was 0×0.
        cy.resize();

        // Wait one animation frame so the browser has painted the layout
        // before we calculate the fit bounding box.
        await new Promise((r) => requestAnimationFrame(r));

        if (cancelled) {
          cy.destroy();
          return;
        }

        cy.fit(undefined, 55);
        cy.center();

        // ── Interactions ─────────────────────────────────────────────────
        //
        // INSPECTOR UPDATE STRATEGY
        // ─────────────────────────
        // We use useStore.getState() inside every Cytoscape callback instead
        // of the component-scope closure variables (selectGraphNode, etc.).
        //
        // Why: Cytoscape registers these handlers once inside init() which
        // runs inside a useEffect.  The closure captures selectGraphNode at
        // the time the effect ran.  In React 18 concurrent mode, even though
        // Zustand actions are "stable", the closure reference can be stale
        // if the component re-renders between mount and the first tap.
        //
        // useStore.getState() always reads the LIVE store at call time —
        // this is the canonical Zustand pattern for callbacks in third-party
        // library event handlers (see Zustand docs: "Reading state outside
        // React components").
        //
        // setFocusMode is a React useState setter which is guaranteed stable
        // by React and is safe to use directly from a closure.

        // tap node → update inspector via live store + visual focus ring
        cy.on("tap", "node", (evt) => {
          const node = evt.target;
          // IMPORTANT: node.data() returns a FROZEN internal reference in
          // Cytoscape.js (confirmed in cytoscape/cytoscape.js#2841).
          // Zustand uses Object.is() to compare old vs new state — if the same
          // frozen reference is passed twice, Object.is(ref, ref) === true and
          // Zustand skips the re-render entirely.
          // Spreading creates a NEW plain object every tap, guaranteeing
          // Object.is(prev, next) === false → Zustand always re-renders.
          const nodeData = { ...node.data() };

          // Read actions from live store — never stale
          const store = useStore.getState();
          store.selectGraphNode(nodeData);
          store.selectGraphEdge(null);
          setFocusMode(true);

          const neighbourhood = node.closedNeighborhood();
          cy.batch(() => {
            cy.elements().addClass("dim").removeClass("focus-root neighbour");
            neighbourhood.removeClass("dim").addClass("neighbour");
            node.removeClass("neighbour").addClass("focus-root");
          });
        });

        // tap edge → update inspector via live store + visual highlight
        cy.on("tap", "edge", (evt) => {
          const edge = evt.target;
          // Same frozen-reference fix as node tap above
          const edgeData = { ...edge.data() };

          const store = useStore.getState();
          store.selectGraphEdge(edgeData);
          store.selectGraphNode(null);
          setFocusMode(true);

          cy.batch(() => {
            cy.elements().addClass("dim").removeClass("focus-root neighbour");
            edge.removeClass("dim");
            edge.connectedNodes().removeClass("dim").addClass("neighbour");
          });
        });

        // tap canvas background → clear inspector via live store + reset visual
        cy.on("tap", (evt) => {
          if (evt.target === cy) {
            const store = useStore.getState();
            store.selectGraphNode(null);
            store.selectGraphEdge(null);
            setFocusMode(false);
            cy.batch(() => {
              cy.elements().removeClass("dim focus-root neighbour");
            });
          }
        });

        // double-tap node → smooth zoom
        cy.on("dbltap", "node", (evt) => {
          cy.animate(
            {
              center: { eles: evt.target },
              zoom: Math.max(cy.zoom() * 1.7, 1.5),
            },
            { duration: 320, easing: "ease-in-out-cubic" },
          );
        });

        cyRef.current = cy;
        setReady(true);
      } catch (err) {
        if (!cancelled) {
          console.error("[GraphsTab] cytoscape init error:", err);
          setCyError(err?.message ?? "Graph render failed");
        }
      }
    };

    init();

    return () => {
      cancelled = true;
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
    // selectGraphNode / selectGraphEdge are stable Zustand action references —
    // they never change between renders, so omitting them from deps is safe and
    // prevents the effect from re-running when they appear to "change".
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphData, currentGraphView]); // selectGraphNode/selectGraphEdge omitted — stable Zustand refs

  // ── toolbar actions ─────────────────────────────────────────────────────────

  // ── Inline node-info overlay ────────────────────────────────────────────────
  // Renders node details directly on the graph canvas so the user always sees
  // them even if the Analyst Inspector panel has rendering quirks.
  // This also acts as a live indicator that selectGraphNode() is working.
  const nodeInfoOverlay = selectedGraphNode ? (
    <div className="absolute bottom-20 left-4 z-20 max-w-[320px] glass-sm rounded-xl border border-accent-warm/25 bg-accent-warm/[0.04] p-3.5 pointer-events-none">
      <div className="flex items-start gap-2 mb-2">
        <span
          className="inline-block w-2.5 h-2.5 rounded-sm flex-shrink-0 mt-1"
          style={{
            backgroundColor: nodeBg(selectedGraphNode.group),
            border: `1.5px solid ${nodeBorder(selectedGraphNode.group)}`,
          }}
        />
        <p className="text-[13px] font-semibold text-accent-warm leading-tight break-all">
          {selectedGraphNode.label}
        </p>
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-0.5 mb-2">
        {selectedGraphNode.kind && (
          <span className="text-[10px] text-white/40 mono uppercase">
            {selectedGraphNode.kind}
          </span>
        )}
        {selectedGraphNode.group && (
          <span className="text-[10px] text-white/30 mono uppercase">
            {GROUP_LABEL[selectedGraphNode.group] ?? selectedGraphNode.group}
          </span>
        )}
      </div>
      {selectedGraphNode.summary && (
        <p className="text-[11px] text-white/55 leading-relaxed">
          {selectedGraphNode.summary}
        </p>
      )}
    </div>
  ) : selectedGraphEdge ? (
    <div className="absolute bottom-20 left-4 z-20 max-w-[280px] glass-sm rounded-xl border border-white/[0.10] p-3 pointer-events-none">
      <p className="text-[12px] font-semibold text-white/75 mb-1">
        {selectedGraphEdge.label || "Edge"}
      </p>
      <p className="text-[10px] text-white/35 mono">
        {selectedGraphEdge.source} → {selectedGraphEdge.target}
      </p>
    </div>
  ) : null;

  const handleFit = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.resize();
    cy.fit(undefined, 55);
    cy.center();
  };

  const handleZoom = (factor) => {
    const cy = cyRef.current;
    if (!cy) return;
    const cx = cy.width() / 2;
    const cy_ = cy.height() / 2;
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cx, y: cy_ } });
  };

  // ── render helpers ──────────────────────────────────────────────────────────

  const nodeCount = graph?.nodes?.length ?? 0;
  const edgeCount = graph?.edges?.length ?? 0;

  // Legend: unique groups present in this graph
  const presentGroups = useMemo(() => {
    if (!graph?.nodes?.length) return [];
    const seen = new Set();
    graph.nodes.forEach((n) => {
      if (n.group) seen.add(n.group);
    });
    return [...seen].slice(0, 8);
  }, [graph]);

  return (
    <div className="h-full flex flex-col dot-pattern">
      {/* ── header row: title + horizontal view tabs + stats ── */}
      <div className="glass border-b border-white/[0.04] px-4 py-2.5 flex items-center gap-3 flex-wrap">
        {/* icon + title */}
        <div className="flex items-center gap-2 flex-shrink-0 mr-1">
          <div className="w-7 h-7 rounded-lg bg-accent-rose/10 border border-accent-rose/20 flex items-center justify-center">
            <GitBranch className="w-3.5 h-3.5 text-accent-rose/70" />
          </div>
          <span className="text-[13px] font-semibold text-white/70">
            Graphs
          </span>
        </div>
        {/* collapse inspector hint */}
        <span className="text-[10px] text-white/20 flex-shrink-0 hidden xl:block">
          Click any node to inspect · double-click to zoom · ✕ to clear focus
        </span>

        {/* horizontal tab pills */}
        <div className="flex items-center gap-1 flex-1 flex-wrap">
          {VIEWS.map((view) => {
            const active = currentGraphView === view.id;
            return (
              <button
                key={view.id}
                onClick={() => {
                  setCyError(null);
                  setCurrentGraphView(view.id);
                }}
                title={view.hint}
                className={[
                  "px-3 py-1.5 rounded-lg border text-[11px] font-medium transition-all duration-150 whitespace-nowrap",
                  active
                    ? "border-accent-warm/35 bg-accent-warm/[0.07] text-accent-warm shadow-[0_0_10px_rgba(212,165,116,0.08)]"
                    : "border-white/[0.05] bg-white/[0.01] text-white/45 hover:border-white/[0.10] hover:text-white/65 hover:bg-white/[0.03]",
                ].join(" ")}
              >
                {view.label}
              </button>
            );
          })}
        </div>

        {/* stats badge */}
        {nodeCount > 0 && (
          <span className="metal-badge px-2.5 py-1 text-[10px] text-white/30 flex-shrink-0">
            {nodeCount} nodes · {edgeCount} edges
          </span>
        )}
      </div>

      {/* ── body: canvas fills everything ── */}
      <div className="flex-1 relative overflow-hidden bg-[#060608]">
        {cyError ? (
          /* Error state */
          <div className="flex flex-col items-center justify-center h-full gap-3">
            <div className="w-14 h-14 rounded-2xl glass-card flex items-center justify-center">
              <GitBranch className="w-6 h-6 text-red-400/50" />
            </div>
            <p className="text-red-400/70 text-sm font-semibold">
              Graph render error
            </p>
            <p className="text-white/25 text-xs mono max-w-xs text-center">
              {cyError}
            </p>
            <button
              onClick={() => setCyError(null)}
              className="key-btn px-4 py-2 text-xs text-white/50 hover:text-white/80 mt-1"
            >
              Dismiss
            </button>
          </div>
        ) : (
          /* ── canvas area ── */
          /* The container div is ALWAYS mounted regardless of whether graphData
             exists.  Conditionally unmounting it causes Cytoscape to initialise
             into a zero-size canvas (display:none parent) and then fail to paint
             when the container reappears — the classic "blank graph" bug.
             Instead we toggle visibility via CSS and call cy.resize() in the
             effect once the container is actually visible. */
          <>
            <div
              ref={containerRef}
              className="cytoscape-container"
              style={{
                width: "100%",
                height: "100%",
                // Hide but keep mounted so Cytoscape always has a valid DOM node
                display: graphData && !cyError ? "block" : "none",
              }}
            />

            {/* Inline node/edge info overlay */}
            {ready && nodeInfoOverlay}

            {/* Placeholder shown when there is no graph data */}
            {!graphData && !cyError && (
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <div className="w-16 h-16 rounded-2xl glass-card flex items-center justify-center mb-4">
                  <Layers className="w-8 h-8 text-white/[0.07]" />
                </div>
                <p className="text-white/25 text-sm font-medium">
                  No graph loaded
                </p>
                <p className="text-white/15 text-xs mt-2 text-center max-w-[220px] leading-relaxed">
                  Select a completed case on the Overview tab,
                  <br />
                  then pick a view above.
                </p>
              </div>
            )}

            {/* active view label (top-left) */}
            {ready && (
              <div className="absolute top-4 left-4 z-10 pointer-events-none flex items-center gap-2">
                <span className="metal-badge px-2.5 py-1 text-[10px] text-white/40 font-medium">
                  {activeView.label}
                </span>
                {nodeCount > 0 && (
                  <span className="metal-badge px-2.5 py-1 text-[10px] text-white/25">
                    {nodeCount} nodes · {edgeCount} edges
                  </span>
                )}
              </div>
            )}

            {/* group legend (top-right) */}
            {ready && presentGroups.length > 0 && (
              <div className="absolute top-4 right-[60px] z-10 pointer-events-none glass-sm rounded-xl border border-white/[0.04] px-3 py-2">
                <div className="flex flex-wrap gap-x-3 gap-y-1.5 max-w-[260px]">
                  {presentGroups.map((g) => (
                    <div key={g} className="flex items-center gap-1.5">
                      <span
                        className="inline-block w-2 h-2 rounded-sm flex-shrink-0"
                        style={{
                          backgroundColor: nodeBg(g),
                          border: `1.5px solid ${nodeBorder(g)}`,
                        }}
                      />
                      <span className="text-[9px] text-white/35 mono uppercase tracking-wide">
                        {GROUP_LABEL[g] ?? g}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Zoom / fit toolbar (bottom-right) */}
            {ready && (
              <div className="absolute bottom-5 right-5 flex flex-col gap-1.5 z-10">
                {focusMode && (
                  <button
                    onClick={() => {
                      cyRef.current
                        ?.elements()
                        .removeClass("dim focus-root neighbour");
                      setFocusMode(false);
                      selectGraphNode(null);
                      selectGraphEdge(null);
                    }}
                    title="Clear focus"
                    className="w-9 h-9 glass-card flex items-center justify-center border-accent-warm/35 bg-accent-warm/[0.06] transition-all duration-150"
                  >
                    <span className="text-accent-warm text-[11px] font-bold">
                      ✕
                    </span>
                  </button>
                )}
                <button
                  onClick={handleFit}
                  title="Fit to screen"
                  className="w-9 h-9 glass-card flex items-center justify-center hover:border-accent-warm/35 hover:bg-accent-warm/[0.04] transition-all duration-150"
                >
                  <Maximize2 className="w-[14px] h-[14px] text-white/45" />
                </button>
                <button
                  onClick={() => handleZoom(1.3)}
                  title="Zoom in"
                  className="w-9 h-9 glass-card flex items-center justify-center hover:border-accent-warm/35 hover:bg-accent-warm/[0.04] transition-all duration-150"
                >
                  <ZoomIn className="w-[14px] h-[14px] text-white/45" />
                </button>
                <button
                  onClick={() => handleZoom(1 / 1.3)}
                  title="Zoom out"
                  className="w-9 h-9 glass-card flex items-center justify-center hover:border-accent-warm/35 hover:bg-accent-warm/[0.04] transition-all duration-150"
                >
                  <ZoomOut className="w-[14px] h-[14px] text-white/45" />
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
