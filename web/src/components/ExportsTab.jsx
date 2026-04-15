import { useRef, useState } from "react";
import { Download, FileJson, Upload } from "lucide-react";
import {
  exportCase,
  exportCaseBundle,
  importCaseBundle,
  listCases,
} from "../api";
import { useStore } from "../store";

export default function ExportsTab() {
  const currentCaseId = useStore((state) => state.currentCaseId);
  const cases = useStore((state) => state.cases);
  const exportsState = useStore((state) => state.exports);
  const setExports = useStore((state) => state.setExports);
  const setCases = useStore((state) => state.setCases);
  const setCurrentCaseId = useStore((state) => state.setCurrentCaseId);

  const [graphmlLoading, setGraphmlLoading] = useState(false);
  const [bundleLoading, setBundleLoading] = useState(false);
  const [importLoading, setImportLoading] = useState(false);
  const [importResult, setImportResult] = useState(null);
  const [importError, setImportError] = useState(null);
  const fileInputRef = useRef(null);

  // ── GraphML export ─────────────────────────────────────────────────────────
  const handleGraphml = async () => {
    if (!currentCaseId) return;
    setGraphmlLoading(true);
    try {
      const { data } = await exportCase(currentCaseId);
      setExports(data.exports || []);
    } finally {
      setGraphmlLoading(false);
    }
  };

  // ── Full case bundle download ──────────────────────────────────────────────
  const handleBundleDownload = async () => {
    if (!currentCaseId) return;
    setBundleLoading(true);
    try {
      const response = await exportCaseBundle(currentCaseId);
      const url = URL.createObjectURL(
        new Blob([response.data], { type: "application/json" }),
      );
      const a = document.createElement("a");
      a.href = url;
      a.download = `reverseorbit-case-${currentCaseId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Bundle export failed:", err);
    } finally {
      setBundleLoading(false);
    }
  };

  // ── Import case bundle ─────────────────────────────────────────────────────
  const handleImportFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportError(null);
    setImportResult(null);
    setImportLoading(true);
    try {
      const text = await file.text();
      const bundle = JSON.parse(text);
      const { data } = await importCaseBundle(bundle);
      setImportResult(data);
      // Refresh case list
      const { data: listData } = await listCases();
      setCases(listData.cases || []);
      // Switch to the newly imported case
      if (data.case_id) setCurrentCaseId(data.case_id);
    } catch (err) {
      console.error("Import failed:", err);
      setImportError(
        err?.response?.data?.error || err?.message || "Import failed",
      );
    } finally {
      setImportLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const hasCase = Boolean(currentCaseId);

  return (
    <div className="h-full overflow-auto p-6 dot-pattern space-y-5">
      {/* ── GraphML export ── */}
      <div className="glass-card p-5 max-w-3xl">
        <h2 className="text-base font-semibold text-white/85 flex items-center gap-2 mb-1">
          <Download className="w-4 h-4 text-accent-warm/70" />
          Export Graphs as GraphML
        </h2>
        <p className="text-sm text-white/30 mb-4">
          Generate GraphML files for Gephi, yFiles, and other graph tools. Files
          are written to the case folder on disk.
        </p>
        <button
          onClick={handleGraphml}
          disabled={!hasCase || graphmlLoading}
          className="btn-primary px-4 py-2.5 text-sm disabled:opacity-40"
        >
          {graphmlLoading ? "Generating…" : "Generate GraphML"}
        </button>
        {!hasCase && (
          <p className="text-[11px] text-white/25 mt-2">
            Select a case on the Overview tab first.
          </p>
        )}
        {exportsState.length > 0 && (
          <div className="space-y-2 mt-5">
            {exportsState.map((entry) => (
              <div
                key={`${entry.view}-${entry.path}`}
                className="glass-sm p-3 rounded-xl border border-white/[0.04]"
              >
                <p className="text-[12px] text-white/75 font-medium">
                  {entry.view}
                </p>
                <p className="text-[11px] text-white/25 mono break-all mt-1">
                  {entry.path}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Full case bundle export ── */}
      <div className="glass-card p-5 max-w-3xl">
        <h2 className="text-base font-semibold text-white/85 flex items-center gap-2 mb-1">
          <FileJson className="w-4 h-4 text-accent-ice/70" />
          Export Case Bundle (JSON)
        </h2>
        <p className="text-sm text-white/30 mb-4">
          Download the entire case as a portable JSON file — manifest, timeline,
          findings, actions, and artifact index. Share it with other
          ReverseOrbit users or back it up. They can import it below.
        </p>
        <button
          onClick={handleBundleDownload}
          disabled={!hasCase || bundleLoading}
          className="key-btn px-4 py-2.5 text-sm text-white/60 hover:text-white/90 disabled:opacity-40"
        >
          {bundleLoading ? "Preparing…" : "Download Case Bundle"}
        </button>
        {!hasCase && (
          <p className="text-[11px] text-white/25 mt-2">
            Select a case on the Overview tab first.
          </p>
        )}
      </div>

      {/* ── Import case bundle ── */}
      <div className="glass-card p-5 max-w-3xl">
        <h2 className="text-base font-semibold text-white/85 flex items-center gap-2 mb-1">
          <Upload className="w-4 h-4 text-accent-sage/70" />
          Import Case Bundle
        </h2>
        <p className="text-sm text-white/30 mb-4">
          Import a case JSON bundle exported by another ReverseOrbit instance. A
          new case is created with a fresh ID so your existing cases are never
          overwritten.
        </p>

        <label className="cursor-pointer">
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={handleImportFile}
            disabled={importLoading}
          />
          <span
            className={`key-btn inline-flex items-center gap-2 px-4 py-2.5 text-sm text-white/60 hover:text-white/90 ${importLoading ? "opacity-40 pointer-events-none" : ""}`}
          >
            <Upload className="w-4 h-4" />
            {importLoading ? "Importing…" : "Choose Bundle File…"}
          </span>
        </label>

        {importResult && (
          <div className="mt-4 glass-sm rounded-xl border border-accent-sage/30 bg-accent-sage/[0.04] p-4">
            <p className="text-[12px] text-accent-sage/90 font-semibold mb-1">
              ✓ Import successful
            </p>
            <p className="text-[11px] text-white/50">
              Case:{" "}
              <span className="text-white/75">
                {importResult.manifest?.label}
              </span>
            </p>
            <p className="text-[11px] text-white/35 mono mt-1">
              ID: {importResult.case_id}
            </p>
          </div>
        )}

        {importError && (
          <div className="mt-4 glass-sm rounded-xl border border-red-400/25 bg-red-500/[0.04] p-4">
            <p className="text-[12px] text-red-400/90 font-semibold mb-1">
              Import failed
            </p>
            <p className="text-[11px] text-white/40 mono">{importError}</p>
          </div>
        )}
      </div>
    </div>
  );
}
