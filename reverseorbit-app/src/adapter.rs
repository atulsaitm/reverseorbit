//! Analysis adapter framework.
//!
//! [`AnalysisAdapter`] is the core extension point for ReverseOrbit.  Every
//! analysis capability (radare2, Ghidra, a custom script engine, …) is
//! expressed as an implementation of this trait.  The app layer depends only
//! on the trait so adapters can be swapped, stacked, or mocked in tests
//! without touching business logic.
//!
//! ## Implementing a new adapter
//!
//! ```text
//! pub struct GhidraAdapter { … }
//!
//! impl AnalysisAdapter for GhidraAdapter {
//!     fn collect_baseline(&self, …) -> Result<BaselineCollection> { … }
//!     fn collect_function_detail(&self, …) -> Result<FunctionDetail> { … }
//!     fn collect_xref_probe(&self, …) -> Result<XrefProbe> { … }
//!     fn run_dynamic_json_query(&self, …) -> Result<Value> { … }
//!     fn search_strings(&self, …) -> Result<Vec<StringEntry>> { … }
//!     fn collect_entrypoints(&self, …) -> Result<Value> { … }
//! }
//! ```
//!
//! Register the adapter in `state::build_state_with_adapter` or pass it
//! directly via `AppState` in tests.

use anyhow::Result;
use serde_json::Value;

use reverseorbit_core::{AnalysisProfile, FunctionDetail, StringEntry, XrefProbe};
use reverseorbit_radare2::{BaselineCollection, Radare2Adapter};

/// Core trait every analysis adapter must implement.
///
/// All methods receive a `target_path` string (the path to the binary on
/// disk) and return `anyhow::Result`.  Blocking I/O is expected — the app
/// layer wraps calls in `run_blocking_with_timeout` where needed.
pub trait AnalysisAdapter: Send + Sync + std::fmt::Debug {
    /// Run a full baseline analysis pass and return all collected artifacts
    /// plus a normalised snapshot.
    fn collect_baseline(
        &self,
        target_path: &str,
        profile: &AnalysisProfile,
        file_size: u64,
        sha256: String,
    ) -> Result<BaselineCollection>;

    /// Collect detailed disassembly and CFG for a single named function.
    fn collect_function_detail(
        &self,
        target_path: &str,
        function_name: &str,
    ) -> Result<FunctionDetail>;

    /// Collect all cross-references to a named target (import, string
    /// address, function name, etc.).
    fn collect_xref_probe(
        &self,
        target_path: &str,
        target: &str,
        target_kind: &str,
    ) -> Result<XrefProbe>;

    /// Run a single read-only JSON query command against the binary and
    /// return the raw parsed JSON value.  Implementations are responsible
    /// for validating that the command is safe (read-only, JSON output).
    fn run_dynamic_json_query(&self, target_path: &str, command: &str) -> Result<Value>;

    /// Search embedded strings for entries that contain `query` (case-
    /// insensitive), returning at most `limit` results.
    fn search_strings(
        &self,
        target_path: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<StringEntry>>;

    /// Return the binary's entry points as a JSON array of objects with at
    /// least `{ "vaddr": u64, "paddr": u64, "type": str }` fields.
    ///
    /// Default implementation runs `iej` through `run_dynamic_json_query`.
    /// Override for adapters that expose a richer entrypoint API.
    fn collect_entrypoints(&self, target_path: &str) -> Result<Value> {
        self.run_dynamic_json_query(target_path, "iej")
    }
}

// ── Radare2 implementation ────────────────────────────────────────────────────

impl AnalysisAdapter for Radare2Adapter {
    fn collect_baseline(
        &self,
        target_path: &str,
        profile: &AnalysisProfile,
        file_size: u64,
        sha256: String,
    ) -> Result<BaselineCollection> {
        Radare2Adapter::collect_baseline(self, target_path, profile, file_size, sha256)
    }

    fn collect_function_detail(
        &self,
        target_path: &str,
        function_name: &str,
    ) -> Result<FunctionDetail> {
        Radare2Adapter::collect_function_detail(self, target_path, function_name)
    }

    fn collect_xref_probe(
        &self,
        target_path: &str,
        target: &str,
        target_kind: &str,
    ) -> Result<XrefProbe> {
        Radare2Adapter::collect_xref_probe(self, target_path, target, target_kind)
    }

    fn run_dynamic_json_query(&self, target_path: &str, command: &str) -> Result<Value> {
        Radare2Adapter::run_dynamic_json_query(self, target_path, command)
    }

    fn search_strings(
        &self,
        target_path: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<StringEntry>> {
        Radare2Adapter::search_strings(self, target_path, query, limit)
    }

    // collect_entrypoints uses the default trait impl (runs `iej`).
}
