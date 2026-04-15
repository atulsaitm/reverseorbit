use std::process::Command;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use serde_json::{Value, json};

use reverseorbit_core::{
    AnalysisProfile, BinaryMetadata, CallEdge, ExportEntry, FunctionDetail, FunctionSummary,
    ImportEntry, NormalizedSnapshot, ProgramSection, StringEntry, SymbolEntry, XrefEntry,
    XrefProbe, suspicious_import_keywords, suspicious_string_keywords,
};

#[derive(Debug, Clone)]
pub struct CollectedArtifact {
    pub kind: String,
    pub label: String,
    pub summary: String,
    pub raw: Value,
    pub normalized: Value,
}

#[derive(Debug, Clone)]
pub struct BaselineCollection {
    pub snapshot: NormalizedSnapshot,
    pub artifacts: Vec<CollectedArtifact>,
}

#[derive(Debug, Default, Clone)]
pub struct Radare2Adapter;

impl Radare2Adapter {
    pub fn new() -> Self {
        Self
    }

    pub fn collect_baseline(
        &self,
        target_path: &str,
        profile: &AnalysisProfile,
        file_size: u64,
        sha256: String,
    ) -> Result<BaselineCollection> {
        let info_raw = self.run_json(target_path, "ij")?;
        let segments_raw = self.run_json(target_path, "iSSj")?;
        let sections_raw = self.run_json(target_path, "iSj")?;
        let imports_raw = self.run_json(target_path, "iij")?;
        let exports_raw = self.run_json(target_path, "iEj")?;
        let symbols_raw = self.run_json(target_path, "isj")?;
        let strings_raw = self.run_json(target_path, "izzj")?;
        let functions_raw = self.run_json(target_path, "aaa;aflj")?;
        let call_graph_raw = self.run_json(target_path, "aaa;agCj")?;

        let metadata = normalize_metadata(&info_raw, file_size, sha256);
        let segments = normalize_sections(&segments_raw);
        let sections = normalize_sections(&sections_raw);
        let imports = normalize_imports(&imports_raw);
        let exports = normalize_exports(&exports_raw);
        let symbols = normalize_symbols(&symbols_raw);
        let strings = normalize_strings(&strings_raw);
        let functions = normalize_functions(&functions_raw);
        let call_edges = normalize_call_edges(&call_graph_raw);

        let suspicious_imports = imports
            .iter()
            .filter(|item| matches_keyword(&item.name, suspicious_import_keywords()))
            .map(|item| item.name.clone())
            .take(24)
            .collect::<Vec<_>>();

        let suspicious_strings = strings
            .iter()
            .filter(|item| matches_keyword(&item.value, suspicious_string_keywords()))
            .map(|item| item.value.clone())
            .take(24)
            .collect::<Vec<_>>();

        let hot_limit = match profile {
            AnalysisProfile::Quick => 6,
            AnalysisProfile::Full => 16,
        };

        let hot_functions = functions
            .iter()
            .filter(|function| !function.name.starts_with("sym.imp."))
            .take(hot_limit)
            .map(|function| function.name.clone())
            .collect::<Vec<_>>();

        let mut function_details = Vec::new();
        let mut xref_probes = Vec::new();
        let mut artifacts = vec![
            artifact(
                "binary-overview",
                "Binary Overview",
                format!(
                    "{} {} {:?}",
                    metadata
                        .arch
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    metadata.bits.unwrap_or_default(),
                    metadata.os
                ),
                json!({
                    "info": info_raw,
                    "segments": segments_raw,
                    "sections": sections_raw,
                }),
                json!({
                    "metadata": metadata,
                    "segments": segments,
                    "sections": sections,
                }),
            ),
            artifact(
                "imports-exports",
                "Imports & Exports",
                format!("{} imports, {} exports", imports.len(), exports.len()),
                json!({ "imports": imports_raw, "exports": exports_raw }),
                json!({ "imports": imports, "exports": exports }),
            ),
            artifact(
                "symbols-strings",
                "Symbols & Strings",
                format!("{} symbols, {} strings", symbols.len(), strings.len()),
                json!({ "symbols": symbols_raw, "strings": strings_raw }),
                json!({ "symbols": symbols, "strings": strings }),
            ),
            artifact(
                "functions",
                "Functions",
                format!("{} analyzed functions", functions.len()),
                json!({ "functions": functions_raw, "call_graph": call_graph_raw }),
                json!({ "functions": functions, "call_edges": call_edges }),
            ),
        ];

        for function_name in hot_functions {
            let detail = self.collect_function_detail(target_path, &function_name)?;
            artifacts.push(artifact(
                "function-detail",
                format!("Function Detail: {function_name}"),
                format!("Detailed disassembly and CFG for {function_name}"),
                json!({
                    "disassembly": detail.disassembly,
                    "cfg": detail.cfg,
                    "xrefs": detail.xrefs,
                }),
                serde_json::to_value(&detail)?,
            ));
            function_details.push(detail);
        }

        for import_name in &suspicious_imports {
            let probe = self.collect_xref_probe(target_path, import_name, "import")?;
            artifacts.push(artifact(
                "xref-probe",
                format!("Xrefs: {import_name}"),
                format!("{} xrefs collected", probe.xrefs.len()),
                json!(probe.xrefs),
                serde_json::to_value(&probe)?,
            ));
            xref_probes.push(probe);
        }

        for string in strings
            .iter()
            .filter(|item| suspicious_strings.contains(&item.value))
            .filter_map(|item| item.vaddr.map(|addr| (item.value.clone(), addr)))
            .take(match profile {
                AnalysisProfile::Quick => 6,
                AnalysisProfile::Full => 16,
            })
        {
            let probe =
                self.collect_xref_probe(target_path, &format!("0x{:x}", string.1), "string")?;
            artifacts.push(artifact(
                "xref-probe",
                format!("String Xrefs: {}", truncate(&string.0)),
                format!("{} xrefs collected", probe.xrefs.len()),
                json!(probe.xrefs),
                serde_json::to_value(&probe)?,
            ));
            xref_probes.push(XrefProbe {
                target: string.0,
                target_kind: "string".to_string(),
                xrefs: probe.xrefs,
            });
        }

        let snapshot = NormalizedSnapshot {
            source: "radare2".to_string(),
            collected_at: Utc::now(),
            metadata,
            segments,
            sections,
            imports,
            exports,
            symbols,
            strings,
            functions,
            function_details,
            xref_probes,
            call_edges,
            suspicious_imports,
            suspicious_strings,
        };

        artifacts.push(artifact(
            "snapshot",
            "Normalized Snapshot",
            "Canonical normalized analysis snapshot".to_string(),
            Value::Null,
            serde_json::to_value(&snapshot)?,
        ));

        Ok(BaselineCollection {
            snapshot,
            artifacts,
        })
    }

    pub fn collect_function_detail(
        &self,
        target_path: &str,
        function_name: &str,
    ) -> Result<FunctionDetail> {
        let pdf = self.run_json(target_path, &format!("aaa;pdfj @ {function_name}"))?;
        let cfg = self.run_json(target_path, &format!("aaa;agfj @ {function_name}"))?;
        let xrefs_raw = self.run_json(target_path, &format!("aaa;axtj @ {function_name}"))?;
        let addr = pdf
            .get("addr")
            .and_then(|value| value.as_u64())
            .unwrap_or_default();
        Ok(FunctionDetail {
            name: function_name.to_string(),
            addr,
            disassembly: pdf,
            cfg,
            xrefs: normalize_xrefs(&xrefs_raw),
        })
    }

    pub fn collect_xref_probe(
        &self,
        target_path: &str,
        target: &str,
        target_kind: &str,
    ) -> Result<XrefProbe> {
        let xrefs_raw = self.run_json(target_path, &format!("aaa;axtj @ {target}"))?;
        Ok(XrefProbe {
            target: target.to_string(),
            target_kind: target_kind.to_string(),
            xrefs: normalize_xrefs(&xrefs_raw),
        })
    }

    pub fn run_dynamic_json_query(&self, target_path: &str, command: &str) -> Result<Value> {
        validate_dynamic_json_command(command)?;
        self.run_json(target_path, command)
    }

    pub fn search_strings(
        &self,
        target_path: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<StringEntry>> {
        let query = query.trim();
        if query.is_empty() {
            return Err(anyhow!("query cannot be empty"));
        }

        let normalized_limit = limit.clamp(1, 500);
        let query_lower = query.to_ascii_lowercase();
        let strings_raw = self.run_json(target_path, "izzj")?;

        Ok(normalize_strings(&strings_raw)
            .into_iter()
            .filter(|entry| entry.value.to_ascii_lowercase().contains(&query_lower))
            .take(normalized_limit)
            .collect())
    }

    fn run_json(&self, target_path: &str, command: &str) -> Result<Value> {
        let output = Command::new("r2")
            .args([
                "-q0",
                "-e",
                "bin.relocs.apply=true",
                "-e",
                "bin.cache=true",
                "-c",
                command,
                target_path,
            ])
            .output()
            .with_context(|| format!("failed to launch radare2 for command `{command}`"))?;

        if !output.status.success() {
            return Err(anyhow!(
                "radare2 command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        // radare2 may append a null byte (\0) when launched with -0 / pipe
        // mode.  Trim trailing null bytes in addition to whitespace before
        // handing the string to serde_json, otherwise serde_json returns a
        // parse error on the trailing garbage byte.
        let raw = String::from_utf8_lossy(&output.stdout);
        let stdout = raw.trim().trim_end_matches('\0').trim();
        if stdout.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(stdout)
            .with_context(|| format!("failed to parse radare2 JSON for command `{command}`"))
    }
}

fn artifact(
    kind: &str,
    label: impl Into<String>,
    summary: impl Into<String>,
    raw: Value,
    normalized: Value,
) -> CollectedArtifact {
    CollectedArtifact {
        kind: kind.to_string(),
        label: label.into(),
        summary: summary.into(),
        raw,
        normalized,
    }
}

fn normalize_metadata(value: &Value, size: u64, sha256: String) -> BinaryMetadata {
    let bin = value.get("bin").cloned().unwrap_or(Value::Null);
    BinaryMetadata {
        file_type: value
            .get("core")
            .and_then(|core| core.get("type"))
            .and_then(|field| field.as_str())
            .map(str::to_string),
        format: bin
            .get("class")
            .and_then(|field| field.as_str())
            .map(str::to_string),
        os: bin
            .get("os")
            .and_then(|field| field.as_str())
            .map(str::to_string),
        arch: bin
            .get("arch")
            .and_then(|field| field.as_str())
            .map(str::to_string),
        machine: bin
            .get("machine")
            .and_then(|field| field.as_str())
            .map(str::to_string),
        bits: bin.get("bits").and_then(|field| field.as_u64()),
        size,
        sha256,
        entry: value
            .get("bin")
            .and_then(|item| item.get("baddr"))
            .and_then(|field| field.as_u64()),
        compiler: bin
            .get("compiler")
            .and_then(|field| field.as_str())
            .map(str::to_string),
    }
}

fn normalize_sections(value: &Value) -> Vec<ProgramSection> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| ProgramSection {
            name: get_string(item, "name"),
            vaddr: item.get("vaddr").and_then(|field| field.as_u64()),
            paddr: item.get("paddr").and_then(|field| field.as_u64()),
            size: item.get("size").and_then(|field| field.as_u64()),
            vsize: item.get("vsize").and_then(|field| field.as_u64()),
            perm: item
                .get("perm")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            section_type: item
                .get("type")
                .and_then(|field| field.as_str())
                .map(str::to_string),
        })
        .collect()
}

fn normalize_imports(value: &Value) -> Vec<ImportEntry> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| ImportEntry {
            name: get_string(item, "name"),
            bind: item
                .get("bind")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            import_type: item
                .get("type")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            plt: item.get("plt").and_then(|field| field.as_u64()),
        })
        .collect()
}

fn normalize_exports(value: &Value) -> Vec<ExportEntry> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| ExportEntry {
            name: get_string(item, "name"),
            export_type: item
                .get("type")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            vaddr: item.get("vaddr").and_then(|field| field.as_u64()),
            size: item.get("size").and_then(|field| field.as_u64()),
        })
        .collect()
}

fn normalize_symbols(value: &Value) -> Vec<SymbolEntry> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| SymbolEntry {
            name: get_string(item, "name"),
            bind: item
                .get("bind")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            symbol_type: item
                .get("type")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            vaddr: item.get("vaddr").and_then(|field| field.as_u64()),
            size: item.get("size").and_then(|field| field.as_u64()),
            imported: item
                .get("is_imported")
                .and_then(|field| field.as_bool())
                .unwrap_or(false),
        })
        .collect()
}

fn normalize_strings(value: &Value) -> Vec<StringEntry> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let value = item.get("string").and_then(|field| field.as_str())?;
            Some(StringEntry {
                id: format!(
                    "string:{}",
                    item.get("ordinal")
                        .and_then(|field| field.as_u64())
                        .unwrap_or_default()
                ),
                value: value.to_string(),
                section: item
                    .get("section")
                    .and_then(|field| field.as_str())
                    .map(str::to_string),
                string_type: item
                    .get("type")
                    .and_then(|field| field.as_str())
                    .map(str::to_string),
                ordinal: item.get("ordinal").and_then(|field| field.as_u64()),
                vaddr: item.get("vaddr").and_then(|field| field.as_u64()),
                length: item.get("length").and_then(|field| field.as_u64()),
            })
        })
        .collect()
}

fn normalize_functions(value: &Value) -> Vec<FunctionSummary> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| FunctionSummary {
            name: get_string(item, "name"),
            addr: item
                .get("addr")
                .and_then(|field| field.as_u64())
                .unwrap_or_default(),
            size: item
                .get("size")
                .and_then(|field| field.as_u64())
                .unwrap_or_default(),
            indegree: item.get("indegree").and_then(|field| field.as_u64()),
            outdegree: item.get("outdegree").and_then(|field| field.as_u64()),
            cyclomatic_cost: item.get("cost").and_then(|field| field.as_u64()),
            call_targets: item
                .get("imports")
                .and_then(|field| field.as_array())
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.as_str().map(str::to_string))
                .collect(),
        })
        .collect()
}

fn normalize_call_edges(value: &Value) -> Vec<CallEdge> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|item| {
            let from = get_string(item, "name");
            item.get("imports")
                .and_then(|field| field.as_array())
                .into_iter()
                .flatten()
                .filter_map(move |target| {
                    target.as_str().map(|target| CallEdge {
                        from: from.clone(),
                        to: target.to_string(),
                        relation: "calls".to_string(),
                    })
                })
        })
        .collect()
}

fn normalize_xrefs(value: &Value) -> Vec<XrefEntry> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| XrefEntry {
            from: item.get("from").and_then(|field| field.as_u64()),
            target: item.get("to").map(|field| match field {
                Value::String(text) => text.clone(),
                Value::Number(number) => format!("0x{:x}", number.as_u64().unwrap_or_default()),
                _ => field.to_string(),
            }),
            kind: item
                .get("type")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            opcode: item
                .get("opcode")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            function_name: item
                .get("fcn_name")
                .and_then(|field| field.as_str())
                .map(str::to_string),
            ref_name: item
                .get("refname")
                .and_then(|field| field.as_str())
                .map(str::to_string),
        })
        .collect()
}

fn get_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|field| field.as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn matches_keyword(value: &str, keywords: &[&str]) -> bool {
    let lower = value.to_ascii_lowercase();
    keywords.iter().any(|keyword| lower.contains(keyword))
}

fn truncate(value: &str) -> String {
    if value.len() > 40 {
        format!("{}...", &value[..40])
    } else {
        value.to_string()
    }
}

fn validate_dynamic_json_command(command: &str) -> Result<()> {
    let command = command.trim();
    if command.is_empty() {
        return Err(anyhow!("command cannot be empty"));
    }
    if command.len() > 256 {
        return Err(anyhow!("command too long; keep under 256 characters"));
    }
    if command.contains('\n') || command.contains('\r') || command.contains('\0') {
        return Err(anyhow!("command contains invalid control characters"));
    }

    for segment in command.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }

        let token = segment.split_whitespace().next().unwrap_or_default();

        if token.is_empty()
            || token == "q"
            || token.starts_with('!')
            || token.starts_with('w')
            || token.starts_with("oo+")
            || token.starts_with("doo")
            || token.starts_with("dc")
            || token.starts_with("db")
            || token.starts_with("dr")
            || token.starts_with("e")
        {
            return Err(anyhow!(
                "command segment `{token}` is not allowed; only read-only JSON queries are permitted"
            ));
        }

        // Analysis bootstraps and the seek command are pure side-effects with
        // no output — they are only useful as prefixes in compound commands.
        if matches!(token, "aaa" | "aaaa" | "aa" | "aaj" | "aaaj" | "s") {
            continue;
        }

        if !is_allowed_dynamic_token(token) {
            return Err(anyhow!(
                "command segment `{token}` is not in the allowed dynamic query set"
            ));
        }
    }

    Ok(())
}

fn is_allowed_dynamic_token(token: &str) -> bool {
    matches!(
        token,
        // ── Binary metadata ───────────────────────────────────────────────────
        "ij"        // full info JSON (arch, bits, OS, entry, compiler …)
        | "iij"     // imports table
        | "iEj"     // exports table
        | "isj"     // symbols table
        | "iSj"     // sections table (names, vaddr, paddr, perm)
        | "iSSj"    // segments table
        | "iej"     // entry points (main, TLS callbacks, DllMain)
        | "ilj"     // linked/imported libraries
        | "ihj"     // PE/ELF file headers
        | "iRj"     // embedded resources (icons, dialogs, manifests)
        | "iVj"     // version information block
        | "icj"     // classes / OOP structure
        | "itj"     // try-catch / exception table
        | "ipj"     // patches applied
        | "ifj"     // fields
        // ── Strings ───────────────────────────────────────────────────────────
        | "izzj"    // all strings in all sections (widest net)
        | "izj"     // strings in data section only
        // ── Functions ────────────────────────────────────────────────────────
        | "aflj"    // function list with address, size, complexity metrics
        | "afij"    // function info at current offset
        | "afbj"    // function basic blocks
        | "afcj"    // function call references
        | "aftj"    // function type signature
        | "afvj"    // function local variables
        | "afxj"    // function cross-references
        | "afnj"    // function name info
        // ── Graphs ────────────────────────────────────────────────────────────
        | "agCj"    // global call graph (all functions)
        | "agfj"    // function CFG at current offset
        | "agj"     // mini call graph at current offset
        | "agtj"    // global call tree
        // ── Cross-references ──────────────────────────────────────────────────
        | "axtj"    // xrefs TO current address/symbol (who calls this)
        | "axfj"    // xrefs FROM current address/symbol (what does it call)
        | "axj"     // all cross-references
        // ── Disassembly ───────────────────────────────────────────────────────
        | "pdfj"    // disassemble full function at current offset
        | "pdj"     // disassemble N instructions at current offset
        | "pdbj"    // disassemble current basic block
        | "pij"     // print N instruction info objects
        // ── Hex / raw bytes ───────────────────────────────────────────────────
        | "pxj"     // print hex dump as JSON at current offset
        | "pcj"     // print bytes as C array JSON
        // ── Search ────────────────────────────────────────────────────────────
        | "/xj"     // search hex bytes, return JSON hit list
        | "/cj"     // search assembler pattern, return JSON hit list
        | "/j"      // search string, return JSON hit list
        | "/rj"     // search referenced strings, return JSON
        // ── Analysis ─────────────────────────────────────────────────────────
        | "aaj"     // short analysis pass (faster than aaa)
        | "aaaj"    // deep analysis pass (slower, more type info)
        | "aobj"    // analyse opcode at current offset
        | "abj"     // analyse basic block at current offset
        | "ablj"    // list all basic blocks in the binary
        // ── Flags ────────────────────────────────────────────────────────────
        | "fj"      // all flags (named address bookmarks)
        | "flj"     // flags list ordered by name
        | "fsj"     // flag spaces (namespaces)
        // ── Types / debug info ────────────────────────────────────────────────
        | "tj"      // types list
        | "toj"     // type objects
        | "tdj"     // type definitions
        // ── Misc read-only ────────────────────────────────────────────────────
        | "?j" // evaluate radare2 expression / address math (JSON)
    )
}

#[cfg(test)]
mod tests {
    use super::validate_dynamic_json_command;

    #[test]
    fn allows_read_only_json_command_matrix() {
        let allowed = [
            "ij",
            "iSj",
            "iSSj",
            "iij",
            "iEj",
            "isj",
            "izzj",
            "izj",
            "aaa;aflj",
            "aa;agCj",
            "aaa;agfj @ sym.main",
            "aaa;pdfj @ 0x401000",
            "aaa;axtj @ sym.imp.socket",
            "pdj 32 @ entry0",
            "  aaa;afij @ sym.main  ",
        ];

        for command in allowed {
            assert!(
                validate_dynamic_json_command(command).is_ok(),
                "expected command to be allowed: {command}"
            );
        }
    }

    #[test]
    fn rejects_dangerous_or_non_json_commands() {
        let rejected = [
            "",
            "   ",
            "q",
            "!sh",
            "wq",
            "wx 90",
            "oo+",
            "doo",
            "dc",
            "db sym.main",
            "dr",
            "e io.cache=true",
            "afl",
            "aaa;afl",
            "ij\naflj",
            "ij\raflj",
            "ij\0aflj",
            "aaa;izzzj",
        ];

        for command in rejected {
            assert!(
                validate_dynamic_json_command(command).is_err(),
                "expected command to be rejected: {command:?}"
            );
        }
    }

    #[test]
    fn rejects_overlong_commands() {
        let overlong = "a".repeat(257);
        assert!(validate_dynamic_json_command(&overlong).is_err());
    }
}
