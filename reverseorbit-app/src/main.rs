mod action_handlers;
mod adapter;
mod analysis;
mod api;
mod error_kind;
mod finding_explain;
mod state;

use std::{
    io::{BufReader, stdout},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;

use reverseorbit_core::{AnalysisProfile, CreateCaseRequest, default_case_request};
use reverseorbit_mcp::{
    ToolSchema, error, error_result, read_message, success, text_result, write_message,
};

use crate::{
    analysis::{
        create_case, export_case, run_action, run_blocking_with_timeout, run_case_analysis,
    },
    finding_explain::build_finding_explanation,
    state::build_state,
};

#[derive(Debug, Parser)]
#[command(name = "reverseorbit")]
#[command(about = "ReverseOrbit local reverse-engineering workbench")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Analyze {
        file: String,
        #[arg(long, value_enum, default_value_t = ProfileArg::Quick)]
        profile: ProfileArg,
        #[arg(long)]
        open_ui: bool,
        #[arg(long)]
        cases_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 4080)]
        port: u16,
    },
    Server {
        #[arg(long)]
        cases_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 4080)]
        port: u16,
    },
    Mcp {
        #[arg(long)]
        cases_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    Quick,
    Full,
}

impl From<ProfileArg> for AnalysisProfile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Quick => AnalysisProfile::Quick,
            ProfileArg::Full => AnalysisProfile::Full,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Always write tracing output to stderr.
    //
    // In MCP mode the server communicates over stdout using the LSP/MCP
    // Content-Length framing protocol.  If the tracing subscriber writes to
    // stdout (the default in tracing-subscriber 0.3), every log line corrupts
    // the framing and the MCP host loses sync immediately.  Redirecting to
    // stderr is safe for all subcommands and costs nothing.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Analyze {
            file,
            profile,
            open_ui,
            cases_dir,
            port,
        } => {
            let state = runtime_state(cases_dir)?;
            let request = default_case_request(file, profile.into());
            let manifest = create_case(&state, &request)?;
            let summary =
                run_case_analysis(state.clone(), manifest.id.clone(), request.profile).await?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            if open_ui {
                let url = format!("http://127.0.0.1:{port}/?case={}", manifest.id);
                let _ = webbrowser::open(&url);
                api::serve(state, port).await?;
            }
        }
        Commands::Server { cases_dir, port } => {
            let state = runtime_state(cases_dir)?;
            api::serve(state, port).await?;
        }
        Commands::Mcp { cases_dir } => {
            let state = runtime_state(cases_dir)?;
            serve_mcp(state).await?;
        }
    }

    Ok(())
}

fn runtime_state(cases_dir: Option<PathBuf>) -> Result<state::AppState> {
    let root = std::env::current_dir()?;
    let cases = cases_dir.unwrap_or_else(|| root.join(".reverseorbit/cases"));
    let web_dist = root.join("web/dist");
    Ok(build_state(cases, web_dist))
}

async fn serve_mcp(state: state::AppState) -> Result<()> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut out = stdout().lock();

    while let Some(message) = read_message(&mut reader)? {
        // Notifications do not carry an id field; silently drop them.
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let method = message
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let params = message.get("params").cloned().unwrap_or(Value::Null);

        // Notifications MUST NOT receive a response — even if the client
        // incorrectly attached an id.  Sending a reply confuses strict rmcp
        // clients (Codex v0.49+) and causes them to drop the connection.
        if method.starts_with("notifications/") || method.starts_with("$/") {
            continue;
        }

        let response = match method {
            "initialize" => {
                // Echo back whatever protocolVersion the client advertised.
                // Codex v0.49+ uses "2025-06-18"; older clients use
                // "2024-11-05".  The strict Rust rmcp client closes the
                // connection if the server responds with a *different* version,
                // so we must mirror it rather than hard-coding our own.
                let protocol_version = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2024-11-05")
                    .to_string();

                success(
                    id,
                    json!({
                        "protocolVersion": protocol_version,
                        "capabilities": {
                            "tools": {
                                "listChanged": false
                            }
                        },
                        "serverInfo": {
                            "name": "reverseorbit",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }),
                )
            }
            // Keepalive / health-check probe sent by many MCP hosts.
            "ping" => success(id, json!({})),
            "tools/list" => success(id, json!({ "tools": tool_schemas() })),
            // Per MCP 2024-11-05: tool execution errors must travel inside
            // `result` as `isError: true`, not as JSON-RPC error objects.
            // Returning a JSON-RPC error for a tool failure causes some hosts
            // to tear down the connection instead of surfacing the message.
            "tools/call" => match handle_tool_call(state.clone(), params).await {
                Ok(result) => success(id, result),
                Err(tool_error) => success(id, error_result(tool_error.to_string())),
            },
            _ => error(Some(id), -32601, "method not found"),
        };
        write_message(&mut out, &response)?;
    }

    Ok(())
}

pub(crate) async fn handle_tool_call(state: state::AppState, params: Value) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("tool name missing"))?;
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    let text = match name {
        "start_case" => {
            let request: CreateCaseRequest = serde_json::from_value(arguments.clone())?;
            let manifest = create_case(&state, &request)?;
            let summary = run_case_analysis(state, manifest.id.clone(), request.profile).await?;
            serde_json::to_string_pretty(&summary)?
        }
        "list_cases" => serde_json::to_string_pretty(&state.store.list_cases()?)?,
        "get_case_summary" => {
            let case_id = required_string(&arguments, "case_id")?;
            serde_json::to_string_pretty(&state.store.case_summary(case_id)?)?
        }
        "get_timeline" => {
            let case_id = required_string(&arguments, "case_id")?;
            serde_json::to_string_pretty(&state.store.load_timeline(case_id)?)?
        }
        "inspect_entity" => {
            let case_id = required_string(&arguments, "case_id")?;
            let entity = required_string(&arguments, "entity")?;
            let detail = inspect_entity(&state, case_id, entity)?;
            serde_json::to_string_pretty(&detail)?
        }
        "query_findings" => {
            let case_id = required_string(&arguments, "case_id")?;
            let query = arguments
                .get("query")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let findings = state
                .store
                .load_findings(case_id)?
                .into_iter()
                .filter(|finding| {
                    query.is_empty()
                        || finding
                            .title
                            .to_ascii_lowercase()
                            .contains(&query.to_ascii_lowercase())
                        || finding
                            .summary
                            .to_ascii_lowercase()
                            .contains(&query.to_ascii_lowercase())
                })
                .collect::<Vec<_>>();
            serde_json::to_string_pretty(&findings)?
        }
        "explain_finding" => {
            let case_id = required_string(&arguments, "case_id")?;
            let finding_id = required_string(&arguments, "finding_id")?;
            serde_json::to_string_pretty(&explain_finding(&state, case_id, finding_id)?)?
        }
        "get_graph_view" => {
            let case_id = required_string(&arguments, "case_id")?;
            let view = required_string(&arguments, "view")?;
            let view = match view {
                "provenance" => reverseorbit_core::GraphViewKind::Provenance,
                "call_graph" => reverseorbit_core::GraphViewKind::CallGraph,
                "cfg" => reverseorbit_core::GraphViewKind::Cfg,
                "xref_view" => reverseorbit_core::GraphViewKind::XrefView,
                "string_relation_view" => reverseorbit_core::GraphViewKind::StringRelationView,
                _ => return Err(anyhow!("unknown graph view")),
            };
            serde_json::to_string_pretty(&state.store.load_graph(case_id, view)?)?
        }
        "run_next_action" => {
            let case_id = required_string(&arguments, "case_id")?;
            let action_id = required_string(&arguments, "action_id")?;
            serde_json::to_string_pretty(
                &run_action(state, case_id.to_string(), action_id.to_string()).await?,
            )?
        }
        "export_case" => {
            let case_id = required_string(&arguments, "case_id")?;
            serde_json::to_string_pretty(&export_case(&state, case_id)?)?
        }
        "list_radare_commands" => serde_json::to_string_pretty(&radare_command_catalog())?,
        "run_radare_query" => {
            let case_id = required_string(&arguments, "case_id")?;
            let command = required_string(&arguments, "command")?.trim().to_string();
            if command.is_empty() {
                return Err(anyhow!("missing `command`"));
            }

            let timeout_sec = optional_u64(&arguments, "timeout_sec", 45, 5, 180);
            let max_items = optional_usize(&arguments, "max_items", 1000, 1, 10_000);
            tracing::info!(
                case_id = %case_id,
                command = %command,
                timeout_sec,
                max_items,
                "running dynamic radare query via MCP"
            );
            let manifest = state.store.load_manifest(case_id)?;
            let target_path = manifest.target_path;
            let adapter = state.adapter.clone();
            let command_for_task = command.clone();

            let result = run_blocking_with_timeout(
                Duration::from_secs(timeout_sec),
                "running dynamic radare2 query",
                move || adapter.run_dynamic_json_query(&target_path, &command_for_task),
            )
            .await
            .map_err(|error| {
                tracing::warn!(
                    case_id = %case_id,
                    command = %command,
                    error = %error,
                    "dynamic radare query failed"
                );
                error
            })?;

            let top_level_items = result.as_array().map(|items| items.len());
            let (result, truncated) = truncate_top_level_array(result, max_items);
            tracing::info!(
                case_id = %case_id,
                command = %command,
                timeout_sec,
                max_items,
                top_level_items = top_level_items.unwrap_or(0),
                truncated,
                "dynamic radare query completed"
            );
            serde_json::to_string_pretty(&json!({
                "case_id": case_id,
                "command": command,
                "timeout_sec": timeout_sec,
                "max_items": max_items,
                "truncated": truncated,
                "result": result,
            }))?
        }
        "search_strings_live" => {
            let case_id = required_string(&arguments, "case_id")?;
            let query = required_string(&arguments, "query")?.to_string();
            let timeout_sec = optional_u64(&arguments, "timeout_sec", 45, 5, 180);
            let limit = optional_usize(&arguments, "limit", 50, 1, 500);
            tracing::info!(
                case_id = %case_id,
                query_len = query.len(),
                timeout_sec,
                limit,
                "running live string search via MCP"
            );
            let manifest = state.store.load_manifest(case_id)?;
            let target_path = manifest.target_path;
            let adapter = state.adapter.clone();
            let query_for_task = query.clone();

            let strings = run_blocking_with_timeout(
                Duration::from_secs(timeout_sec),
                "searching strings with radare2",
                move || adapter.search_strings(&target_path, &query_for_task, limit),
            )
            .await
            .map_err(|error| {
                tracing::warn!(
                    case_id = %case_id,
                    query_len = query.len(),
                    error = %error,
                    "live string search failed"
                );
                error
            })?;

            tracing::info!(
                case_id = %case_id,
                query_len = query.len(),
                timeout_sec,
                limit,
                match_count = strings.len(),
                "live string search completed"
            );

            serde_json::to_string_pretty(&json!({
                "case_id": case_id,
                "query": query,
                "limit": limit,
                "timeout_sec": timeout_sec,
                "count": strings.len(),
                "strings": strings,
            }))?
        }
        "analyze_crackme" => {
            let case_id = required_string(&arguments, "case_id")?;
            let timeout_sec = optional_u64(&arguments, "timeout_sec", 120, 10, 300);
            let manifest = state.store.load_manifest(case_id)?;
            let target_path = manifest.target_path.clone();
            let adapter = state.adapter.clone();

            // 1. Entry points
            let entries = run_blocking_with_timeout(
                Duration::from_secs(timeout_sec),
                "collecting entry points",
                move || adapter.collect_entrypoints(&target_path),
            )
            .await
            .unwrap_or(serde_json::Value::Null);

            // 2. All findings already generated
            let findings = state.store.load_findings(case_id)?;

            // 3. Snapshot for imports + strings
            let artifacts = state.store.load_artifacts(case_id)?;
            let snapshot_art = artifacts.iter().find(|a| a.kind == "snapshot");
            let comparison_imports: Vec<String>;
            let validation_strings: Vec<String>;
            if let Some(art) = snapshot_art {
                let (_, normalized, _) = state.store.load_artifact_payload(case_id, &art.id)?;
                let snap: reverseorbit_core::NormalizedSnapshot =
                    serde_json::from_value(normalized)?;
                comparison_imports = snap
                    .suspicious_imports
                    .iter()
                    .filter(|i| {
                        let l = i.to_ascii_lowercase();
                        l.contains("strcmp")
                            || l.contains("memcmp")
                            || l.contains("lstrcmp")
                            || l.contains("stricmp")
                            || l.contains("getwindowtext")
                            || l.contains("getdlgitemtext")
                    })
                    .cloned()
                    .collect();
                validation_strings = snap
                    .suspicious_strings
                    .iter()
                    .filter(|s| {
                        let l = s.to_ascii_lowercase();
                        l.contains("correct")
                            || l.contains("wrong")
                            || l.contains("bad boy")
                            || l.contains("good boy")
                            || l.contains("congratul")
                            || l.contains("invalid")
                            || l.contains("access")
                            || l.contains("serial")
                            || l.contains("license")
                    })
                    .cloned()
                    .collect();
            } else {
                comparison_imports = vec![];
                validation_strings = vec![];
            }

            let crackme_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.category.as_str(),
                        "string_comparison"
                            | "input_capture"
                            | "crackme_validation"
                            | "license_check"
                            | "anti_debug"
                            | "memory_manipulation"
                    )
                })
                .collect();

            serde_json::to_string_pretty(&serde_json::json!({
                "case_id": case_id,
                "target": manifest.target_path,
                "entry_points": entries,
                "crackme_relevant_findings": crackme_findings,
                "comparison_imports": comparison_imports,
                "validation_strings": validation_strings,
                "recommended_workflow": [
                    "1. Use inspect_entity or run_radare_query with `aaa;axtj @ sym.imp.strcmp` to find where comparisons happen",
                    "2. Use run_radare_query with `aaa;pdfj @ <function_addr>` to disassemble the key-check function",
                    "3. Look at the validation_strings xrefs — the branch before 'Correct!' is the patch point",
                    "4. Use run_radare_query with `izzj` to dump all strings and search for the expected key",
                    "5. Check comparison_imports xrefs to find what the binary compares your input against"
                ]
            }))?
        }
        "get_entrypoints" => {
            let case_id = required_string(&arguments, "case_id")?;
            let manifest = state.store.load_manifest(case_id)?;
            let target_path = manifest.target_path;
            let adapter = state.adapter.clone();
            let result = run_blocking_with_timeout(
                Duration::from_secs(60),
                "collecting entry points",
                move || adapter.collect_entrypoints(&target_path),
            )
            .await?;
            serde_json::to_string_pretty(&result)?
        }
        _ => return Err(anyhow!("unknown tool")),
    };

    Ok(text_result(text))
}

pub(crate) fn tool_schemas() -> Vec<ToolSchema> {
    vec![
        ToolSchema {
            name: "start_case".to_string(),
            description: "Create a ReverseOrbit case and run baseline static analysis on a local binary.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["target_path"],
                "properties": {
                    "target_path": { "type": "string" },
                    "label": { "type": "string" },
                    "profile": { "type": "string", "enum": ["quick", "full"] }
                }
            }),
        },
        ToolSchema {
            name: "list_cases".to_string(),
            description: "List locally stored ReverseOrbit cases.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        ToolSchema {
            name: "get_case_summary".to_string(),
            description: "Return summary metadata and counts for a case.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id"],
                "properties": { "case_id": { "type": "string" } }
            }),
        },
        ToolSchema {
            name: "get_timeline".to_string(),
            description: "Return the step-by-step reverse engineering timeline for a case.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id"],
                "properties": { "case_id": { "type": "string" } }
            }),
        },
        ToolSchema {
            name: "inspect_entity".to_string(),
            description: "Inspect a function, import, string, or artifact related to a case.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id", "entity"],
                "properties": {
                    "case_id": { "type": "string" },
                    "entity": { "type": "string" }
                }
            }),
        },
        ToolSchema {
            name: "query_findings".to_string(),
            description: "Search the deterministic findings generated for a case.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id"],
                "properties": {
                    "case_id": { "type": "string" },
                    "query": { "type": "string" }
                }
            }),
        },
        ToolSchema {
            name: "explain_finding".to_string(),
            description: "Explain why a finding was created, including evidence-backed context and related next actions.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id", "finding_id"],
                "properties": {
                    "case_id": { "type": "string" },
                    "finding_id": { "type": "string" }
                }
            }),
        },
        ToolSchema {
            name: "get_graph_view".to_string(),
            description: "Return a specific graph view as node and edge JSON.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id", "view"],
                "properties": {
                    "case_id": { "type": "string" },
                    "view": { "type": "string", "enum": ["provenance", "call_graph", "cfg", "xref_view", "string_relation_view"] }
                }
            }),
        },
        ToolSchema {
            name: "run_next_action".to_string(),
            description: "Execute one ReverseOrbit follow-up action such as xref collection or CFG expansion.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id", "action_id"],
                "properties": {
                    "case_id": { "type": "string" },
                    "action_id": { "type": "string" }
                }
            }),
        },
        ToolSchema {
            name: "list_radare_commands".to_string(),
            description: "List supported dynamic radare2 JSON query command templates for MCP-driven exploration.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        ToolSchema {
            name: "run_radare_query".to_string(),
            description: "Run a safe dynamic radare2 JSON query command against a case target binary.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id", "command"],
                "properties": {
                    "case_id": { "type": "string" },
                    "command": { "type": "string" },
                    "timeout_sec": { "type": "integer", "minimum": 5, "maximum": 180 },
                    "max_items": { "type": "integer", "minimum": 1, "maximum": 10000 }
                }
            }),
        },
        ToolSchema {
            name: "search_strings_live".to_string(),
            description: "Run a live radare2-backed string search against the case target binary.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id", "query"],
                "properties": {
                    "case_id": { "type": "string" },
                    "query": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500 },
                    "timeout_sec": { "type": "integer", "minimum": 5, "maximum": 180 }
                }
            }),
        },
        ToolSchema {
            name: "export_case".to_string(),
            description: "Export case graphs as GraphML files inside the case folder.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id"],
                "properties": { "case_id": { "type": "string" } }
            }),
        },
        ToolSchema {
            name: "analyze_crackme".to_string(),
            description: "Run a targeted crackme analysis: finds comparison functions, validation strings, entry points, and crackme-specific findings. Returns a structured workflow for cracking the binary.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id"],
                "properties": {
                    "case_id": { "type": "string" },
                    "timeout_sec": { "type": "integer", "minimum": 10, "maximum": 300 }
                }
            }),
        },
        ToolSchema {
            name: "get_entrypoints".to_string(),
            description: "Return all binary entry points (main, TLS callbacks, DllMain, etc.) with addresses.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["case_id"],
                "properties": { "case_id": { "type": "string" } }
            }),
        },
    ]
}

fn inspect_entity(state: &state::AppState, case_id: &str, entity: &str) -> Result<Value> {
    let artifacts = state.store.load_artifacts(case_id)?;
    if let Some(artifact) = artifacts
        .iter()
        .find(|artifact| artifact.id == entity || artifact.label == entity)
    {
        let (_, normalized, raw) = state.store.load_artifact_payload(case_id, &artifact.id)?;
        return Ok(json!({ "artifact": artifact, "normalized": normalized, "raw": raw }));
    }

    let (_, normalized, _) = {
        let snapshot_artifact = artifacts
            .iter()
            .find(|artifact| artifact.kind == "snapshot")
            .ok_or_else(|| anyhow!("snapshot missing"))?;
        state
            .store
            .load_artifact_payload(case_id, &snapshot_artifact.id)?
    };
    let snapshot: reverseorbit_core::NormalizedSnapshot = serde_json::from_value(normalized)?;

    if let Some(function) = snapshot
        .functions
        .iter()
        .find(|function| function.name == entity)
    {
        return Ok(serde_json::to_value(function)?);
    }
    if let Some(detail) = snapshot
        .function_details
        .iter()
        .find(|detail| detail.name == entity)
    {
        return Ok(serde_json::to_value(detail)?);
    }
    if let Some(import_entry) = snapshot
        .imports
        .iter()
        .find(|import_entry| import_entry.name == entity)
    {
        return Ok(serde_json::to_value(import_entry)?);
    }
    if let Some(string) = snapshot
        .strings
        .iter()
        .find(|string| string.value == entity)
    {
        return Ok(serde_json::to_value(string)?);
    }
    Err(anyhow!("entity not found"))
}

fn explain_finding(state: &state::AppState, case_id: &str, finding_id: &str) -> Result<Value> {
    build_finding_explanation(&state.store, case_id, finding_id)
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(|item| item.as_str())
        .ok_or_else(|| anyhow!("missing `{key}`"))
}

fn optional_u64(value: &Value, key: &str, default: u64, min: u64, max: u64) -> u64 {
    value
        .get(key)
        .and_then(|item| item.as_u64())
        .map(|raw| raw.clamp(min, max))
        .unwrap_or(default)
}

fn optional_usize(value: &Value, key: &str, default: usize, min: usize, max: usize) -> usize {
    value
        .get(key)
        .and_then(|item| item.as_u64())
        .and_then(|raw| usize::try_from(raw).ok())
        .map(|raw| raw.clamp(min, max))
        .unwrap_or(default)
}

fn truncate_top_level_array(value: Value, max_items: usize) -> (Value, bool) {
    match value {
        Value::Array(mut items) => {
            let truncated = items.len() > max_items;
            if truncated {
                items.truncate(max_items);
            }
            (Value::Array(items), truncated)
        }
        other => (other, false),
    }
}

fn radare_command_catalog() -> Value {
    json!({
        // ── CATEGORY: Binary metadata ──────────────────────────────────────────
        "binary_metadata": [
            { "cmd": "ij",    "json": true,  "desc": "Full binary info: arch, bits, OS, endian, entry, compiler, pic, nx, canary" },
            { "cmd": "iij",   "json": true,  "desc": "Imports table — DLL/SO names + function names + PLT addresses" },
            { "cmd": "iEj",   "json": true,  "desc": "Exports table — exported function names and addresses" },
            { "cmd": "isj",   "json": true,  "desc": "Symbols — all named symbols (including debug info if present)" },
            { "cmd": "iSj",   "json": true,  "desc": "Sections: .text, .data, .rdata, .rsrc … with vaddr/paddr/perm" },
            { "cmd": "iSSj",  "json": true,  "desc": "Segments (PE headers, ELF load segments)" },
            { "cmd": "iej",   "json": true,  "desc": "Entry points: main, TLS callbacks, DllMain, _start" },
            { "cmd": "ilj",   "json": true,  "desc": "Linked libraries (DLL/SO dependencies)" },
            { "cmd": "ihj",   "json": true,  "desc": "File headers (PE/ELF/Mach-O native header fields)" },
            { "cmd": "iRj",   "json": true,  "desc": "Resources: icons, dialogs, version blocks, manifests (PE)" },
            { "cmd": "iVj",   "json": true,  "desc": "Version information block (ProductName, FileVersion …)" },
            { "cmd": "ipj",   "json": true,  "desc": "Patches that have been applied (write-mode only)" },
            { "cmd": "icj",   "json": true,  "desc": "Classes / OOP structures detected by radare2" }
        ],

        // ── CATEGORY: Strings ──────────────────────────────────────────────────
        "strings": [
            { "cmd": "izzj",                   "json": true,  "desc": "ALL strings in every section — widest net; use this first for crackmes to find 'Good cracker!', 'Bad password!'" },
            { "cmd": "izj",                    "json": true,  "desc": "Strings in data section only (faster, misses code-section strings)" },
            { "cmd": "aa; izz~<keyword>",      "json": false, "desc": "Search strings containing keyword (text grep, not JSON). E.g. 'aa; izz~Password'" },
            { "cmd": "aa; izz~Good cracker",   "json": false, "desc": "Find the success message string (crackme-specific)" },
            { "cmd": "aa; izz~Bad password",   "json": false, "desc": "Find the failure message string (crackme-specific)" },
            { "cmd": "aa; izz~Password :",     "json": false, "desc": "Find the password prompt string (crackme-specific)" }
        ],

        // ── CATEGORY: Search ───────────────────────────────────────────────────
        "search": [
            { "cmd": "/xj <hex>",                  "json": true,  "desc": "Search hex byte pattern — returns JSON list of hit addresses. E.g. '/xj 3d37a354007507'" },
            { "cmd": "/xj 3d37a354007507",         "json": true,  "desc": "CRACKME: search for 'cmp eax, 0x54a337; jne' byte sequence (specific to crackme-easy-1.exe)" },
            { "cmd": "/cj <asm>",                  "json": true,  "desc": "Search for assembly pattern — e.g. '/cj jne'" },
            { "cmd": "/j <string>",                "json": true,  "desc": "Search for ASCII string bytes in binary" },
            { "cmd": "/rj <string>",               "json": true,  "desc": "Search referenced strings matching pattern" }
        ],

        // ── CATEGORY: Functions ────────────────────────────────────────────────
        "functions": [
            { "cmd": "aaa;aflj",          "json": true,  "desc": "Full analysis then function list: name, addr, size, cyclomatic complexity, call degree" },
            { "cmd": "aaa;afij",          "json": true,  "desc": "Function info at current offset (bounds, size, locals, args)" },
            { "cmd": "aaa;afbj",          "json": true,  "desc": "Basic blocks of function at current offset" },
            { "cmd": "aaa;afvj",          "json": true,  "desc": "Local variables of function at current offset" },
            { "cmd": "aaa;afxj",          "json": true,  "desc": "All xrefs for function at current offset" }
        ],

        // ── CATEGORY: Disassembly ──────────────────────────────────────────────
        "disassembly": [
            { "cmd": "aaa;pdfj @ <func_or_addr>",  "json": true,  "desc": "Disassemble complete function at name or address" },
            { "cmd": "aaa;pdfj @ entry0",           "json": true,  "desc": "Disassemble the main entry point function" },
            { "cmd": "s <addr>; pdfj",              "json": true,  "desc": "Seek to address then disassemble function. E.g. 's 0x401090; pdfj'" },
            { "cmd": "s 0x401090; pdfj",            "json": true,  "desc": "CRACKME: disassemble the hash/key routine at 0x401090 (crackme-easy-1.exe)" },
            { "cmd": "s 0x401020; pdj 24",          "json": true,  "desc": "CRACKME: disassemble 24 instructions starting at 0x401020 (crackme-easy-1.exe main check)" },
            { "cmd": "pdj <n> @ <addr>",            "json": true,  "desc": "Disassemble N instructions at address. E.g. 'pdj 32 @ 0x401040'" },
            { "cmd": "pdbj",                        "json": true,  "desc": "Disassemble current basic block" }
        ],

        // ── CATEGORY: Hex / bytes ──────────────────────────────────────────────
        "hex_bytes": [
            { "cmd": "s <addr>; pxj <n>",    "json": true,  "desc": "Seek to address then print N hex bytes as JSON. E.g. 's 0x40104b; pxj 8'" },
            { "cmd": "s 0x40104b; pxj 2",    "json": true,  "desc": "CRACKME: inspect the 2 bytes at the patch address 0x40104b (crackme-easy-1.exe)" },
            { "cmd": "pcj <n> @ <addr>",      "json": true,  "desc": "Print N bytes at address as C array JSON" }
        ],

        // ── CATEGORY: Cross-references ─────────────────────────────────────────
        "xrefs": [
            { "cmd": "aaa;axtj @ sym.imp.strcmp",           "json": true,  "desc": "CRACKME: all callers of strcmp — find the key comparison site" },
            { "cmd": "aaa;axtj @ sym.imp.lstrcmpA",         "json": true,  "desc": "CRACKME: callers of lstrcmpA (Windows wide strcmp)" },
            { "cmd": "aaa;axtj @ sym.imp.memcmp",           "json": true,  "desc": "CRACKME: callers of memcmp — raw memory comparison" },
            { "cmd": "aaa;axtj @ sym.imp.GetWindowTextA",   "json": true,  "desc": "CRACKME: where dialog text (the serial you type) is read" },
            { "cmd": "aaa;axtj @ sym.imp.GetDlgItemTextA",  "json": true,  "desc": "CRACKME: where dialog field text is captured" },
            { "cmd": "aaa;axtj @ sym.imp.IsDebuggerPresent","json": true,  "desc": "CRACKME: anti-debug check — find it to bypass" },
            { "cmd": "aaa;axtj @ <addr_or_sym>",            "json": true,  "desc": "All callers / references to any address or symbol" },
            { "cmd": "aaa;axfj @ <addr_or_sym>",            "json": true,  "desc": "All calls / references FROM an address or function" }
        ],

        // ── CATEGORY: CFG / graphs ─────────────────────────────────────────────
        "graphs": [
            { "cmd": "aaa;agfj @ <func_or_addr>", "json": true,  "desc": "Control-flow graph of function (nodes = basic blocks, edges = branches)" },
            { "cmd": "aaa;agCj",                  "json": true,  "desc": "Global call graph across all functions" }
        ],

        // ── CATEGORY: Flags ────────────────────────────────────────────────────
        "flags": [
            { "cmd": "fj",    "json": true,  "desc": "All flags (named addresses: functions, strings, imports, …)" },
            { "cmd": "flj",   "json": true,  "desc": "Flags sorted by name" },
            { "cmd": "fsj",   "json": true,  "desc": "Flag spaces / namespaces (sym, str, reloc, …)" }
        ],

        // ── CRACKME QUICKSTART ─────────────────────────────────────────────────
        "crackme_quickstart": {
            "description": "5-step workflow to crack crackme-easy-1.exe (or any serial crackme)",
            "steps": [
                {
                    "step": 1,
                    "goal": "Find validation strings",
                    "cmd": "izzj",
                    "why": "Dump all strings — look for 'Good cracker!', 'Bad password!', 'Password :'. Their addresses will anchor the key-check function."
                },
                {
                    "step": 2,
                    "goal": "Find the byte sequence for the comparison + branch",
                    "cmd": "/xj 3d37a354007507",
                    "why": "Search for the exact bytes of 'cmp eax, 0x54a337; jne'. crackme-easy-1.exe: hit at 0x401046. For other crackmes substitute the cmp+jne bytes."
                },
                {
                    "step": 3,
                    "goal": "Disassemble around the check",
                    "cmd": "s 0x401020; pdfj",
                    "why": "Disassemble the full function containing the comparison. Identify: (a) the call to the hash/key routine, (b) the cmp eax, EXPECTED_VALUE, (c) the jne/je that selects success vs failure."
                },
                {
                    "step": 4,
                    "goal": "Inspect the hash routine",
                    "cmd": "s 0x401090; pdfj",
                    "why": "Disassemble the function called just before the comparison — this computes a hash/checksum of your input. Understanding it lets you find a valid key without patching."
                },
                {
                    "step": 5,
                    "goal": "Confirm the patch point bytes",
                    "cmd": "s 0x40104b; pxj 8",
                    "why": "Hex-dump the 8 bytes at the jne address. Original: 75 07 (jne +7). Patched: 90 90 (two NOPs). This is the byte offset to patch in the file."
                }
            ],
            "patch_note": "The crack for crackme-easy-1.exe is: file offset 0x44b, change bytes 75 07 → 90 90. This NOPs the jne so the program always falls through to 'Good cracker!'.",
            "valid_password": ":Rew  (one valid password for the unpatched binary — derived from the hash routine at 0x401090)"
        },

        // ── SAFETY RULES ──────────────────────────────────────────────────────
        "safety_rules": [
            "Only read-only JSON commands are accepted (no -w write mode, no wx/wq/wf write commands).",
            "Use 's <addr>; <cmd>' to analyse at a specific address within a single r2 invocation.",
            "Use timeout_sec to cap long analysis passes (aaa on large binaries can take minutes).",
            "Use max_items to prevent huge function lists or string dumps from flooding the context."
        ]
    })
}
