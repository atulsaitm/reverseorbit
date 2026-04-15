use std::net::SocketAddr;

use anyhow::{Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path, State, WebSocketUpgrade, ws::Message},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde_json::{Value, json};
use tower_http::services::{ServeDir, ServeFile};

use reverseorbit_core::{
    AnalyzeCaseRequest, ArtifactNode, CaseSummary, CreateCaseRequest, Finding, GraphViewKind,
    NextAction,
};

use crate::{
    analysis,
    error_kind::{ErrorKind, classify_error_kind},
    finding_explain::build_finding_explanation,
    state::AppState,
};

pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/mcp", post(mcp_http))
        .route("/ws", get(ws_handler))
        .route("/api/cases", get(list_cases).post(create_case))
        .route("/api/cases/import", post(import_case_bundle))
        .route("/api/cases/{id}", get(get_case).delete(delete_case_handler))
        .route("/api/cases/{id}/bundle", get(export_case_bundle))
        .route("/api/cases/{id}/analyze", post(start_analysis))
        .route("/api/cases/{id}/timeline", get(get_timeline))
        .route("/api/cases/{id}/findings", get(get_findings))
        .route(
            "/api/cases/{id}/findings/{finding_id}/explain",
            get(explain_finding),
        )
        .route("/api/cases/{id}/graphs/{view}", get(get_graph))
        .route("/api/cases/{id}/artifacts/{artifact_id}", get(get_artifact))
        .route("/api/cases/{id}/actions/{action_id}/run", post(run_action))
        .route("/api/cases/{id}/export", get(export_case))
        .with_state(state.clone());

    if state.web_dist_dir.exists() {
        api.fallback_service(
            ServeDir::new(state.web_dist_dir.clone())
                .not_found_service(ServeFile::new(state.web_dist_dir.join("index.html"))),
        )
    } else {
        api.fallback(root_placeholder)
    }
}

pub async fn serve(state: AppState, port: u16) -> Result<()> {
    let app = build_router(state);
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!("reverseorbit server listening on http://{}", address);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn list_cases(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.list_cases() {
        Ok(cases) => Json(json!({ "cases": cases })).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn create_case(
    State(state): State<AppState>,
    Json(request): Json<CreateCaseRequest>,
) -> impl IntoResponse {
    match analysis::create_case(&state, &request)
        .and_then(|manifest| load_case_payload(&state, &manifest.id))
    {
        Ok(payload) => (StatusCode::CREATED, Json(payload)).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn get_case(State(state): State<AppState>, Path(case_id): Path<String>) -> impl IntoResponse {
    match load_case_payload(&state, &case_id) {
        Ok(payload) => Json(payload).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn start_analysis(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(request): Json<AnalyzeCaseRequest>,
) -> impl IntoResponse {
    let response_case_id = case_id.clone();
    let cloned = state.clone();
    tokio::spawn(async move {
        if let Err(error) =
            analysis::run_case_analysis(cloned.clone(), case_id.clone(), request.profile).await
        {
            tracing::error!(?error, "analysis failed");
            let _ = cloned.store.update_manifest(&case_id, |current| {
                current.status = reverseorbit_core::CaseStatus::Failed;
                current.summary = Some(error.to_string());
            });
        }
    });
    Json(json!({ "status": "queued", "case_id": response_case_id })).into_response()
}

async fn get_timeline(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
) -> impl IntoResponse {
    match state.store.load_timeline(&case_id) {
        Ok(timeline) => Json(json!({ "timeline": timeline })).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn get_findings(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
) -> impl IntoResponse {
    match state.store.load_findings(&case_id) {
        Ok(findings) => Json(json!({ "findings": findings })).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn explain_finding(
    State(state): State<AppState>,
    Path((case_id, finding_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match build_finding_explanation(&state.store, &case_id, &finding_id) {
        Ok(payload) => Json(payload).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn get_graph(
    State(state): State<AppState>,
    Path((case_id, view)): Path<(String, String)>,
) -> impl IntoResponse {
    match parse_view(&view).and_then(|view| state.store.load_graph(&case_id, view)) {
        Ok(graph) => Json(json!({ "graph": graph })).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn get_artifact(
    State(state): State<AppState>,
    Path((case_id, artifact_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.store.load_artifact_payload(&case_id, &artifact_id) {
        Ok((artifact, normalized, raw)) => Json(json!({
            "artifact": artifact,
            "normalized": normalized,
            "raw": raw,
        }))
        .into_response(),
        Err(error) => error_response(&error),
    }
}

async fn run_action(
    State(state): State<AppState>,
    Path((case_id, action_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match analysis::run_action(state, case_id, action_id).await {
        Ok(result) => Json(json!({ "result": result })).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn export_case(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
) -> impl IntoResponse {
    match analysis::export_case(&state, &case_id) {
        Ok(exports) => Json(json!({ "exports": exports })).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        let mut receiver = state.broadcaster.subscribe();
        while let Ok(event) = receiver.recv().await {
            let payload = match serde_json::to_string(&event) {
                Ok(payload) => payload,
                Err(_) => continue,
            };
            if socket.send(Message::Text(payload.into())).await.is_err() {
                break;
            }
        }
    })
}

/// Streamable HTTP MCP endpoint (MCP 2025-06-18).
///
/// Codex CLI v0.118+ on Linux has a confirmed bug where it never sends
/// `initialize` over stdio (github.com/openai/codex/issues/17024).
/// Exposing MCP over HTTP bypasses the broken stdio transport entirely.
///
/// Workflow:
///   1. `cargo run -p reverseorbit-app -- server --port 4080`
///   2. In .codex/config.toml set `url = "http://localhost:4080/mcp"`
///   3. `codex`
async fn mcp_http(State(state): State<AppState>, Json(request): Json<Value>) -> impl IntoResponse {
    let method = request
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let params = request.get("params").cloned().unwrap_or(Value::Null);

    // MCP notifications have no `id` and must not receive a response.
    // Requests whose method starts with "notifications/" are also notifications
    // (some clients send them with an id — still no response expected).
    if method.starts_with("notifications/") || method.starts_with("$/") {
        return (StatusCode::ACCEPTED, "").into_response();
    }
    let Some(id) = request.get("id").cloned() else {
        return (StatusCode::ACCEPTED, "").into_response();
    };

    let rpc_result: Result<Value> = match method {
        "initialize" => {
            // Echo back the client's protocolVersion so strict rmcp clients
            // (Codex v0.49+) do not close the connection on a version mismatch.
            let version = params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or("2024-11-05")
                .to_string();
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": {
                    "name": "reverseorbit",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": crate::tool_schemas() })),
        // For tools/call, `params` contains {"name":"...", "arguments":{...}}
        // which is exactly what handle_tool_call expects.
        "tools/call" => crate::handle_tool_call(state, params).await,
        _ => Err(anyhow!("method not found")),
    };

    let body = match rpc_result {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            // Per MCP spec, tool errors go inside result with isError:true,
            // not as a JSON-RPC error object.
            "result": reverseorbit_mcp::error_result(e.to_string()),
        }),
    };

    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn delete_case_handler(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
) -> impl IntoResponse {
    match state.store.delete_case(&case_id) {
        Ok(()) => Json(json!({ "deleted": true, "case_id": case_id })).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn export_case_bundle(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
) -> impl IntoResponse {
    match state.store.export_case_bundle(&case_id) {
        Ok(bundle) => {
            let filename = format!("reverseorbit-case-{case_id}.json");
            (
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "application/json".to_string(),
                    ),
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{filename}\""),
                    ),
                ],
                serde_json::to_string_pretty(&bundle).unwrap_or_default(),
            )
                .into_response()
        }
        Err(error) => error_response(&error),
    }
}

async fn import_case_bundle(
    State(state): State<AppState>,
    Json(bundle): Json<Value>,
) -> impl IntoResponse {
    match state.store.import_case_bundle(&bundle) {
        Ok(manifest) => (
            StatusCode::CREATED,
            Json(json!({ "case_id": manifest.id, "manifest": manifest })),
        )
            .into_response(),
        Err(error) => error_response(&error),
    }
}

async fn root_placeholder() -> Html<&'static str> {
    Html(
        "<html><body style='font-family: sans-serif; background: #0a0a0c; color: #f4f4f5; padding: 2rem;'><h1>ReverseOrbit</h1><p>The backend is running, but the frontend has not been built yet.</p></body></html>",
    )
}

fn parse_view(value: &str) -> Result<GraphViewKind> {
    match value {
        "provenance" => Ok(GraphViewKind::Provenance),
        "call_graph" => Ok(GraphViewKind::CallGraph),
        "cfg" => Ok(GraphViewKind::Cfg),
        "xref_view" => Ok(GraphViewKind::XrefView),
        "string_relation_view" => Ok(GraphViewKind::StringRelationView),
        _ => Err(anyhow!("unknown graph view")),
    }
}

fn load_case_payload(state: &AppState, case_id: &str) -> Result<Value> {
    let summary = state.store.case_summary(case_id)?;
    let findings = state.store.load_findings(case_id)?;
    let actions = state.store.load_actions(case_id)?;
    let artifacts = state.store.load_artifacts(case_id)?;
    Ok(case_payload(summary, findings, actions, artifacts))
}

fn case_payload(
    summary: CaseSummary,
    findings: Vec<Finding>,
    actions: Vec<NextAction>,
    artifacts: Vec<ArtifactNode>,
) -> Value {
    // Single canonical envelope — no duplication.
    json!({
        "case": {
            "manifest": summary.manifest,
            "counts": {
                "timeline": summary.timeline_count,
                "findings": summary.findings_count,
                "actions": summary.actions_count,
                "artifacts": summary.artifact_count,
            },
            "findings": findings,
            "actions": actions,
            "artifacts": artifacts,
        }
    })
}

fn classify_error_status(message: &str) -> StatusCode {
    match classify_error_kind(message) {
        ErrorKind::BadRequest => StatusCode::BAD_REQUEST,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Timeout => StatusCode::GATEWAY_TIMEOUT,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn error_response(error: &anyhow::Error) -> axum::response::Response {
    let message = error.to_string();
    let kind = classify_error_kind(&message);
    let status = classify_error_status(&message);
    (
        status,
        Json(json!({
            "error": message,
            "kind": kind.as_str(),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_for_not_found() {
        assert_eq!(
            classify_error_status("artifact not found"),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn error_status_for_bad_request() {
        assert_eq!(
            classify_error_status("missing `case_id`"),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn error_status_for_timeout() {
        assert_eq!(
            classify_error_status("timed out after 90s while collecting xref probe"),
            StatusCode::GATEWAY_TIMEOUT
        );
    }

    #[test]
    fn error_kind_for_bad_request() {
        assert_eq!(
            classify_error_kind("missing `case_id`").as_str(),
            "bad_request"
        );
    }

    #[test]
    fn error_kind_for_internal() {
        assert_eq!(
            classify_error_kind("adapter crashed unexpectedly").as_str(),
            "internal"
        );
    }
}
