use std::time::Duration;

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use reverseorbit_core::{
    ActionRunResult, AnalysisProfile, CaseManifest, CaseSummary, CreateCaseRequest, GraphBundle,
    NextAction, NextActionStatus, NormalizedSnapshot, TimelineEventKind, TimelineStepStatus,
    capability_set,
    finding_teaching_summary,
    export_graphml, generate_findings_and_actions, make_artifact, make_timeline_step,
    rebuild_graphs, status_event,
};

use crate::{
    action_handlers::{self, ActionExecution},
    error_kind::classify_error_kind,
    state::AppState,
};

const BASELINE_TIMEOUT_SECONDS: u64 = 180;

pub fn create_case(state: &AppState, request: &CreateCaseRequest) -> Result<CaseManifest> {
    state.store.create_case(request, capability_set())
}

pub async fn run_case_analysis(
    state: AppState,
    case_id: String,
    profile_override: Option<AnalysisProfile>,
) -> Result<CaseSummary> {
    match run_case_analysis_inner(state.clone(), case_id.clone(), profile_override).await {
        Ok(summary) => Ok(summary),
        Err(error) => {
            let _ = persist_case_analysis_failure(&state, &case_id, &error);
            Err(error)
        }
    }
}

async fn run_case_analysis_inner(
    state: AppState,
    case_id: String,
    profile_override: Option<AnalysisProfile>,
) -> Result<CaseSummary> {
    let mut manifest = state.store.load_manifest(&case_id)?;
    let profile = profile_override.unwrap_or_else(|| manifest.profile.clone());
    manifest = state.store.update_manifest(&case_id, |current| {
        current.status = reverseorbit_core::CaseStatus::Analyzing;
        current.profile = profile.clone();
        current.summary = Some("ReverseOrbit is collecting radare2 artifacts".to_string());
    })?;
    emit(
        &state,
        status_event(
            &case_id,
            TimelineEventKind::StatusChanged,
            "Analysis started",
            Some(0.02),
            json!({ "status": manifest.status }),
        ),
    );

    let (file_size, sha256) = state.store.file_sha256(&manifest.target_path)?;
    let adapter = state.adapter.clone();
    let target_path = manifest.target_path.clone();
    let profile_for_task = profile.clone();
    emit(
        &state,
        status_event(
            &case_id,
            TimelineEventKind::Progress,
            "Launching radare2 baseline collection",
            Some(0.08),
            json!({ "target_path": target_path }),
        ),
    );

    let collection = run_blocking_with_timeout(
        Duration::from_secs(BASELINE_TIMEOUT_SECONDS),
        "collecting radare2 baseline",
        move || adapter.collect_baseline(&target_path, &profile_for_task, file_size, sha256),
    )
    .await?;

    manifest = state.store.update_manifest(&case_id, |current| {
        current.architecture = collection.snapshot.metadata.arch.clone();
        current.binary_format = collection.snapshot.metadata.format.clone();
        current.file_size = Some(collection.snapshot.metadata.size);
        current.sha256 = Some(collection.snapshot.metadata.sha256.clone());
    })?;

    for (index, collected) in collection.artifacts.iter().enumerate() {
        let artifact = make_artifact(
            &case_id,
            &collected.kind,
            &collected.label,
            &collected.summary,
            json!({
                "kind": collected.kind,
                "label": collected.label,
            }),
        );
        let persisted_artifact = state.store.upsert_artifact(
            &case_id,
            artifact.clone(),
            if collected.raw.is_null() { None } else { Some(&collected.raw) },
            &collected.normalized,
        )?;
        let persisted_artifact_id = persisted_artifact.id.clone();
        let (title, why, how) = step_copy_for_artifact(&collected.kind, &collected.label);
        let mut step = make_timeline_step(
            &case_id,
            title,
            why,
            how,
            "radare2",
            vec![manifest.target_path.clone()],
            collected.summary.clone(),
            Some(format!("artifact:{}", collected.kind)),
        );
        step.artifact_ids.push(persisted_artifact_id.clone());
        state.store.append_timeline_step(&case_id, &step)?;
        emit(
            &state,
            status_event(
                &case_id,
                TimelineEventKind::StepComplete,
                &step.title,
                Some(0.12 + ((index as f32 + 1.0) / collection.artifacts.len() as f32) * 0.52),
                json!({ "step": step, "artifact_id": persisted_artifact_id }),
            ),
        );
    }

    let (findings, actions) = generate_findings_and_actions(&case_id, &collection.snapshot);
    state.store.save_actions(&case_id, &actions)?;
    let mut published_findings = Vec::new();
    state.store.save_findings(&case_id, &published_findings)?;
    let mut analysis_step = make_timeline_step(
        &case_id,
        "Generate findings and next actions",
        "Turn raw reverse-engineering evidence into analyst-facing findings and explicit pivots.",
        "Apply deterministic ReverseOrbit playbooks over imports, strings, functions, and xref probes.",
        "reverseorbit-playbook",
        vec![profile_label(&profile).to_string()],
        format!("{} findings and {} actions generated", findings.len(), actions.len()),
        None,
    );
    analysis_step.finding_ids = findings.iter().map(|item| item.id.clone()).collect();
    analysis_step.next_action_ids = actions.iter().map(|item| item.id.clone()).collect();
    state.store.append_timeline_step(&case_id, &analysis_step)?;
    emit(
        &state,
        status_event(
            &case_id,
            TimelineEventKind::FindingCreated,
            "Generated findings and analyst actions",
            Some(0.78),
            json!({
                "findings_count": findings.len(),
                "actions_count": actions.len(),
            }),
        ),
    );

    let artifacts = state.store.load_artifacts(&case_id)?;
    let timeline = state.store.load_timeline(&case_id)?;

    for (index, finding) in findings.iter().enumerate() {
        published_findings.push(finding.clone());
        state.store.save_findings(&case_id, &published_findings)?;
        persist_provenance_graph(
            &state,
            &manifest,
            &timeline,
            &published_findings,
            &actions,
            &artifacts,
            &collection.snapshot,
            Some(finding_progress(index, findings.len())),
        )?;

        let related_entity_ids = finding
            .entity_refs
            .iter()
            .map(|entity| entity.id.clone())
            .collect::<Vec<_>>();
        let mut event = status_event(
            &case_id,
            TimelineEventKind::FindingCreated,
            &format!("Finding ready: {}", finding.title),
            Some(finding_progress(index, findings.len())),
            json!({
                "finding": finding,
                "finding_id": finding.id,
                "next_action_ids": finding.next_action_ids,
            }),
        );
        event.teaching_summary = Some(finding_teaching_summary(finding));
        event.related_entity_ids = related_entity_ids;
        event.llm_context = json!({
            "finding_id": finding.id,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "rule_id": finding.playbook_rule_id,
            "next_action_ids": finding.next_action_ids,
        });
        emit(&state, event);
    }

    persist_graphs(&state, &manifest, &timeline, &findings, &actions, &artifacts, &collection.snapshot)?;

    manifest = state.store.update_manifest(&case_id, |current| {
        current.status = reverseorbit_core::CaseStatus::Complete;
        current.summary = Some(format!(
            "{} findings, {} actions, {} graphs",
            findings.len(),
            actions.len(),
            5
        ));
    })?;
    emit(
        &state,
        status_event(
            &case_id,
            TimelineEventKind::StatusChanged,
            "Analysis complete",
            Some(1.0),
            json!({ "status": manifest.status }),
        ),
    );
    state.store.case_summary(&case_id)
}

fn persist_case_analysis_failure(
    state: &AppState,
    case_id: &str,
    error: &anyhow::Error,
) -> Result<()> {
    let error_message = error.to_string();
    let error_kind = classify_error_kind(&error_message);

    state.store.update_manifest(case_id, |current| {
        current.status = reverseorbit_core::CaseStatus::Failed;
        current.summary = Some(error_message.clone());
    })?;

    let mut failure_step = make_timeline_step(
        case_id,
        "Analysis failed",
        "ReverseOrbit could not complete the analysis pipeline for this case.",
        "Inspect the error details, correct environment or target issues, and rerun analysis.",
        "reverseorbit",
        Vec::new(),
        format!("Analysis failed: {error_message}"),
        None,
    );
    failure_step.status = TimelineStepStatus::Failed;
    state.store.append_timeline_step(case_id, &failure_step)?;

    emit(
        state,
        status_event(
            case_id,
            TimelineEventKind::StatusChanged,
            "Analysis failed",
            Some(1.0),
            json!({
                "status": reverseorbit_core::CaseStatus::Failed,
                "error": error_message,
                "error_kind": error_kind.as_str(),
                "step": failure_step,
            }),
        ),
    );

    Ok(())
}

pub async fn run_action(
    state: AppState,
    case_id: String,
    action_id: String,
) -> Result<ActionRunResult> {
    let _action_guard = state.action_guard.lock().await;
    let manifest = state.store.load_manifest(&case_id)?;
    let mut actions = state.store.load_actions(&case_id)?;
    let Some(index) = actions.iter().position(|action| action.id == action_id) else {
        return Err(anyhow!("action not found"));
    };
    let action = actions[index].clone();
    emit(
        &state,
        status_event(
            &case_id,
            TimelineEventKind::ActionRecommended,
            &format!("Running action: {}", action.title),
            Some(0.85),
            json!({ "action_id": action.id }),
        ),
    );

    let ActionExecution {
        artifact_ids,
        timeline_step,
        updated_snapshot,
    } = match action_handlers::execute_action_handler(&state, &case_id, &manifest, &action).await {
        Ok(Some(execution)) => execution,
        Ok(None) => {
            actions[index].status = NextActionStatus::Unsupported;
            state.store.save_actions(&case_id, &actions)?;
            let step = make_timeline_step(
                &case_id,
                &action.title,
                &action.why,
                &action.how,
                "reverseorbit",
                Vec::new(),
                "This action type is reserved for a future phase".to_string(),
                None,
            );
            state.store.append_timeline_step(&case_id, &step)?;
            return Ok(ActionRunResult {
                action: actions[index].clone(),
                timeline_step: step,
                artifact_ids: Vec::new(),
            });
        }
        Err(error) => {
            let error_message = error.to_string();
            let error_kind = classify_error_kind(&error_message);
            actions[index].status = NextActionStatus::Failed;
            state.store.save_actions(&case_id, &actions)?;

            let mut step = make_timeline_step(
                &case_id,
                &action.title,
                &action.why,
                &action.how,
                "reverseorbit",
                Vec::new(),
                format!("Action failed: {error_message}"),
                None,
            );
            step.status = TimelineStepStatus::Failed;
            step.next_action_ids.push(action.id.clone());
            state.store.append_timeline_step(&case_id, &step)?;
            emit(
                &state,
                status_event(
                    &case_id,
                    TimelineEventKind::StepComplete,
                    &step.title,
                    Some(1.0),
                    json!({
                        "step": step,
                        "action_id": action.id,
                        "error": error_message,
                        "error_kind": error_kind.as_str(),
                        "status": "failed",
                    }),
                ),
            );
            return Err(error);
        }
    };

    actions[index].status = NextActionStatus::Complete;
    state.store.save_actions(&case_id, &actions)?;
    state.store.append_timeline_step(&case_id, &timeline_step)?;

    let findings = state.store.load_findings(&case_id)?;
    let artifacts = state.store.load_artifacts(&case_id)?;
    let timeline = state.store.load_timeline(&case_id)?;
    let manifest = state.store.load_manifest(&case_id)?;
    persist_graphs(&state, &manifest, &timeline, &findings, &actions, &artifacts, &updated_snapshot)?;

    emit(
        &state,
        status_event(
            &case_id,
            TimelineEventKind::StepComplete,
            &timeline_step.title,
            Some(1.0),
            json!({ "step": timeline_step, "artifact_ids": artifact_ids }),
        ),
    );

    Ok(ActionRunResult {
        action: actions[index].clone(),
        timeline_step,
        artifact_ids,
    })
}

pub fn export_case(state: &AppState, case_id: &str) -> Result<Vec<Value>> {
    let graphs = state.store.list_graphs(case_id)?;
    let mut exports = Vec::new();
    for graph in graphs {
        let filename = format!("{}.graphml", graph.view.as_str());
        let path = state.store.save_export(case_id, &filename, &export_graphml(&graph))?;
        exports.push(json!({
            "view": graph.view.as_str(),
            "path": path,
        }));
    }
    Ok(exports)
}

fn persist_graphs(
    state: &AppState,
    manifest: &CaseManifest,
    timeline: &[reverseorbit_core::TimelineStep],
    findings: &[reverseorbit_core::Finding],
    actions: &[NextAction],
    artifacts: &[reverseorbit_core::ArtifactNode],
    snapshot: &NormalizedSnapshot,
) -> Result<Vec<GraphBundle>> {
    let graphs = rebuild_graphs(manifest, timeline, findings, actions, artifacts, Some(snapshot));
    for graph in &graphs {
        state.store.save_graph(&manifest.id, graph)?;
        emit(
            state,
            status_event(
                &manifest.id,
                TimelineEventKind::GraphUpdated,
                &format!("Updated graph: {}", graph.title),
                Some(0.92),
                json!({
                    "view": graph.view.as_str(),
                    "nodes": graph.nodes.len(),
                    "edges": graph.edges.len(),
                }),
            ),
        );
    }
    Ok(graphs)
}

fn persist_provenance_graph(
    state: &AppState,
    manifest: &CaseManifest,
    timeline: &[reverseorbit_core::TimelineStep],
    findings: &[reverseorbit_core::Finding],
    actions: &[NextAction],
    artifacts: &[reverseorbit_core::ArtifactNode],
    snapshot: &NormalizedSnapshot,
    progress: Option<f32>,
) -> Result<()> {
    let provenance = rebuild_graphs(manifest, timeline, findings, actions, artifacts, Some(snapshot))
        .into_iter()
        .find(|graph| graph.view == reverseorbit_core::GraphViewKind::Provenance)
        .ok_or_else(|| anyhow!("provenance graph missing"))?;

    state.store.save_graph(&manifest.id, &provenance)?;
    emit(
        state,
        status_event(
            &manifest.id,
            TimelineEventKind::GraphUpdated,
            &format!("Updated graph: {}", provenance.title),
            progress,
            json!({
                "view": provenance.view.as_str(),
                "nodes": provenance.nodes.len(),
                "edges": provenance.edges.len(),
            }),
        ),
    );
    Ok(())
}

fn finding_progress(index: usize, total: usize) -> f32 {
    if total == 0 {
        return 0.8;
    }

    let start = 0.8_f32;
    let end = 0.95_f32;
    let ratio = (index as f32 + 1.0) / total as f32;
    start + ((end - start) * ratio)
}

pub(crate) async fn run_blocking_with_timeout<T, F>(
    timeout: Duration,
    context: &str,
    operation: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let joined = tokio::time::timeout(timeout, tokio::task::spawn_blocking(operation))
        .await
        .map_err(|_| anyhow!("timed out after {}s while {context}", timeout.as_secs()))?;
    let result = joined.map_err(|error| anyhow!("blocking task failed while {context}: {error}"))?;
    result
}

pub(crate) fn update_snapshot<F>(
    state: &AppState,
    case_id: &str,
    mutator: F,
) -> Result<NormalizedSnapshot>
where
    F: FnOnce(&mut NormalizedSnapshot),
{
    let artifacts = state.store.load_artifacts(case_id)?;
    let snapshot_artifact = artifacts
        .iter()
        .find(|artifact| artifact.kind == "snapshot")
        .ok_or_else(|| anyhow!("snapshot artifact missing"))?
        .clone();
    let (_, normalized, raw) = state.store.load_artifact_payload(case_id, &snapshot_artifact.id)?;
    let mut snapshot: NormalizedSnapshot = serde_json::from_value(normalized)?;
    mutator(&mut snapshot);
    state.store.upsert_artifact(
        case_id,
        snapshot_artifact,
        raw.as_ref(),
        &serde_json::to_value(&snapshot)?,
    )?;
    Ok(snapshot)
}

fn step_copy_for_artifact(kind: &str, _label: &str) -> (&'static str, &'static str, &'static str) {
    match kind {
        "binary-overview" => (
            "Fingerprint binary",
            "Establish file type, architecture, layout, and trust boundaries before deeper RE work.",
            "Use radare2 JSON metadata and segment enumeration to map the binary structure.",
        ),
        "imports-exports" => (
            "Map imports and exports",
            "Imports and exports reveal capabilities, dependencies, and likely pivot points.",
            "Collect import/export tables from radare2 and normalize them for downstream playbooks.",
        ),
        "symbols-strings" => (
            "Extract symbols and strings",
            "Symbols and embedded strings often expose protocols, secrets, and execution intent.",
            "Collect JSON strings and symbol tables, then normalize them into entity records.",
        ),
        "functions" => (
            "Analyze functions and call graph",
            "Function summaries and call relationships define where to spend manual time next.",
            "Run radare2 analysis and normalize function/call graph summaries.",
        ),
        "function-detail" => (
            "Expand hot function",
            "Hot functions deserve CFG and disassembly detail because they often orchestrate behavior.",
            "Collect PDF and AGF JSON for the function to support graph and inspector views.",
        ),
        "xref-probe" => (
            "Probe xrefs",
            "A finding is only useful when you know which code paths actually reference it.",
            "Collect radare2 cross references for the selected import, string, or function target.",
        ),
        _ => (
            "Store artifact",
            "Persist normalized analysis state for later visualization and follow-up actions.",
            "Freeze the artifact inside the case folder and expose it through the API and MCP surfaces.",
        ),
    }
}

fn emit(state: &AppState, event: reverseorbit_core::ServerEvent) {
    let _ = state.broadcaster.send(event);
}

fn profile_label(profile: &AnalysisProfile) -> &'static str {
    match profile {
        AnalysisProfile::Quick => "quick",
        AnalysisProfile::Full => "full",
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc, time::Duration};

    use chrono::Utc;
    use serde_json::json;
    use tokio::sync::broadcast;

    use reverseorbit_core::{
        AnalysisProfile, CaseStatus, CreateCaseRequest, FunctionDetail, NextAction,
        NextActionStatus, ServerEvent, TimelineEventKind, TimelineStepStatus, XrefProbe,
    };
    use reverseorbit_radare2::BaselineCollection;

    use crate::{
        adapter::AnalysisAdapter,
        state::{
            build_state, build_state_with_adapter, build_state_with_adapter_and_action_timeout,
        },
    };

    use super::{create_case, run_action, run_case_analysis};

    #[tokio::test]
    async fn run_action_marks_unknown_action_as_unsupported() {
        let cases_dir = unique_test_dir("unsupported-action");
        let state = build_state(cases_dir.clone(), cases_dir.join("web-dist"));

        let request = CreateCaseRequest {
            label: Some("Unsupported Action Case".to_string()),
            target_path: "/bin/ls".to_string(),
            profile: None,
        };
        let manifest = create_case(&state, &request).expect("case should be created");

        let action = NextAction {
            id: "action-unsupported-1".to_string(),
            case_id: manifest.id.clone(),
            title: "Reserved action".to_string(),
            why: "Exercise unsupported action path".to_string(),
            how: "Invoke run_action with unknown action type".to_string(),
            action_type: "decode_function".to_string(),
            params: json!({}),
            related_entity_ids: Vec::new(),
            related_finding_ids: Vec::new(),
            generated_from: None,
            skip_consequences: String::new(),
            execution_path: Vec::new(),
            created_at: Utc::now(),
            status: NextActionStatus::Pending,
        };
        state
            .store
            .save_actions(&manifest.id, std::slice::from_ref(&action))
            .expect("action should be stored");

        let result = run_action(state.clone(), manifest.id.clone(), action.id.clone())
            .await
            .expect("run_action should handle unsupported action");

        assert_eq!(result.action.status, NextActionStatus::Unsupported);
        assert!(result.artifact_ids.is_empty());
        assert_eq!(result.timeline_step.tool, "reverseorbit");

        let stored_actions = state
            .store
            .load_actions(&manifest.id)
            .expect("actions should be loadable");
        assert_eq!(stored_actions[0].status, NextActionStatus::Unsupported);

        let timeline = state
            .store
            .load_timeline(&manifest.id)
            .expect("timeline should be loadable");
        assert!(!timeline.is_empty());
        assert_eq!(timeline.last().map(|step| step.title.as_str()), Some("Reserved action"));

        let _ = fs::remove_dir_all(cases_dir);
    }

    #[tokio::test]
    async fn run_action_returns_not_found_for_unknown_action_id() {
        let cases_dir = unique_test_dir("missing-action-id");
        let state = build_state(cases_dir.clone(), cases_dir.join("web-dist"));

        let request = CreateCaseRequest {
            label: Some("Missing Action Case".to_string()),
            target_path: "/bin/ls".to_string(),
            profile: None,
        };
        let manifest = create_case(&state, &request).expect("case should be created");

        let error = run_action(
            state.clone(),
            manifest.id.clone(),
            "action-not-found".to_string(),
        )
        .await
        .expect_err("run_action should fail for unknown action id");

        assert!(error.to_string().contains("action not found"));

        let _ = fs::remove_dir_all(cases_dir);
    }

    #[tokio::test]
    async fn run_action_propagates_validation_error_for_supported_action() {
        let cases_dir = unique_test_dir("invalid-supported-action");
        let state = build_state(cases_dir.clone(), cases_dir.join("web-dist"));

        let request = CreateCaseRequest {
            label: Some("Invalid Supported Action".to_string()),
            target_path: "/bin/ls".to_string(),
            profile: None,
        };
        let manifest = create_case(&state, &request).expect("case should be created");

        let action = NextAction {
            id: "action-invalid-inspect-1".to_string(),
            case_id: manifest.id.clone(),
            title: "Inspect xrefs with missing params".to_string(),
            why: "Validate action parameter checking".to_string(),
            how: "Call inspect_xrefs without required target".to_string(),
            action_type: "inspect_xrefs".to_string(),
            params: json!({}),
            related_entity_ids: Vec::new(),
            related_finding_ids: Vec::new(),
            generated_from: None,
            skip_consequences: String::new(),
            execution_path: Vec::new(),
            created_at: Utc::now(),
            status: NextActionStatus::Pending,
        };
        state
            .store
            .save_actions(&manifest.id, std::slice::from_ref(&action))
            .expect("action should be stored");
        let mut receiver = state.broadcaster.subscribe();

        let error = run_action(state.clone(), manifest.id.clone(), action.id.clone())
            .await
            .expect_err("run_action should fail for invalid supported action params");
        assert!(error.to_string().contains("action target missing"));

        let stored_actions = state
            .store
            .load_actions(&manifest.id)
            .expect("actions should be loadable");
        assert_eq!(stored_actions[0].status, NextActionStatus::Failed);

        let timeline = state
            .store
            .load_timeline(&manifest.id)
            .expect("timeline should be loadable");
        let last_step = timeline.last().expect("failed step should be appended");
        assert_eq!(last_step.status, TimelineStepStatus::Failed);
        assert!(last_step.result_summary.contains("Action failed:"));

        let failed_event = recv_failed_event(&mut receiver).await;
        assert_eq!(failed_event.event, TimelineEventKind::StepComplete);
        assert_eq!(
            failed_event
                .payload
                .get("error_kind")
                .and_then(|value| value.as_str()),
            Some("bad_request")
        );
        let event_error = failed_event
            .payload
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        assert!(event_error.contains("action target missing"));

        let _ = fs::remove_dir_all(cases_dir);
    }

    #[tokio::test]
    async fn run_action_propagates_timeout_for_slow_adapter() {
        let cases_dir = unique_test_dir("timeout-action");
        let state = build_state_with_adapter_and_action_timeout(
            cases_dir.clone(),
            cases_dir.join("web-dist"),
            Arc::new(SlowXrefAdapter {
                sleep_for: Duration::from_millis(200),
            }),
            Duration::from_millis(20),
        );

        let request = CreateCaseRequest {
            label: Some("Timeout Action Case".to_string()),
            target_path: "/bin/ls".to_string(),
            profile: None,
        };
        let manifest = create_case(&state, &request).expect("case should be created");

        let action = NextAction {
            id: "action-timeout-inspect-1".to_string(),
            case_id: manifest.id.clone(),
            title: "Inspect xrefs timeout".to_string(),
            why: "Validate timeout propagation for handler execution".to_string(),
            how: "Use a fake slow adapter for inspect_xrefs".to_string(),
            action_type: "inspect_xrefs".to_string(),
            params: json!({
                "target": "sym.main",
                "target_kind": "function",
            }),
            related_entity_ids: Vec::new(),
            related_finding_ids: Vec::new(),
            generated_from: None,
            skip_consequences: String::new(),
            execution_path: Vec::new(),
            created_at: Utc::now(),
            status: NextActionStatus::Pending,
        };
        state
            .store
            .save_actions(&manifest.id, std::slice::from_ref(&action))
            .expect("action should be stored");
        let mut receiver = state.broadcaster.subscribe();

        let error = run_action(state.clone(), manifest.id.clone(), action.id.clone())
            .await
            .expect_err("run_action should timeout for slow adapter");
        let message = error.to_string();
        assert!(message.contains("timed out"));
        assert!(message.contains("collecting xref probe"));

        let stored_actions = state
            .store
            .load_actions(&manifest.id)
            .expect("actions should be loadable");
        assert_eq!(stored_actions[0].status, NextActionStatus::Failed);

        let timeline = state
            .store
            .load_timeline(&manifest.id)
            .expect("timeline should be loadable");
        let last_step = timeline.last().expect("failed step should be appended");
        assert_eq!(last_step.status, TimelineStepStatus::Failed);
        assert!(last_step.result_summary.contains("Action failed:"));

        let failed_event = recv_failed_event(&mut receiver).await;
        assert_eq!(failed_event.event, TimelineEventKind::StepComplete);
        assert_eq!(
            failed_event
                .payload
                .get("error_kind")
                .and_then(|value| value.as_str()),
            Some("timeout")
        );
        let event_error = failed_event
            .payload
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        assert!(event_error.contains("timed out"));

        let _ = fs::remove_dir_all(cases_dir);
    }

    #[tokio::test]
    async fn run_case_analysis_marks_manifest_failed_on_baseline_error() {
        let cases_dir = unique_test_dir("analysis-baseline-failure");
        let state = build_state_with_adapter(
            cases_dir.clone(),
            cases_dir.join("web-dist"),
            Arc::new(FailingBaselineAdapter),
        );

        let request = CreateCaseRequest {
            label: Some("Baseline Failure Case".to_string()),
            target_path: "/bin/ls".to_string(),
            profile: None,
        };
        let manifest = create_case(&state, &request).expect("case should be created");
        let mut receiver = state.broadcaster.subscribe();

        let error = run_case_analysis(state.clone(), manifest.id.clone(), None)
            .await
            .expect_err("run_case_analysis should fail when baseline collection fails");
        assert!(error.to_string().contains("intentional baseline failure"));

        let updated_manifest = state
            .store
            .load_manifest(&manifest.id)
            .expect("manifest should be loadable");
        assert_eq!(updated_manifest.status, CaseStatus::Failed);
        let summary = updated_manifest.summary.unwrap_or_default();
        assert!(summary.contains("intentional baseline failure"));

        let timeline = state
            .store
            .load_timeline(&manifest.id)
            .expect("timeline should be loadable");
        let last_step = timeline.last().expect("failed analysis step should be appended");
        assert_eq!(last_step.title, "Analysis failed");
        assert_eq!(last_step.status, TimelineStepStatus::Failed);
        assert!(last_step.result_summary.contains("Analysis failed:"));

        let failed_event = recv_failed_event(&mut receiver).await;
        assert_eq!(failed_event.event, TimelineEventKind::StatusChanged);
        assert_eq!(
            failed_event
                .payload
                .get("error_kind")
                .and_then(|value| value.as_str()),
            Some("internal")
        );
        let event_error = failed_event
            .payload
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        assert!(event_error.contains("intentional baseline failure"));

        let _ = fs::remove_dir_all(cases_dir);
    }

    async fn recv_failed_event(receiver: &mut broadcast::Receiver<ServerEvent>) -> ServerEvent {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match receiver.recv().await {
                    Ok(event)
                        if event.payload.get("status").and_then(|value| value.as_str())
                            == Some("failed") =>
                    {
                        return event;
                    }
                    Ok(_) => continue,
                    Err(_) => continue,
                }
            }
        })
        .await
        .expect("failed event should be emitted")
    }

    #[derive(Debug)]
    struct FailingBaselineAdapter;

    impl AnalysisAdapter for FailingBaselineAdapter {
        fn collect_baseline(
            &self,
            _target_path: &str,
            _profile: &AnalysisProfile,
            _file_size: u64,
            _sha256: String,
        ) -> anyhow::Result<BaselineCollection> {
            Err(anyhow::anyhow!("intentional baseline failure"))
        }

        fn collect_function_detail(
            &self,
            _target_path: &str,
            _function_name: &str,
        ) -> anyhow::Result<FunctionDetail> {
            Err(anyhow::anyhow!(
                "collect_function_detail is not used in this test"
            ))
        }

        fn collect_xref_probe(
            &self,
            _target_path: &str,
            _target: &str,
            _target_kind: &str,
        ) -> anyhow::Result<XrefProbe> {
            Err(anyhow::anyhow!("collect_xref_probe is not used in this test"))
        }

        fn run_dynamic_json_query(
            &self,
            _target_path: &str,
            _command: &str,
        ) -> anyhow::Result<serde_json::Value> {
            Err(anyhow::anyhow!(
                "run_dynamic_json_query is not used in this test"
            ))
        }

        fn search_strings(
            &self,
            _target_path: &str,
            _query: &str,
            _limit: usize,
        ) -> anyhow::Result<Vec<reverseorbit_core::StringEntry>> {
            Err(anyhow::anyhow!("search_strings is not used in this test"))
        }
    }

    #[derive(Debug)]
    struct SlowXrefAdapter {
        sleep_for: Duration,
    }

    impl AnalysisAdapter for SlowXrefAdapter {
        fn collect_baseline(
            &self,
            _target_path: &str,
            _profile: &AnalysisProfile,
            _file_size: u64,
            _sha256: String,
        ) -> anyhow::Result<BaselineCollection> {
            Err(anyhow::anyhow!("collect_baseline is not used in this test"))
        }

        fn collect_function_detail(
            &self,
            _target_path: &str,
            _function_name: &str,
        ) -> anyhow::Result<FunctionDetail> {
            Err(anyhow::anyhow!(
                "collect_function_detail is not used in this test"
            ))
        }

        fn collect_xref_probe(
            &self,
            _target_path: &str,
            target: &str,
            target_kind: &str,
        ) -> anyhow::Result<XrefProbe> {
            std::thread::sleep(self.sleep_for);
            Ok(XrefProbe {
                target: target.to_string(),
                target_kind: target_kind.to_string(),
                xrefs: Vec::new(),
            })
        }

        fn run_dynamic_json_query(
            &self,
            _target_path: &str,
            _command: &str,
        ) -> anyhow::Result<serde_json::Value> {
            Err(anyhow::anyhow!(
                "run_dynamic_json_query is not used in this test"
            ))
        }

        fn search_strings(
            &self,
            _target_path: &str,
            _query: &str,
            _limit: usize,
        ) -> anyhow::Result<Vec<reverseorbit_core::StringEntry>> {
            Err(anyhow::anyhow!("search_strings is not used in this test"))
        }
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push("reverseorbit-app-tests");
        path.push(format!(
            "{}-{}-{}",
            label,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path
    }
}
