use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use futures_util::future::BoxFuture;
use serde_json::json;

use reverseorbit_core::{
    CaseManifest, NextAction, NormalizedSnapshot, TimelineStep, make_artifact, make_timeline_step,
};

use crate::{
    analysis::{run_blocking_with_timeout, update_snapshot},
    state::AppState,
};

pub(crate) struct ActionExecution {
    pub(crate) artifact_ids: Vec<String>,
    pub(crate) timeline_step: TimelineStep,
    pub(crate) updated_snapshot: NormalizedSnapshot,
}

type ActionHandler = for<'a> fn(
    &'a AppState,
    &'a str,
    &'a CaseManifest,
    &'a NextAction,
) -> BoxFuture<'a, Result<ActionExecution>>;

pub(crate) async fn execute_action_handler(
    state: &AppState,
    case_id: &str,
    manifest: &CaseManifest,
    action: &NextAction,
) -> Result<Option<ActionExecution>> {
    let Some(handler) = resolve_action_handler(action.action_type.as_str()) else {
        return Ok(None);
    };

    Ok(Some(handler(state, case_id, manifest, action).await?))
}

fn action_handler_registry() -> BTreeMap<&'static str, ActionHandler> {
    BTreeMap::from([
        ("inspect_xrefs", run_inspect_xrefs_handler as ActionHandler),
        ("expand_cfg", run_expand_cfg_handler as ActionHandler),
    ])
}

fn resolve_action_handler(action_type: &str) -> Option<ActionHandler> {
    action_handler_registry().get(action_type).copied()
}

fn run_inspect_xrefs_handler<'a>(
    state: &'a AppState,
    case_id: &'a str,
    manifest: &'a CaseManifest,
    action: &'a NextAction,
) -> BoxFuture<'a, Result<ActionExecution>> {
    Box::pin(async move {
        let target = action
            .params
            .get("target")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow!("action target missing"))?
            .to_string();
        let target_kind = action
            .params
            .get("target_kind")
            .and_then(|value| value.as_str())
            .unwrap_or("xref")
            .to_string();
        let adapter = state.adapter.clone();
        let target_path = manifest.target_path.clone();
        let probe = run_blocking_with_timeout(
            state.action_timeout,
            "collecting xref probe",
            move || adapter.collect_xref_probe(&target_path, &target, &target_kind),
        )
        .await?;
        let artifact = make_artifact(
            case_id,
            "xref-probe",
            &action.title,
            &format!("{} xrefs collected", probe.xrefs.len()),
            json!({
                "target": probe.target,
                "target_kind": probe.target_kind,
            }),
        );
        let persisted_artifact = state
            .store
            .upsert_artifact(case_id, artifact, None, &serde_json::to_value(&probe)?)?;
        let snapshot = update_snapshot(state, case_id, |current| {
            current.xref_probes.retain(|existing| {
                !(existing.target == probe.target && existing.target_kind == probe.target_kind)
            });
            current.xref_probes.push(probe.clone());
        })?;
        let mut step = make_timeline_step(
            case_id,
            &action.title,
            &action.why,
            &action.how,
            "radare2",
            vec![manifest.target_path.clone()],
            format!(
                "xref probe completed with {} references",
                snapshot
                    .xref_probes
                    .last()
                    .map(|item| item.xrefs.len())
                    .unwrap_or_default()
            ),
            None,
        );
        step.artifact_ids.push(persisted_artifact.id.clone());
        step.next_action_ids.push(action.id.clone());

        Ok(ActionExecution {
            artifact_ids: vec![persisted_artifact.id],
            timeline_step: step,
            updated_snapshot: snapshot,
        })
    })
}

fn run_expand_cfg_handler<'a>(
    state: &'a AppState,
    case_id: &'a str,
    manifest: &'a CaseManifest,
    action: &'a NextAction,
) -> BoxFuture<'a, Result<ActionExecution>> {
    Box::pin(async move {
        let function_name = action
            .params
            .get("function")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow!("function name missing"))?
            .to_string();
        let adapter = state.adapter.clone();
        let target_path = manifest.target_path.clone();
        let detail = run_blocking_with_timeout(
            state.action_timeout,
            "collecting function detail",
            move || adapter.collect_function_detail(&target_path, &function_name),
        )
        .await?;
        let artifact = make_artifact(
            case_id,
            "function-detail",
            &action.title,
            &format!("CFG and disassembly expanded for {}", detail.name),
            json!({
                "function": detail.name,
                "addr": detail.addr,
            }),
        );
        let persisted_artifact = state
            .store
            .upsert_artifact(case_id, artifact, None, &serde_json::to_value(&detail)?)?;
        let snapshot = update_snapshot(state, case_id, |current| {
            current
                .function_details
                .retain(|existing| existing.name != detail.name);
            current.function_details.push(detail.clone());
        })?;
        let mut step = make_timeline_step(
            case_id,
            &action.title,
            &action.why,
            &action.how,
            "radare2",
            vec![manifest.target_path.clone()],
            "Function detail collected and CFG refreshed".to_string(),
            None,
        );
        step.artifact_ids.push(persisted_artifact.id.clone());
        step.next_action_ids.push(action.id.clone());

        Ok(ActionExecution {
            artifact_ids: vec![persisted_artifact.id],
            timeline_step: step,
            updated_snapshot: snapshot,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_action_handler;

    #[test]
    fn resolves_registered_action_handlers() {
        assert!(resolve_action_handler("inspect_xrefs").is_some());
        assert!(resolve_action_handler("expand_cfg").is_some());
    }

    #[test]
    fn unknown_action_handler_is_not_resolved() {
        assert!(resolve_action_handler("decode_function").is_none());
    }
}
