use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use reverseorbit_core::{CaseStore, Finding, NextAction, finding_teaching_summary};

pub(crate) fn build_finding_explanation(
    store: &CaseStore,
    case_id: &str,
    finding_id: &str,
) -> Result<Value> {
    let finding = store
        .load_findings(case_id)?
        .into_iter()
        .find(|item| item.id == finding_id)
        .ok_or_else(|| anyhow!("finding not found"))?;
    let related_actions = collect_related_actions(store, case_id, &finding)?;

    Ok(json!({
        "finding": finding,
        "teaching_summary": finding_teaching_summary(&finding),
        "related_actions": related_actions,
    }))
}

fn collect_related_actions(
    store: &CaseStore,
    case_id: &str,
    finding: &Finding,
) -> Result<Vec<NextAction>> {
    let actions = store
        .load_actions(case_id)?
        .into_iter()
        .filter(|action| {
            finding.next_action_ids.iter().any(|action_id| action_id == &action.id)
                || action
                    .related_finding_ids
                    .iter()
                    .any(|related_id| related_id == &finding.id)
        })
        .collect::<Vec<_>>();

    Ok(actions)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::Utc;
    use serde_json::json;

    use reverseorbit_core::{
        AnalysisProfile, CreateCaseRequest, EntityRef, Finding, FindingSeverity, FindingStatus,
        InferenceStep, NextAction, NextActionStatus, PlaybookRuleKind, capability_set,
    };

    use super::build_finding_explanation;

    #[test]
    fn build_finding_explanation_returns_shared_contract() {
        let base = std::env::temp_dir().join(format!(
            "reverseorbit-explain-test-{}",
            std::process::id()
        ));
        let store = reverseorbit_core::CaseStore::new(base.clone());
        let manifest = store
            .create_case(
                &CreateCaseRequest {
                    label: Some("explain-test".to_string()),
                    target_path: "/bin/ls".to_string(),
                    profile: Some(AnalysisProfile::Quick),
                },
                capability_set(),
            )
            .expect("case should be created");

        let action = NextAction {
            id: "action-1".to_string(),
            case_id: manifest.id.clone(),
            title: "Inspect xrefs".to_string(),
            why: "why".to_string(),
            how: "how".to_string(),
            action_type: "inspect_xrefs".to_string(),
            params: json!({"target": "socket"}),
            related_entity_ids: vec!["socket".to_string()],
            related_finding_ids: vec!["finding-1".to_string()],
            generated_from: Some("import.network_behavior".to_string()),
            skip_consequences: "skip".to_string(),
            execution_path: Vec::new(),
            created_at: Utc::now(),
            status: NextActionStatus::Pending,
        };
        store
            .save_actions(&manifest.id, std::slice::from_ref(&action))
            .expect("actions should save");

        let finding = Finding {
            id: "finding-1".to_string(),
            case_id: manifest.id.clone(),
            title: "Network import".to_string(),
            summary: "summary".to_string(),
            category: "network_behavior".to_string(),
            severity: FindingSeverity::Medium,
            status: FindingStatus::New,
            rationale: "rationale".to_string(),
            confidence: 0.8,
            source: "radare2".to_string(),
            tags: vec!["import".to_string()],
            entity_refs: vec![EntityRef {
                kind: "import".to_string(),
                id: "socket".to_string(),
                label: Some("socket".to_string()),
            }],
            evidence: Vec::new(),
            playbook_rule_id: "import.network_behavior".to_string(),
            playbook_rule_kind: Some(PlaybookRuleKind::SuspiciousImport),
            inference_chain: vec![InferenceStep {
                premise: "import exists".to_string(),
                conclusion: "network behavior".to_string(),
                confidence_contribution: 0.5,
            }],
            confidence_rationale: "confidence rationale".to_string(),
            counter_evidence: vec!["none yet".to_string()],
            next_action_ids: vec![action.id.clone()],
            created_at: Utc::now(),
        };
        store
            .save_findings(&manifest.id, std::slice::from_ref(&finding))
            .expect("findings should save");

        let payload = build_finding_explanation(&store, &manifest.id, &finding.id)
            .expect("explanation should be built");
        assert_eq!(
            payload
                .get("finding")
                .and_then(|value| value.get("id"))
                .and_then(|value| value.as_str()),
            Some("finding-1")
        );
        assert_eq!(
            payload
                .get("related_actions")
                .and_then(|value| value.as_array())
                .map(|items| items.len()),
            Some(1)
        );
        assert!(payload
            .get("teaching_summary")
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.trim().is_empty()));

        let _ = fs::remove_dir_all(base);
    }
}
