use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::*;

#[derive(Debug, Clone)]
pub struct CaseStore {
    base_dir: PathBuf,
}

impl CaseStore {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn ensure_base(&self) -> Result<()> {
        fs::create_dir_all(&self.base_dir)
            .with_context(|| format!("failed to create {}", self.base_dir.display()))
    }

    pub fn create_case(
        &self,
        request: &CreateCaseRequest,
        capabilities: Vec<AnalyzerCapability>,
    ) -> Result<CaseManifest> {
        self.ensure_base()?;
        let case_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let label = request.label.clone().unwrap_or_else(|| {
            Path::new(&request.target_path)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("reverseorbit-case")
                .to_string()
        });
        let manifest = CaseManifest {
            id: case_id.clone(),
            label,
            target_path: request.target_path.clone(),
            source: "radare2".to_string(),
            status: CaseStatus::Created,
            profile: request.profile.clone().unwrap_or_default(),
            created_at: now,
            updated_at: now,
            summary: Some("Case created and awaiting analysis".to_string()),
            architecture: None,
            binary_format: None,
            file_size: None,
            sha256: None,
            capabilities,
        };
        self.ensure_case_layout(&case_id)?;
        self.save_manifest(&manifest)?;
        self.save_json_pretty(
            self.case_dir(&case_id).join("findings.json"),
            &Vec::<Finding>::new(),
        )?;
        self.save_json_pretty(
            self.case_dir(&case_id).join("actions.json"),
            &Vec::<NextAction>::new(),
        )?;
        self.save_json_pretty(
            self.case_dir(&case_id).join("artifacts/index.json"),
            &Vec::<ArtifactNode>::new(),
        )?;
        Ok(manifest)
    }

    pub fn ensure_case_layout(&self, case_id: &str) -> Result<()> {
        for path in [
            self.case_dir(case_id),
            self.case_dir(case_id).join("graphs"),
            self.case_dir(case_id).join("exports"),
            self.case_dir(case_id).join("artifacts"),
            self.case_dir(case_id).join("artifacts/raw"),
            self.case_dir(case_id).join("artifacts/normalized"),
        ] {
            fs::create_dir_all(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
        }
        Ok(())
    }

    pub fn case_dir(&self, case_id: &str) -> PathBuf {
        self.base_dir.join(case_id)
    }

    pub fn list_cases(&self) -> Result<Vec<CaseSummary>> {
        self.ensure_base()?;
        let mut summaries = Vec::new();
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let case_id = entry.file_name().to_string_lossy().to_string();
            if let Ok(summary) = self.case_summary(&case_id) {
                summaries.push(summary);
            }
        }
        summaries.sort_by(|left, right| right.manifest.updated_at.cmp(&left.manifest.updated_at));
        Ok(summaries)
    }

    pub fn case_summary(&self, case_id: &str) -> Result<CaseSummary> {
        Ok(CaseSummary {
            manifest: self.load_manifest(case_id)?,
            timeline_count: self.load_timeline(case_id)?.len(),
            findings_count: self.load_findings(case_id)?.len(),
            actions_count: self.load_actions(case_id)?.len(),
            artifact_count: self.load_artifacts(case_id)?.len(),
        })
    }

    pub fn load_manifest(&self, case_id: &str) -> Result<CaseManifest> {
        self.load_json(self.case_dir(case_id).join("manifest.json"))
    }

    pub fn save_manifest(&self, manifest: &CaseManifest) -> Result<()> {
        self.save_json_pretty(self.case_dir(&manifest.id).join("manifest.json"), manifest)
    }

    pub fn update_manifest<F>(&self, case_id: &str, mutator: F) -> Result<CaseManifest>
    where
        F: FnOnce(&mut CaseManifest),
    {
        let mut manifest = self.load_manifest(case_id)?;
        mutator(&mut manifest);
        manifest.updated_at = Utc::now();
        self.save_manifest(&manifest)?;
        Ok(manifest)
    }

    pub fn append_timeline_step(&self, case_id: &str, step: &TimelineStep) -> Result<()> {
        let path = self.case_dir(case_id).join("timeline.jsonl");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        let line = serde_json::to_string(step)?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    pub fn load_timeline(&self, case_id: &str) -> Result<Vec<TimelineStep>> {
        let path = self.case_dir(case_id).join("timeline.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&path)?;
        let reader = BufReader::new(file);
        let mut steps = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            steps.push(serde_json::from_str(&line)?);
        }
        Ok(steps)
    }

    pub fn save_findings(&self, case_id: &str, findings: &[Finding]) -> Result<()> {
        self.save_json_pretty(self.case_dir(case_id).join("findings.json"), findings)
    }

    pub fn load_findings(&self, case_id: &str) -> Result<Vec<Finding>> {
        self.load_json_or_default(self.case_dir(case_id).join("findings.json"))
    }

    pub fn save_actions(&self, case_id: &str, actions: &[NextAction]) -> Result<()> {
        self.save_json_pretty(self.case_dir(case_id).join("actions.json"), actions)
    }

    pub fn load_actions(&self, case_id: &str) -> Result<Vec<NextAction>> {
        self.load_json_or_default(self.case_dir(case_id).join("actions.json"))
    }

    pub fn save_artifacts(&self, case_id: &str, artifacts: &[ArtifactNode]) -> Result<()> {
        self.save_json_pretty(
            self.case_dir(case_id).join("artifacts/index.json"),
            artifacts,
        )
    }

    pub fn load_artifacts(&self, case_id: &str) -> Result<Vec<ArtifactNode>> {
        self.load_json_or_default(self.case_dir(case_id).join("artifacts/index.json"))
    }

    pub fn upsert_artifact(
        &self,
        case_id: &str,
        artifact: ArtifactNode,
        raw: Option<&Value>,
        normalized: &Value,
    ) -> Result<ArtifactNode> {
        let mut artifacts = self.load_artifacts(case_id)?;
        let incoming_signature =
            artifact_signature(&artifact.kind, &artifact.label, normalized, raw)?;

        for existing in &artifacts {
            if existing.id == artifact.id
                || existing.kind != artifact.kind
                || existing.label != artifact.label
            {
                continue;
            }

            let Ok((existing_normalized, existing_raw)) =
                self.load_artifact_values(case_id, &existing.id)
            else {
                continue;
            };

            let Ok(existing_signature) = artifact_signature(
                &existing.kind,
                &existing.label,
                &existing_normalized,
                existing_raw.as_ref(),
            ) else {
                continue;
            };

            if existing_signature == incoming_signature {
                return Ok(existing.clone());
            }
        }

        artifacts.retain(|existing| existing.id != artifact.id);
        artifacts.push(artifact.clone());
        artifacts.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        self.save_artifacts(case_id, &artifacts)?;
        if let Some(raw_value) = raw {
            self.save_json_pretty(
                self.case_dir(case_id)
                    .join("artifacts/raw")
                    .join(format!("{}.json", artifact.id)),
                raw_value,
            )?;
        }
        self.save_json_pretty(
            self.case_dir(case_id)
                .join("artifacts/normalized")
                .join(format!("{}.json", artifact.id)),
            normalized,
        )?;
        Ok(artifact)
    }

    pub fn load_artifact_payload(
        &self,
        case_id: &str,
        artifact_id: &str,
    ) -> Result<(ArtifactNode, Value, Option<Value>)> {
        let artifact = self
            .load_artifacts(case_id)?
            .into_iter()
            .find(|item| item.id == artifact_id)
            .ok_or_else(|| anyhow!("artifact not found"))?;
        let (normalized, raw) = self.load_artifact_values(case_id, artifact_id)?;
        Ok((artifact, normalized, raw))
    }

    pub fn save_graph(&self, case_id: &str, graph: &GraphBundle) -> Result<()> {
        self.save_json_pretty(
            self.case_dir(case_id)
                .join("graphs")
                .join(format!("{}.json", graph.view.as_str())),
            graph,
        )
    }

    pub fn load_graph(&self, case_id: &str, view: GraphViewKind) -> Result<GraphBundle> {
        self.load_json(
            self.case_dir(case_id)
                .join("graphs")
                .join(format!("{}.json", view.as_str())),
        )
    }

    pub fn list_graphs(&self, case_id: &str) -> Result<Vec<GraphBundle>> {
        let mut graphs = Vec::new();
        let dir = self.case_dir(case_id).join("graphs");
        if !dir.exists() {
            return Ok(graphs);
        }
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) == Some("json") {
                graphs.push(self.load_json(path)?);
            }
        }
        graphs.sort_by(|left, right| left.title.cmp(&right.title));
        Ok(graphs)
    }

    pub fn save_export(&self, case_id: &str, name: &str, contents: &str) -> Result<PathBuf> {
        let path = self.case_dir(case_id).join("exports").join(name);
        fs::write(&path, contents)?;
        Ok(path)
    }

    pub fn file_sha256(&self, target_path: &str) -> Result<(u64, String)> {
        let bytes = fs::read(target_path)
            .with_context(|| format!("failed to read binary at {target_path}"))?;
        let size = bytes.len() as u64;
        let digest = Sha256::digest(bytes);
        Ok((size, format!("{digest:x}")))
    }

    fn load_json<T: DeserializeOwned>(&self, path: PathBuf) -> Result<T> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }

    fn load_artifact_values(
        &self,
        case_id: &str,
        artifact_id: &str,
    ) -> Result<(Value, Option<Value>)> {
        let normalized = self.load_json(
            self.case_dir(case_id)
                .join("artifacts/normalized")
                .join(format!("{}.json", artifact_id)),
        )?;
        let raw_path = self
            .case_dir(case_id)
            .join("artifacts/raw")
            .join(format!("{}.json", artifact_id));
        let raw = if raw_path.exists() {
            Some(self.load_json(raw_path)?)
        } else {
            None
        };
        Ok((normalized, raw))
    }

    fn load_json_or_default<T>(&self, path: PathBuf) -> Result<T>
    where
        T: DeserializeOwned + Default,
    {
        if !path.exists() {
            return Ok(T::default());
        }
        self.load_json(path)
    }

    fn save_json_pretty<T: Serialize + ?Sized>(&self, path: PathBuf, value: &T) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let serialized = serde_json::to_string_pretty(value)?;
        fs::write(&path, serialized).with_context(|| format!("failed to write {}", path.display()))
    }

    /// Permanently delete a case and all its files from disk.
    pub fn delete_case(&self, case_id: &str) -> Result<()> {
        let dir = self.case_dir(case_id);
        if !dir.exists() {
            return Err(anyhow!("case not found"));
        }
        fs::remove_dir_all(&dir)
            .with_context(|| format!("failed to delete case directory {}", dir.display()))
    }

    /// Serialize a complete case into a portable JSON bundle that can be
    /// shared with other ReverseOrbit instances and re-imported via
    /// `import_case_bundle`.  Artifact *payloads* (the raw radare2 JSON
    /// files) are not included to keep the bundle small; only the artifact
    /// index metadata is exported.
    pub fn export_case_bundle(&self, case_id: &str) -> Result<Value> {
        Ok(json!({
            "version": "reverseorbit-case-v1",
            "exported_at": Utc::now(),
            "manifest": self.load_manifest(case_id)?,
            "timeline": self.load_timeline(case_id)?,
            "findings": self.load_findings(case_id)?,
            "actions": self.load_actions(case_id)?,
            "artifacts": self.load_artifacts(case_id)?,
        }))
    }

    /// Import a case bundle produced by `export_case_bundle`.  Creates a
    /// brand-new case with a fresh UUID so it never overwrites an existing
    /// one.  Artifact payloads are not restored (they were not exported).
    pub fn import_case_bundle(&self, bundle: &Value) -> Result<CaseManifest> {
        let version = bundle
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !version.starts_with("reverseorbit-case") {
            return Err(anyhow!("invalid bundle: missing or unknown version field"));
        }

        let raw_manifest = bundle
            .get("manifest")
            .cloned()
            .ok_or_else(|| anyhow!("bundle is missing `manifest`"))?;
        let mut manifest: CaseManifest = serde_json::from_value(raw_manifest)
            .with_context(|| "failed to deserialise manifest from bundle")?;

        // Give the imported case a fresh identity
        manifest.id = Uuid::new_v4().to_string();
        manifest.updated_at = Utc::now();
        manifest.label = format!("[imported] {}", manifest.label);

        self.ensure_base()?;
        self.ensure_case_layout(&manifest.id)?;
        self.save_manifest(&manifest)?;

        // Initialise empty files so the case is always readable
        self.save_findings(&manifest.id, &[])?;
        self.save_actions(&manifest.id, &[])?;
        self.save_artifacts(&manifest.id, &[])?;

        // Restore timeline (each step appended individually)
        if let Some(steps) = bundle.get("timeline").and_then(|v| v.as_array()) {
            for step_val in steps {
                if let Ok(step) = serde_json::from_value::<TimelineStep>(step_val.clone()) {
                    let _ = self.append_timeline_step(&manifest.id, &step);
                }
            }
        }

        // Restore findings
        if let Some(findings_val) = bundle.get("findings") {
            if let Ok(findings) = serde_json::from_value::<Vec<Finding>>(findings_val.clone()) {
                self.save_findings(&manifest.id, &findings)?;
            }
        }

        // Restore actions
        if let Some(actions_val) = bundle.get("actions") {
            if let Ok(actions) = serde_json::from_value::<Vec<NextAction>>(actions_val.clone()) {
                self.save_actions(&manifest.id, &actions)?;
            }
        }

        // Restore artifact index (metadata only — no payloads)
        if let Some(artifacts_val) = bundle.get("artifacts") {
            if let Ok(artifacts) =
                serde_json::from_value::<Vec<ArtifactNode>>(artifacts_val.clone())
            {
                self.save_artifacts(&manifest.id, &artifacts)?;
            }
        }

        Ok(manifest)
    }
}

pub fn make_artifact(
    case_id: &str,
    kind: &str,
    label: &str,
    summary: &str,
    metadata: Value,
) -> ArtifactNode {
    ArtifactNode {
        id: Uuid::new_v4().to_string(),
        case_id: case_id.to_string(),
        kind: kind.to_string(),
        label: label.to_string(),
        source: "radare2".to_string(),
        summary: summary.to_string(),
        created_at: Utc::now(),
        metadata,
    }
}

pub fn make_timeline_step(
    case_id: &str,
    title: &str,
    why: &str,
    how: &str,
    tool: &str,
    tool_args: Vec<String>,
    result_summary: String,
    raw_command: Option<String>,
) -> TimelineStep {
    TimelineStep {
        id: Uuid::new_v4().to_string(),
        case_id: case_id.to_string(),
        created_at: Utc::now(),
        status: TimelineStepStatus::Complete,
        title: title.to_string(),
        why: why.to_string(),
        how: how.to_string(),
        tool: tool.to_string(),
        tool_args,
        result_summary,
        artifact_ids: Vec::new(),
        finding_ids: Vec::new(),
        next_action_ids: Vec::new(),
        raw_command,
        playbook_context: Value::Null,
        snapshot_diff: None,
        teaching_summary: String::new(),
    }
}

pub fn capability_set() -> Vec<AnalyzerCapability> {
    vec![
        AnalyzerCapability {
            key: "static.radare2".to_string(),
            label: "Static analysis via radare2".to_string(),
            category: "static".to_string(),
            available: true,
            notes: Some(
                "Collects binary metadata, symbols, strings, functions, CFGs, and xrefs"
                    .to_string(),
            ),
        },
        AnalyzerCapability {
            key: "runtime.emulation".to_string(),
            label: "Runtime emulation".to_string(),
            category: "runtime".to_string(),
            available: false,
            notes: Some("Reserved for a future phase".to_string()),
        },
        AnalyzerCapability {
            key: "runtime.debugging".to_string(),
            label: "Interactive debugging".to_string(),
            category: "runtime".to_string(),
            available: false,
            notes: Some("Reserved for a future phase".to_string()),
        },
    ]
}

pub fn default_case_request(target_path: String, profile: AnalysisProfile) -> CreateCaseRequest {
    CreateCaseRequest {
        label: None,
        target_path,
        profile: Some(profile),
    }
}

pub fn status_event(
    case_id: &str,
    event: TimelineEventKind,
    message: &str,
    progress: Option<f32>,
    payload: Value,
) -> ServerEvent {
    ServerEvent {
        event,
        case_id: case_id.to_string(),
        timestamp: Utc::now(),
        message: message.to_string(),
        progress,
        payload,
        teaching_summary: None,
        related_entity_ids: Vec::new(),
        llm_context: Value::Null,
    }
}

pub fn manifest_snapshot(manifest: &CaseManifest) -> Value {
    json!({
        "status": manifest.status,
        "profile": manifest.profile,
        "architecture": manifest.architecture,
        "binary_format": manifest.binary_format,
        "file_size": manifest.file_size,
        "sha256": manifest.sha256,
    })
}

fn artifact_signature(
    kind: &str,
    label: &str,
    normalized: &Value,
    raw: Option<&Value>,
) -> Result<String> {
    let payload = json!({
        "kind": kind,
        "label": label,
        "normalized": normalized,
        "raw": raw,
    });
    let digest = Sha256::digest(serde_json::to_vec(&payload)?);
    Ok(format!("{digest:x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_store() -> (CaseStore, String, PathBuf) {
        let base =
            std::env::temp_dir().join(format!("reverseorbit-storage-test-{}", Uuid::new_v4()));
        let store = CaseStore::new(base.clone());
        let request = CreateCaseRequest {
            label: Some("test-case".to_string()),
            target_path: "/bin/ls".to_string(),
            profile: Some(AnalysisProfile::Quick),
        };
        let manifest = store
            .create_case(&request, capability_set())
            .expect("test case should be created");
        (store, manifest.id, base)
    }

    #[test]
    fn upsert_artifact_dedups_same_payload() {
        let (store, case_id, base) = make_test_store();

        let first = make_artifact(
            &case_id,
            "xref-probe",
            "Xrefs: connect",
            "first",
            json!({"target": "connect"}),
        );
        let persisted_first = store
            .upsert_artifact(&case_id, first, None, &json!({"xrefs": [1, 2, 3]}))
            .expect("first artifact should be inserted");

        let second = make_artifact(
            &case_id,
            "xref-probe",
            "Xrefs: connect",
            "second",
            json!({"target": "connect"}),
        );
        let persisted_second = store
            .upsert_artifact(&case_id, second, None, &json!({"xrefs": [1, 2, 3]}))
            .expect("second artifact should dedup");

        assert_eq!(persisted_first.id, persisted_second.id);
        assert_eq!(
            store
                .load_artifacts(&case_id)
                .expect("artifacts should load")
                .len(),
            1
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn upsert_artifact_keeps_distinct_payloads() {
        let (store, case_id, base) = make_test_store();

        let first = make_artifact(
            &case_id,
            "xref-probe",
            "Xrefs: connect",
            "first",
            json!({"target": "connect"}),
        );
        store
            .upsert_artifact(&case_id, first, None, &json!({"xrefs": [1, 2, 3]}))
            .expect("first artifact should be inserted");

        let second = make_artifact(
            &case_id,
            "xref-probe",
            "Xrefs: connect",
            "second",
            json!({"target": "connect"}),
        );
        store
            .upsert_artifact(&case_id, second, None, &json!({"xrefs": [4, 5, 6]}))
            .expect("second artifact should be inserted");

        assert_eq!(
            store
                .load_artifacts(&case_id)
                .expect("artifacts should load")
                .len(),
            2
        );

        let _ = fs::remove_dir_all(base);
    }
}
