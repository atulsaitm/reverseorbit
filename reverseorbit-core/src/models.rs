use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Created,
    Analyzing,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisProfile {
    Quick,
    Full,
}

impl Default for AnalysisProfile {
    fn default() -> Self {
        Self::Quick
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GraphViewKind {
    Provenance,
    CallGraph,
    Cfg,
    XrefView,
    StringRelationView,
}

impl GraphViewKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Provenance => "provenance",
            Self::CallGraph => "call_graph",
            Self::Cfg => "cfg",
            Self::XrefView => "xref_view",
            Self::StringRelationView => "string_relation_view",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimelineStepStatus {
    Pending,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Confirmed,
    Intermediate,
    Noise,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NextActionStatus {
    Pending,
    Complete,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventKind {
    Progress,
    StepStart,
    StepComplete,
    FindingCreated,
    ActionRecommended,
    GraphUpdated,
    StatusChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerCapability {
    pub key: String,
    pub label: String,
    pub category: String,
    pub available: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseManifest {
    pub id: String,
    pub label: String,
    pub target_path: String,
    pub source: String,
    pub status: CaseStatus,
    pub profile: AnalysisProfile,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub summary: Option<String>,
    pub architecture: Option<String>,
    pub binary_format: Option<String>,
    pub file_size: Option<u64>,
    pub sha256: Option<String>,
    pub capabilities: Vec<AnalyzerCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactNode {
    pub id: String,
    pub case_id: String,
    pub kind: String,
    pub label: String,
    pub source: String,
    pub summary: String,
    pub created_at: DateTime<Utc>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEdge {
    pub from_id: String,
    pub to_id: String,
    pub relation: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub label: String,
    pub entity_id: Option<String>,
    pub artifact_id: Option<String>,
    pub snippet: Option<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRef {
    pub kind: String,
    pub id: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceStep {
    pub premise: String,
    pub conclusion: String,
    pub confidence_contribution: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookRuleKind {
    SuspiciousImport,
    SuspiciousString,
    FunctionHeuristic,
    RuntimeSignal,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPathSegment {
    pub function: String,
    pub instruction_addr: u64,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextAction {
    pub id: String,
    pub case_id: String,
    pub title: String,
    pub why: String,
    pub how: String,
    pub action_type: String,
    pub params: Value,
    pub related_entity_ids: Vec<String>,
    #[serde(default)]
    pub related_finding_ids: Vec<String>,
    pub generated_from: Option<String>,
    #[serde(default)]
    pub skip_consequences: String,
    #[serde(default)]
    pub execution_path: Vec<ExecutionPathSegment>,
    pub created_at: DateTime<Utc>,
    pub status: NextActionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineStep {
    pub id: String,
    pub case_id: String,
    pub created_at: DateTime<Utc>,
    pub status: TimelineStepStatus,
    pub title: String,
    pub why: String,
    pub how: String,
    pub tool: String,
    pub tool_args: Vec<String>,
    pub result_summary: String,
    pub artifact_ids: Vec<String>,
    pub finding_ids: Vec<String>,
    pub next_action_ids: Vec<String>,
    pub raw_command: Option<String>,
    #[serde(default)]
    pub playbook_context: Value,
    #[serde(default)]
    pub snapshot_diff: Option<String>,
    #[serde(default)]
    pub teaching_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub case_id: String,
    pub title: String,
    pub summary: String,
    pub category: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub rationale: String,
    pub confidence: f32,
    pub source: String,
    pub tags: Vec<String>,
    pub entity_refs: Vec<EntityRef>,
    pub evidence: Vec<EvidenceItem>,
    #[serde(default)]
    pub playbook_rule_id: String,
    #[serde(default)]
    pub playbook_rule_kind: Option<PlaybookRuleKind>,
    #[serde(default)]
    pub inference_chain: Vec<InferenceStep>,
    #[serde(default)]
    pub confidence_rationale: String,
    #[serde(default)]
    pub counter_evidence: Vec<String>,
    pub next_action_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub group: String,
    pub summary: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub label: String,
    pub kind: String,
    pub weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphBundle {
    pub case_id: String,
    pub view: GraphViewKind,
    pub title: String,
    pub description: String,
    pub updated_at: DateTime<Utc>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMetadata {
    pub file_type: Option<String>,
    pub format: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub machine: Option<String>,
    pub bits: Option<u64>,
    pub size: u64,
    pub sha256: String,
    pub entry: Option<u64>,
    pub compiler: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramSection {
    pub name: String,
    pub vaddr: Option<u64>,
    pub paddr: Option<u64>,
    pub size: Option<u64>,
    pub vsize: Option<u64>,
    pub perm: Option<String>,
    pub section_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub name: String,
    pub bind: Option<String>,
    pub import_type: Option<String>,
    pub plt: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub export_type: Option<String>,
    pub vaddr: Option<u64>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    pub name: String,
    pub bind: Option<String>,
    pub symbol_type: Option<String>,
    pub vaddr: Option<u64>,
    pub size: Option<u64>,
    pub imported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub id: String,
    pub value: String,
    pub section: Option<String>,
    pub string_type: Option<String>,
    pub ordinal: Option<u64>,
    pub vaddr: Option<u64>,
    pub length: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub indegree: Option<u64>,
    pub outdegree: Option<u64>,
    pub cyclomatic_cost: Option<u64>,
    pub call_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefEntry {
    pub from: Option<u64>,
    pub target: Option<String>,
    pub kind: Option<String>,
    pub opcode: Option<String>,
    pub function_name: Option<String>,
    pub ref_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDetail {
    pub name: String,
    pub addr: u64,
    pub disassembly: Value,
    pub cfg: Value,
    pub xrefs: Vec<XrefEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefProbe {
    pub target: String,
    pub target_kind: String,
    pub xrefs: Vec<XrefEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedSnapshot {
    pub source: String,
    pub collected_at: DateTime<Utc>,
    pub metadata: BinaryMetadata,
    pub segments: Vec<ProgramSection>,
    pub sections: Vec<ProgramSection>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub symbols: Vec<SymbolEntry>,
    pub strings: Vec<StringEntry>,
    pub functions: Vec<FunctionSummary>,
    pub function_details: Vec<FunctionDetail>,
    pub xref_probes: Vec<XrefProbe>,
    pub call_edges: Vec<CallEdge>,
    pub suspicious_imports: Vec<String>,
    pub suspicious_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSummary {
    pub manifest: CaseManifest,
    pub timeline_count: usize,
    pub findings_count: usize,
    pub actions_count: usize,
    pub artifact_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    pub label: Option<String>,
    pub target_path: String,
    pub profile: Option<AnalysisProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeCaseRequest {
    pub profile: Option<AnalysisProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRunResult {
    pub action: NextAction,
    pub timeline_step: TimelineStep,
    pub artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEvent {
    pub event: TimelineEventKind,
    pub case_id: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub progress: Option<f32>,
    pub payload: Value,
    #[serde(default)]
    pub teaching_summary: Option<String>,
    #[serde(default)]
    pub related_entity_ids: Vec<String>,
    #[serde(default)]
    pub llm_context: Value,
}
