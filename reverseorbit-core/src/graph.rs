use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::Utc;
use serde_json::json;

use crate::models::*;

pub fn rebuild_graphs(
    manifest: &CaseManifest,
    timeline: &[TimelineStep],
    findings: &[Finding],
    actions: &[NextAction],
    artifacts: &[ArtifactNode],
    snapshot: Option<&NormalizedSnapshot>,
) -> Vec<GraphBundle> {
    let mut graphs = vec![build_provenance_graph(
        manifest, timeline, findings, actions, artifacts,
    )];
    if let Some(snapshot) = snapshot {
        graphs.push(build_call_graph(manifest.id.as_str(), snapshot));
        graphs.push(build_cfg_graph(manifest.id.as_str(), snapshot));
        graphs.push(build_xref_graph(manifest.id.as_str(), snapshot));
        graphs.push(build_string_relation_graph(manifest.id.as_str(), snapshot));
    }
    graphs
}

fn build_provenance_graph(
    manifest: &CaseManifest,
    timeline: &[TimelineStep],
    findings: &[Finding],
    actions: &[NextAction],
    artifacts: &[ArtifactNode],
) -> GraphBundle {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut seen = HashSet::new();

    let case_node_id = format!("case:{}", manifest.id);
    nodes.push(GraphNode {
        id: case_node_id.clone(),
        label: manifest.label.clone(),
        kind: "case".to_string(),
        group: "case".to_string(),
        summary: manifest.summary.clone().unwrap_or_default(),
        metadata: json!({
            "status": manifest.status,
            "target_path": manifest.target_path,
            "profile": manifest.profile,
        }),
    });
    seen.insert(case_node_id.clone());

    for artifact in artifacts {
        nodes.push(GraphNode {
            id: artifact.id.clone(),
            label: artifact.label.clone(),
            kind: artifact.kind.clone(),
            group: "artifact".to_string(),
            summary: artifact.summary.clone(),
            metadata: artifact.metadata.clone(),
        });
        edges.push(GraphEdge {
            id: format!("edge:{}:{}", case_node_id, artifact.id),
            source: case_node_id.clone(),
            target: artifact.id.clone(),
            label: "produced".to_string(),
            kind: "provenance".to_string(),
            weight: 1.0,
        });
    }

    for step in timeline {
        if seen.insert(step.id.clone()) {
            nodes.push(GraphNode {
                id: step.id.clone(),
                label: step.title.clone(),
                kind: "timeline_step".to_string(),
                group: "timeline".to_string(),
                summary: step.result_summary.clone(),
                metadata: json!({
                    "why": step.why,
                    "how": step.how,
                    "tool": step.tool,
                }),
            });
        }
        edges.push(GraphEdge {
            id: format!("edge:{}:{}", case_node_id, step.id),
            source: case_node_id.clone(),
            target: step.id.clone(),
            label: "timeline".to_string(),
            kind: "provenance".to_string(),
            weight: 1.0,
        });

        for artifact_id in &step.artifact_ids {
            edges.push(GraphEdge {
                id: format!("edge:{}:{}", step.id, artifact_id),
                source: step.id.clone(),
                target: artifact_id.clone(),
                label: "generated".to_string(),
                kind: "provenance".to_string(),
                weight: 1.0,
            });
        }
        for finding_id in &step.finding_ids {
            edges.push(GraphEdge {
                id: format!("edge:{}:{}", step.id, finding_id),
                source: step.id.clone(),
                target: finding_id.clone(),
                label: "flagged".to_string(),
                kind: "provenance".to_string(),
                weight: 1.0,
            });
        }
        for action_id in &step.next_action_ids {
            edges.push(GraphEdge {
                id: format!("edge:{}:{}", step.id, action_id),
                source: step.id.clone(),
                target: action_id.clone(),
                label: "recommended".to_string(),
                kind: "provenance".to_string(),
                weight: 1.0,
            });
        }
    }

    for finding in findings {
        if seen.insert(finding.id.clone()) {
            nodes.push(GraphNode {
                id: finding.id.clone(),
                label: finding.title.clone(),
                kind: "finding".to_string(),
                group: "finding".to_string(),
                summary: finding.summary.clone(),
                metadata: json!({
                    "severity": finding.severity,
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "rule_id": finding.playbook_rule_id,
                    "rule_kind": finding.playbook_rule_kind,
                }),
            });
        }
        edges.push(GraphEdge {
            id: format!("edge:{}:{}", case_node_id, finding.id),
            source: case_node_id.clone(),
            target: finding.id.clone(),
            label: "finding".to_string(),
            kind: "provenance".to_string(),
            weight: 1.0,
        });
        for action_id in &finding.next_action_ids {
            edges.push(GraphEdge {
                id: format!("edge:{}:{}", finding.id, action_id),
                source: finding.id.clone(),
                target: action_id.clone(),
                label: "next".to_string(),
                kind: "provenance".to_string(),
                weight: 1.0,
            });
        }

        for (index, evidence_item) in finding.evidence.iter().enumerate() {
            let evidence_node_id = format!("evidence:{}:{}", finding.id, index);
            if seen.insert(evidence_node_id.clone()) {
                nodes.push(GraphNode {
                    id: evidence_node_id.clone(),
                    label: evidence_item.label.clone(),
                    kind: "evidence".to_string(),
                    group: "evidence".to_string(),
                    summary: evidence_item
                        .snippet
                        .clone()
                        .unwrap_or_else(|| "Evidence supporting this finding".to_string()),
                    metadata: evidence_item.metadata.clone(),
                });
            }

            edges.push(GraphEdge {
                id: format!("edge:{}:{}", finding.id, evidence_node_id),
                source: finding.id.clone(),
                target: evidence_node_id.clone(),
                label: "supported_by".to_string(),
                kind: "evidence".to_string(),
                weight: 0.8,
            });

            if let Some(entity_id) = &evidence_item.entity_id {
                let related_entity = finding
                    .entity_refs
                    .iter()
                    .find(|entity| entity.id == *entity_id);
                let entity_kind = related_entity
                    .map(|entity| entity.kind.clone())
                    .unwrap_or_else(|| "entity".to_string());
                let entity_label = related_entity
                    .and_then(|entity| entity.label.clone())
                    .unwrap_or_else(|| entity_id.clone());
                let entity_node_id = format!("entity:{}:{}", entity_kind, entity_id);

                if seen.insert(entity_node_id.clone()) {
                    nodes.push(GraphNode {
                        id: entity_node_id.clone(),
                        label: entity_label,
                        kind: "entity".to_string(),
                        group: "entity".to_string(),
                        summary: format!("Referenced {} indicator", entity_kind),
                        metadata: json!({
                            "entity_id": entity_id,
                            "entity_kind": entity_kind,
                        }),
                    });
                }

                edges.push(GraphEdge {
                    id: format!("edge:{}:{}", evidence_node_id, entity_node_id),
                    source: evidence_node_id.clone(),
                    target: entity_node_id,
                    label: "references".to_string(),
                    kind: "evidence".to_string(),
                    weight: 0.7,
                });
            }
        }
    }

    for action in actions {
        if seen.insert(action.id.clone()) {
            nodes.push(GraphNode {
                id: action.id.clone(),
                label: action.title.clone(),
                kind: "action".to_string(),
                group: "action".to_string(),
                summary: action.why.clone(),
                metadata: json!({
                    "action_type": action.action_type,
                    "status": action.status,
                    "generated_from": action.generated_from,
                }),
            });
        }

        for finding_id in &action.related_finding_ids {
            edges.push(GraphEdge {
                id: format!("edge:{}:{}:motivates", finding_id, action.id),
                source: finding_id.clone(),
                target: action.id.clone(),
                label: "motivates".to_string(),
                kind: "causality".to_string(),
                weight: 1.0,
            });
        }
    }

    GraphBundle {
        case_id: manifest.id.clone(),
        view: GraphViewKind::Provenance,
        title: "Provenance".to_string(),
        description: "How steps, findings, artifacts, and analyst actions connect within the case."
            .to_string(),
        updated_at: Utc::now(),
        nodes,
        edges,
    }
}

fn build_call_graph(case_id: &str, snapshot: &NormalizedSnapshot) -> GraphBundle {
    let mut nodes = BTreeMap::<String, GraphNode>::new();
    let mut edges = Vec::new();
    for function in &snapshot.functions {
        nodes.insert(
            function.name.clone(),
            GraphNode {
                id: function.name.clone(),
                label: function.name.clone(),
                kind: "function".to_string(),
                group: "function".to_string(),
                summary: format!("size {} at 0x{:x}", function.size, function.addr),
                metadata: json!({
                    "addr": function.addr,
                    "size": function.size,
                    "indegree": function.indegree,
                    "outdegree": function.outdegree,
                }),
            },
        );
    }
    for edge in &snapshot.call_edges {
        edges.push(GraphEdge {
            id: format!("call:{}:{}", edge.from, edge.to),
            source: edge.from.clone(),
            target: edge.to.clone(),
            label: edge.relation.clone(),
            kind: "call".to_string(),
            weight: 1.0,
        });
        nodes.entry(edge.to.clone()).or_insert_with(|| GraphNode {
            id: edge.to.clone(),
            label: edge.to.clone(),
            kind: "callee".to_string(),
            group: if edge.to.starts_with("sym.imp.") {
                "import".to_string()
            } else {
                "function".to_string()
            },
            summary: "Referenced call target".to_string(),
            metadata: json!({}),
        });
    }
    GraphBundle {
        case_id: case_id.to_string(),
        view: GraphViewKind::CallGraph,
        title: "Call Graph".to_string(),
        description: "Call relationships derived from analyzed function summaries.".to_string(),
        updated_at: Utc::now(),
        nodes: nodes.into_values().collect(),
        edges,
    }
}

fn build_cfg_graph(case_id: &str, snapshot: &NormalizedSnapshot) -> GraphBundle {
    let mut nodes = Vec::new();
    let mut pending_edges = Vec::new();

    for detail in &snapshot.function_details {
        nodes.push(GraphNode {
            id: detail.name.clone(),
            label: detail.name.clone(),
            kind: "function_detail".to_string(),
            group: "function".to_string(),
            summary: format!("Detailed CFG available for 0x{:x}", detail.addr),
            metadata: json!({
                "addr": detail.addr,
                "cfg_blocks": detail.cfg.get(0).and_then(|cfg| cfg.get("blocks")).and_then(|blocks| blocks.as_array()).map(|items| items.len()),
            }),
        });

        if let Some(blocks) = detail
            .cfg
            .get(0)
            .and_then(|cfg| cfg.get("blocks"))
            .and_then(|blocks| blocks.as_array())
        {
            for block in blocks {
                let Some(addr) = block.get("addr").and_then(|value| value.as_u64()) else {
                    continue;
                };
                let node_id = format!("{}:bb:{addr:x}", detail.name);

                nodes.push(GraphNode {
                    id: node_id.clone(),
                    label: format!("0x{addr:x}"),
                    kind: "basic_block".to_string(),
                    group: "cfg".to_string(),
                    summary: format!("Basic block in {}", detail.name),
                    metadata: block.clone(),
                });

                // function → basic-block containment edge (always valid)
                pending_edges.push(GraphEdge {
                    id: format!("cfg:{}:{}", detail.name, node_id),
                    source: detail.name.clone(),
                    target: node_id.clone(),
                    label: "contains".to_string(),
                    kind: "cfg".to_string(),
                    weight: 1.0,
                });

                // Control-flow edges — recorded now, validated after all nodes exist
                for relation in ["jump", "fail"] {
                    if let Some(target_addr) = block.get(relation).and_then(|v| v.as_u64()) {
                        pending_edges.push(GraphEdge {
                            id: format!("cfg:{}:{addr:x}:{relation}:{target_addr:x}", detail.name),
                            source: node_id.clone(),
                            target: format!("{}:bb:{target_addr:x}", detail.name),
                            label: relation.to_string(),
                            kind: "cfg".to_string(),
                            weight: 1.0,
                        });
                    }
                }
            }
        }
    }

    // Build a set of all valid node IDs so we can drop dangling edges.
    // Dagre (and most layout engines) crash silently when an edge references
    // a node that does not exist, producing a blank canvas in the frontend.
    let valid_ids: HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let edges = pending_edges
        .into_iter()
        .filter(|e| valid_ids.contains(&e.source) && valid_ids.contains(&e.target))
        .collect();

    GraphBundle {
        case_id: case_id.to_string(),
        view: GraphViewKind::Cfg,
        title: "CFG".to_string(),
        description: "Basic-block control flow derived from selected hot functions.".to_string(),
        updated_at: Utc::now(),
        nodes,
        edges,
    }
}

fn build_xref_graph(case_id: &str, snapshot: &NormalizedSnapshot) -> GraphBundle {
    let mut nodes = HashMap::<String, GraphNode>::new();
    let mut edges = Vec::new();

    for probe in &snapshot.xref_probes {
        nodes
            .entry(probe.target.clone())
            .or_insert_with(|| GraphNode {
                id: probe.target.clone(),
                label: probe.target.clone(),
                kind: probe.target_kind.clone(),
                group: "xref_target".to_string(),
                summary: "Collected xref probe target".to_string(),
                metadata: json!({
                    "target_kind": probe.target_kind,
                    "xref_count": probe.xrefs.len(),
                }),
            });
        for xref in &probe.xrefs {
            let caller = xref
                .function_name
                .clone()
                .unwrap_or_else(|| format!("sub_{:x}", xref.from.unwrap_or_default()));
            nodes.entry(caller.clone()).or_insert_with(|| GraphNode {
                id: caller.clone(),
                label: caller.clone(),
                kind: "function".to_string(),
                group: "function".to_string(),
                summary: "Function discovered through xref probing".to_string(),
                metadata: json!({
                    "from": xref.from,
                }),
            });
            edges.push(GraphEdge {
                id: format!("xref:{}:{}", caller, probe.target),
                source: caller,
                target: probe.target.clone(),
                label: xref.kind.clone().unwrap_or_else(|| "xref".to_string()),
                kind: "xref".to_string(),
                weight: 1.0,
            });
        }
    }

    GraphBundle {
        case_id: case_id.to_string(),
        view: GraphViewKind::XrefView,
        title: "Xrefs".to_string(),
        description:
            "Function-to-target reference pivots collected during analysis and follow-up actions."
                .to_string(),
        updated_at: Utc::now(),
        nodes: nodes.into_values().collect(),
        edges,
    }
}

fn build_string_relation_graph(case_id: &str, snapshot: &NormalizedSnapshot) -> GraphBundle {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let suspicious: HashSet<&String> = snapshot.suspicious_strings.iter().collect();
    for string in snapshot
        .strings
        .iter()
        .filter(|item| suspicious.contains(&item.value))
        .take(40)
    {
        nodes.push(GraphNode {
            id: string.id.clone(),
            label: truncate(&string.value),
            kind: "string".to_string(),
            group: "string".to_string(),
            summary: format!("Suspicious string at {:?}", string.vaddr),
            metadata: json!({
                "value": string.value,
                "vaddr": string.vaddr,
                "section": string.section,
            }),
        });
    }

    for string in snapshot
        .strings
        .iter()
        .filter(|item| suspicious.contains(&item.value))
        .take(40)
    {
        for probe in snapshot.xref_probes.iter().filter(|probe| {
            probe.target_kind == "string"
                && (probe.target == string.value
                    || probe.target == format!("0x{:x}", string.vaddr.unwrap_or_default()))
        }) {
            for xref in &probe.xrefs {
                let caller = xref
                    .function_name
                    .clone()
                    .unwrap_or_else(|| format!("sub_{:x}", xref.from.unwrap_or_default()));
                nodes.push(GraphNode {
                    id: caller.clone(),
                    label: caller.clone(),
                    kind: "function".to_string(),
                    group: "function".to_string(),
                    summary: "References suspicious string".to_string(),
                    metadata: json!({ "from": xref.from }),
                });
                edges.push(GraphEdge {
                    id: format!("string:{}:{}", caller, string.id),
                    source: caller,
                    target: string.id.clone(),
                    label: "references".to_string(),
                    kind: "string_ref".to_string(),
                    weight: 1.0,
                });
            }
        }
    }

    GraphBundle {
        case_id: case_id.to_string(),
        view: GraphViewKind::StringRelationView,
        title: "String Relations".to_string(),
        description: "Suspicious strings and the functions that reference them.".to_string(),
        updated_at: Utc::now(),
        nodes,
        edges,
    }
}

pub fn export_graphml(graph: &GraphBundle) -> String {
    let mut output = String::new();
    output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    output.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
    output.push_str("  <graph edgedefault=\"directed\">\n");
    for node in &graph.nodes {
        output.push_str(&format!(
            "    <node id=\"{}\"><data key=\"label\">{}</data><data key=\"kind\">{}</data><data key=\"group\">{}</data></node>\n",
            escape_xml(&node.id),
            escape_xml(&node.label),
            escape_xml(&node.kind),
            escape_xml(&node.group)
        ));
    }
    for edge in &graph.edges {
        output.push_str(&format!(
            "    <edge id=\"{}\" source=\"{}\" target=\"{}\"><data key=\"label\">{}</data><data key=\"kind\">{}</data></edge>\n",
            escape_xml(&edge.id),
            escape_xml(&edge.source),
            escape_xml(&edge.target),
            escape_xml(&edge.label),
            escape_xml(&edge.kind)
        ));
    }
    output.push_str("  </graph>\n</graphml>\n");
    output
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn truncate(value: &str) -> String {
    if value.len() > 42 {
        format!("{}...", &value[..42])
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphml_export_contains_nodes_and_edges() {
        let graph = GraphBundle {
            case_id: "case-1".to_string(),
            view: GraphViewKind::Provenance,
            title: "Test".to_string(),
            description: "desc".to_string(),
            updated_at: Utc::now(),
            nodes: vec![
                GraphNode {
                    id: "n1".to_string(),
                    label: "Node 1".to_string(),
                    kind: "case".to_string(),
                    group: "case".to_string(),
                    summary: String::new(),
                    metadata: json!({}),
                },
                GraphNode {
                    id: "n2".to_string(),
                    label: "Node 2".to_string(),
                    kind: "step".to_string(),
                    group: "timeline".to_string(),
                    summary: String::new(),
                    metadata: json!({}),
                },
            ],
            edges: vec![GraphEdge {
                id: "e1".to_string(),
                source: "n1".to_string(),
                target: "n2".to_string(),
                label: "links".to_string(),
                kind: "provenance".to_string(),
                weight: 1.0,
            }],
        };

        let graphml = export_graphml(&graph);
        assert!(graphml.contains("<node id=\"n1\">"));
        assert!(graphml.contains("<edge id=\"e1\" source=\"n1\" target=\"n2\">"));
    }
}
