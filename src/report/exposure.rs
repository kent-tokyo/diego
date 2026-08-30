use serde::{Deserialize, Serialize};

use chrono::{DateTime, Utc};

use super::{Confidence, Finding, Report, Severity};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExposureNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub source_finding_ids: Vec<String>,
    pub confidence: Confidence,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExposureEdge {
    pub from: String,
    pub to: String,
    pub relationship: String,
    pub source_finding_ids: Vec<String>,
    pub confidence: Confidence,
    pub observed_at: DateTime<Utc>,
}

/// A deliberately bounded graph: it contains only relationships evidenced by
/// diego findings, not a claim of complete AD/BloodHound graph coverage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExposureGraph {
    pub schema_version: String,
    pub scope: String,
    pub complete: bool,
    pub missing_data: Vec<String>,
    pub nodes: Vec<ExposureNode>,
    pub edges: Vec<ExposureEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationSimulation {
    pub simulated_finding_ids: Vec<String>,
    pub remaining_finding_ids: Vec<String>,
    pub removed_finding_ids: Vec<String>,
    pub remaining_graph: ExposureGraph,
    pub assumptions: Vec<String>,
}

pub fn build(report: &Report) -> ExposureGraph {
    let root = "context:standard_user".to_string();
    let protected = "target:protected-assets".to_string();
    let mut nodes = vec![ExposureNode {
        id: root.clone(),
        kind: "context".into(),
        label: "Authenticated standard user context".into(),
        source_finding_ids: Vec::new(),
        confidence: Confidence::High,
        observed_at: report.generated_at,
    }];
    let mut edges = Vec::new();

    for finding in &report.findings {
        let finding_node = format!("finding:{}", finding.id);
        nodes.push(ExposureNode {
            id: finding_node.clone(),
            kind: "finding".into(),
            label: finding.title.clone(),
            source_finding_ids: vec![finding.id.clone()],
            confidence: finding.confidence.clone(),
            observed_at: finding.timestamp,
        });
        let object = object_node(finding, report.generated_at);
        if let Some(object) = object {
            let object_id = object.id.clone();
            nodes.push(object);
            edges.push(ExposureEdge {
                from: root.clone(),
                to: object_id.clone(),
                relationship: "standard-user-readable object evidence".into(),
                source_finding_ids: vec![finding.id.clone()],
                confidence: finding.confidence.clone(),
                observed_at: finding.timestamp,
            });
            edges.push(ExposureEdge {
                from: object_id,
                to: finding_node.clone(),
                relationship: "object produces documented finding".into(),
                source_finding_ids: vec![finding.id.clone()],
                confidence: finding.confidence.clone(),
                observed_at: finding.timestamp,
            });
        }
        edges.push(ExposureEdge {
            from: root.clone(),
            to: finding_node.clone(),
            relationship: "standard-user-visible exposure".into(),
            source_finding_ids: vec![finding.id.clone()],
            confidence: finding.confidence.clone(),
            observed_at: finding.timestamp,
        });

        if indicates_protected_impact(finding) {
            if !nodes.iter().any(|node| node.id == protected) {
                nodes.push(ExposureNode {
                    id: protected.clone(),
                    kind: "bounded-target".into(),
                    label: "Protected or privileged assets (scope-limited)".into(),
                    source_finding_ids: Vec::new(),
                    confidence: Confidence::Low,
                    observed_at: report.generated_at,
                });
            }
            edges.push(ExposureEdge {
                from: finding_node.clone(),
                to: protected.clone(),
                relationship: "may affect protected assets".into(),
                source_finding_ids: vec![finding.id.clone()],
                confidence: finding.confidence.clone(),
                observed_at: finding.timestamp,
            });
        }

        for (index, step) in finding.remediation_steps.iter().enumerate() {
            let remediation_id = format!("remediation:{}:{}", finding.id, index + 1);
            nodes.push(ExposureNode {
                id: remediation_id.clone(),
                kind: "remediation-candidate".into(),
                label: step.clone(),
                source_finding_ids: vec![finding.id.clone()],
                confidence: finding.confidence.clone(),
                observed_at: finding.timestamp,
            });
            edges.push(ExposureEdge {
                from: finding_node.clone(),
                to: remediation_id,
                relationship: "candidate remediation reduces this documented exposure".into(),
                source_finding_ids: vec![finding.id.clone()],
                confidence: finding.confidence.clone(),
                observed_at: finding.timestamp,
            });
        }
    }

    ExposureGraph {
        schema_version: "1".into(),
        scope: "Only diego findings and their documented standard-user-visible impact; not a complete directory graph.".into(),
        complete: false,
        missing_data: vec![
            "Full group membership and SID relationship graph".into(),
            "ACL security descriptors not collected by the current read-only queries".into(),
            "Trust topology and certificate-template relationships".into(),
            "Object-to-protected-asset reachability is not inferred without collected ACL/SID evidence".into(),
        ],
        nodes,
        edges,
    }
}

fn object_node(finding: &Finding, observed_at: DateTime<Utc>) -> Option<ExposureNode> {
    let (kind, key) = if finding.evidence.get("account").is_some() {
        ("account", "account")
    } else if finding.evidence.get("computer").is_some() {
        ("computer", "computer")
    } else if finding.evidence.get("cn").is_some() {
        ("directory-object", "cn")
    } else {
        return None;
    };
    let label = finding.evidence.get(key).and_then(serde_json::Value::as_str)?.to_string();
    Some(ExposureNode { id: format!("object:{}:{}", kind, label.to_ascii_lowercase()), kind: kind.into(), label, source_finding_ids: vec![finding.id.clone()], confidence: finding.confidence.clone(), observed_at })
}

pub fn simulate(report: &Report, finding_ids: &[String]) -> RemediationSimulation {
    let simulated: Vec<String> = finding_ids.iter().map(|id| id.to_ascii_uppercase()).collect();
    let removed_finding_ids: Vec<String> = report
        .findings
        .iter()
        .filter(|finding| simulated.iter().any(|id| id.eq_ignore_ascii_case(&finding.id)))
        .map(|finding| finding.id.clone())
        .collect();
    let remaining_finding_ids: Vec<String> = report
        .findings
        .iter()
        .filter(|finding| !removed_finding_ids.iter().any(|id| id == &finding.id))
        .map(|finding| finding.id.clone())
        .collect();
    let remaining_findings: Vec<Finding> = report
        .findings
        .iter()
        .filter(|finding| remaining_finding_ids.iter().any(|id| id == &finding.id))
        .cloned()
        .collect();
    let mut remaining_report = report.clone();
    remaining_report.findings = remaining_findings;
    remaining_report.summary = super::Summary {
        critical: remaining_report.findings.iter().filter(|f| f.severity == Severity::Critical).count(),
        high: remaining_report.findings.iter().filter(|f| f.severity == Severity::High).count(),
        medium: remaining_report.findings.iter().filter(|f| f.severity == Severity::Medium).count(),
        low: remaining_report.findings.iter().filter(|f| f.severity == Severity::Low).count(),
        info: remaining_report.findings.iter().filter(|f| f.severity == Severity::Info).count(),
        total: remaining_report.findings.len(),
    };

    RemediationSimulation {
        simulated_finding_ids: simulated,
        remaining_finding_ids,
        removed_finding_ids,
        remaining_graph: build(&remaining_report),
        assumptions: vec![
            "Simulation removes selected finding nodes only; it does not modify Active Directory.".into(),
            "Relationships not evidenced by diego remain unknown rather than being inferred.".into(),
        ],
    }
}

fn indicates_protected_impact(finding: &Finding) -> bool {
    finding.severity == Severity::Critical
        || finding.id.contains("PRIVESC")
        || finding.id.contains("ASREP")
        || finding.id.contains("KERBEROAST")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, ScanContext};

    fn report() -> Report {
        Report::new(
            ScanContext {
                dc_ip: "192.0.2.1".into(),
                domain: "corp.local".into(),
                username: "auditor".into(),
                privilege_level: "standard_user".into(),
                modules_run: vec!["ldap".into()],
                duration_secs: 1,
            },
            vec![Finding::new(
                "LDAP-RBCD-APP01", "ldap", Severity::Critical, "RBCD", "test",
                serde_json::json!({"cn": "APP01"}), None,
            )],
        )
    }

    #[test]
    fn graph_is_bounded_and_provenance_is_preserved() {
        let graph = build(&report());
        assert!(!graph.complete);
        assert!(!graph.missing_data.is_empty());
        assert!(graph.edges.iter().all(|edge| !edge.source_finding_ids.is_empty()));
    }

    #[test]
    fn simulation_does_not_mutate_the_original_report() {
        let original = report();
        let simulation = simulate(&original, &["LDAP-RBCD-APP01".into()]);
        assert_eq!(simulation.removed_finding_ids, vec!["LDAP-RBCD-APP01"]);
        assert!(simulation.remaining_finding_ids.is_empty());
        assert_eq!(original.findings.len(), 1);
        assert!(simulation.assumptions.iter().any(|a| a.contains("does not modify")));
    }
}
