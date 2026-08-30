//! Deterministic, defensive attack-path summary from collected finding hints.
//!
//! This is a report projection only. It does not infer new relationships, send
//! traffic, execute actions, or expose credential material.

use super::{Report, Severity};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackPathReport {
    pub schema: &'static str,
    pub domain: String,
    pub from: &'static str,
    pub target: &'static str,
    pub steps: Vec<AttackPathStep>,
    pub limitation: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackPathStep {
    pub finding_id: String,
    pub title: String,
    pub severity: Severity,
    pub hint: String,
}

pub fn build(report: &Report) -> AttackPathReport {
    let mut findings = report
        .findings
        .iter()
        .filter(|finding| {
            finding.attack_path_hint.is_some()
                && matches!(finding.severity, Severity::Critical | Severity::High)
        })
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.id.cmp(&right.id))
    });

    AttackPathReport {
        schema: "diego.attack-path.v1",
        domain: report.domain.clone(),
        from: "standard_user",
        target: "protected assets",
        steps: findings
            .into_iter()
            .filter_map(|finding| {
                finding
                    .attack_path_hint
                    .as_ref()
                    .map(|hint| AttackPathStep {
                        finding_id: finding.id.clone(),
                        title: finding.title.clone(),
                        severity: finding.severity.clone(),
                        hint: hint.clone(),
                    })
            })
            .collect(),
        limitation: "This is a bounded summary of observed finding hints, not an exploit path or a complete directory graph.",
    }
}

pub fn generate_json(report: &Report) -> anyhow::Result<String> {
    serde_json::to_string_pretty(&build(report)).map_err(Into::into)
}

pub fn generate_markdown(report: &Report) -> String {
    let path = build(report);
    let mut output = format!(
        "# Defensive Attack Path — {}\n\nFrom `{}` to `{}`.\n\n",
        path.domain, path.from, path.target
    );
    if path.steps.is_empty() {
        output.push_str("No Critical/High finding contains an attack-path hint.\n\n");
    } else {
        for (index, step) in path.steps.iter().enumerate() {
            output.push_str(&format!(
                "{}. **[{}] {}** (`{}`): {}\n",
                index + 1,
                step.severity,
                step.title,
                step.finding_id,
                step.hint
            ));
        }
        output.push('\n');
    }
    output.push_str(&format!("_Limitation: {}_\n", path.limitation));
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::sample::sample_report;

    #[test]
    fn orders_path_by_severity_and_uses_stable_schema() {
        let report = sample_report();
        let path = build(&report);
        assert_eq!(path.schema, "diego.attack-path.v1");
        assert_eq!(path.from, "standard_user");
        assert_eq!(path.steps[0].severity, Severity::Critical);
        assert!(path.steps.iter().all(|step| step.hint != ""));
        assert!(!generate_json(&report).unwrap().contains("evidence"));
    }
}
