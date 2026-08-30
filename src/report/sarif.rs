//! SARIF 2.1.0 output for CI and security-platform integrations.
//!
//! The SARIF projection intentionally contains finding metadata and operator
//! guidance only. Evidence is kept in the normal diego report so the audit
//! mode redaction boundary cannot be bypassed by requesting SARIF output.

use super::{diff::DiffEntry, Finding, Report, Severity};
use serde::Serialize;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

#[derive(Debug, Serialize)]
pub struct SarifLog {
    pub version: &'static str,
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: &'static str,
    pub version: &'static str,
    pub information_uri: &'static str,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub short_description: SarifMessage,
    pub full_description: SarifMessage,
    pub help: SarifMessage,
}

#[derive(Debug, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: &'static str,
    pub message: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_state: Option<&'static str>,
    pub properties: serde_json::Value,
}

/// Convert a report to a SARIF 2.1.0 document without copying evidence.
pub fn generate(report: &Report) -> anyhow::Result<String> {
    let mut rules = report.findings.iter().map(rule_for).collect::<Vec<_>>();
    let mut results = report
        .findings
        .iter()
        .map(|finding| result_for(finding, state_for(report, finding)))
        .collect::<Vec<_>>();
    if let Some(diff) = &report.diff {
        for entry in &diff.resolved {
            rules.push(rule_for_diff(entry));
            results.push(result_for_diff(entry));
        }
    }

    let log = SarifLog {
        version: SARIF_VERSION,
        schema: SARIF_SCHEMA,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "diego",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/kent-tokyo/diego",
                    rules,
                },
            },
            results,
        }],
    };
    serde_json::to_string_pretty(&log).map_err(Into::into)
}

fn rule_for(finding: &Finding) -> SarifRule {
    rule(
        finding.id.clone(),
        finding.title.clone(),
        finding.description.clone(),
        finding.remediation_steps.join(" "),
    )
}

fn rule_for_diff(entry: &DiffEntry) -> SarifRule {
    rule(
        entry.id.clone(),
        entry.title.clone(),
        "Finding was present in the baseline but is absent from the current scan.".into(),
        "Validate the remediation and retain the baseline for audit history.".into(),
    )
}

fn rule(id: String, title: String, description: String, help: String) -> SarifRule {
    SarifRule {
        id,
        short_description: SarifMessage { text: title },
        full_description: SarifMessage { text: description },
        help: SarifMessage {
            text: if help.is_empty() {
                "Review the finding and validate the affected configuration.".into()
            } else {
                help
            },
        },
    }
}

fn result_for(finding: &Finding, baseline_state: Option<&'static str>) -> SarifResult {
    SarifResult {
        rule_id: finding.id.clone(),
        level: level_for(&finding.severity),
        message: SarifMessage {
            text: finding.description.clone(),
        },
        baseline_state,
        properties: properties_for(finding),
    }
}

fn result_for_diff(entry: &DiffEntry) -> SarifResult {
    SarifResult {
        rule_id: entry.id.clone(),
        level: level_for(&entry.severity),
        message: SarifMessage {
            text: "Finding is absent from the current scan.".into(),
        },
        baseline_state: Some("absent"),
        properties: serde_json::json!({ "severity": entry.severity.to_string() }),
    }
}

fn properties_for(finding: &Finding) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "module".into(),
        serde_json::Value::String(finding.module.clone()),
    );
    properties.insert(
        "severity".into(),
        serde_json::Value::String(finding.severity.to_string()),
    );
    properties.insert(
        "confidence".into(),
        serde_json::Value::String(finding.confidence.to_string()),
    );
    properties.insert(
        "observedAt".into(),
        serde_json::Value::String(finding.timestamp.to_rfc3339()),
    );
    if let Some(mitre_id) = &finding.mitre_id {
        properties.insert(
            "mitreId".into(),
            serde_json::Value::String(mitre_id.clone()),
        );
    }

    serde_json::Value::Object(properties)
}

fn state_for(report: &Report, finding: &Finding) -> Option<&'static str> {
    let diff = report.diff.as_ref()?;
    if diff.new.iter().any(|entry| entry.id == finding.id) {
        Some("new")
    } else if diff
        .severity_changed
        .iter()
        .any(|entry| entry.id == finding.id)
    {
        Some("updated")
    } else {
        Some("unchanged")
    }
}

fn level_for(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::sample::sample_report;

    #[test]
    fn emits_sarif_contract_without_evidence_payload() {
        let value: serde_json::Value =
            serde_json::from_str(&generate(&sample_report()).unwrap()).unwrap();
        assert_eq!(value["version"], SARIF_VERSION);
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "diego");
        assert_eq!(value["runs"][0]["results"].as_array().unwrap().len(), 6);
        assert!(value["runs"][0]["results"][0].get("evidence").is_none());
        assert!(serde_json::to_string(&value).unwrap().contains("AS-REP"));
        assert!(!serde_json::to_string(&value)
            .unwrap()
            .contains("hashcat_hash"));
    }

    #[test]
    fn maps_baseline_lifecycle_to_sarif_states() {
        let value: serde_json::Value =
            serde_json::from_str(&generate(&sample_report()).unwrap()).unwrap();
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results
                .iter()
                .find(|r| r["ruleId"] == "KRB-KERBEROAST-mssql")
                .unwrap()["baselineState"],
            "new"
        );
        assert_eq!(
            results
                .iter()
                .find(|r| r["ruleId"] == "KRB-ASREP-svc_backup")
                .unwrap()["baselineState"],
            "unchanged"
        );
        assert_eq!(
            results
                .iter()
                .find(|r| r["ruleId"] == "LDAP-OLD-RESOLVED")
                .unwrap()["baselineState"],
            "absent"
        );
    }

    #[test]
    fn maps_severity_to_sarif_level() {
        assert_eq!(level_for(&Severity::Critical), "error");
        assert_eq!(level_for(&Severity::Medium), "warning");
        assert_eq!(level_for(&Severity::Info), "note");
    }
}
