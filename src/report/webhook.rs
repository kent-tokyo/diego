//! Evidence-safe webhook/SIEM event projection.
//!
//! This module creates a local, transport-neutral payload. It excludes finding
//! evidence and crackable material so delivery remains under operator control.

use super::{Report, Severity, diff::DiffEntry};
use serde::Serialize;

const EVENT_SCHEMA: &str = "diego.scan.completed.v1";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookEvent<'a> {
    schema: &'static str,
    event: &'static str,
    tool: &'static str,
    version: &'static str,
    generated_at: String,
    domain: &'a str,
    summary: WebhookSummary,
    findings: Vec<WebhookFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline: Option<WebhookBaseline>,
}

#[derive(Debug, Serialize)]
struct WebhookSummary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    total: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookFinding {
    id: String,
    title: String,
    severity: Severity,
    baseline_state: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookBaseline {
    baseline_generated_at: String,
    new: usize,
    resolved: usize,
    severity_changed: usize,
    unchanged: usize,
}

/// Generate a transport-neutral event without copying report evidence.
pub fn generate(report: &Report) -> anyhow::Result<String> {
    let mut findings: Vec<WebhookFinding> = report
        .findings
        .iter()
        .map(|finding| WebhookFinding {
            id: finding.id.clone(),
            title: finding.title.clone(),
            severity: finding.severity.clone(),
            baseline_state: state_for(report, &finding.id),
        })
        .collect();
    if let Some(diff) = &report.diff {
        findings.extend(diff.resolved.iter().map(resolved_finding));
    }
    let baseline = report.diff.as_ref().map(|diff| WebhookBaseline {
        baseline_generated_at: diff.baseline_generated_at.to_rfc3339(),
        new: diff.new.len(),
        resolved: diff.resolved.len(),
        severity_changed: diff.severity_changed.len(),
        unchanged: diff.unchanged_count,
    });
    serde_json::to_string_pretty(&WebhookEvent {
        schema: EVENT_SCHEMA,
        event: "scan.completed",
        tool: "diego",
        version: env!("CARGO_PKG_VERSION"),
        generated_at: report.generated_at.to_rfc3339(),
        domain: &report.domain,
        summary: WebhookSummary {
            critical: report.summary.critical,
            high: report.summary.high,
            medium: report.summary.medium,
            low: report.summary.low,
            info: report.summary.info,
            total: report.summary.total,
        },
        findings,
        baseline,
    })
    .map_err(Into::into)
}

fn resolved_finding(entry: &DiffEntry) -> WebhookFinding {
    WebhookFinding {
        id: entry.id.clone(),
        title: entry.title.clone(),
        severity: entry.severity.clone(),
        baseline_state: "absent",
    }
}

fn state_for(report: &Report, id: &str) -> &'static str {
    let Some(diff) = &report.diff else {
        return "current";
    };
    if diff.new.iter().any(|entry| entry.id == id) {
        "new"
    } else if diff.severity_changed.iter().any(|entry| entry.id == id) {
        "updated"
    } else {
        "unchanged"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::sample::sample_report;

    #[test]
    fn emits_safe_contract_and_baseline_counts() {
        let value: serde_json::Value =
            serde_json::from_str(&generate(&sample_report()).unwrap()).unwrap();
        assert_eq!(value["schema"], EVENT_SCHEMA);
        assert_eq!(value["event"], "scan.completed");
        assert_eq!(value["findings"].as_array().unwrap().len(), 6);
        assert_eq!(value["baseline"]["new"], 3);
        assert_eq!(value["baseline"]["resolved"], 1);
        assert_eq!(value["findings"][0]["baselineState"], "unchanged");
        assert_eq!(
            value["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|finding| finding["id"] == "LDAP-OLD-RESOLVED")
                .unwrap()["baselineState"],
            "absent"
        );
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(!encoded.contains("evidence"));
        assert!(!encoded.contains("hashcat_hash"));
    }
}
