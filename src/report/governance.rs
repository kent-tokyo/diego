//! Local scoring and remediation lifecycle assessment.
//!
//! This is intentionally a sidecar format: operational ownership data never
//! needs to be embedded in the raw finding evidence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::{Finding, Report, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub default_owner: String,
    #[serde(default)]
    pub weights: ScoreWeights,
    #[serde(default)]
    pub findings: HashMap<String, FindingMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingMetadata {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub ticket_id: String,
    #[serde(default)]
    pub due_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub suppression_reason: String,
    #[serde(default)]
    pub exception_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreWeights {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[allow(clippy::derivable_impls)]
impl Default for GovernanceConfig {
    fn default() -> Self {
        Self { organization: String::new(), default_owner: String::new(), weights: ScoreWeights::default(), findings: HashMap::new() }
    }
}

impl Default for ScoreWeights {
    fn default() -> Self { Self { critical: 10, high: 6, medium: 3, low: 1, info: 0 } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceReport {
    pub organization: String,
    pub generated_at: DateTime<Utc>,
    pub config_sha256: String,
    pub score: u32,
    pub max_score: u32,
    pub open_score: u32,
    pub fixed_count: usize,
    pub regressed_count: usize,
    pub unknown_count: usize,
    pub sla_breached_count: usize,
    pub findings: Vec<GovernedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernedFinding {
    pub id: String,
    pub state: String,
    pub severity: Severity,
    pub confidence: super::Confidence,
    pub score: u32,
    pub owner: String,
    pub ticket_id: String,
    pub due_at: Option<DateTime<Utc>>,
    pub suppression_reason: String,
    pub exception_expires_at: Option<DateTime<Utc>>,
    pub sla_breached: bool,
}

pub fn config_sha256(config: &GovernanceConfig) -> String {
    let bytes = serde_json::to_vec(config).expect("governance config is serializable");
    hex::encode(Sha256::digest(bytes))
}

pub fn assess(current: &Report, baseline: Option<&Report>, config: &GovernanceConfig) -> GovernanceReport {
    let now = Utc::now();
    let resolved: std::collections::HashSet<&str> = baseline
        .map(|old| old.findings.iter().filter(|f| !current.findings.iter().any(|c| c.id == f.id)).map(|f| f.id.as_str()).collect())
        .unwrap_or_default();
    let regressed: std::collections::HashSet<&str> = current.diff.as_ref()
        .map(|d| d.severity_changed.iter().filter(|e| severity_rank(&e.to) > severity_rank(&e.from)).map(|e| e.id.as_str()).collect())
        .unwrap_or_default();
        let mut findings = Vec::new();
    for finding in &current.findings {
        findings.push(governed(finding, "open", config, &now));
    }
    if let Some(old) = baseline {
        for finding in &old.findings {
            if resolved.contains(finding.id.as_str()) {
                findings.push(governed(finding, "fixed", config, &now));
            }
        }
    }
    for finding in &mut findings {
        if regressed.contains(finding.id.as_str()) { finding.state = "regressed".into(); }
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    let max_score = findings.iter().map(|f| f.score).sum();
    let open_score = findings.iter().filter(|f| f.state == "open" || f.state == "regressed").map(|f| f.score).sum();
    GovernanceReport {
        organization: config.organization.clone(), generated_at: now, config_sha256: config_sha256(config), score: open_score,
        max_score, open_score, fixed_count: findings.iter().filter(|f| f.state == "fixed").count(),
        regressed_count: findings.iter().filter(|f| f.state == "regressed").count(), unknown_count: 0,
        sla_breached_count: findings.iter().filter(|f| f.sla_breached).count(), findings,
    }
}

fn governed(finding: &Finding, state: &str, config: &GovernanceConfig, now: &DateTime<Utc>) -> GovernedFinding {
    let metadata = config.findings.get(&finding.id);
    let owner = metadata.map(|m| m.owner.clone()).filter(|v| !v.is_empty()).unwrap_or_else(|| config.default_owner.clone());
    let due_at = metadata.and_then(|m| m.due_at);
    GovernedFinding { id: finding.id.clone(), state: state.into(), severity: finding.severity.clone(), confidence: finding.confidence.clone(), score: weight(&finding.severity, &config.weights), owner,
        ticket_id: metadata.map(|m| m.ticket_id.clone()).unwrap_or_default(), due_at,
        suppression_reason: metadata.map(|m| m.suppression_reason.clone()).unwrap_or_default(),
        exception_expires_at: metadata.and_then(|m| m.exception_expires_at), sla_breached: due_at.is_some_and(|deadline| deadline < *now) }
}

fn weight(severity: &Severity, weights: &ScoreWeights) -> u32 { match severity { Severity::Critical => weights.critical, Severity::High => weights.high, Severity::Medium => weights.medium, Severity::Low => weights.low, Severity::Info => weights.info } }
fn severity_rank(value: &Severity) -> u8 {
    match value {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, ScanContext};
    use serde_json::json;

    fn report(ids: &[(&str, Severity)]) -> Report {
        Report::new(ScanContext { dc_ip: "10.0.0.1".into(), domain: "corp.local".into(), username: "jdoe".into(), privilege_level: "standard_user".into(), modules_run: vec!["ldap".into()], duration_secs: 0 }, ids.iter().map(|(id, severity)| Finding::new(*id, "ldap", severity.clone(), "test", "test", json!({}), None)).collect())
    }

    #[test]
    fn scoring_and_fixed_state_are_local_and_deterministic() {
        let baseline = report(&[("A", Severity::High), ("B", Severity::Low)]);
        let current = report(&[("A", Severity::High)]);
        let config = GovernanceConfig { organization: "Acme".into(), ..Default::default() };
        let result = assess(&current, Some(&baseline), &config);
        assert_eq!(result.fixed_count, 1);
        assert_eq!(result.open_score, 6);
        assert_eq!(result.max_score, 7);
        assert_eq!(result.organization, "Acme");
        assert_eq!(result.config_sha256.len(), 64);
    }
}
