//! Multi-domain execution plans and their bounded aggregate result.
//!
//! The plan format deliberately contains no credentials. Authentication is
//! inherited from the CLI environment, so a plan can be checked into a
//! repository without becoming a password container.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

use super::{Report, Summary};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPlan {
    /// Schema version for the plan file, currently "1".
    pub version: String,
    /// Selection boundary: domain, forest, or all.
    pub scope: String,
    pub targets: Vec<PlanTarget>,
    #[serde(default)]
    pub exclude_domains: Vec<String>,
    /// Reserved execution-control field. v0.7 executes targets sequentially
    /// to keep LDAP/Kerberos query volume predictable.
    #[serde(default = "default_parallelism")]
    pub max_parallel: usize,
}

fn default_parallelism() -> usize {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanTarget {
    pub id: String,
    pub domain: String,
    pub dc: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetReport {
    pub tool: String,
    pub version: String,
    pub plan_version: String,
    pub scope: String,
    pub generated_at: DateTime<Utc>,
    pub results: Vec<TargetResult>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetResult {
    pub id: String,
    pub domain: String,
    pub dc: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ScanPlan {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != "1" {
            anyhow::bail!("unsupported scan plan version: {}", self.version);
        }
        if !matches!(
            self.scope.to_ascii_lowercase().as_str(),
            "domain" | "forest" | "all"
        ) {
            anyhow::bail!("scope must be one of: domain, forest, all");
        }
        if self.targets.is_empty() {
            anyhow::bail!("scan plan contains no targets");
        }
        if !(1..=8).contains(&self.max_parallel) {
            anyhow::bail!("max_parallel must be between 1 and 8");
        }

        let mut seen = HashSet::new();
        for target in &self.targets {
            if target.id.trim().is_empty() || target.domain.trim().is_empty() {
                anyhow::bail!("target id and domain must not be empty");
            }
            target.dc.parse::<IpAddr>().map_err(|_| {
                anyhow::anyhow!("target {} has invalid DC IP: {}", target.id, target.dc)
            })?;
            let key = format!("{}@{}", target.domain.to_ascii_lowercase(), target.dc);
            if !seen.insert(key) {
                anyhow::bail!("duplicate target: {}", target.id);
            }
        }
        Ok(())
    }

    pub fn selected_targets(&self) -> Vec<PlanTarget> {
        let excluded: HashSet<String> = self
            .exclude_domains
            .iter()
            .map(|domain| domain.trim().to_ascii_lowercase())
            .collect();
        self.targets
            .iter()
            .filter(|target| {
                target.enabled && !excluded.contains(&target.domain.trim().to_ascii_lowercase())
            })
            .cloned()
            .collect()
    }
}

impl FleetReport {
    pub fn new(plan: &ScanPlan, results: Vec<TargetResult>) -> Self {
        let mut summary = Summary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            total: 0,
        };
        for result in &results {
            if let Some(report) = &result.report {
                summary.critical += report.summary.critical;
                summary.high += report.summary.high;
                summary.medium += report.summary.medium;
                summary.low += report.summary.low;
                summary.info += report.summary.info;
                summary.total += report.summary.total;
            }
        }
        Self {
            tool: "diego".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            plan_version: plan.version.clone(),
            scope: plan.scope.clone(),
            generated_at: Utc::now(),
            results,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ScanPlan {
        ScanPlan {
            version: "1".into(),
            scope: "forest".into(),
            max_parallel: 1,
            exclude_domains: vec!["excluded.example".into()],
            targets: vec![
                PlanTarget {
                    id: "root".into(),
                    domain: "corp.example".into(),
                    dc: "10.0.0.1".into(),
                    enabled: true,
                },
                PlanTarget {
                    id: "child".into(),
                    domain: "child.corp.example".into(),
                    dc: "10.0.0.2".into(),
                    enabled: true,
                },
                PlanTarget {
                    id: "excluded".into(),
                    domain: "excluded.example".into(),
                    dc: "10.0.0.3".into(),
                    enabled: true,
                },
            ],
        }
    }

    #[test]
    fn validation_and_selection_are_explicit() {
        let p = plan();
        p.validate().unwrap();
        let selected = p.selected_targets();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[1].domain, "child.corp.example");
    }

    #[test]
    fn disabled_targets_are_not_selected() {
        let mut p = plan();
        p.targets[1].enabled = false;
        p.validate().unwrap();
        assert_eq!(p.selected_targets().len(), 1);
    }
}
