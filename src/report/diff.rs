//! Baseline diff: compare the current report against a prior diego JSON report.
//!
//! Findings are matched by their stable `id`. A finding present only in the
//! current report is NEW; one present only in the baseline is RESOLVED; one in
//! both with a changed severity is recorded in `severity_changed`; otherwise it
//! is counted as unchanged.
//!
//! Note: `ReportDiff` owns its data rather than borrowing, because RESOLVED
//! entries exist only in the baseline (not in `current.findings`) and so cannot
//! be represented as a per-current-finding status. `Report` is not `Clone`, so
//! owned copies of the small subset of fields we surface are the natural fit.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{Report, Severity};

/// A finding that appeared or disappeared between baseline and current.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffEntry {
    pub id: String,
    pub title: String,
    pub severity: Severity,
}

/// A finding present in both reports whose severity changed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeverityChange {
    pub id: String,
    pub title: String,
    pub from: Severity,
    pub to: Severity,
}

/// The result of diffing a current report against a baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportDiff {
    /// When the baseline report was generated.
    pub baseline_generated_at: DateTime<Utc>,
    /// Findings present now but not in the baseline.
    pub new: Vec<DiffEntry>,
    /// Findings present in the baseline but no longer detected.
    pub resolved: Vec<DiffEntry>,
    /// Findings present in both with a changed severity.
    pub severity_changed: Vec<SeverityChange>,
    /// Count of findings present in both with the same severity.
    pub unchanged_count: usize,
}

/// Compute the diff of `current` against `baseline`, matching findings by `id`.
pub fn compute_diff(current: &Report, baseline: &Report) -> ReportDiff {
    let baseline_by_id: HashMap<&str, &super::Finding> =
        baseline.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let current_ids: HashMap<&str, &super::Finding> =
        current.findings.iter().map(|f| (f.id.as_str(), f)).collect();

    let mut new = Vec::new();
    let mut severity_changed = Vec::new();
    let mut unchanged_count = 0usize;

    for f in &current.findings {
        match baseline_by_id.get(f.id.as_str()) {
            None => new.push(DiffEntry {
                id: f.id.clone(),
                title: f.title.clone(),
                severity: f.severity.clone(),
            }),
            Some(prev) => {
                if prev.severity != f.severity {
                    severity_changed.push(SeverityChange {
                        id: f.id.clone(),
                        title: f.title.clone(),
                        from: prev.severity.clone(),
                        to: f.severity.clone(),
                    });
                } else {
                    unchanged_count += 1;
                }
            }
        }
    }

    let resolved = baseline
        .findings
        .iter()
        .filter(|f| !current_ids.contains_key(f.id.as_str()))
        .map(|f| DiffEntry {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: f.severity.clone(),
        })
        .collect();

    ReportDiff {
        baseline_generated_at: baseline.generated_at,
        new,
        resolved,
        severity_changed,
        unchanged_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, Report, ScanContext, Severity};

    fn ctx() -> ScanContext {
        ScanContext {
            dc_ip: "10.0.0.1".into(),
            domain: "corp.local".into(),
            username: "jdoe".into(),
            privilege_level: "standard_user".into(),
            modules_run: vec!["ldap".into()],
            duration_secs: 1,
        }
    }

    fn finding(id: &str, sev: Severity) -> Finding {
        Finding::new(
            id,
            "ldap",
            sev,
            format!("title {id}"),
            "desc",
            serde_json::Value::Null,
            None,
        )
    }

    #[test]
    fn detects_new_resolved_changed_unchanged() {
        // baseline: A(High), B(Medium), C(Low)
        let baseline = Report::new(
            ctx(),
            vec![
                finding("A", Severity::High),
                finding("B", Severity::Medium),
                finding("C", Severity::Low),
            ],
        );
        // current: A(High) unchanged, B(Critical) escalated, D(High) new; C resolved
        let current = Report::new(
            ctx(),
            vec![
                finding("A", Severity::High),
                finding("B", Severity::Critical),
                finding("D", Severity::High),
            ],
        );

        let d = compute_diff(&current, &baseline);

        assert_eq!(d.new.len(), 1);
        assert_eq!(d.new[0].id, "D");

        // RESOLVED lives only in the baseline — the structurally easy miss.
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.resolved[0].id, "C");

        assert_eq!(d.severity_changed.len(), 1);
        assert_eq!(d.severity_changed[0].id, "B");
        assert_eq!(d.severity_changed[0].from, Severity::Medium);
        assert_eq!(d.severity_changed[0].to, Severity::Critical);

        assert_eq!(d.unchanged_count, 1); // A
    }

    #[test]
    fn empty_baseline_makes_everything_new() {
        let baseline = Report::new(ctx(), vec![]);
        let current = Report::new(ctx(), vec![finding("A", Severity::High)]);
        let d = compute_diff(&current, &baseline);
        assert_eq!(d.new.len(), 1);
        assert!(d.resolved.is_empty());
        assert_eq!(d.unchanged_count, 0);
    }

    #[test]
    fn empty_current_resolves_everything() {
        let baseline = Report::new(ctx(), vec![finding("A", Severity::High)]);
        let current = Report::new(ctx(), vec![]);
        let d = compute_diff(&current, &baseline);
        assert!(d.new.is_empty());
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.resolved[0].id, "A");
    }
}
