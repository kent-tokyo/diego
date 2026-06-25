//! Integration test for baseline diff: exercises the real serde round-trip that
//! `main.rs` performs when `--baseline` points at a prior diego JSON report.

use diego::report::diff::compute_diff;
use diego::report::{Finding, Report, ScanContext, Severity};

fn ctx() -> ScanContext {
    ScanContext {
        dc_ip: "10.0.0.1".into(),
        domain: "corp.local".into(),
        username: "jdoe".into(),
        privilege_level: "standard_user".into(),
        modules_run: vec!["ldap".into(), "kerberos".into()],
        duration_secs: 3,
    }
}

fn finding(id: &str, sev: Severity) -> Finding {
    Finding::new(
        id,
        "ldap",
        sev,
        format!("Finding {id}"),
        "description",
        serde_json::json!({ "account": id }),
        Some(format!("attack hint for {id}")),
    )
}

#[test]
fn baseline_json_roundtrip_then_diff() {
    // Build a baseline report and serialize it exactly as diego writes JSON.
    let baseline = Report::new(
        ctx(),
        vec![
            finding("KRB-ASREP-svc1", Severity::Critical),
            finding("LDAP-UNCONSTRAINED-host1", Severity::High),
            finding("LDAP-DESC-leak1", Severity::Medium),
        ],
    );
    let baseline_json = diego::report::json::generate(&baseline).expect("serialize baseline");

    // Read it back the way main.rs does (serde_json::from_str into Report).
    let baseline_loaded: Report =
        serde_json::from_str(&baseline_json).expect("deserialize baseline JSON");

    // Current run: svc1 escalates context but same severity, host1 resolved,
    // leak1 escalated to High, and a brand-new SPN finding appears.
    let current = Report::new(
        ctx(),
        vec![
            finding("KRB-ASREP-svc1", Severity::Critical),
            finding("LDAP-DESC-leak1", Severity::High),
            finding("KRB-SPN-svc2", Severity::High),
        ],
    );

    let d = compute_diff(&current, &baseline_loaded);

    assert_eq!(d.new.len(), 1, "new findings");
    assert_eq!(d.new[0].id, "KRB-SPN-svc2");

    assert_eq!(d.resolved.len(), 1, "resolved findings (baseline-only)");
    assert_eq!(d.resolved[0].id, "LDAP-UNCONSTRAINED-host1");

    assert_eq!(d.severity_changed.len(), 1, "severity changes");
    assert_eq!(d.severity_changed[0].id, "LDAP-DESC-leak1");
    assert_eq!(d.severity_changed[0].from, Severity::Medium);
    assert_eq!(d.severity_changed[0].to, Severity::High);

    assert_eq!(d.unchanged_count, 1, "svc1 unchanged");
}

/// Guards the premise the whole feature rests on: the *same* real-world object
/// yields the *same* finding id on two separate scans, regardless of result
/// ordering or case. The modules build ids as e.g.
/// `format!("KERB-ASREP-{}", username.to_uppercase())`, so a re-scan that
/// returns the same accounts in a different order / different case must diff as
/// entirely unchanged — not as a churn of new+resolved.
#[test]
fn rescan_same_objects_is_stable_regardless_of_order_and_case() {
    // Mirror the modules' id convention: stable identifier, uppercased.
    let id = |account: &str| format!("KERB-ASREP-{}", account.to_uppercase());

    let baseline = Report::new(
        ctx(),
        vec![
            Finding::new(id("svc_backup"), "kerberos", Severity::Critical, "AS-REP", "", serde_json::Value::Null, None),
            Finding::new(id("svc_sql"), "kerberos", Severity::High, "AS-REP", "", serde_json::Value::Null, None),
        ],
    );
    // Re-scan: same two accounts, reversed order, different source-case.
    let current = Report::new(
        ctx(),
        vec![
            Finding::new(id("SVC_SQL"), "kerberos", Severity::High, "AS-REP", "", serde_json::Value::Null, None),
            Finding::new(id("Svc_Backup"), "kerberos", Severity::Critical, "AS-REP", "", serde_json::Value::Null, None),
        ],
    );

    let d = compute_diff(&current, &baseline);
    assert!(d.new.is_empty(), "stable ids must not appear as new: {:?}", d.new);
    assert!(d.resolved.is_empty(), "stable ids must not appear as resolved: {:?}", d.resolved);
    assert!(d.severity_changed.is_empty());
    assert_eq!(d.unchanged_count, 2);
}

/// A baseline produced by an older diego build has no `confidence` field on its
/// findings. The `--baseline` flow deserializes such JSON, so it must still
/// parse (defaulting confidence to HIGH) rather than erroring.
#[test]
fn legacy_baseline_without_confidence_field_still_loads() {
    let legacy_json = r#"{
        "tool": "diego",
        "version": "0.1.1",
        "domain": "corp.local",
        "generated_at": "2026-06-01T10:00:00Z",
        "scan_context": {
            "dc_ip": "10.0.0.1",
            "domain": "corp.local",
            "username": "jdoe",
            "privilege_level": "standard_user",
            "modules_run": ["ldap"],
            "duration_secs": 2
        },
        "findings": [
            {
                "id": "KRB-ASREP-SVC1",
                "module": "kerberos",
                "severity": "CRITICAL",
                "title": "AS-REP Roastable Account",
                "description": "pre-auth disabled",
                "evidence": null,
                "attack_path_hint": null,
                "timestamp": "2026-06-01T10:00:01Z",
                "llm_context": "",
                "remediation_steps": []
            }
        ],
        "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 1 }
    }"#;

    let baseline: Report =
        serde_json::from_str(legacy_json).expect("legacy baseline (no confidence) must deserialize");
    assert_eq!(baseline.findings.len(), 1);
    assert_eq!(baseline.findings[0].confidence, diego::report::Confidence::High);

    // And it must diff cleanly against a current-format report.
    let current = Report::new(ctx(), vec![finding("KRB-ASREP-SVC1", Severity::Critical)]);
    let d = compute_diff(&current, &baseline);
    assert!(d.new.is_empty());
    assert!(d.resolved.is_empty());
    assert_eq!(d.unchanged_count, 1);
}

#[test]
fn diff_is_embedded_in_serialized_report() {
    let baseline = Report::new(ctx(), vec![finding("A", Severity::High)]);
    let current = Report::new(ctx(), vec![finding("B", Severity::High)]);
    let d = compute_diff(&current, &baseline);
    let with_diff = current.with_diff(d);

    let json = diego::report::json::generate(&with_diff).expect("serialize");
    // The diff section must round-trip through serde and survive in JSON output.
    assert!(json.contains("\"diff\""));
    assert!(json.contains("\"resolved\""));
    let reparsed: Report = serde_json::from_str(&json).expect("reparse");
    assert!(reparsed.diff.is_some());
}
