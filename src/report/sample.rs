//! Synthetic sample report used by the `sample_report` example, the golden
//! test, and the JSON-schema test. Keeping the fixture in one place keeps those
//! three consumers from drifting apart.
//!
//! The data is illustrative (a small fictional `corp.local`) and deliberately
//! includes markup in a description field to exercise HTML escaping.

use super::{diff, Confidence, Finding, Report, ScanContext, Severity};

/// Build a deterministic-in-shape sample report (timestamps are still wall-clock;
/// consumers that need byte stability should normalise timestamp fields).
pub fn sample_report() -> Report {
    let ctx = ScanContext {
        dc_ip: "10.0.0.1".into(),
        domain: "corp.local".into(),
        username: "jdoe".into(),
        privilege_level: "standard_user".into(),
        modules_run: vec!["ldap".into(), "kerberos".into(), "passive".into()],
        duration_secs: 7,
    };

    let findings = vec![
        Finding::new(
            "KRB-ASREP-svc_backup",
            "kerberos",
            Severity::Critical,
            "AS-REP Roastable Account",
            "Account 'svc_backup' has Kerberos pre-authentication disabled, allowing offline cracking of its AS-REP hash.",
            serde_json::json!({ "account": "svc_backup", "hashcat_hash": "$krb5asrep$23$svc_backup@CORP.LOCAL:...", "hashcat_mode": 18200 }),
            Some("AS-REP roast svc_backup, then crack offline to gain initial credentials.".into()),
        )
        .with_mitre("T1558.004")
        .with_remediation(vec!["Enable Kerberos pre-authentication on svc_backup"]),
        Finding::new(
            "KRB-KERBEROAST-mssql",
            "kerberos",
            Severity::High,
            "Kerberoastable Service Account",
            "SPN account 'mssql-svc' uses RC4 and a weak password.",
            serde_json::json!({ "spn": "MSSQLSvc/db01.corp.local", "enc": "RC4-HMAC" }),
            Some("Kerberoast mssql-svc, crack offline, pivot to DB host.".into()),
        )
        .with_mitre("T1558.003"),
        Finding::new(
            "LDAP-UNCONSTRAINED-host01",
            "ldap",
            Severity::High,
            "Unconstrained Delegation",
            "Computer 'admin-host-01' is configured for unconstrained delegation.",
            serde_json::json!({ "computer": "admin-host-01" }),
            Some("Coerce DC auth to admin-host-01, capture TGT, impersonate.".into()),
        ),
        Finding::new(
            "LDAP-DESC-leak-helpdesk",
            "ldap",
            Severity::Medium,
            "Credential in Description Field",
            "Account 'helpdesk' description contains a possible password: 'Welcome2024! <b>do not change</b>'.",
            serde_json::json!({ "account": "helpdesk", "description": "Welcome2024! <b>do not change</b>" }),
            None,
        )
        // Heuristic keyword match → Medium confidence (needs human review).
        .with_confidence(Confidence::Medium),
        Finding::new(
            "LDAP-PWPOLICY",
            "ldap",
            Severity::Low,
            "Weak Lockout Threshold",
            "Account lockout threshold is high (10), enabling password spraying.",
            serde_json::json!({ "lockout_threshold": 10, "min_length": 7 }),
            None,
        ),
    ];

    // Synthetic baseline: host01 didn't exist before, the leak was only Low, and
    // an old finding has since been resolved.
    let baseline = Report::new(
        ScanContext { duration_secs: 6, ..ctx.clone() },
        vec![
            Finding::new("KRB-ASREP-svc_backup", "kerberos", Severity::Critical, "AS-REP Roastable Account", "", serde_json::Value::Null, None),
            Finding::new("LDAP-DESC-leak-helpdesk", "ldap", Severity::Low, "Credential in Description Field", "", serde_json::Value::Null, None),
            Finding::new("LDAP-OLD-RESOLVED", "ldap", Severity::High, "Previously-flagged stale admin", "", serde_json::Value::Null, None),
        ],
    );

    let report = Report::new(ctx, findings);
    let d = diff::compute_diff(&report, &baseline);
    report.with_diff(d)
}
