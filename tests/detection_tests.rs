//! Detection tests: given representative directory objects, assert the expected
//! findings (id, severity, confidence) are produced.
//!
//! Scope: this exercises diego's *analysis logic* (`modules::ldap::analyze`)
//! against synthetic `LdapObject` fixtures — the "this config → this finding"
//! contract. It does not stand up a live Domain Controller (a mock-DC / corpus
//! is a ROADMAP item); the LDAP *filter/fetch* side is covered separately in
//! `ldap_integration_tests.rs`.

use std::collections::HashMap;

use diego::modules::ldap::analyze;
use diego::modules::ldap::parser::LdapObject;
use diego::report::{Confidence, Severity};

const DOMAIN: &str = "corp.local";

fn obj(dn: &str, attrs: &[(&str, &[&str])]) -> LdapObject {
    let mut map = HashMap::new();
    for (k, vals) in attrs {
        map.insert(k.to_string(), vals.iter().map(|v| v.to_string()).collect());
    }
    LdapObject { dn: dn.into(), attrs: map }
}

#[test]
fn asrep_candidates_produce_one_aggregate_finding() {
    let objs = vec![
        obj("CN=svc1,DC=corp,DC=local", &[("sAMAccountName", &["svc1"])]),
        obj("CN=svc2,DC=corp,DC=local", &[("sAMAccountName", &["svc2"])]),
    ];
    let f = analyze::build_asrep_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].id, "LDAP-ASREP-CANDIDATES");
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[0].mitre_id.as_deref(), Some("T1558.004"));
    // Both accounts are captured in evidence.
    let accounts = f[0].evidence["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 2);
}

#[test]
fn no_asrep_candidates_produce_nothing() {
    assert!(analyze::build_asrep_findings(&[], DOMAIN).is_empty());
}

#[test]
fn description_with_credential_keyword_is_medium_confidence() {
    let objs = vec![obj(
        "CN=helpdesk,DC=corp,DC=local",
        &[("sAMAccountName", &["helpdesk"]), ("description", &["Password123!"])],
    )];
    let f = analyze::build_description_leak_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1, "credential-looking description must be flagged");
    assert_eq!(f[0].id, "LDAP-DESC-LEAK-HELPDESK");
    assert_eq!(f[0].confidence, Confidence::Medium, "keyword match without explicit format → Medium");
}

#[test]
fn description_with_explicit_format_is_high_confidence() {
    let objs = vec![obj(
        "CN=svc,DC=corp,DC=local",
        &[("sAMAccountName", &["svc"]), ("description", &["password=Welcome2024!"])],
    )];
    let f = analyze::build_description_leak_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].confidence, Confidence::High, "password= format → High confidence");
}

#[test]
fn description_with_key_only_is_low_confidence() {
    let objs = vec![obj(
        "CN=pm,DC=corp,DC=local",
        &[("sAMAccountName", &["pm"]), ("description", &["key account manager"])],
    )];
    let f = analyze::build_description_leak_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1, "key-only descriptions should still produce a finding at Low confidence");
    assert_eq!(f[0].confidence, Confidence::Low, "ambiguous term → Low confidence");
}

#[test]
fn description_with_token_only_is_low_confidence() {
    // False-positive regression: "token" alone is common in business language
    let objs = vec![obj(
        "CN=user,DC=corp,DC=local",
        &[("sAMAccountName", &["user"]), ("description", &["token migration project"])],
    )];
    let f = analyze::build_description_leak_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].confidence, Confidence::Low);
}

#[test]
fn benign_description_is_not_flagged() {
    // False-positive guard: ordinary descriptions must not produce findings.
    let objs = vec![obj(
        "CN=jdoe,DC=corp,DC=local",
        &[("sAMAccountName", &["jdoe"]), ("description", &["Senior Engineer, IT"])],
    )];
    assert!(analyze::build_description_leak_findings(&objs, DOMAIN).is_empty());
}

#[test]
fn unconstrained_delegation_is_critical() {
    let objs = vec![obj(
        "CN=WS01,DC=corp,DC=local",
        &[("cn", &["WS01"]), ("dnsHostName", &["ws01.corp.local"])],
    )];
    let f = analyze::build_unconstrained_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].id, "LDAP-UNCON-DELEG-WS01");
    assert_eq!(f[0].severity, Severity::Critical);
}

#[test]
fn spn_rc4_capable_account_is_high() {
    // enc_types == 0 means not configured → RC4 allowed by default → High
    let objs = vec![obj(
        "CN=mssql,DC=corp,DC=local",
        &[("sAMAccountName", &["mssql"]), ("servicePrincipalName", &["MSSQLSvc/db01"])],
    )];
    let f = analyze::build_spn_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].id, "LDAP-SPN-MSSQL");
    assert_eq!(f[0].severity, Severity::High, "RC4-capable (enc_types=0) → High");
    assert_eq!(f[0].mitre_id.as_deref(), Some("T1558.003"));
}

#[test]
fn spn_rc4_capable_admin_is_critical() {
    // adminCount=1 + RC4 capable → Critical
    let objs = vec![obj(
        "CN=svc_da,DC=corp,DC=local",
        &[
            ("sAMAccountName", &["svc_da"]),
            ("servicePrincipalName", &["HTTP/app"]),
            ("adminCount", &["1"]),
        ],
    )];
    let f = analyze::build_spn_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, Severity::Critical, "RC4 + adminCount=1 → Critical");
}

#[test]
fn spn_aes_only_account_is_medium() {
    // enc_types = 0x18 (AES128 + AES256), no RC4 → Medium
    let objs = vec![obj(
        "CN=svc_aes,DC=corp,DC=local",
        &[
            ("sAMAccountName", &["svc_aes"]),
            ("servicePrincipalName", &["HTTP/aes-app"]),
            ("msDS-SupportedEncryptionTypes", &["24"]), // 0x18 = AES128|AES256
        ],
    )];
    let f = analyze::build_spn_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, Severity::Medium, "AES-only → Medium");
}

#[test]
fn privileged_group_severity_depends_on_group() {
    // Domain Admins membership is expected (Info); other privileged groups are
    // unexpected escalation paths (High).
    let da = vec![(
        "Domain Admins".to_string(),
        vec![obj("CN=admin,DC=corp,DC=local", &[("sAMAccountName", &["admin"])])],
    )];
    let f_da = analyze::build_privileged_group_findings(&da, DOMAIN);
    assert_eq!(f_da.len(), 1);
    assert_eq!(f_da[0].severity, Severity::Info);

    let backup = vec![(
        "Backup Operators".to_string(),
        vec![obj("CN=bob,DC=corp,DC=local", &[("sAMAccountName", &["bob"])])],
    )];
    let f_bo = analyze::build_privileged_group_findings(&backup, DOMAIN);
    assert_eq!(f_bo[0].severity, Severity::High);
    assert_eq!(f_bo[0].id, "LDAP-PRIVESC-GROUP-BACKUP-OPERATORS");
}

#[test]
fn weak_password_policy_no_lockout_is_flagged() {
    let policy = vec![obj(
        "DC=corp,DC=local",
        &[("minPwdLength", &["7"]), ("lockoutThreshold", &["0"])],
    )];
    let f = analyze::build_password_policy_findings(&policy, DOMAIN);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].id, "LDAP-PWD-POLICY");
    assert_eq!(f[0].severity, Severity::Medium);
    let spray = f[0].evidence["password_spray_estimation"].as_str().unwrap();
    assert!(spray.to_lowercase().contains("unrestricted"), "no-lockout → unrestricted spray");
}

#[test]
fn adequate_password_policy_is_info() {
    let policy = vec![obj(
        "DC=corp,DC=local",
        &[("minPwdLength", &["14"]), ("lockoutThreshold", &["5"]), ("lockoutDuration", &["18000000000"])],
    )];
    let f = analyze::build_password_policy_findings(&policy, DOMAIN);
    assert_eq!(f[0].severity, Severity::Info);
}

#[test]
fn constrained_delegation_with_t2a4d_flag_is_detected() {
    // UAC 0x1000000 = 16777216 = TRUSTED_TO_AUTH_FOR_DELEGATION (Protocol Transition / T2A4D)
    let objs = vec![obj(
        "CN=svc_t2a4d,DC=corp,DC=local",
        &[
            ("sAMAccountName", &["svc_t2a4d"]),
            ("userAccountControl", &["16777216"]),
            ("msDS-AllowedToDelegateTo", &["ldap/dc01.corp.local"]),
        ],
    )];
    let f = analyze::build_constrained_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert!(
        f[0].description.contains("Protocol Transition"),
        "UAC=16777216 must trigger T2A4D label, got: {}",
        f[0].description
    );
    assert!(
        f[0].evidence["protocol_transition_t2a4d"].as_bool().unwrap_or(false),
        "evidence.protocol_transition_t2a4d must be true"
    );
}

#[test]
fn constrained_delegation_not_delegated_bit_is_not_t2a4d() {
    // UAC 0x100000 = 1048576 = NOT_DELEGATED — must NOT be treated as T2A4D
    let objs = vec![obj(
        "CN=svc_nodele,DC=corp,DC=local",
        &[
            ("sAMAccountName", &["svc_nodele"]),
            ("userAccountControl", &["1048576"]),
            ("msDS-AllowedToDelegateTo", &["http/web01.corp.local"]),
        ],
    )];
    let f = analyze::build_constrained_findings(&objs, DOMAIN);
    assert_eq!(f.len(), 1);
    assert!(
        !f[0].description.contains("Protocol Transition"),
        "UAC=1048576 (NOT_DELEGATED) must NOT trigger T2A4D label, got: {}",
        f[0].description
    );
    assert!(
        !f[0].evidence["protocol_transition_t2a4d"].as_bool().unwrap_or(true),
        "evidence.protocol_transition_t2a4d must be false for NOT_DELEGATED"
    );
}

#[test]
fn stale_password_age_is_computed_from_filetime() {
    // pwdLastSet ~ 2021-01-01 in Windows FILETIME; fixed "now" ~ 2026-01-01.
    let now_2026 = 1_767_225_600_i64; // 2026-01-01T00:00:00Z
    let filetime_2021 = "132539328000000000"; // ~2021-01-01 in FILETIME
    let objs = vec![obj(
        "CN=svc_old,DC=corp,DC=local",
        &[("sAMAccountName", &["svc_old"]), ("pwdLastSet", &[filetime_2021]), ("servicePrincipalName", &["HTTP/app"])],
    )];
    let f = analyze::build_stale_password_findings(&objs, DOMAIN, now_2026);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].id, "LDAP-STALE-PWD-SVC_OLD");
    assert_eq!(f[0].severity, Severity::Medium);
    let age = f[0].evidence["password_age_days"].as_i64().unwrap();
    assert!(age > 1500 && age < 2000, "≈5 years in days, got {age}");
}
