//! Regression tests over a recorded, synthetic LDAP corpus.
//!
//! The fixture contains no real directory data. Keeping the input in the same
//! JSON shape as `LdapObject` verifies the load boundary in addition to the
//! analyzer contracts covered by `detection_tests.rs`.

use diego::modules::ldap::{analyze, parser::LdapObject};
use diego::report::{Confidence, Severity};

const DOMAIN: &str = "corp.local";

fn corpus() -> Vec<LdapObject> {
    serde_json::from_str(include_str!("corpus/representative-domain.json"))
        .expect("representative LDAP corpus must remain valid JSON")
}

#[test]
fn representative_corpus_preserves_expected_detection_contracts() {
    let objects = corpus();

    let asrep = analyze::build_asrep_findings(&objects, DOMAIN);
    assert_eq!(asrep.len(), 1);
    assert_eq!(asrep[0].severity, Severity::High);

    let spn = analyze::build_spn_findings(&objects, DOMAIN);
    assert_eq!(spn.len(), 2);
    assert!(spn.iter().any(|f| f.severity == Severity::Critical));
    assert!(spn.iter().any(|f| f.severity == Severity::Medium));

    let leaks = analyze::build_description_leak_findings(&objects, DOMAIN);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].confidence, Confidence::High);

    let unconstrained = analyze::build_unconstrained_findings(
        &objects
            .iter()
            .filter(|object| object.get_first("cn") == Some("WS-DELEG"))
            .cloned()
            .collect::<Vec<_>>(),
        DOMAIN,
    );
    assert_eq!(unconstrained.len(), 1);
    assert_eq!(unconstrained[0].severity, Severity::Critical);

    let constrained = analyze::build_constrained_findings(
        &objects
            .iter()
            .filter(|object| object.get_first("msDS-AllowedToDelegateTo").is_some())
            .cloned()
            .collect::<Vec<_>>(),
        DOMAIN,
    );
    assert_eq!(constrained.len(), 1);
    assert!(constrained[0].evidence["protocol_transition_t2a4d"]
        .as_bool()
        .expect("T2A4D evidence must be boolean"));

    let rbcd = analyze::build_rbcd_findings(
        &objects
            .iter()
            .filter(|object| object.get_first("msDS-AllowedToActOnBehalfOfOtherIdentity").is_some())
            .cloned()
            .collect::<Vec<_>>(),
        DOMAIN,
    );
    assert_eq!(rbcd.len(), 1);
    assert_eq!(rbcd[0].id, "LDAP-RBCD-APP01");

    let policy = analyze::build_password_policy_findings(
        &objects
            .iter()
            .filter(|object| object.get_first("minPwdLength").is_some())
            .cloned()
            .collect::<Vec<_>>(),
        DOMAIN,
    );
    assert_eq!(policy.len(), 1);
    assert_eq!(policy[0].severity, Severity::Medium);

    let stale = analyze::build_stale_password_findings(
        &objects
            .iter()
            .filter(|object| object.get_first("pwdLastSet").is_some())
            .cloned()
            .collect::<Vec<_>>(),
        DOMAIN,
        1_767_225_600,
    );
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].id, "LDAP-STALE-PWD-SVC_BACKUP");
}

#[test]
fn corpus_format_round_trips_without_changing_attributes() {
    let objects = corpus();
    let encoded = serde_json::to_string(&objects).expect("corpus should serialize");
    let decoded: Vec<LdapObject> = serde_json::from_str(&encoded).expect("corpus should deserialize");
    assert_eq!(decoded.len(), objects.len());
    assert_eq!(decoded[0].attrs["sAMAccountName"], vec!["svc_backup"]);
}
