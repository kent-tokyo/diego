use super::Finding;

/// Operator-facing provenance for a detector family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorMetadata {
    pub detector: &'static str,
    pub required_permissions: &'static str,
    pub collection: &'static str,
    pub false_positives: &'static str,
    pub confidence_rationale: &'static str,
}

/// Resolve metadata from the stable prefix of a finding ID.
pub fn metadata_for(finding_id: &str) -> DetectorMetadata {
    let (detector, collection, false_positives, confidence_rationale) = if finding_id.starts_with("LDAP-ASREP-") {
        ("LDAP AS-REP candidate", "LDAP bitwise UAC query", "Disabled or service-specific legacy accounts may be intentionally configured.", "High: the UAC flag is deterministic.")
    } else if finding_id.starts_with("LDAP-SPN-") || finding_id.starts_with("LDAP-STALE-PWD-") {
        ("LDAP service-account exposure", "LDAP SPN, encryption-type, adminCount, and pwdLastSet attributes", "Some service accounts are intentionally long-lived; business ownership review is required.", "High: SPN and age attributes are explicit; impact depends on password strength.")
    } else if finding_id.starts_with("LDAP-DESC-") {
        ("LDAP description credential heuristic", "LDAP description attribute", "Terms such as key or token can be ordinary business language.", "Medium or Low: keyword matching is heuristic and must be manually verified.")
    } else if finding_id.starts_with("LDAP-UNCON-") {
        ("LDAP unconstrained delegation", "LDAP computer UAC bitwise query", "Legacy application requirements can make delegation intentional.", "High: the delegation flag is deterministic.")
    } else if finding_id.starts_with("LDAP-CONST-") || finding_id.starts_with("LDAP-RBCD-") {
        ("LDAP constrained delegation", "LDAP delegation target or resource-based delegation attributes", "Delegation may be approved for a documented service boundary.", "High: the relevant delegation attribute or flag is explicit.")
    } else if finding_id.starts_with("LDAP-PRIVESC-GROUP-") {
        ("LDAP privileged group membership", "LDAP recursive memberOf query", "Some memberships are expected for operations and break-glass accounts.", "High for membership; severity reflects the group, not exploitability.")
    } else if finding_id.starts_with("LDAP-PWD-") {
        ("LDAP password policy", "LDAP domain root password-policy attributes", "Policy thresholds may be governed by an external compensating control.", "Medium: the values are deterministic, but risk depends on the surrounding controls.")
    } else if finding_id.starts_with("PASSIVE-") {
        ("Passive network exposure", "Local passive packet capture", "A short observation window may miss intermittent traffic.", "Medium: absence is not proof of absence; captured protocol evidence is direct.")
    } else if finding_id.starts_with("KERB-") {
        ("Kerberos exposure", "Standard Kerberos requests and responses", "KDC policy and account configuration can change between collection and review.", "High for observed protocol evidence; inferred impact still needs account-owner review.")
    } else {
        ("Unknown detector", "Not declared", "The detector family is not recognised by this diego version.", "Unknown: treat as requiring manual review.")
    };

    DetectorMetadata {
        detector,
        required_permissions: "Standard authenticated domain-user read access; no administrator rights.",
        collection,
        false_positives,
        confidence_rationale,
    }
}

/// Render a safe, operator-facing explanation. Evidence is already redacted by
/// `run_scan` when audit mode is active, and this function never reconstructs
/// or emits raw credential material.
pub fn render(finding: &Finding) -> String {
    let metadata = metadata_for(&finding.id);
    let evidence = serde_json::to_string_pretty(&finding.evidence).unwrap_or_else(|_| "null".into());
    let remediation = if finding.remediation_steps.is_empty() {
        "(No remediation steps recorded.)".to_string()
    } else {
        finding.remediation_steps.iter().map(|step| format!("- {step}")).collect::<Vec<_>>().join("\n")
    };

    format!(
        "Finding: {}\nTitle: {}\nSeverity: {}\nConfidence: {}\nDetector: {}\nRequired permissions: {}\nCollection: {}\nExpected false positives: {}\nConfidence rationale: {}\n\nEvidence:\n{}\n\nRemediation:\n{}",
        finding.id,
        finding.title,
        finding.severity,
        finding.confidence,
        metadata.detector,
        metadata.required_permissions,
        metadata.collection,
        metadata.false_positives,
        metadata.confidence_rationale,
        evidence,
        remediation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, Severity};

    #[test]
    fn metadata_is_stable_for_ldap_finding_prefixes() {
        let metadata = metadata_for("LDAP-DESC-LEAK-HELPDESK");
        assert_eq!(metadata.detector, "LDAP description credential heuristic");
        assert!(metadata.confidence_rationale.contains("heuristic"));
    }

    #[test]
    fn explanation_contains_safe_evidence_and_remediation() {
        let finding = Finding::new(
            "KRB-ASREP-ALICE",
            "kerberos",
            Severity::High,
            "AS-REP candidate",
            "test",
            serde_json::json!({"hashcat_hash": "[REDACTED]", "account": "alice"}),
            None,
        ).with_remediation(vec!["Review the account configuration"]);
        let explanation = render(&finding);
        assert!(explanation.contains("Required permissions:"));
        assert!(explanation.contains("[REDACTED]"));
        assert!(explanation.contains("Review the account configuration"));
    }
}
