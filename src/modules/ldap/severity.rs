/// Severity determination helpers for LDAP findings.

use crate::report::Severity;

/// Determine severity for privileged group membership.
/// Domain Admins / Enterprise Admins → Info (expected in some contexts)
/// Other privileged groups → High (unexpected membership requires investigation)
pub fn privileged_group_severity(group_name: &str) -> Severity {
    if group_name.contains("Domain Admins") || group_name.contains("Enterprise Admins") {
        Severity::Info // Expected for some legitimate admins
    } else {
        Severity::High // Backup Ops, Account Ops, etc. are red flags
    }
}

/// Determine severity for password policy issues.
/// Weak if: min length < 8 bytes OR no account lockout.
pub fn password_policy_severity(min_len: u32, lockout_threshold: u32) -> Severity {
    if min_len < 8 || lockout_threshold == 0 {
        Severity::Medium // Brute-force / spray risk
    } else {
        Severity::Info // Adequate policy
    }
}

/// Determine severity for password age.
/// Stale if > 365 days on a service account (increases crack likelihood).
pub fn password_age_severity(age_days: i64) -> Severity {
    if age_days > 365 {
        Severity::Medium // Increased offline crack risk
    } else if age_days > 180 {
        Severity::Low // Somewhat aged
    } else {
        Severity::Info // Recently changed
    }
}

/// Determine severity for Kerberos encryption type.
/// RC4 only → Medium (weak, should support AES)
/// AES present → Low (acceptable)
pub fn encryption_type_severity(has_aes: bool, rc4_only: bool) -> Severity {
    if rc4_only {
        Severity::Medium // Weak, should enable AES
    } else if has_aes {
        Severity::Low // Acceptable
    } else {
        Severity::High // No supported encryption
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privileged_group_domain_admins() {
        // Domain Admins is expected in some contexts → Info
        let severity = privileged_group_severity("CN=Domain Admins,OU=Groups,DC=corp,DC=local");
        assert_eq!(severity, Severity::Info, "Domain Admins should be Info (expected)");
    }

    #[test]
    fn test_privileged_group_enterprise_admins() {
        // Enterprise Admins is expected → Info
        let severity = privileged_group_severity("Enterprise Admins");
        assert_eq!(severity, Severity::Info, "Enterprise Admins should be Info (expected)");
    }

    #[test]
    fn test_privileged_group_backup_operators() {
        // Backup Operators is a red flag → High
        let severity = privileged_group_severity("Backup Operators");
        assert_eq!(severity, Severity::High, "Backup Operators should be High (unexpected)");
    }

    #[test]
    fn test_privileged_group_account_operators() {
        // Account Operators is suspicious → High
        let severity = privileged_group_severity("Account Operators");
        assert_eq!(severity, Severity::High, "Account Operators should be High");
    }

    #[test]
    fn test_privileged_group_print_operators() {
        // Print Operators is a red flag → High
        let severity = privileged_group_severity("Print Operators");
        assert_eq!(severity, Severity::High, "Print Operators should be High");
    }

    #[test]
    fn test_password_policy_weak_length() {
        // Min length < 8 bytes → Medium (weak)
        let severity = password_policy_severity(7, 5);
        assert_eq!(severity, Severity::Medium, "Short password should be Medium");
    }

    #[test]
    fn test_password_policy_weak_no_lockout() {
        // No account lockout (threshold = 0) → Medium (spray risk)
        let severity = password_policy_severity(14, 0);
        assert_eq!(severity, Severity::Medium, "No lockout should be Medium");
    }

    #[test]
    fn test_password_policy_adequate() {
        // Min length >= 8 AND lockout enabled → Info (adequate)
        let severity = password_policy_severity(8, 5);
        assert_eq!(severity, Severity::Info, "Adequate policy should be Info");
    }

    #[test]
    fn test_password_policy_strong() {
        // Min length = 14, lockout = 10 → Info
        let severity = password_policy_severity(14, 10);
        assert_eq!(severity, Severity::Info, "Strong policy should be Info");
    }

    #[test]
    fn test_password_age_very_stale() {
        // Password > 365 days old → Medium (crack risk)
        let severity = password_age_severity(400);
        assert_eq!(severity, Severity::Medium, "Very stale password should be Medium");
    }

    #[test]
    fn test_password_age_somewhat_stale() {
        // Password 180-365 days old → Low (somewhat aged)
        let severity = password_age_severity(270);
        assert_eq!(severity, Severity::Low, "Somewhat aged password should be Low");
    }

    #[test]
    fn test_password_age_recent() {
        // Password < 180 days old → Info (recently changed)
        let severity = password_age_severity(90);
        assert_eq!(severity, Severity::Info, "Recent password should be Info");
    }

    #[test]
    fn test_password_age_boundaries() {
        // Test exact boundaries: > 365 is Medium, > 180 is Low, else Info
        let age_180 = password_age_severity(180);
        let age_181 = password_age_severity(181);
        let age_365 = password_age_severity(365);
        let age_366 = password_age_severity(366);

        assert_eq!(age_180, Severity::Info, "180 days should be Info (not > 180)");
        assert_eq!(age_181, Severity::Low, "181 days should be Low (> 180)");
        assert_eq!(age_365, Severity::Low, "365 days should be Low (not > 365)");
        assert_eq!(age_366, Severity::Medium, "366 days should be Medium (> 365)");
    }

    #[test]
    fn test_encryption_type_rc4_only() {
        // RC4 only, no AES → Medium (weak)
        let severity = encryption_type_severity(false, true);
        assert_eq!(severity, Severity::Medium, "RC4-only should be Medium");
    }

    #[test]
    fn test_encryption_type_with_aes() {
        // Has AES → Low (acceptable)
        let severity = encryption_type_severity(true, false);
        assert_eq!(severity, Severity::Low, "With AES should be Low");
    }

    #[test]
    fn test_encryption_type_no_supported() {
        // No AES and not RC4-only (shouldn't happen, but edge case) → High
        let severity = encryption_type_severity(false, false);
        assert_eq!(severity, Severity::High, "No supported encryption should be High");
    }

    #[test]
    fn test_encryption_type_aes_and_rc4() {
        // Both AES and RC4 → Low (has acceptable)
        // (rc4_only = false because AES is present)
        let severity = encryption_type_severity(true, false);
        assert_eq!(severity, Severity::Low, "With AES should be Low");
    }

    #[test]
    fn test_severity_comparison_order() {
        // Enum derives Ord: Critical < High < Medium < Low < Info (by declaration order)
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }
}
