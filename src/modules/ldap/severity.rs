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
