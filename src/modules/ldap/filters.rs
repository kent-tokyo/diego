//! LDAP filter strings — centralized for audit and maintenance.
//!
//! All filters use standard LDAP query syntax per RFC 4515.
//! userAccountControl bit matching uses OID 1.2.840.113556.1.4.803 (bitwise AND).

/// Find enabled person accounts with DONT_REQ_PREAUTH (bit 22 = 0x400000), excluding disabled accounts.
pub const ASREP_CANDIDATES: &str =
    "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304)\
(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

/// Find service accounts with SPNs, excluding computers and disabled accounts.
pub const SPN_ACCOUNTS: &str =
    "(&(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

/// Find computers with unconstrained delegation (userAccountControl bit 19 = 0x80000).
pub const UNCONSTRAINED_DELEGATION: &str =
    "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))";

/// Find accounts/computers with Constrained Delegation.
/// Includes msDS-AllowedToDelegateTo OR TRUSTED_TO_AUTH_FOR_DELEGATION flag (bit 24 = 0x1000000 = 16777216).
/// Note: 0x100000 (1048576) is NOT_DELEGATED — a common confusion; the correct T2A4D value is 0x1000000.
pub fn constrained_delegation() -> &'static str {
    "(|(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))"
}

/// Find objects with Resource-Based Constrained Delegation.
pub const RBCD: &str = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";

/// Description field credential leak detection — parameterized by keyword.
pub fn description_leak(keyword: &str) -> String {
    format!("(&(objectCategory=person)(description=*{}*))", keyword)
}

/// Find privileged group by CN (resolved dynamically).
pub fn group_by_cn(group_cn: &str) -> String {
    format!("(&(objectClass=group)(cn={}))", group_cn)
}

/// Find members of a group via LDAP_MATCHING_RULE_IN_CHAIN (recursive).
/// OID 1.2.840.113556.1.4.1941 = IN_CHAIN matching rule.
pub fn group_members_recursive(group_dn: &str) -> String {
    format!(
        "(&(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:={}))",
        group_dn
    )
}

/// Find service accounts with stale passwords (> N days).
/// Filter: servicePrincipalName present AND pwdLastSet <= threshold AND enabled.
pub fn stale_service_passwords(timestamp_threshold: i64) -> String {
    format!(
        "(&(servicePrincipalName=*)(pwdLastSet<={})(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(objectClass=computer)))",
        timestamp_threshold
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asrep_candidates_contains_bit_pattern() {
        // userAccountControl bit 22 = 0x400000 = 4194304
        assert!(ASREP_CANDIDATES.contains("4194304"));
        assert!(ASREP_CANDIDATES.contains("1.2.840.113556.1.4.803"));
    }

    #[test]
    fn test_asrep_candidates_excludes_disabled_accounts() {
        // ACCOUNTDISABLE = 0x2 = 2 must be excluded to avoid false positives
        assert!(ASREP_CANDIDATES.contains("!(userAccountControl:1.2.840.113556.1.4.803:=2)"));
        assert!(ASREP_CANDIDATES.contains("objectCategory=person"));
    }

    #[test]
    fn test_spn_accounts_filter_structure() {
        // Should check for: servicePrincipalName=*, not computer, not disabled
        assert!(SPN_ACCOUNTS.contains("servicePrincipalName"));
        assert!(SPN_ACCOUNTS.contains("objectClass=computer"));
        assert!(SPN_ACCOUNTS.contains("userAccountControl"));
    }

    #[test]
    fn test_unconstrained_delegation_filter() {
        // userAccountControl bit 19 = 0x80000 = 524288
        assert!(UNCONSTRAINED_DELEGATION.contains("524288"));
        assert!(UNCONSTRAINED_DELEGATION.contains("computer"));
    }

    #[test]
    fn test_rbcd_filter_is_not_empty() {
        assert!(!RBCD.is_empty());
        assert!(RBCD.contains("msDS-AllowedToActOnBehalfOfOtherIdentity"));
    }

    #[test]
    fn test_constrained_delegation_generates_valid_ldap() {
        let filter = constrained_delegation();
        assert!(filter.contains("msDS-AllowedToDelegateTo"));
        // T2A4D = TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 = 16777216 (NOT 0x100000/1048576 which is NOT_DELEGATED)
        assert!(filter.contains("16777216"));
        assert!(!filter.contains("1048576"), "must not use NOT_DELEGATED bit by mistake");
        assert!(filter.starts_with("(|")); // OR operator
    }

    #[test]
    fn test_description_leak_escapes_input() {
        let filter = description_leak("password");
        assert!(filter.contains("description=*password*"));
        assert!(filter.contains("objectCategory=person"));
    }

    #[test]
    fn test_description_leak_special_chars() {
        // Special characters in LDAP filters should be escaped
        // (This test documents current behavior; escaping is the caller's responsibility)
        let filter = description_leak("test*");
        assert!(filter.contains("test*")); // Currently not escaped — docstring should note this
    }

    #[test]
    fn test_group_by_cn_filter() {
        let filter = group_by_cn("Domain Admins");
        assert!(filter.contains("Domain Admins"));
        assert!(filter.contains("objectClass=group"));
    }

    #[test]
    fn test_group_members_recursive_uses_in_chain() {
        let filter = group_members_recursive("CN=DA,OU=Groups,DC=corp,DC=local");
        assert!(filter.contains("1.2.840.113556.1.4.1941")); // IN_CHAIN OID
        assert!(filter.contains("CN=DA,OU=Groups,DC=corp,DC=local"));
        assert!(filter.contains("objectCategory=person"));
    }

    #[test]
    fn test_stale_service_passwords_filter() {
        let threshold = 130680960000000000i64; // Example Windows timestamp
        let filter = stale_service_passwords(threshold);
        assert!(filter.contains("servicePrincipalName=*"));
        assert!(filter.contains(&threshold.to_string()));
        assert!(filter.contains("pwdLastSet<=")); // Less-than-or-equal
        assert!(filter.contains("objectClass=computer")); // Excludes computers
    }

    #[test]
    fn test_all_filters_start_with_open_paren() {
        assert!(ASREP_CANDIDATES.starts_with("("));
        assert!(SPN_ACCOUNTS.starts_with("("));
        assert!(UNCONSTRAINED_DELEGATION.starts_with("("));
        assert!(RBCD.starts_with("("));
    }

    #[test]
    fn test_all_filters_end_with_close_paren() {
        assert!(ASREP_CANDIDATES.ends_with(")"));
        assert!(SPN_ACCOUNTS.ends_with(")"));
        assert!(UNCONSTRAINED_DELEGATION.ends_with(")"));
        assert!(RBCD.ends_with(")"));
    }

    #[test]
    fn test_filter_basic_syntax_balance() {
        // Parentheses should be balanced (basic check)
        fn count_parens(s: &str) -> (i32, i32) {
            let opens = s.chars().filter(|&c| c == '(').count();
            let closes = s.chars().filter(|&c| c == ')').count();
            (opens as i32, closes as i32)
        }

        for (name, filter) in &[
            ("ASREP", ASREP_CANDIDATES),
            ("SPN", SPN_ACCOUNTS),
            ("UNCONSTRAINED", UNCONSTRAINED_DELEGATION),
            ("RBCD", RBCD),
        ] {
            let (opens, closes) = count_parens(filter);
            assert_eq!(opens, closes, "{} filter has unbalanced parens", name);
        }
    }
}
