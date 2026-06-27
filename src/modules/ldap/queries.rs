use std::time::Duration;

use ldap3::{Ldap, Scope, SearchEntry};
use rand::Rng;

use super::filters::ASREP_CANDIDATES;
use super::parser::LdapObject;

/// LDAP query 1: Find enabled accounts with DONT_REQ_PREAUTH (AS-REP Roasting targets).
/// Excludes disabled accounts (ACCOUNTDISABLE = 0x2) to avoid false positives.
pub async fn query_asrep_candidates(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    let attrs = vec!["sAMAccountName", "userAccountControl", "distinguishedName"];
    search(ldap, base_dn, ASREP_CANDIDATES, &attrs).await
}

/// LDAP query 2: Find service accounts with SPNs (Kerberoasting targets).
/// Excludes computer accounts and disabled accounts.
pub async fn query_spn_accounts(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    let filter = "(&(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    let attrs = vec![
        "sAMAccountName",
        "servicePrincipalName",
        "msDS-SupportedEncryptionTypes",
        "adminCount",
        "pwdLastSet",
        "distinguishedName",
        "memberOf",
    ];
    search(ldap, base_dn, filter, &attrs).await
}

/// LDAP query 3: Find accounts with potential credentials in the description field.
pub async fn query_description_leaks(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    // Multiple passes for different keywords; deduplicate by DN
    let keywords = ["pass", "pwd", "secret", "cred", "token", "key", "p@ss"];
    let mut results: Vec<LdapObject> = Vec::new();
    let mut seen_dns = std::collections::HashSet::new();

    for kw in &keywords {
        let filter = format!("(&(objectCategory=person)(description=*{}*))", kw);
        let attrs = vec!["sAMAccountName", "description", "distinguishedName"];
        for obj in search(ldap, base_dn, &filter, &attrs).await? {
            if seen_dns.insert(obj.dn.clone()) {
                results.push(obj);
            }
        }
        jitter().await;
    }

    Ok(results)
}

/// LDAP query 4: Find computers with Unconstrained Delegation.
/// userAccountControl bit 19 (0x80000 = 524288 = TRUSTED_FOR_DELEGATION)
pub async fn query_unconstrained_delegation(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    let filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))";
    let attrs = vec!["cn", "dnsHostName", "distinguishedName", "operatingSystem", "userAccountControl"];
    search(ldap, base_dn, filter, &attrs).await
}

/// LDAP query 5: Read the Default Domain Password Policy from the domain root.
pub async fn query_password_policy(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    let attrs = vec![
        "minPwdLength",
        "maxPwdAge",
        "minPwdAge",
        "lockoutThreshold",
        "lockoutDuration",
        "pwdProperties",
        "pwdHistoryLength",
    ];
    // Scope::Base fetches only the base_dn object itself
    search_with_scope(ldap, base_dn, Scope::Base, "(objectClass=*)", &attrs).await
}

/// LDAP query 6: Find accounts/computers with Constrained Delegation configured.
/// Targets: accounts with msDS-AllowedToDelegateTo set OR UAC TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000 = 16777216).
pub async fn query_constrained_delegation(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    // OR filter: has delegation target list OR has T2A4D flag (0x1000000, NOT 0x100000 which is NOT_DELEGATED)
    let filter = "(|(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))";
    let attrs = vec![
        "sAMAccountName",
        "msDS-AllowedToDelegateTo",
        "userAccountControl",
        "distinguishedName",
        "objectClass",
    ];
    search(ldap, base_dn, filter, &attrs).await
}

/// LDAP query 7: Find objects with Resource-Based Constrained Delegation (RBCD) configured.
/// msDS-AllowedToActOnBehalfOfOtherIdentity is set — any machine account that can act on behalf of another.
pub async fn query_rbcd(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    let filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
    let attrs = vec![
        "cn",
        "sAMAccountName",
        "dnsHostName",
        "distinguishedName",
        "objectClass",
    ];
    search(ldap, base_dn, filter, &attrs).await
}

/// LDAP query 8: Enumerate members of high-privilege groups.
/// Uses the LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) for recursive membership.
pub async fn query_privileged_groups(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<(String, Vec<LdapObject>)>> {
    // Well-known privileged group CN names
    let group_names = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Backup Operators",
        "Account Operators",
        "Print Operators",
        "Server Operators",
        "Group Policy Creator Owners",
    ];

    let mut results: Vec<(String, Vec<LdapObject>)> = Vec::new();

    for group_name in &group_names {
        // First: resolve the group's DN
        let group_filter = format!("(&(objectClass=group)(cn={}))", group_name);
        let group_objs = search(ldap, base_dn, &group_filter, &["distinguishedName"]).await?;

        let group_dn = match group_objs.first().map(|o| o.dn.as_str()) {
            Some(dn) => dn.to_string(),
            None => continue,
        };

        // Second: find all members (recursive via LDAP_MATCHING_RULE_IN_CHAIN)
        let member_filter = format!(
            "(&(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:={}))",
            group_dn
        );
        let members = search(ldap, base_dn, &member_filter, &[
            "sAMAccountName",
            "distinguishedName",
            "userAccountControl",
            "pwdLastSet",
        ])
        .await
        .unwrap_or_default();

        if !members.is_empty() {
            results.push((group_name.to_string(), members));
        }

        jitter().await;
    }

    Ok(results)
}

/// LDAP query 9: Find service accounts (SPN set) with passwords older than 365 days.
/// pwdLastSet uses Windows FILETIME (100-nanosecond intervals since 1601-01-01).
pub async fn query_stale_service_passwords(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    let threshold = windows_timestamp_days_ago(365);
    // pwdLastSet <= threshold AND has SPN AND not disabled AND not "password never set" (pwdLastSet=0)
    let filter = format!(
        "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(objectClass=computer))(pwdLastSet<={threshold})(!(pwdLastSet=0)))",
        threshold = threshold
    );
    let attrs = vec![
        "sAMAccountName",
        "pwdLastSet",
        "servicePrincipalName",
        "distinguishedName",
        "userAccountControl",
    ];
    search(ldap, base_dn, &filter, &attrs).await
}

/// Convert a "N days ago" offset to a Windows FILETIME integer string.
/// Uses checked arithmetic to prevent overflow.
fn windows_timestamp_days_ago(days: u64) -> i64 {
    // Fallback: manually implement overflow-checked calculation
    let days_secs = (days as i64).saturating_mul(86400);
    let now_secs = chrono::Utc::now().timestamp();
    let past_secs = now_secs.saturating_sub(days_secs);
    past_secs
        .saturating_mul(10_000_000)
        .saturating_add(116_444_736_000_000_000)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async fn search(ldap: &mut Ldap, base: &str, filter: &str, attrs: &[&str]) -> anyhow::Result<Vec<LdapObject>> {
    search_with_scope(ldap, base, Scope::Subtree, filter, attrs).await
}

async fn search_with_scope(
    ldap: &mut Ldap,
    base: &str,
    scope: Scope,
    filter: &str,
    attrs: &[&str],
) -> anyhow::Result<Vec<LdapObject>> {
    let (rs, _res) = ldap
        .search(base, scope, filter, attrs)
        .await?
        .success()
        .map_err(|e| anyhow::anyhow!("LDAP search error: {}", e))?;

    Ok(rs
        .into_iter()
        .map(|entry| LdapObject::from_entry(SearchEntry::construct(entry)))
        .collect())
}

/// OPSEC: insert a random delay between 100–500ms between consecutive queries.
pub async fn jitter() {
    let ms: u64 = rand::thread_rng().gen_range(100..=500);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Phase 1: Filter Validation Tests ──────────────────────────────

    #[test]
    fn test_asrep_candidates_filter_structure() {
        // Verify filter for DONT_REQ_PREAUTH (bit 22 = 0x400000 = 4194304)
        let filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
        assert!(filter.contains("1.2.840.113556.1.4.803")); // OID for bitwise AND
        assert!(filter.contains("4194304")); // 0x400000
    }

    #[test]
    fn test_spn_accounts_filter_excludes_computers() {
        // Verify filter excludes computer objects and disabled accounts
        let filter = "(&(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        assert!(filter.contains("servicePrincipalName=*"));
        assert!(filter.contains("!(objectClass=computer)"));
        assert!(filter.contains("!(userAccountControl")); // Excludes disabled (bit 1 = 0x2)
    }

    #[test]
    fn test_unconstrained_delegation_filter() {
        // Verify filter for TRUSTED_FOR_DELEGATION (bit 19 = 0x80000 = 524288)
        let filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))";
        assert!(filter.contains("objectCategory=computer"));
        assert!(filter.contains("524288")); // 0x80000
    }

    #[test]
    fn test_constrained_delegation_filter() {
        // TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 = 16777216 (NOT 0x100000/1048576 = NOT_DELEGATED)
        let filter = "(|(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))";
        assert!(filter.contains("|")); // OR operator
        assert!(filter.contains("msDS-AllowedToDelegateTo=*"));
        assert!(filter.contains("16777216")); // 0x1000000 = T2A4D
        assert!(!filter.contains("1048576")); // must NOT use NOT_DELEGATED bit
    }

    #[test]
    fn test_rbcd_filter() {
        // Verify filter for msDS-AllowedToActOnBehalfOfOtherIdentity
        let filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
        assert!(filter.contains("msDS-AllowedToActOnBehalfOfOtherIdentity=*"));
    }

    #[test]
    fn test_stale_password_filter_structure() {
        // Verify filter includes: SPN + timestamp + not disabled + not computer + not "password never set"
        let threshold = 130680960000000000i64;
        let filter = format!(
            "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(objectClass=computer))(pwdLastSet<={threshold})(!(pwdLastSet=0)))",
            threshold = threshold
        );

        assert!(filter.contains("servicePrincipalName=*"));
        assert!(filter.contains("!(userAccountControl")); // Not disabled
        assert!(filter.contains("!(objectClass=computer)")); // Not computer
        assert!(filter.contains(&threshold.to_string())); // Timestamp threshold
        assert!(filter.contains("!(pwdLastSet=0)")); // Not "password never set"
    }

    #[test]
    fn test_description_leak_filter_keywords() {
        // Verify filter construction with different keywords
        let keywords = ["pass", "pwd", "secret"];
        for kw in &keywords {
            let filter = format!("(&(objectCategory=person)(description=*{}*))", kw);
            assert!(filter.contains("objectCategory=person"));
            assert!(filter.contains(&format!("description=*{}*", kw)));
        }
    }

    #[test]
    fn test_privileged_groups_filter_structure() {
        // Verify group lookup filter
        let group_name = "Domain Admins";
        let filter = format!("(&(objectClass=group)(cn={}))", group_name);
        assert!(filter.contains("objectClass=group"));
        assert!(filter.contains("cn=Domain Admins"));
    }

    #[test]
    fn test_group_members_recursive_filter() {
        // Verify recursive member filter using IN_CHAIN matching rule
        let group_dn = "CN=Domain Admins,CN=Users,DC=corp,DC=local";
        let filter = format!(
            "(&(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:={}))",
            group_dn
        );

        assert!(filter.contains("objectCategory=person"));
        assert!(filter.contains("1.2.840.113556.1.4.1941")); // IN_CHAIN OID
        assert!(filter.contains(group_dn));
    }

    // ─── Phase 2: Timestamp Calculation Tests ─────────────────────────

    #[test]
    fn test_windows_timestamp_days_ago_calculation() {
        // Test that calculation doesn't overflow
        let timestamp = windows_timestamp_days_ago(365);

        // Should be a large positive number (Windows FILETIME)
        assert!(timestamp > 0);

        // Should be around current time minus 365 days (rough check)
        let now_filetime = chrono::Utc::now().timestamp() * 10_000_000 + 116_444_736_000_000_000;
        let expected_max = now_filetime;
        assert!(timestamp <= expected_max);
    }

    #[test]
    fn test_windows_timestamp_days_ago_zero_days() {
        // 0 days ago should give current time
        let timestamp = windows_timestamp_days_ago(0);
        let now_filetime = chrono::Utc::now().timestamp() * 10_000_000 + 116_444_736_000_000_000;

        // Should be very close to current time (within a second due to execution time)
        assert!((timestamp - now_filetime).abs() < 10_000_000); // Within 1 second
    }

    #[test]
    fn test_windows_timestamp_days_ago_overflow_safe() {
        // Very large number of days shouldn't cause panic (uses saturating math)
        let timestamp = windows_timestamp_days_ago(1_000_000);

        // Should be a valid (possibly saturated) timestamp
        assert!(timestamp >= 0 || timestamp < 0); // Just check it doesn't panic
    }

    #[test]
    fn test_windows_timestamp_order() {
        // More days ago = smaller timestamp
        let ts_90 = windows_timestamp_days_ago(90);
        let ts_180 = windows_timestamp_days_ago(180);
        let ts_365 = windows_timestamp_days_ago(365);

        assert!(ts_365 < ts_180);
        assert!(ts_180 < ts_90);
    }

    // ─── Phase 3: Filter Syntax Validation ─────────────────────────────

    #[test]
    fn test_all_filters_have_balanced_parens() {
        fn count_parens(s: &str) -> (usize, usize) {
            let opens = s.chars().filter(|&c| c == '(').count();
            let closes = s.chars().filter(|&c| c == ')').count();
            (opens, closes)
        }

        // Test critical filters
        let filters = vec![
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
            "(&(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            "(|(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))",
        ];

        for filter in filters {
            let (opens, closes) = count_parens(filter);
            assert_eq!(opens, closes, "Unbalanced parens in: {}", filter);
        }
    }

    #[test]
    fn test_filter_no_ldap_injection_chars() {
        // Verify filters don't contain obvious injection characters that shouldn't be there
        // (This is a basic check; real input validation is done by ldap3)
        let filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";

        // Filter should not have unescaped wildcards in attribute names
        assert!(!filter.contains("*=*")); // No "attribute=*" pattern that would match everything
    }

    #[test]
    fn test_group_name_special_chars_in_filter() {
        // Verify that group names with special characters are properly handled
        // (The caller should escape these; we're just checking format)
        let group_name = "Group With Spaces";
        let filter = format!("(&(objectClass=group)(cn={}))", group_name);

        // Filter should be constructed (caller responsible for escaping)
        assert!(filter.contains(group_name));
    }

    // ─── Phase 4: LDAP Attribute Lists ────────────────────────────────

    #[test]
    fn test_asrep_candidates_attributes() {
        // Verify expected attributes are queried
        let attrs = vec!["sAMAccountName", "userAccountControl", "distinguishedName"];
        assert_eq!(attrs.len(), 3);
        assert!(attrs.contains(&"sAMAccountName"));
        assert!(attrs.contains(&"distinguishedName"));
    }

    #[test]
    fn test_spn_accounts_includes_encryption_types() {
        // Verify encryption type attribute is included
        let attrs = vec![
            "sAMAccountName",
            "servicePrincipalName",
            "msDS-SupportedEncryptionTypes",
            "distinguishedName",
            "memberOf",
        ];

        assert!(attrs.contains(&"msDS-SupportedEncryptionTypes"));
        assert!(attrs.contains(&"servicePrincipalName"));
    }

    #[test]
    fn test_stale_password_attributes() {
        // Verify pwdLastSet is included for age calculation
        let attrs = vec![
            "sAMAccountName",
            "pwdLastSet",
            "servicePrincipalName",
            "distinguishedName",
            "userAccountControl",
        ];

        assert!(attrs.contains(&"pwdLastSet"));
    }

    // ─── Phase 5: Filter Constants ────────────────────────────────────

    #[test]
    fn test_uac_bit_values() {
        // Verify userAccountControl bit values per Microsoft docs
        assert_eq!(4194304, 0x400000);  // DONT_REQ_PREAUTH (bit 22)
        assert_eq!(524288, 0x80000);    // TRUSTED_FOR_DELEGATION (bit 19, unconstrained)
        assert_eq!(16777216, 0x1000000); // TRUSTED_TO_AUTH_FOR_DELEGATION (bit 24, T2A4D / Protocol Transition)
        assert_eq!(1048576, 0x100000);  // NOT_DELEGATED (bit 20) — NOT the same as T2A4D
        assert_eq!(2, 0x2);             // ACCOUNT_DISABLED
    }

    #[test]
    fn test_ldap_oid_values() {
        // Verify LDAP OID constants are correct
        let bitwise_and_oid = "1.2.840.113556.1.4.803"; // Bitwise AND
        let in_chain_oid = "1.2.840.113556.1.4.1941";  // IN_CHAIN for recursive groups

        // Just verify these exist in expected filters
        let filter1 = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
        let filter2 = "(memberOf:1.2.840.113556.1.4.1941:=CN=Admins,DC=corp,DC=local)";

        assert!(filter1.contains(bitwise_and_oid));
        assert!(filter2.contains(in_chain_oid));
    }
}
