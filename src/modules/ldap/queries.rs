use std::time::Duration;

use ldap3::{Ldap, Scope, SearchEntry};
use rand::Rng;

use super::parser::LdapObject;

/// LDAP query 1: Find accounts with DONT_REQ_PREAUTH (AS-REP Roasting targets).
/// userAccountControl bit 22 (0x400000 = 4194304)
pub async fn query_asrep_candidates(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    let filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
    let attrs = vec!["sAMAccountName", "userAccountControl", "distinguishedName"];
    search(ldap, base_dn, filter, &attrs).await
}

/// LDAP query 2: Find service accounts with SPNs (Kerberoasting targets).
/// Excludes computer accounts.
pub async fn query_spn_accounts(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    let filter = "(&(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    let attrs = vec![
        "sAMAccountName",
        "servicePrincipalName",
        "msDS-SupportedEncryptionTypes",
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
/// Targets: accounts with msDS-AllowedToDelegateTo set OR UAC TRUSTED_TO_AUTH_FOR_DELEGATION (0x100000).
pub async fn query_constrained_delegation(ldap: &mut Ldap, base_dn: &str) -> anyhow::Result<Vec<LdapObject>> {
    // OR filter: has delegation target list OR has T2A4D flag
    let filter = "(|(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))";
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

        let group_dn = match group_objs.first().and_then(|o| Some(o.dn.as_str())) {
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
/// Windows epoch: 1601-01-01 00:00:00 UTC
/// Difference from Unix epoch: 116444736000000000 * 100-ns intervals
fn windows_timestamp_days_ago(days: u64) -> i64 {
    let unix_secs = chrono::Utc::now().timestamp() - (days as i64 * 86400);
    (unix_secs * 10_000_000) + 116_444_736_000_000_000
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
