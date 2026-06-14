/// LDAP filter strings — centralized for audit and maintenance.
///
/// All filters use standard LDAP query syntax per RFC 4515.
/// userAccountControl bit matching uses OID 1.2.840.113556.1.4.803 (bitwise AND).

/// Find accounts with DONT_REQ_PREAUTH (userAccountControl bit 22 = 0x400000).
pub const ASREP_CANDIDATES: &str = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";

/// Find service accounts with SPNs, excluding computers and disabled accounts.
pub const SPN_ACCOUNTS: &str =
    "(&(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

/// Find computers with unconstrained delegation (userAccountControl bit 19 = 0x80000).
pub const UNCONSTRAINED_DELEGATION: &str =
    "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))";

/// Find accounts/computers with Constrained Delegation.
/// Includes msDS-AllowedToDelegateTo OR TRUSTED_TO_AUTH_FOR_DELEGATION flag (bit 20 = 0x100000).
pub fn constrained_delegation() -> &'static str {
    "(|(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))"
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
