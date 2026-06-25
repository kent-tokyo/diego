//! Pure analysis: turn fetched LDAP objects into `Finding`s.
//!
//! These functions take already-fetched `LdapObject`s (see `queries.rs` for the
//! fetch side) and contain no I/O, so the detection logic — including severity
//! and confidence assignment — is unit-testable with synthetic fixtures
//! (`tests/detection_tests.rs`). `LdapModule::run` is the thin I/O wrapper that
//! fetches then calls these.

use crate::report::{Confidence, Finding, Severity};

use super::parser::{detect_description_leak, LdapObject};

/// AS-REP roastable accounts (DONT_REQ_PREAUTH) → one aggregate finding.
pub fn build_asrep_findings(asrep_objs: &[LdapObject], domain: &str) -> Vec<Finding> {
    if asrep_objs.is_empty() {
        return vec![];
    }
    let names: Vec<String> = asrep_objs
        .iter()
        .filter_map(|o| o.get_first("sAMAccountName").map(String::from))
        .collect();
    vec![Finding::new(
        "LDAP-ASREP-CANDIDATES",
        "ldap",
        Severity::High,
        format!("{} account(s) without Kerberos pre-authentication", names.len()),
        "These accounts have DONT_REQ_PREAUTH set (userAccountControl bit 22). \
         An attacker can request an AS-REP without providing valid credentials, \
         then crack the encrypted response offline.",
        serde_json::json!({ "accounts": names }),
        Some("Run Hashcat mode 18200 on the extracted hashes to recover plaintext passwords.".into()),
    )
    .with_llm_context(format!(
        "{} account(s) in domain '{}' have DONT_REQ_PREAUTH set: {}. \
         This means any network attacker (no credentials needed) can request an AS-REP \
         and attempt to crack it offline using Hashcat mode 18200. \
         If any of these accounts have elevated privileges, this is a direct path to privilege escalation.",
        names.len(), domain, names.join(", ")
    ))
    .with_remediation(vec![
        "Enable Kerberos pre-authentication on all affected accounts (uncheck 'Do not require Kerberos preauthentication' in ADUC)",
        "If pre-auth must be disabled for a legacy application, ensure that account has a long random password (20+ chars) and minimal privileges",
        "Audit why pre-authentication was disabled — it is almost always a misconfiguration",
    ])
    .with_mitre("T1558.004")]
}

/// SPN (Kerberoastable) accounts → one aggregate finding.
pub fn build_spn_findings(spn_objs: &[LdapObject], domain: &str) -> Vec<Finding> {
    if spn_objs.is_empty() {
        return vec![];
    }
    let spns: Vec<serde_json::Value> = spn_objs
        .iter()
        .filter_map(|o| {
            let name = o.get_first("sAMAccountName")?;
            let spns = o.get_all("servicePrincipalName");
            Some(serde_json::json!({ "account": name, "spns": spns }))
        })
        .collect();
    vec![Finding::new(
        "LDAP-SPN-ACCOUNTS",
        "ldap",
        Severity::Medium,
        format!("{} Kerberoastable service account(s)", spn_objs.len()),
        "Service accounts with SPNs can be targeted for Kerberoasting: \
         any domain user can request a service ticket (TGS) for these accounts \
         and crack them offline to recover the service account password.",
        serde_json::json!({ "accounts": spns }),
        Some("Service account passwords are often long-lived and weak. Crack with Hashcat mode 13100.".into()),
    )
    .with_llm_context(format!(
        "{} service account(s) in domain '{}' have Service Principal Names (SPNs) registered. \
         Any authenticated domain user can request a Kerberos service ticket (TGS) for these accounts. \
         The encrypted ticket can be extracted and cracked offline (Hashcat mode 13100). \
         Service accounts often have long-lived, weak passwords set years ago by sysadmins.",
        spn_objs.len(), domain
    ))
    .with_remediation(vec![
        "Implement Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA) — passwords are auto-rotated by AD",
        "For existing service accounts, set passwords to 25+ character random strings and rotate them",
        "Remove unnecessary SPNs from user accounts",
        "Enable AES-only encryption on service accounts (disable RC4) to make cracking harder",
    ])
    .with_mitre("T1558.003")]
}

/// Description-field credential leaks → one finding per matching account.
/// Heuristic keyword match → Medium confidence.
pub fn build_description_leak_findings(desc_objs: &[LdapObject], domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for obj in desc_objs {
        if let Some(desc) = detect_description_leak(obj) {
            let name = obj.get_first("sAMAccountName").unwrap_or("?");
            findings.push(
                Finding::new(
                    format!("LDAP-DESC-LEAK-{}", name.to_uppercase()),
                    "ldap",
                    Severity::High,
                    format!("Potential credential in description: {}", name),
                    format!("Account '{}' has a suspicious description that may contain a credential.", name),
                    serde_json::json!({ "account": name, "dn": obj.dn, "description": desc }),
                    Some("Verify the description manually. If it contains a password, update and clear the field immediately.".into()),
                )
                .with_llm_context(format!(
                    "Account '{}' in domain '{}' has a description field that appears to contain credential material: \"{}\". \
                     The description attribute is readable by all domain users by default. \
                     This is a common legacy pattern where admins stored passwords in AD for convenience.",
                    name, domain, desc
                ))
                .with_remediation(vec![
                    "Immediately clear the description field for this account",
                    "Change the account's password if it was exposed",
                    "Audit all accounts for credential material in description, comment, and info attributes",
                    "Implement a policy prohibiting credentials in AD attribute fields",
                ])
                .with_confidence(Confidence::Medium),
            );
        }
    }
    findings
}

/// Unconstrained delegation → one finding per computer.
pub fn build_unconstrained_findings(deleg_objs: &[LdapObject], _domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for obj in deleg_objs {
        let cn = obj.get_first("cn").unwrap_or("?");
        let dns = obj.get_first("dnsHostName").unwrap_or("?");
        findings.push(
            Finding::new(
                format!("LDAP-UNCON-DELEG-{}", cn.to_uppercase()),
                "ldap",
                Severity::Critical,
                format!("Unconstrained Delegation: {}", cn),
                format!(
                    "Computer '{}' ({}) has Unconstrained Delegation enabled. \
                     Any service running on this machine can impersonate ANY user \
                     who authenticates to it, including Domain Admins. \
                     Attacker can coerce DC authentication (e.g. PrinterBug/PetitPotam) \
                     and capture a Domain Admin TGT.",
                    cn, dns
                ),
                serde_json::json!({ "cn": cn, "dnsHostName": dns, "dn": obj.dn, "os": obj.get_first("operatingSystem") }),
                Some("Unconstrained Delegation → coerce DC auth → capture TGT → impersonate DA → full domain compromise.".into()),
            )
            .with_llm_context(format!(
                "Computer '{}' ({}) has Unconstrained Delegation enabled (TrustedForDelegation flag set). \
                 When any user (including a Domain Admin) authenticates to any service on this machine, \
                 their full TGT is cached in memory. An attacker with local admin on '{}' can extract \
                 this TGT and impersonate that user anywhere in the domain. \
                 Combined with coercion attacks (PrinterBug, PetitPotam, DFSCoerce), \
                 an attacker can force the DC to authenticate to '{}' and capture a DC TGT, \
                 achieving full domain compromise.",
                cn, dns, cn, cn
            ))
            .with_remediation(vec![
                "Remove the TrustedForDelegation flag from this computer account (set 'Account is sensitive and cannot be delegated' on service accounts that connect to it)",
                "If delegation is required, migrate to Constrained Delegation or Resource-Based Constrained Delegation (RBCD)",
                "Block coercion attack vectors: disable the Print Spooler service on DCs, patch PetitPotam (MS-EFSR)",
                "Enable Protected Users security group for all privileged accounts — members cannot be delegated",
            ])
            .with_mitre("T1558.001"),
        );
    }
    findings
}

/// Constrained delegation (S4U2Self/S4U2Proxy) → one finding per account.
pub fn build_constrained_findings(const_deleg_objs: &[LdapObject], _domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for obj in const_deleg_objs {
        let name = obj.get_first("sAMAccountName").unwrap_or("?");
        let targets = obj.get_all("msDS-AllowedToDelegateTo");
        let t2a4d = obj.get_u32("userAccountControl").unwrap_or(0) & 0x100000 != 0;
        findings.push(
            Finding::new(
                format!("LDAP-CONST-DELEG-{}", name.to_uppercase()),
                "ldap",
                Severity::Critical,
                format!("Constrained Delegation: {}", name),
                format!(
                    "Account '{}' is configured for Constrained Delegation{}. \
                     S4U2Self + S4U2Proxy allows this account to obtain service tickets \
                     for any user to the listed target services.",
                    name,
                    if t2a4d { " with Protocol Transition (T2A4D)" } else { "" }
                ),
                serde_json::json!({ "account": name, "dn": obj.dn, "delegation_targets": targets, "protocol_transition_t2a4d": t2a4d }),
                Some("Constrained Delegation → S4U2Self → S4U2Proxy → impersonate any user to target services.".into()),
            )
            .with_llm_context(format!(
                "Account '{}' has Constrained Delegation configured{}. \
                 It can impersonate ANY domain user (including Domain Admins) to the following services: {}. \
                 Protocol Transition (T2A4D) makes this even more dangerous — it allows obtaining a \
                 service ticket for a user without that user ever authenticating.",
                name,
                if t2a4d { " with Protocol Transition (T2A4D flag set)" } else { "" },
                targets.join(", ")
            ))
            .with_remediation(vec![
                "Restrict Constrained Delegation to only the specific service accounts that genuinely require it",
                "Remove Protocol Transition (T2A4D / TRUSTED_TO_AUTH_FOR_DELEGATION) unless explicitly needed",
                "Add high-privilege accounts to the Protected Users security group — members cannot be impersonated via delegation",
                "Audit which services are listed in msDS-AllowedToDelegateTo and remove unnecessary entries",
            ])
            .with_mitre("T1558.001"),
        );
    }
    findings
}

/// Resource-Based Constrained Delegation → one finding per object.
pub fn build_rbcd_findings(rbcd_objs: &[LdapObject], _domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for obj in rbcd_objs {
        let name = obj
            .get_first("cn")
            .or_else(|| obj.get_first("sAMAccountName"))
            .unwrap_or("?");
        let dns = obj.get_first("dnsHostName").unwrap_or("?");
        findings.push(
            Finding::new(
                format!("LDAP-RBCD-{}", name.to_uppercase()),
                "ldap",
                Severity::Critical,
                format!("Resource-Based Constrained Delegation: {}", name),
                format!(
                    "Object '{}' ({}) has msDS-AllowedToActOnBehalfOfOtherIdentity set. \
                     An attacker who controls a machine account in that attribute's ACE \
                     can impersonate any user to services on '{}'.",
                    name, dns, name
                ),
                serde_json::json!({ "cn": name, "dnsHostName": dns, "dn": obj.dn }),
                Some("RBCD: control a listed machine account → S4U2Self + S4U2Proxy → impersonate DA to target.".into()),
            )
            .with_llm_context(format!(
                "Object '{}' ({}) has Resource-Based Constrained Delegation configured \
                 (msDS-AllowedToActOnBehalfOfOtherIdentity is set). \
                 An attacker who controls any machine account listed in this attribute's security descriptor \
                 can perform S4U2Self + S4U2Proxy to impersonate ANY user — including Domain Admins — \
                 to services running on '{}'. \
                 This is a common post-exploitation target: if an attacker has GenericWrite on a computer \
                 object, they can configure RBCD themselves.",
                name, dns, name
            ))
            .with_remediation(vec![
                "Audit msDS-AllowedToActOnBehalfOfOtherIdentity on all computer objects — remove unexpected entries",
                "Restrict who has GenericWrite / WriteProperty on computer objects in AD",
                "Consider enabling 'Account is sensitive and cannot be delegated' on privileged accounts",
                "Use Protected Users group for all high-privilege accounts",
            ])
            .with_mitre("T1558.001"),
        );
    }
    findings
}

/// Privileged group membership → one finding per group.
pub fn build_privileged_group_findings(priv_groups: &[(String, Vec<LdapObject>)], _domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (group_name, members) in priv_groups {
        let member_names: Vec<&str> = members.iter().filter_map(|m| m.get_first("sAMAccountName")).collect();
        // Domain/Enterprise Admins are expected memberships (Info); other
        // built-in privileged groups are unexpected escalation paths (High).
        let severity = if group_name.contains("Domain Admins") || group_name.contains("Enterprise Admins") {
            Severity::Info
        } else {
            Severity::High
        };
        findings.push(
            Finding::new(
                format!("LDAP-PRIVESC-GROUP-{}", group_name.to_uppercase().replace(' ', "-")),
                "ldap",
                severity,
                format!("Privileged group membership: {} ({} members)", group_name, members.len()),
                format!("Group '{}' has {} member(s): {}.", group_name, members.len(), member_names.join(", ")),
                serde_json::json!({ "group": group_name, "member_count": members.len(), "members": member_names }),
                Some(format!(
                    "Members of '{}' have elevated privileges that can be abused for lateral movement or DA escalation.",
                    group_name
                )),
            )
            .with_llm_context(format!(
                "Group '{}' has {} member(s): {}. \
                 This group grants significant AD privileges. \
                 Groups like Backup Operators can read all files on DCs (including NTDS.dit backups); \
                 Account Operators can create/modify non-admin accounts; \
                 Print Operators have local admin on DCs. \
                 These are often overlooked as escalation paths.",
                group_name, members.len(), member_names.join(", ")
            ))
            .with_remediation(vec![
                "Review whether each member genuinely requires membership in this privileged group",
                "Apply the principle of least privilege — use role-specific groups instead of built-in privileged groups",
                "For Backup Operators: consider using Windows Server Backup with a dedicated service account instead",
                "Enable alerting in your SIEM for any changes to these group memberships",
            ])
            .with_mitre("T1069.002"),
        );
    }
    findings
}

/// Stale service-account passwords → one finding per account.
/// `now_unix` is the current time (seconds) so age is testable.
pub fn build_stale_password_findings(stale_objs: &[LdapObject], _domain: &str, now_unix: i64) -> Vec<Finding> {
    let mut findings = Vec::new();
    for obj in stale_objs {
        let name = obj.get_first("sAMAccountName").unwrap_or("?");
        let pwd_last_set_raw = obj.get_first("pwdLastSet").unwrap_or("0");
        let spns = obj.get_all("servicePrincipalName");
        // Windows FILETIME → approximate age in days.
        let age_days = pwd_last_set_raw
            .parse::<i64>()
            .map(|ts| {
                let unix_secs = (ts - 116_444_736_000_000_000) / 10_000_000;
                (now_unix - unix_secs) / 86400
            })
            .unwrap_or(0);
        findings.push(
            Finding::new(
                format!("LDAP-STALE-PWD-{}", name.to_uppercase()),
                "ldap",
                Severity::Medium,
                format!("Stale service account password: {} (~{} days)", name, age_days),
                format!(
                    "Service account '{}' has not changed its password in approximately {} days. \
                     Old passwords on Kerberoastable accounts are significantly easier to crack offline.",
                    name, age_days
                ),
                serde_json::json!({ "account": name, "dn": obj.dn, "password_age_days": age_days, "spns": spns }),
                Some(format!(
                    "Service account '{}' has SPNs registered. Old password + Kerberoasting = high crackability.",
                    name
                )),
            )
            .with_llm_context(format!(
                "Service account '{}' (SPNs: {}) has not had its password changed in ~{} days. \
                 Any domain user can request a TGS ticket for this account (Kerberoasting). \
                 Passwords that are months or years old are far more likely to be in common wordlists. \
                 This significantly increases the probability of successful offline cracking.",
                name, spns.join(", "), age_days
            ))
            .with_remediation(vec![
                "Migrate to Group Managed Service Accounts (gMSA) — AD auto-rotates the 240-character password",
                "If gMSA is not possible, rotate the password immediately to a 25+ character random value",
                "Implement a password rotation policy: service accounts should rotate every 90 days maximum",
                "Disable RC4 encryption on this account to slow offline cracking (set msDS-SupportedEncryptionTypes = 0x18)",
            ])
            .with_mitre("T1078.002"),
        );
    }
    findings
}

/// Domain password policy → zero or one finding.
pub fn build_password_policy_findings(policy_objs: &[LdapObject], domain: &str) -> Vec<Finding> {
    let Some(policy) = policy_objs.first() else {
        return vec![];
    };
    let min_len = policy.get_u32("minPwdLength").unwrap_or(0);
    let lockout = policy.get_u32("lockoutThreshold").unwrap_or(0);

    let severity = if min_len < 8 || lockout == 0 { Severity::Medium } else { Severity::Info };

    let mut issues = Vec::new();
    if min_len < 8 {
        issues.push(format!("minPwdLength={} (recommended: ≥14)", min_len));
    }
    if lockout == 0 {
        issues.push("lockoutThreshold=0 (no lockout — brute-force possible)".into());
    }

    let lockout_duration_secs = policy
        .get_u32("lockoutDuration")
        .map(|raw| (raw as i64).unsigned_abs() / 10_000_000)
        .unwrap_or(1800);

    let spray_hint = if lockout == 0 {
        "No lockout — unlimited spray attempts possible. Spray rate: unrestricted.".to_string()
    } else {
        let safe_attempts = lockout.saturating_sub(1);
        let wait_mins = lockout_duration_secs / 60;
        format!(
            "Safe spray rate: {} attempt(s) per {} minutes per account (stay below lockout threshold of {}).",
            safe_attempts, wait_mins, lockout
        )
    };

    vec![Finding::new(
        "LDAP-PWD-POLICY",
        "ldap",
        severity,
        "Domain Password Policy",
        if issues.is_empty() {
            "Password policy appears adequate.".to_string()
        } else {
            format!("Weak password policy detected: {}", issues.join("; "))
        },
        serde_json::json!({
            "minPwdLength": min_len,
            "lockoutThreshold": lockout,
            "lockoutDuration_secs": lockout_duration_secs,
            "pwdHistoryLength": policy.get_u32("pwdHistoryLength"),
            "password_spray_estimation": spray_hint,
        }),
        Some(spray_hint.clone()),
    )
    .with_llm_context(format!(
        "Domain '{}' password policy: minPwdLength={}, lockoutThreshold={}, lockoutDuration={}s. {}",
        domain, min_len, lockout, lockout_duration_secs, spray_hint
    ))
    .with_remediation(if lockout == 0 {
        vec![
            "Enable account lockout: set lockoutThreshold to 5-10 in Default Domain Policy",
            "Enable lockout duration: set lockoutDuration to 30+ minutes",
            "Consider using Fine-Grained Password Policy (PSO) for privileged accounts with stricter settings",
        ]
    } else if min_len < 14 {
        vec![
            "Increase minPwdLength to at least 14 characters (prefer passphrase policy)",
            "Enable password complexity requirements",
            "Consider a FIDO2/passkey policy for privileged accounts",
        ]
    } else {
        vec!["Password policy is adequate; ensure it is applied to all OUs"]
    })]
}
