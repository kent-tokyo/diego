use std::collections::HashMap;

use ldap3::SearchEntry;

use crate::modules::SpnAccount;

#[derive(Debug, Clone)]
pub struct LdapObject {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
}

impl LdapObject {
    pub fn from_entry(entry: SearchEntry) -> Self {
        LdapObject {
            dn: entry.dn,
            attrs: entry.attrs,
        }
    }

    pub fn get_first(&self, attr: &str) -> Option<&str> {
        self.attrs.get(attr)?.first().map(String::as_str)
    }

    pub fn get_all(&self, attr: &str) -> Vec<&str> {
        self.attrs
            .get(attr)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn get_u32(&self, attr: &str) -> Option<u32> {
        self.get_first(attr)?.parse().ok()
    }
}

/// Extract AS-REP Roasting candidates: accounts with DONT_REQ_PREAUTH
pub fn extract_asrep_candidates(objects: &[LdapObject]) -> Vec<String> {
    objects
        .iter()
        .filter_map(|o| o.get_first("sAMAccountName").map(String::from))
        .collect()
}

/// Extract Kerberoastable service accounts
pub fn extract_spn_accounts(objects: &[LdapObject]) -> Vec<SpnAccount> {
    objects
        .iter()
        .filter_map(|o| {
            let sam_name = o.get_first("sAMAccountName")?.to_string();
            let spns: Vec<String> = o.get_all("servicePrincipalName")
                .into_iter()
                .map(String::from)
                .collect();
            if spns.is_empty() {
                return None;
            }
            let supported_enc_types = o.get_u32("msDS-SupportedEncryptionTypes").unwrap_or(0);
            let pwd_last_set = o.get_first("pwdLastSet").and_then(|s| s.parse::<i64>().ok());
            let admin_count = o.get_u32("adminCount").unwrap_or(0);
            Some(SpnAccount { sam_name, spns, supported_enc_types, pwd_last_set, admin_count })
        })
        .collect()
}

/// Confidence tier for a description-field credential match.
/// High = explicit credential format; Low = ambiguous term that often appears in business language.
#[derive(Debug, Clone, PartialEq)]
pub enum DescLeakConfidence { High, Medium, Low }

/// A detected credential leak in a description field.
#[derive(Debug, Clone)]
pub struct DescLeak {
    pub description: String,
    pub confidence: DescLeakConfidence,
}

/// Detect potential hardcoded passwords in the description field.
///
/// Three-tier detection:
/// - High: explicit credential-format patterns (`password=`, `pwd:`, `secret=`, `p@ss`)
/// - Medium: core credential keywords (`pass`, `pwd`, `secret`, `cred`, `hash`)
/// - Low: ambiguous terms that appear in business language (`key`, `token`)
pub fn detect_description_leak(obj: &LdapObject) -> Option<DescLeak> {
    let desc = obj.get_first("description")?;
    let lower = desc.to_lowercase();

    // High: explicit credential-format patterns
    let high_patterns = ["password=", "password:", "pwd=", "pwd:", "secret=", "secret:", "pass=", "pass:", "p@ss"];
    if high_patterns.iter().any(|p| lower.contains(p)) {
        return Some(DescLeak { description: desc.to_string(), confidence: DescLeakConfidence::High });
    }

    // Medium: core keywords that are rarely benign in AD descriptions
    let medium_keywords = ["pass", "pwd", "secret", "cred", "hash"];
    if medium_keywords.iter().any(|kw| lower.contains(kw)) {
        return Some(DescLeak { description: desc.to_string(), confidence: DescLeakConfidence::Medium });
    }

    // Low: terms that appear in business language ("key account manager", "token migration")
    let low_keywords = ["key", "token"];
    if low_keywords.iter().any(|kw| lower.contains(kw)) {
        return Some(DescLeak { description: desc.to_string(), confidence: DescLeakConfidence::Low });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_obj(attrs: &[(&str, &[&str])]) -> LdapObject {
        let mut map = HashMap::new();
        for (k, vals) in attrs {
            map.insert(k.to_string(), vals.iter().map(|v| v.to_string()).collect());
        }
        LdapObject { dn: "CN=test,DC=corp,DC=local".into(), attrs: map }
    }

    #[test]
    fn test_extract_asrep_candidates() {
        let objs = vec![make_obj(&[("sAMAccountName", &["alice"])])];
        assert_eq!(extract_asrep_candidates(&objs), vec!["alice"]);
    }

    #[test]
    fn test_detect_description_leak_positive() {
        let obj = make_obj(&[
            ("sAMAccountName", &["svc_deploy"]),
            ("description", &["Password123!"]),
        ]);
        assert!(detect_description_leak(&obj).is_some());
    }

    #[test]
    fn test_detect_description_leak_negative() {
        let obj = make_obj(&[
            ("sAMAccountName", &["jdoe"]),
            ("description", &["Senior Engineer"]),
        ]);
        assert!(detect_description_leak(&obj).is_none());
    }

    #[test]
    fn test_detect_description_leak_explicit_format_is_high() {
        let obj = make_obj(&[
            ("sAMAccountName", &["svc"]),
            ("description", &["password=Welcome2024!"]),
        ]);
        let leak = detect_description_leak(&obj).unwrap();
        assert_eq!(leak.confidence, DescLeakConfidence::High);
    }

    #[test]
    fn test_detect_description_leak_keyword_only_is_medium() {
        let obj = make_obj(&[
            ("sAMAccountName", &["svc"]),
            ("description", &["Password123!"]),
        ]);
        let leak = detect_description_leak(&obj).unwrap();
        assert_eq!(leak.confidence, DescLeakConfidence::Medium);
    }

    #[test]
    fn test_detect_description_leak_key_only_is_low() {
        let obj = make_obj(&[
            ("sAMAccountName", &["pm"]),
            ("description", &["key account manager"]),
        ]);
        let leak = detect_description_leak(&obj).unwrap();
        assert_eq!(leak.confidence, DescLeakConfidence::Low);
    }

    #[test]
    fn test_detect_description_leak_token_is_low() {
        let obj = make_obj(&[
            ("sAMAccountName", &["pm"]),
            ("description", &["token migration notes"]),
        ]);
        let leak = detect_description_leak(&obj).unwrap();
        assert_eq!(leak.confidence, DescLeakConfidence::Low);
    }
}
