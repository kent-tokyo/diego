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
            Some(SpnAccount { sam_name, spns, supported_enc_types })
        })
        .collect()
}

/// Detect potential hardcoded passwords in the description field
pub fn detect_description_leak(obj: &LdapObject) -> Option<String> {
    let desc = obj.get_first("description")?;
    let lower = desc.to_lowercase();
    // Heuristic keywords — flag for human review rather than false-certainty
    let keywords = ["pass", "pwd", "secret", "cred", "key", "token", "hash", "p@ss"];
    if keywords.iter().any(|kw| lower.contains(kw)) {
        Some(desc.to_string())
    } else {
        None
    }
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
}
