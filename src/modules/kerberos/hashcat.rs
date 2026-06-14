//! Hashcat output format for offline cracking.
//!
//! Mode 18200: AS-REP Roasting ($krb5asrep$)
//! Mode 13100: Kerberoasting / TGS-REP ($krb5tgs$)

/// Format an AS-REP enc_part for Hashcat mode 18200.
///
/// Format: $krb5asrep$<etype>$<user>@<REALM>:<first16hex>$<rest_hex>
pub fn format_asrep_18200(etype: i32, username: &str, realm: &str, cipher: &[u8]) -> String {
    if cipher.len() < 16 {
        return format!(
            "$krb5asrep${}${}@{}:{}$",
            etype,
            username,
            realm.to_uppercase(),
            hex::encode(cipher)
        );
    }
    let (head, tail) = cipher.split_at(16);
    format!(
        "$krb5asrep${}${}@{}:{}${}",
        etype,
        username,
        realm.to_uppercase(),
        hex::encode(head),
        hex::encode(tail)
    )
}

/// Format a TGS-REP enc_part for Hashcat mode 13100.
///
/// Format: $krb5tgs$<etype>$*<user>$<REALM>$<spn>*$<first16hex>$<rest_hex>
pub fn format_tgsrep_13100(
    etype: i32,
    username: &str,
    realm: &str,
    spn: &str,
    cipher: &[u8],
) -> String {
    if cipher.len() < 16 {
        return format!(
            "$krb5tgs${}$*{}${}${}*${}$",
            etype,
            username,
            realm.to_uppercase(),
            spn,
            hex::encode(cipher)
        );
    }
    let (head, tail) = cipher.split_at(16);
    format!(
        "$krb5tgs${}$*{}${}${}*${}${}",
        etype,
        username,
        realm.to_uppercase(),
        spn,
        hex::encode(head),
        hex::encode(tail)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asrep_format_18200() {
        let cipher = vec![0xaau8; 32];
        let hash = format_asrep_18200(23, "alice", "corp.local", &cipher);
        assert!(hash.starts_with("$krb5asrep$23$alice@CORP.LOCAL:"));
        assert!(hash.contains('$'));
    }

    #[test]
    fn test_tgsrep_format_13100() {
        let cipher = vec![0xbbu8; 32];
        let hash = format_tgsrep_13100(23, "svc_sql", "corp.local", "MSSQLSvc/db01.corp.local:1433", &cipher);
        assert!(hash.starts_with("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01.corp.local:1433*$"));
    }
}
