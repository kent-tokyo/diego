//! TLS wire encoding/decoding for transport-hygiene probing.
//!
//! Hand-written (no TLS-scanner crate) in diego's minimal-dependency style. This
//! is **read-only detection**, not a handshake implementation: for each probed
//! protocol version we send one ClientHello and classify the server's first
//! response (ServerHello = accepted, Alert = refused). We never complete a
//! handshake, negotiate keys, or send application data. Certificate validity is
//! read from the cleartext Certificate message of a TLS 1.2 handshake.

pub const V10: u16 = 0x0301;
pub const V11: u16 = 0x0302;
pub const V12: u16 = 0x0303;
pub const V13: u16 = 0x0304;

fn u16b(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn vec16(body: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(body.len() + 2);
    o.extend_from_slice(&(body.len() as u16).to_be_bytes());
    o.extend_from_slice(body);
    o
}

fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&u16b(kind));
    o.extend_from_slice(&vec16(data));
    o
}

/// Build a ClientHello probing a specific protocol version. For <=1.2 the
/// client_version field is set to the probed version and no supported_versions
/// extension is sent, so the server negotiates that version or returns an
/// alert. For 1.3, client_version stays 0x0303 and supported_versions=[0x0304]
/// plus a key_share are added (arbitrary key bytes — acceptance detection only).
pub fn client_hello(legacy_version: u16, probe_13: bool, sni: &str) -> Vec<u8> {
    let suites: [u16; 17] = [
        0x1302, 0x1303, 0x1301, 0xC02F, 0xC02B, 0xC030, 0xC02C, 0xC013, 0xC014, 0xC009, 0xC00A,
        0x009C, 0x009D, 0x002F, 0x0035, 0x000A, 0x00FF,
    ];
    let mut cs = Vec::new();
    for s in suites {
        cs.extend_from_slice(&u16b(s));
    }

    let mut exts = Vec::new();
    // server_name
    let mut sni_list = Vec::new();
    sni_list.push(0u8);
    sni_list.extend_from_slice(&vec16(sni.as_bytes()));
    exts.extend_from_slice(&ext(0x0000, &vec16(&sni_list)));
    // supported_groups
    let mut groups = Vec::new();
    for g in [0x001du16, 0x0017, 0x0018] {
        groups.extend_from_slice(&u16b(g));
    }
    exts.extend_from_slice(&ext(0x000a, &vec16(&groups)));
    // ec_point_formats: uncompressed
    exts.extend_from_slice(&ext(0x000b, &[0x01, 0x00]));
    // signature_algorithms
    let mut sigs = Vec::new();
    for s in [
        0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0203, 0x0201,
    ] {
        sigs.extend_from_slice(&u16b(s));
    }
    exts.extend_from_slice(&ext(0x000d, &vec16(&sigs)));
    // renegotiation_info (empty)
    exts.extend_from_slice(&ext(0xff01, &[0x00]));
    if probe_13 {
        exts.extend_from_slice(&ext(0x002b, &[0x02, 0x03, 0x04])); // supported_versions [1.3]
        let mut ks_entry = Vec::new();
        ks_entry.extend_from_slice(&u16b(0x001d)); // x25519
        ks_entry.extend_from_slice(&vec16(&[0x42u8; 32]));
        exts.extend_from_slice(&ext(0x0033, &vec16(&ks_entry))); // key_share
    }

    let mut ch = Vec::new();
    ch.extend_from_slice(&u16b(0x0303)); // client_version (adjusted below for <=1.2)
    ch.extend_from_slice(&[0x11u8; 32]); // random (detection only)
    ch.push(0); // session_id length
    ch.extend_from_slice(&vec16(&cs));
    ch.push(1);
    ch.push(0); // null compression
    ch.extend_from_slice(&vec16(&exts));
    if !probe_13 {
        ch[0] = (legacy_version >> 8) as u8;
        ch[1] = (legacy_version & 0xff) as u8;
    }

    let mut hs = Vec::new();
    hs.push(0x01);
    let l = ch.len();
    hs.push((l >> 16) as u8);
    hs.push((l >> 8) as u8);
    hs.push(l as u8);
    hs.extend_from_slice(&ch);

    let rec_ver = if probe_13 { V12 } else { legacy_version };
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&u16b(rec_ver));
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServerResp {
    ServerHello { negotiated: u16, cipher: u16 },
    Alert { level: u8, desc: u8 },
    Incomplete,
    Other,
}

/// Classify the server's first TLS record.
pub fn classify(raw: &[u8]) -> ServerResp {
    if raw.len() < 5 {
        return ServerResp::Incomplete;
    }
    let content = raw[0];
    let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    let body = &raw[5..];
    if content == 21 {
        if body.len() >= 2 {
            return ServerResp::Alert { level: body[0], desc: body[1] };
        }
        return ServerResp::Incomplete;
    }
    if content != 22 {
        return ServerResp::Other;
    }
    if body.is_empty() || body.len() < rec_len.min(4) {
        return ServerResp::Incomplete;
    }
    if body[0] != 0x02 {
        return ServerResp::Other;
    }
    if body.len() < 4 {
        return ServerResp::Incomplete;
    }
    let sh = &body[4..];
    if sh.len() < 2 + 32 + 1 {
        return ServerResp::Incomplete;
    }
    let legacy = u16::from_be_bytes([sh[0], sh[1]]);
    let sid_len = sh[34] as usize;
    let mut p = 35 + sid_len;
    if sh.len() < p + 3 {
        return ServerResp::Incomplete;
    }
    let cipher = u16::from_be_bytes([sh[p], sh[p + 1]]);
    p += 2;
    p += 1; // compression method
    let mut negotiated = legacy;
    if sh.len() >= p + 2 {
        let ext_total = u16::from_be_bytes([sh[p], sh[p + 1]]) as usize;
        p += 2;
        let end = (p + ext_total).min(sh.len());
        while p + 4 <= end {
            let et = u16::from_be_bytes([sh[p], sh[p + 1]]);
            let el = u16::from_be_bytes([sh[p + 2], sh[p + 3]]) as usize;
            p += 4;
            if et == 0x002b && el >= 2 && p + 2 <= sh.len() {
                negotiated = u16::from_be_bytes([sh[p], sh[p + 1]]);
            }
            p += el;
        }
    }
    ServerResp::ServerHello { negotiated, cipher }
}

/// Concatenate handshake-message bytes across TLS records, stopping at an alert.
pub fn collect_handshake(raw: &[u8]) -> (Vec<u8>, Option<(u8, u8)>) {
    let mut hs = Vec::new();
    let mut pos = 0;
    while pos + 5 <= raw.len() {
        let content = raw[pos];
        let rec_len = u16::from_be_bytes([raw[pos + 3], raw[pos + 4]]) as usize;
        let start = pos + 5;
        let end = (start + rec_len).min(raw.len());
        if content == 21 && end >= start + 2 {
            return (hs, Some((raw[start], raw[start + 1])));
        }
        if content == 22 {
            hs.extend_from_slice(&raw[start..end]);
        }
        pos = end;
    }
    (hs, None)
}

/// Parse handshake messages into (type, body) pairs.
pub fn parse_messages(hs: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= hs.len() {
        let t = hs[i];
        let l = ((hs[i + 1] as usize) << 16) | ((hs[i + 2] as usize) << 8) | hs[i + 3] as usize;
        let s = i + 4;
        if s + l > hs.len() {
            break;
        }
        out.push((t, hs[s..s + l].to_vec()));
        i = s + l;
    }
    out
}

/// First (leaf) certificate DER from a Certificate handshake message (TLS 1.2).
pub fn first_cert_der(cert_msg_body: &[u8]) -> Option<Vec<u8>> {
    if cert_msg_body.len() < 3 {
        return None;
    }
    let list_len = ((cert_msg_body[0] as usize) << 16)
        | ((cert_msg_body[1] as usize) << 8)
        | cert_msg_body[2] as usize;
    let mut i = 3;
    let end = (3 + list_len).min(cert_msg_body.len());
    if i + 3 > end {
        return None;
    }
    let clen = ((cert_msg_body[i] as usize) << 16)
        | ((cert_msg_body[i + 1] as usize) << 8)
        | cert_msg_body[i + 2] as usize;
    i += 3;
    if i + clen > cert_msg_body.len() {
        return None;
    }
    Some(cert_msg_body[i..i + clen].to_vec())
}

/// Read one DER TLV: (tag, content_start, content_len, next_pos).
fn der_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    if pos + 2 > buf.len() {
        return None;
    }
    let tag = buf[pos];
    let l0 = buf[pos + 1];
    let (len, hdr) = if l0 & 0x80 == 0 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || pos + 2 + n > buf.len() {
            return None;
        }
        let mut v = 0usize;
        for k in 0..n {
            v = (v << 8) | buf[pos + 2 + k] as usize;
        }
        (v, 2 + n)
    };
    let cs = pos + hdr;
    if cs + len > buf.len() {
        return None;
    }
    Some((tag, cs, len, cs + len))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1Time {
    pub y: i64,
    pub mo: i64,
    pub d: i64,
    pub h: i64,
    pub mi: i64,
    pub s: i64,
}

/// Days since 1970-01-01 (proleptic Gregorian; Howard Hinnant's algorithm).
pub fn civil_to_days(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

impl Asn1Time {
    pub fn to_epoch_secs(&self) -> i64 {
        civil_to_days(self.y, self.mo, self.d) * 86400 + self.h * 3600 + self.mi * 60 + self.s
    }
    pub fn rfc3339(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.y, self.mo, self.d, self.h, self.mi, self.s
        )
    }
}

/// Parse ASN.1 UTCTime (0x17) or GeneralizedTime (0x18).
pub fn parse_asn1_time(tag: u8, v: &[u8]) -> Option<Asn1Time> {
    let s: String = v.iter().map(|&b| b as char).collect();
    let dig = |a: &str| a.parse::<i64>().ok();
    if tag == 0x17 {
        if s.len() < 12 {
            return None;
        }
        let yy = dig(&s[0..2])?;
        let y = if yy < 50 { 2000 + yy } else { 1900 + yy };
        Some(Asn1Time { y, mo: dig(&s[2..4])?, d: dig(&s[4..6])?, h: dig(&s[6..8])?, mi: dig(&s[8..10])?, s: dig(&s[10..12])? })
    } else if tag == 0x18 {
        if s.len() < 14 {
            return None;
        }
        Some(Asn1Time { y: dig(&s[0..4])?, mo: dig(&s[4..6])?, d: dig(&s[6..8])?, h: dig(&s[8..10])?, mi: dig(&s[10..12])?, s: dig(&s[12..14])? })
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CertInfo {
    pub not_before: Asn1Time,
    pub not_after: Asn1Time,
    pub self_signed: bool,
}

/// Extract validity + a self-signed heuristic from a leaf certificate DER.
pub fn cert_info(der: &[u8]) -> Option<CertInfo> {
    let (_t, cs, _l, _n) = der_tlv(der, 0)?; // Certificate
    let (_tt, tcs, tlen, _tn) = der_tlv(der, cs)?; // tbsCertificate
    let tbs_end = tcs + tlen;
    let mut p = tcs;
    let (tag, _s0, _l0, n0) = der_tlv(der, p)?;
    if tag == 0xA0 {
        p = n0; // skip [0] version
    }
    let (_ts, _ss, _ls, ns) = der_tlv(der, p)?; // serialNumber
    p = ns;
    let (_ta, _sa, _la, na) = der_tlv(der, p)?; // signatureAlgorithm
    p = na;
    let (_ti, si, li, ni) = der_tlv(der, p)?; // issuer
    let issuer = &der[si..si + li];
    p = ni;
    let (_tv, sv, _lv, nv) = der_tlv(der, p)?; // validity
    let (tb, sb, lb, nb) = der_tlv(der, sv)?;
    let not_before = parse_asn1_time(tb, &der[sb..sb + lb])?;
    let (taf, saf, laf, _naf) = der_tlv(der, nb)?;
    let not_after = parse_asn1_time(taf, &der[saf..saf + laf])?;
    p = nv;
    if p > tbs_end {
        return None;
    }
    let (_tsub, ssub, lsub, _nsub) = der_tlv(der, p)?; // subject
    let subject = &der[ssub..ssub + lsub];
    Some(CertInfo { not_before, not_after, self_signed: issuer == subject })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello_record(legacy: u16, cipher: u16, sv_ext: Option<u16>) -> Vec<u8> {
        let mut sh = Vec::new();
        sh.extend_from_slice(&legacy.to_be_bytes());
        sh.extend_from_slice(&[0u8; 32]);
        sh.push(0);
        sh.extend_from_slice(&cipher.to_be_bytes());
        sh.push(0);
        let mut exts = Vec::new();
        if let Some(v) = sv_ext {
            exts.extend_from_slice(&0x002bu16.to_be_bytes());
            exts.extend_from_slice(&2u16.to_be_bytes());
            exts.extend_from_slice(&v.to_be_bytes());
        }
        sh.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        sh.extend_from_slice(&exts);
        let mut hs = vec![0x02u8];
        let l = sh.len();
        hs.push((l >> 16) as u8);
        hs.push((l >> 8) as u8);
        hs.push(l as u8);
        hs.extend_from_slice(&sh);
        let mut rec = vec![0x16u8];
        rec.extend_from_slice(&V12.to_be_bytes());
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn classify_serverhello_tls12() {
        let r = server_hello_record(V12, 0xC02F, None);
        assert_eq!(classify(&r), ServerResp::ServerHello { negotiated: V12, cipher: 0xC02F });
    }

    #[test]
    fn classify_serverhello_tls13_via_ext() {
        let r = server_hello_record(V12, 0x1301, Some(V13));
        assert_eq!(classify(&r), ServerResp::ServerHello { negotiated: V13, cipher: 0x1301 });
    }

    #[test]
    fn classify_alert() {
        let r = vec![0x15u8, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
        assert_eq!(classify(&r), ServerResp::Alert { level: 2, desc: 0x46 });
    }

    #[test]
    fn classify_incomplete() {
        assert_eq!(classify(&[0x16, 0x03]), ServerResp::Incomplete);
    }

    #[test]
    fn client_hello_shapes() {
        let ch12 = client_hello(V12, false, "example.com");
        assert_eq!(ch12[0], 0x16);
        assert_eq!(ch12[5], 0x01);
        assert_eq!(&ch12[9..11], &[0x03, 0x03]);
        let ch10 = client_hello(V10, false, "example.com");
        assert_eq!(&ch10[9..11], &[0x03, 0x01]);
        let ch13 = client_hello(V12, true, "example.com");
        assert_eq!(ch13[0], 0x16);
    }

    #[test]
    fn cert_parse_fixture() {
        let der = include_bytes!("testdata/fixture_cert.der");
        let info = cert_info(der).expect("parse fixture cert");
        assert!(info.self_signed);
        assert!(info.not_after.to_epoch_secs() > info.not_before.to_epoch_secs());
        assert_eq!(info.not_before.y, 2026);
        assert_eq!(info.not_after.y, 2036);
    }

    #[test]
    fn asn1_time_utc_and_generalized() {
        let u = parse_asn1_time(0x17, b"260926130000Z").unwrap();
        assert_eq!((u.y, u.mo, u.d), (2026, 9, 26));
        let g = parse_asn1_time(0x18, b"20360923130000Z").unwrap();
        assert_eq!((g.y, g.mo, g.d), (2036, 9, 23));
    }

    #[test]
    fn civil_days_epoch() {
        assert_eq!(civil_to_days(1970, 1, 1), 0);
        assert_eq!(civil_to_days(2000, 1, 1), 10957);
    }
}
