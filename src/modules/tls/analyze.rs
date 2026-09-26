//! TLS transport-hygiene analysis: probe results in, prioritised issues out.
//! Pure and deterministic (real time is injected), so it is unit-tested below.
//! `mod.rs` maps `Issue` onto the shared `report::Finding` type.

use super::probe::{Asn1Time, CertInfo, V10, V11, V12, V13};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sev {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conf {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub id: String,
    pub sev: Sev,
    pub conf: Conf,
    pub title: String,
    pub desc: String,
    pub remediation: Vec<String>,
    pub evidence: Vec<(String, String)>,
}

impl Issue {
    fn n(id: &str, sev: Sev, conf: Conf, title: &str, desc: &str) -> Self {
        Issue {
            id: id.into(),
            sev,
            conf,
            title: title.into(),
            desc: desc.into(),
            remediation: vec![],
            evidence: vec![],
        }
    }
    fn rem(mut self, s: &[&str]) -> Self {
        self.remediation = s.iter().map(|x| x.to_string()).collect();
        self
    }
    fn ev(mut self, k: &str, v: &str) -> Self {
        self.evidence.push((k.into(), v.into()));
        self
    }
}

pub fn ver_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        V10 => "TLS 1.0",
        V11 => "TLS 1.1",
        V12 => "TLS 1.2",
        V13 => "TLS 1.3",
        _ => "unknown",
    }
}

/// Known weak negotiated ciphers (3DES / RC4). The offered set excludes
/// NULL/EXPORT/anon, so those are not solicited.
pub fn is_weak_cipher(c: u16) -> bool {
    matches!(
        c,
        0x000A | 0xC012 | 0xC008 | 0x0016 | 0x0005 | 0x0004 | 0xC011 | 0xC007
    )
}

/// `accepts`: (version, accepted?, negotiated_cipher). `target` for evidence.
pub fn analyze_versions(target: &str, accepts: &[(u16, bool, Option<u16>)]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let acc = |v: u16| accepts.iter().any(|(x, ok, _)| *x == v && *ok);
    if acc(V10) {
        issues.push(
            Issue::n(
                "TLS-PROTO-TLS10",
                Sev::High,
                Conf::High,
                "Server accepts TLS 1.0",
                "TLS 1.0 is deprecated (RFC 8996) and exposed to known weaknesses (e.g. BEAST, \
                 weak ciphers). It should be disabled.",
            )
            .rem(&["Disable TLS 1.0; require TLS 1.2 or higher."])
            .ev("target", target),
        );
    }
    if acc(V11) {
        issues.push(
            Issue::n(
                "TLS-PROTO-TLS11",
                Sev::Medium,
                Conf::High,
                "Server accepts TLS 1.1",
                "TLS 1.1 is deprecated (RFC 8996) and should be disabled in favour of TLS 1.2+.",
            )
            .rem(&["Disable TLS 1.1; require TLS 1.2 or higher."])
            .ev("target", target),
        );
    }
    let has12 = acc(V12);
    let has13 = acc(V13);
    if !has12 && !has13 {
        issues.push(
            Issue::n(
                "TLS-PROTO-NO-MODERN",
                Sev::High,
                Conf::High,
                "No modern TLS (1.2/1.3) accepted",
                "The endpoint did not accept TLS 1.2 or 1.3 in this probe; it may support only \
                 deprecated protocols or be unreachable for a TLS handshake.",
            )
            .rem(&["Enable TLS 1.2 and 1.3."])
            .ev("target", target),
        );
    } else if !has13 {
        issues.push(
            Issue::n(
                "TLS-PROTO-NO-TLS13",
                Sev::Low,
                Conf::High,
                "TLS 1.3 not offered",
                "The endpoint accepts TLS 1.2 but not TLS 1.3. Enabling TLS 1.3 improves security \
                 and performance.",
            )
            .rem(&["Enable TLS 1.3."])
            .ev("target", target),
        );
    } else {
        issues.push(
            Issue::n(
                "TLS-PROTO-OK",
                Sev::Info,
                Conf::High,
                "Modern TLS supported",
                "The endpoint accepts TLS 1.3 (and/or 1.2) and did not accept the probed legacy \
                 versions.",
            )
            .ev("target", target),
        );
    }
    for (v, ok, cipher) in accepts {
        if *ok
            && let Some(c) = cipher
            && is_weak_cipher(*c)
        {
            issues.push(
                Issue::n(
                    "TLS-WEAK-CIPHER",
                    Sev::Medium,
                    Conf::High,
                    "Weak cipher negotiated",
                    "The server negotiated a weak cipher (3DES or RC4), which is \
                     considered broken/legacy.",
                )
                .rem(&["Disable 3DES and RC4 cipher suites."])
                .ev("target", target)
                .ev("version", ver_name(*v))
                .ev("cipher", &format!("0x{:04x}", c)),
            );
            break;
        }
    }
    issues
}

/// `now_secs` is injected for deterministic testing.
pub fn analyze_cert(target: &str, cert: &CertInfo, now_secs: i64) -> Vec<Issue> {
    let mut issues = Vec::new();
    let na = cert.not_after.to_epoch_secs();
    let nb = cert.not_before.to_epoch_secs();
    let day = 86400;
    if now_secs > na {
        issues.push(
            Issue::n(
                "TLS-CERT-EXPIRED",
                Sev::Critical,
                Conf::High,
                "Certificate expired",
                "The leaf certificate's validity period has ended; clients will reject or warn.",
            )
            .rem(&["Renew and deploy a valid certificate immediately."])
            .ev("target", target)
            .ev("notAfter", &cert.not_after.rfc3339()),
        );
    } else if na - now_secs <= 30 * day {
        let days = (na - now_secs) / day;
        issues.push(
            Issue::n(
                "TLS-CERT-EXPIRING",
                Sev::High,
                Conf::High,
                "Certificate expiring soon",
                "The leaf certificate expires within 30 days.",
            )
            .rem(&["Renew the certificate before it expires."])
            .ev("target", target)
            .ev("daysRemaining", &days.to_string())
            .ev("notAfter", &cert.not_after.rfc3339()),
        );
    } else if now_secs < nb {
        issues.push(
            Issue::n(
                "TLS-CERT-NOT-YET-VALID",
                Sev::High,
                Conf::High,
                "Certificate not yet valid",
                "The certificate's notBefore is in the future; clients will reject it.",
            )
            .rem(&["Check the certificate and the system clock."])
            .ev("target", target)
            .ev("notBefore", &cert.not_before.rfc3339()),
        );
    } else {
        issues.push(
            Issue::n(
                "TLS-CERT-OK",
                Sev::Info,
                Conf::High,
                "Certificate within validity",
                "The leaf certificate is currently within its validity period.",
            )
            .ev("target", target)
            .ev("notAfter", &cert.not_after.rfc3339()),
        );
    }
    if cert.self_signed {
        issues.push(
            Issue::n(
                "TLS-CERT-SELF-SIGNED",
                Sev::Medium,
                Conf::Medium,
                "Self-signed certificate",
                "Issuer and subject match, indicating a self-signed certificate not chained to a \
                 public CA. Acceptable only for internal/pinned use.",
            )
            .rem(&["Use a CA-issued certificate for public endpoints."])
            .ev("target", target),
        );
    }
    issues
}

/// Build a synthetic Asn1Time from an epoch second count (for callers/tests).
pub fn asn1_from_epoch(secs: i64) -> Asn1Time {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, mo, d) = days_to_civil(days);
    Asn1Time { y, mo, d, h: rem / 3600, mi: (rem % 3600) / 60, s: rem % 60 }
}

fn days_to_civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::super::probe::parse_asn1_time;
    use super::*;

    #[test]
    fn analyze_tls10_is_high() {
        let a = analyze_versions(
            "h:443",
            &[(V10, true, Some(0xC013)), (V12, true, Some(0xC02F)), (V13, true, Some(0x1301))],
        );
        assert!(a.iter().any(|i| i.id == "TLS-PROTO-TLS10" && i.sev == Sev::High));
    }

    #[test]
    fn analyze_modern_ok() {
        let a = analyze_versions(
            "h:443",
            &[(V10, false, None), (V11, false, None), (V12, true, Some(0xC02F)), (V13, true, Some(0x1301))],
        );
        assert!(a.iter().any(|i| i.id == "TLS-PROTO-OK"));
        assert!(!a.iter().any(|i| i.id == "TLS-PROTO-TLS10"));
    }

    #[test]
    fn analyze_no_tls13() {
        let a = analyze_versions("h:443", &[(V12, true, Some(0xC02F)), (V13, false, None)]);
        assert!(a.iter().any(|i| i.id == "TLS-PROTO-NO-TLS13" && i.sev == Sev::Low));
    }

    #[test]
    fn analyze_weak_cipher() {
        let a = analyze_versions("h:443", &[(V12, true, Some(0x000A))]);
        assert!(a.iter().any(|i| i.id == "TLS-WEAK-CIPHER"));
    }

    #[test]
    fn analyze_cert_expired_and_ok() {
        let c = CertInfo {
            not_before: parse_asn1_time(0x17, b"200101000000Z").unwrap(),
            not_after: parse_asn1_time(0x17, b"210101000000Z").unwrap(),
            self_signed: false,
        };
        let now = parse_asn1_time(0x17, b"260101000000Z").unwrap().to_epoch_secs();
        assert!(analyze_cert("h:443", &c, now).iter().any(|i| i.id == "TLS-CERT-EXPIRED" && i.sev == Sev::Critical));
        let c2 = CertInfo {
            not_before: parse_asn1_time(0x17, b"260101000000Z").unwrap(),
            not_after: parse_asn1_time(0x18, b"20360101000000Z").unwrap(),
            self_signed: false,
        };
        assert!(analyze_cert("h:443", &c2, now).iter().any(|i| i.id == "TLS-CERT-OK"));
    }

    #[test]
    fn analyze_cert_expiring_soon() {
        let now = 1_700_000_000i64;
        let na = asn1_from_epoch(now + 10 * 86400);
        let c = CertInfo {
            not_before: parse_asn1_time(0x17, b"200101000000Z").unwrap(),
            not_after: na,
            self_signed: false,
        };
        assert!(analyze_cert("h:443", &c, now).iter().any(|i| i.id == "TLS-CERT-EXPIRING" && i.sev == Sev::High));
    }

    #[test]
    fn analyze_self_signed_flagged() {
        let c = CertInfo {
            not_before: parse_asn1_time(0x17, b"250101000000Z").unwrap(),
            not_after: parse_asn1_time(0x18, b"20360101000000Z").unwrap(),
            self_signed: true,
        };
        let now = parse_asn1_time(0x17, b"260101000000Z").unwrap().to_epoch_secs();
        assert!(analyze_cert("h:443", &c, now).iter().any(|i| i.id == "TLS-CERT-SELF-SIGNED"));
    }
}
