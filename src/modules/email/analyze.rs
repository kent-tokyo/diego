//! Email & domain authentication hygiene analysis.
//!
//! Pure functions: DNS records in, prioritised `Issue`s out. No network, no
//! secrets (every input is a public DNS record), fully deterministic — unit
//! tested below. `mod.rs` maps `Issue` onto the shared `report::Finding` type.

/// Local severity, mapped to `report::Severity` in `mod.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sev {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Local confidence, mapped to `report::Confidence` in `mod.rs`.
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
    pub mitre: Option<String>,
    pub evidence: Vec<(String, String)>,
}

impl Issue {
    fn new(id: &str, sev: Sev, conf: Conf, title: &str, desc: &str) -> Self {
        Issue {
            id: id.into(),
            sev,
            conf,
            title: title.into(),
            desc: desc.into(),
            remediation: Vec::new(),
            mitre: None,
            evidence: Vec::new(),
        }
    }
    fn rem(mut self, steps: &[&str]) -> Self {
        self.remediation = steps.iter().map(|s| s.to_string()).collect();
        self
    }
    fn mitre(mut self, id: &str) -> Self {
        self.mitre = Some(id.into());
        self
    }
    fn ev(mut self, k: &str, v: &str) -> Self {
        self.evidence.push((k.into(), v.into()));
        self
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SpfAll {
    Fail,     // -all
    SoftFail, // ~all
    Neutral,  // ?all
    Pass,     // +all / all
    None,     // no all mechanism
}

fn spf_all_qualifier(record: &str) -> SpfAll {
    let mut result = SpfAll::None;
    for tok in record.split_whitespace() {
        match tok.to_ascii_lowercase().as_str() {
            "-all" => result = SpfAll::Fail,
            "~all" => result = SpfAll::SoftFail,
            "?all" => result = SpfAll::Neutral,
            "+all" | "all" => result = SpfAll::Pass,
            _ => {}
        }
    }
    result
}

/// Count mechanisms that trigger a DNS lookup (RFC 7208 §4.6.4 caps this at 10).
fn spf_lookup_count(record: &str) -> usize {
    record
        .split_whitespace()
        .filter(|tok| {
            let t = tok.trim_start_matches(['+', '-', '~', '?']).to_ascii_lowercase();
            t.starts_with("include:")
                || t.starts_with("a:")
                || t == "a"
                || t.starts_with("mx")
                || t.starts_with("ptr")
                || t.starts_with("exists:")
                || t.starts_with("redirect=")
        })
        .count()
}

pub fn analyze_spf(apex_txts: &[String]) -> Vec<Issue> {
    let spf: Vec<&String> = apex_txts
        .iter()
        .filter(|t| t.to_ascii_lowercase().starts_with("v=spf1"))
        .collect();
    let mut issues = Vec::new();
    if spf.is_empty() {
        issues.push(
            Issue::new(
                "EMAIL-SPF-MISSING",
                Sev::High,
                Conf::High,
                "No SPF record published",
                "The domain publishes no SPF (v=spf1) TXT record. Receivers cannot tell which \
                 hosts are authorised to send mail as this domain, easing spoofing.",
            )
            .rem(&["Publish a v=spf1 TXT record enumerating authorised senders, ending in -all."])
            .mitre("T1566"),
        );
        return issues;
    }
    if spf.len() > 1 {
        issues.push(
            Issue::new(
                "EMAIL-SPF-MULTIPLE",
                Sev::Medium,
                Conf::High,
                "Multiple SPF records published",
                "More than one v=spf1 record exists. RFC 7208 requires exactly one; multiple \
                 records cause a PermError and SPF is treated as unusable by many receivers.",
            )
            .rem(&["Merge all authorised senders into a single v=spf1 TXT record."])
            .ev("count", &spf.len().to_string()),
        );
    }
    let record = spf[0];
    match spf_all_qualifier(record) {
        SpfAll::Pass => issues.push(
            Issue::new(
                "EMAIL-SPF-PLUSALL",
                Sev::Critical,
                Conf::High,
                "SPF authorises all senders (+all)",
                "The SPF record ends in +all (or a bare all), authorising every host on the \
                 internet to send as this domain. This is effectively no protection at all.",
            )
            .rem(&["Replace +all with -all and list only legitimate senders."])
            .mitre("T1566")
            .ev("record", record),
        ),
        SpfAll::Neutral => issues.push(
            Issue::new(
                "EMAIL-SPF-NEUTRAL",
                Sev::Medium,
                Conf::High,
                "SPF uses a neutral (?all) policy",
                "?all tells receivers to treat unlisted senders as neutral, providing no \
                 meaningful protection against spoofing.",
            )
            .rem(&["Change ?all to -all once authorised senders are confirmed."])
            .ev("record", record),
        ),
        SpfAll::SoftFail => issues.push(
            Issue::new(
                "EMAIL-SPF-SOFTFAIL",
                Sev::Low,
                Conf::High,
                "SPF uses softfail (~all)",
                "~all asks receivers to accept-but-mark unlisted senders. Acceptable alongside \
                 an enforcing DMARC policy, but -all is stronger.",
            )
            .rem(&["Move to -all when confident the sender list is complete."])
            .ev("record", record),
        ),
        SpfAll::None => issues.push(
            Issue::new(
                "EMAIL-SPF-NOALL",
                Sev::Medium,
                Conf::High,
                "SPF record has no all mechanism",
                "Without a trailing all mechanism the default is neutral, so unlisted senders \
                 are not rejected.",
            )
            .rem(&["Append -all to the SPF record."])
            .ev("record", record),
        ),
        SpfAll::Fail => issues.push(
            Issue::new(
                "EMAIL-SPF-OK",
                Sev::Info,
                Conf::High,
                "SPF publishes an enforcing (-all) policy",
                "The SPF record ends in -all, instructing receivers to reject unlisted senders.",
            )
            .ev("record", record),
        ),
    }
    let lookups = spf_lookup_count(record);
    if lookups > 10 {
        issues.push(
            Issue::new(
                "EMAIL-SPF-LOOKUPS",
                Sev::Medium,
                Conf::High,
                "SPF exceeds the 10 DNS-lookup limit",
                "The record requires more than 10 DNS lookups to evaluate. RFC 7208 caps this \
                 at 10; exceeding it yields a PermError and SPF stops being enforced.",
            )
            .rem(&["Flatten includes or reduce lookup-causing mechanisms to 10 or fewer."])
            .ev("lookups", &lookups.to_string()),
        );
    }
    issues
}

fn dmarc_tag(record: &str, key: &str) -> Option<String> {
    for part in record.split(';') {
        if let Some((k, v)) = part.trim().split_once('=')
            && k.trim().eq_ignore_ascii_case(key)
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

pub fn analyze_dmarc(dmarc_txt: Option<&str>) -> Vec<Issue> {
    let mut issues = Vec::new();
    let Some(record) = dmarc_txt else {
        issues.push(
            Issue::new(
                "EMAIL-DMARC-MISSING",
                Sev::High,
                Conf::High,
                "No DMARC record published",
                "No _dmarc TXT record exists. Without DMARC, receivers have no domain-owner \
                 policy for messages that fail SPF/DKIM, and the owner gets no abuse visibility.",
            )
            .rem(&[
                "Publish a _dmarc TXT record starting with v=DMARC1; begin at p=none with rua \
                 reporting, then raise to quarantine and reject.",
            ])
            .mitre("T1566"),
        );
        return issues;
    };
    match dmarc_tag(record, "p").as_deref() {
        Some("reject") => issues.push(
            Issue::new(
                "EMAIL-DMARC-OK",
                Sev::Info,
                Conf::High,
                "DMARC enforces p=reject",
                "The domain publishes an enforcing DMARC policy.",
            )
            .ev("record", record),
        ),
        Some("quarantine") => issues.push(
            Issue::new(
                "EMAIL-DMARC-QUARANTINE",
                Sev::Low,
                Conf::High,
                "DMARC set to p=quarantine",
                "Failing mail is quarantined rather than rejected. Reject is the stronger \
                 end-state once reporting confirms no legitimate mail is affected.",
            )
            .rem(&["Move to p=reject after validating aggregate reports."])
            .ev("record", record),
        ),
        Some("none") => issues.push(
            Issue::new(
                "EMAIL-DMARC-POLICY-NONE",
                Sev::Medium,
                Conf::High,
                "DMARC in monitor-only mode (p=none)",
                "p=none only monitors; it does not tell receivers to act on failing mail, so \
                 spoofed messages are still delivered.",
            )
            .rem(&["Progress to p=quarantine then p=reject once reports look clean."])
            .mitre("T1566")
            .ev("record", record),
        ),
        _ => issues.push(
            Issue::new(
                "EMAIL-DMARC-MALFORMED",
                Sev::Medium,
                Conf::Medium,
                "DMARC record missing a valid policy tag",
                "A _dmarc record exists but has no recognisable p= policy, so receiver \
                 behaviour is undefined.",
            )
            .rem(&["Add an explicit p= tag (none/quarantine/reject)."])
            .ev("record", record),
        ),
    }
    if dmarc_tag(record, "rua").is_none() && dmarc_tag(record, "ruf").is_none() {
        issues.push(
            Issue::new(
                "EMAIL-DMARC-NO-RUA",
                Sev::Low,
                Conf::High,
                "DMARC has no reporting address",
                "No rua/ruf tag means the domain owner receives no aggregate/forensic reports \
                 and is blind to spoofing attempts and misconfigured senders.",
            )
            .rem(&["Add rua=mailto: (and optionally ruf=) to receive DMARC reports."])
            .ev("record", record),
        );
    }
    issues
}

pub fn analyze_dkim(results: &[(String, Option<String>)]) -> Vec<Issue> {
    let found: Vec<&String> = results
        .iter()
        .filter(|(_, v)| {
            v.as_deref()
                .map(|s| s.to_ascii_lowercase().contains("v=dkim1"))
                .unwrap_or(false)
        })
        .map(|(sel, _)| sel)
        .collect();
    if !found.is_empty() {
        let list = found.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
        return vec![Issue::new(
            "EMAIL-DKIM-FOUND",
            Sev::Info,
            Conf::High,
            "DKIM selector(s) published",
            "At least one DKIM key was found for the probed selectors.",
        )
        .ev("selectors", &list)];
    }
    vec![Issue::new(
        "EMAIL-DKIM-NONE-FOUND",
        Sev::Low,
        Conf::Low,
        "No DKIM key found for common selectors",
        "None of the commonly used selectors returned a DKIM key. DKIM selectors are not \
         enumerable from DNS, so this is inconclusive — the domain may use a custom selector. \
         Confirm with the mail provider.",
    )
    .rem(&["Verify the DKIM selector with your mail provider and confirm a v=DKIM1 key is published."])]
}

pub fn analyze_mta_sts(txt: Option<&str>) -> Vec<Issue> {
    match txt {
        Some(r) if r.to_ascii_lowercase().contains("v=stsv1") => vec![Issue::new(
            "EMAIL-MTASTS-OK",
            Sev::Info,
            Conf::High,
            "MTA-STS record present",
            "An _mta-sts TXT record is published, signalling SMTP TLS enforcement support. \
             Full policy validation requires fetching the policy file, which is out of scope \
             for the passive DNS tier.",
        )
        .ev("record", r)],
        _ => vec![Issue::new(
            "EMAIL-MTASTS-MISSING",
            Sev::Low,
            Conf::High,
            "No MTA-STS record",
            "No _mta-sts TXT record. Inbound SMTP is more exposed to downgrade/interception \
             because senders cannot discover a TLS-enforcement policy.",
        )
        .rem(&["Publish an _mta-sts TXT record and host a policy on the mta-sts. host."])],
    }
}

pub fn analyze_tlsrpt(txt: Option<&str>) -> Vec<Issue> {
    match txt {
        Some(r) if r.to_ascii_lowercase().contains("v=tlsrptv1") => vec![Issue::new(
            "EMAIL-TLSRPT-OK",
            Sev::Info,
            Conf::High,
            "SMTP TLS reporting enabled",
            "A _smtp._tls TXT record is published for TLS-RPT reporting.",
        )
        .ev("record", r)],
        _ => vec![Issue::new(
            "EMAIL-TLSRPT-MISSING",
            Sev::Low,
            Conf::High,
            "No SMTP TLS reporting (TLS-RPT)",
            "No _smtp._tls record, so the domain receives no reports about inbound SMTP TLS \
             failures.",
        )
        .rem(&["Publish a _smtp._tls TXT record with v=TLSRPTv1 and an rua endpoint."])],
    }
}

pub fn analyze_caa(records: &[(u8, String, String)]) -> Vec<Issue> {
    if records.is_empty() {
        return vec![Issue::new(
            "EMAIL-CAA-MISSING",
            Sev::Low,
            Conf::High,
            "No CAA records",
            "The domain publishes no CAA records, so any certificate authority may issue \
             certificates for it. CAA limits issuance to named CAs.",
        )
        .rem(&["Publish CAA records naming only your authorised certificate authorities."])];
    }
    let issuers = records
        .iter()
        .filter(|(_, tag, _)| tag.eq_ignore_ascii_case("issue") || tag.eq_ignore_ascii_case("issuewild"))
        .map(|(_, _, v)| v.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    vec![Issue::new(
        "EMAIL-CAA-OK",
        Sev::Info,
        Conf::High,
        "CAA records present",
        "CAA records restrict which certificate authorities may issue for this domain.",
    )
    .ev("issuers", &issuers)]
}

pub fn analyze_dnssec(ds_present: bool, ad_flag: bool) -> Vec<Issue> {
    if ds_present || ad_flag {
        vec![Issue::new(
            "EMAIL-DNSSEC-OK",
            Sev::Info,
            Conf::Medium,
            "DNSSEC appears to be enabled",
            "A DS record and/or the resolver's Authenticated Data flag indicates the zone is \
             DNSSEC-signed. diego performs a bounded check, not full chain validation.",
        )]
    } else {
        vec![Issue::new(
            "EMAIL-DNSSEC-MISSING",
            Sev::Medium,
            Conf::Medium,
            "DNSSEC not detected",
            "No DS record and no Authenticated Data flag were observed, suggesting the zone is \
             unsigned and its DNS answers (including SPF/DMARC/MX) can be tampered with in \
             transit. This is a bounded heuristic, not full validation.",
        )
        .rem(&["Sign the zone with DNSSEC and publish a DS record at the parent."])]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_missing_is_high() {
        let issues = analyze_spf(&[]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "EMAIL-SPF-MISSING");
        assert_eq!(issues[0].sev, Sev::High);
    }

    #[test]
    fn spf_plus_all_is_critical() {
        let issues = analyze_spf(&["v=spf1 include:_spf.example.com +all".into()]);
        assert!(issues.iter().any(|i| i.id == "EMAIL-SPF-PLUSALL" && i.sev == Sev::Critical));
    }

    #[test]
    fn spf_bare_all_is_critical() {
        assert!(analyze_spf(&["v=spf1 all".into()]).iter().any(|i| i.id == "EMAIL-SPF-PLUSALL"));
    }

    #[test]
    fn spf_dash_all_is_info() {
        assert!(analyze_spf(&["v=spf1 mx -all".into()])
            .iter()
            .any(|i| i.id == "EMAIL-SPF-OK" && i.sev == Sev::Info));
    }

    #[test]
    fn spf_softfail_is_low() {
        assert!(analyze_spf(&["v=spf1 mx ~all".into()])
            .iter()
            .any(|i| i.id == "EMAIL-SPF-SOFTFAIL" && i.sev == Sev::Low));
    }

    #[test]
    fn spf_multiple_records_flagged() {
        assert!(analyze_spf(&["v=spf1 -all".into(), "v=spf1 ~all".into()])
            .iter()
            .any(|i| i.id == "EMAIL-SPF-MULTIPLE"));
    }

    #[test]
    fn spf_too_many_lookups() {
        let rec = "v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j include:k -all";
        assert!(analyze_spf(&[rec.into()]).iter().any(|i| i.id == "EMAIL-SPF-LOOKUPS"));
    }

    #[test]
    fn spf_lookup_count_under_limit() {
        assert_eq!(spf_lookup_count("v=spf1 mx include:_spf.google.com -all"), 2);
    }

    #[test]
    fn dmarc_missing_is_high() {
        assert!(analyze_dmarc(None).iter().any(|i| i.id == "EMAIL-DMARC-MISSING" && i.sev == Sev::High));
    }

    #[test]
    fn dmarc_p_none_and_reject() {
        let none = analyze_dmarc(Some("v=DMARC1; p=none; rua=mailto:d@example.com"));
        assert!(none.iter().any(|i| i.id == "EMAIL-DMARC-POLICY-NONE"));
        assert!(!none.iter().any(|i| i.id == "EMAIL-DMARC-NO-RUA"));
        let rej = analyze_dmarc(Some("v=DMARC1; p=reject; rua=mailto:d@example.com"));
        assert!(rej.iter().any(|i| i.id == "EMAIL-DMARC-OK" && i.sev == Sev::Info));
    }

    #[test]
    fn dmarc_no_rua_flagged() {
        assert!(analyze_dmarc(Some("v=DMARC1; p=reject")).iter().any(|i| i.id == "EMAIL-DMARC-NO-RUA"));
    }

    #[test]
    fn dkim_found_and_none() {
        assert!(analyze_dkim(&[("default".into(), Some("v=DKIM1; k=rsa; p=MIGf".into()))])
            .iter()
            .any(|i| i.id == "EMAIL-DKIM-FOUND"));
        assert!(analyze_dkim(&[("default".into(), None), ("google".into(), None)])
            .iter()
            .any(|i| i.id == "EMAIL-DKIM-NONE-FOUND" && i.conf == Conf::Low));
    }

    #[test]
    fn mtasts_present_absent() {
        assert!(analyze_mta_sts(Some("v=STSv1; id=2026")).iter().any(|i| i.id == "EMAIL-MTASTS-OK"));
        assert!(analyze_mta_sts(None).iter().any(|i| i.id == "EMAIL-MTASTS-MISSING"));
    }

    #[test]
    fn caa_present_absent() {
        assert!(analyze_caa(&[]).iter().any(|i| i.id == "EMAIL-CAA-MISSING"));
        assert!(analyze_caa(&[(0, "issue".into(), "letsencrypt.org".into())])
            .iter()
            .any(|i| i.id == "EMAIL-CAA-OK"));
    }

    #[test]
    fn dnssec_detected_and_missing() {
        assert!(analyze_dnssec(true, false).iter().any(|i| i.id == "EMAIL-DNSSEC-OK"));
        assert!(analyze_dnssec(false, true).iter().any(|i| i.id == "EMAIL-DNSSEC-OK"));
        assert!(analyze_dnssec(false, false).iter().any(|i| i.id == "EMAIL-DNSSEC-MISSING"));
    }
}
