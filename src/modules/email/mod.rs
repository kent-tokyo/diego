//! Email & domain authentication hygiene module (Surface A).
//!
//! Fully passive, read-only posture assessment over **public DNS only**: SPF,
//! DMARC, DKIM (common selectors), MTA-STS, TLS-RPT, CAA, and a bounded DNSSEC
//! check. It queries the operator's own recursive resolver, needs no
//! credentials and no privilege, and never connects to the target's mail hosts
//! (MTA-STS policy-file fetch is intentionally out of scope for this tier).

pub mod analyze;
pub mod dns;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::Config;
use crate::modules::DiagnosticModule;
use crate::report::{Confidence, Finding, Severity};

use self::analyze::{Conf, Issue, Sev};

/// Selectors probed when the operator does not supply their own. DKIM selectors
/// are not enumerable from DNS, so a miss is inconclusive (reported LOW/Low).
const DEFAULT_DKIM_SELECTORS: &[&str] = &[
    "default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2", "smtp",
];

pub struct EmailModule;

impl Default for EmailModule {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailModule {
    pub fn new() -> Self {
        EmailModule
    }
}

fn map_sev(s: Sev) -> Severity {
    match s {
        Sev::Critical => Severity::Critical,
        Sev::High => Severity::High,
        Sev::Medium => Severity::Medium,
        Sev::Low => Severity::Low,
        Sev::Info => Severity::Info,
    }
}

fn map_conf(c: Conf) -> Confidence {
    match c {
        Conf::High => Confidence::High,
        Conf::Medium => Confidence::Medium,
        Conf::Low => Confidence::Low,
    }
}

fn issue_to_finding(issue: Issue) -> Finding {
    let evidence = if issue.evidence.is_empty() {
        serde_json::Value::Null
    } else {
        let map: serde_json::Map<String, serde_json::Value> = issue
            .evidence
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        serde_json::Value::Object(map)
    };
    let mut finding = Finding::new(
        issue.id,
        "email",
        map_sev(issue.sev),
        issue.title,
        issue.desc,
        evidence,
        None,
    )
    .with_confidence(map_conf(issue.conf));
    if !issue.remediation.is_empty() {
        let steps: Vec<&str> = issue.remediation.iter().map(String::as_str).collect();
        finding = finding.with_remediation(steps);
    }
    if let Some(m) = issue.mitre {
        finding = finding.with_mitre(m);
    }
    finding
}

/// Resolve the recursive resolver to query: explicit config, else the system
/// resolver from /etc/resolv.conf, else a public fallback (1.1.1.1).
fn resolve_resolver(config: &Config) -> SocketAddr {
    if let Some(spec) = &config.dns_resolver {
        if let Ok(addr) = spec.parse::<SocketAddr>() {
            return addr;
        }
        if let Ok(ip) = spec.parse::<IpAddr>() {
            return SocketAddr::new(ip, 53);
        }
    }
    if let Some(ip) = dns::system_resolver() {
        return SocketAddr::new(ip, 53);
    }
    SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53)
}

#[async_trait]
impl DiagnosticModule for EmailModule {
    fn name(&self) -> &'static str {
        "email"
    }

    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>> {
        let domain = config.domain.trim_end_matches('.').to_string();
        if domain.is_empty() {
            return Ok(vec![Finding::skipped("email", "No target domain provided")]);
        }
        let resolver = resolve_resolver(&config);
        let per_query = Duration::from_secs(config.timeout_secs.max(3));
        eprintln!("[+] email: querying {} via resolver {}", domain, resolver);

        let mut findings = Vec::new();

        // ── SPF (apex TXT) ────────────────────────────────────────────────
        match dns::query(resolver, &domain, dns::T_TXT, false, per_query).await {
            Ok(resp) => {
                for issue in analyze::analyze_spf(&resp.txt_strings()) {
                    findings.push(issue_to_finding(issue));
                }
            }
            Err(e) => findings.push(Finding::skipped("email-spf", &format!("SPF TXT lookup failed: {e}"))),
        }

        // ── DMARC (_dmarc TXT) ────────────────────────────────────────────
        let dmarc_name = format!("_dmarc.{domain}");
        match dns::query(resolver, &dmarc_name, dns::T_TXT, false, per_query).await {
            Ok(resp) => {
                let dmarc = resp
                    .txt_strings()
                    .into_iter()
                    .find(|t| t.to_ascii_lowercase().starts_with("v=dmarc1"));
                for issue in analyze::analyze_dmarc(dmarc.as_deref()) {
                    findings.push(issue_to_finding(issue));
                }
            }
            Err(e) => findings.push(Finding::skipped("email-dmarc", &format!("DMARC lookup failed: {e}"))),
        }

        // ── DKIM (common selectors) ───────────────────────────────────────
        let selectors: Vec<String> = if config.dkim_selectors.is_empty() {
            DEFAULT_DKIM_SELECTORS.iter().map(|s| s.to_string()).collect()
        } else {
            config.dkim_selectors.clone()
        };
        let mut dkim_results: Vec<(String, Option<String>)> = Vec::new();
        for sel in &selectors {
            let name = format!("{sel}._domainkey.{domain}");
            match dns::query(resolver, &name, dns::T_TXT, false, per_query).await {
                Ok(resp) => {
                    let key = resp
                        .txt_strings()
                        .into_iter()
                        .find(|t| t.to_ascii_lowercase().contains("v=dkim1"));
                    dkim_results.push((sel.clone(), key));
                }
                Err(_) => dkim_results.push((sel.clone(), None)),
            }
        }
        for issue in analyze::analyze_dkim(&dkim_results) {
            findings.push(issue_to_finding(issue));
        }

        // ── MTA-STS (_mta-sts TXT) ────────────────────────────────────────
        let mtasts_name = format!("_mta-sts.{domain}");
        match dns::query(resolver, &mtasts_name, dns::T_TXT, false, per_query).await {
            Ok(resp) => {
                let rec = resp
                    .txt_strings()
                    .into_iter()
                    .find(|t| t.to_ascii_lowercase().contains("v=stsv1"));
                for issue in analyze::analyze_mta_sts(rec.as_deref()) {
                    findings.push(issue_to_finding(issue));
                }
            }
            Err(e) => findings.push(Finding::skipped("email-mtasts", &format!("MTA-STS lookup failed: {e}"))),
        }

        // ── TLS-RPT (_smtp._tls TXT) ──────────────────────────────────────
        let tlsrpt_name = format!("_smtp._tls.{domain}");
        match dns::query(resolver, &tlsrpt_name, dns::T_TXT, false, per_query).await {
            Ok(resp) => {
                let rec = resp
                    .txt_strings()
                    .into_iter()
                    .find(|t| t.to_ascii_lowercase().contains("v=tlsrptv1"));
                for issue in analyze::analyze_tlsrpt(rec.as_deref()) {
                    findings.push(issue_to_finding(issue));
                }
            }
            Err(e) => findings.push(Finding::skipped("email-tlsrpt", &format!("TLS-RPT lookup failed: {e}"))),
        }

        // ── CAA (apex) ────────────────────────────────────────────────────
        match dns::query(resolver, &domain, dns::T_CAA, false, per_query).await {
            Ok(resp) => {
                let caa: Vec<(u8, String, String)> = resp
                    .answers
                    .iter()
                    .filter_map(|r| match &r.data {
                        dns::RData::Caa { flags, tag, value } => {
                            Some((*flags, tag.clone(), value.clone()))
                        }
                        _ => None,
                    })
                    .collect();
                for issue in analyze::analyze_caa(&caa) {
                    findings.push(issue_to_finding(issue));
                }
            }
            Err(e) => findings.push(Finding::skipped("email-caa", &format!("CAA lookup failed: {e}"))),
        }

        // ── DNSSEC (bounded: DS presence + resolver AD flag) ──────────────
        match dns::query(resolver, &domain, dns::T_DS, true, per_query).await {
            Ok(resp) => {
                let ds_present = resp.has_type(dns::T_DS);
                for issue in analyze::analyze_dnssec(ds_present, resp.ad) {
                    findings.push(issue_to_finding(issue));
                }
            }
            Err(e) => findings.push(Finding::skipped("email-dnssec", &format!("DNSSEC lookup failed: {e}"))),
        }

        Ok(findings)
    }
}
