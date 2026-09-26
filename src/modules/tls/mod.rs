//! TLS transport-hygiene module (Surface B).
//!
//! Read-only posture assessment of endpoints the operator explicitly names
//! (`--tls-target host[:port]`). For each target diego probes TLS 1.0/1.1/1.2/1.3
//! by sending one ClientHello per version and classifying the reply, then reads
//! certificate validity from the cleartext TLS 1.2 Certificate message. It never
//! scans port ranges, completes a handshake, sends application data, or attempts
//! exploits. Needs no credentials and no Domain Controller.

pub mod analyze;
pub mod probe;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::modules::DiagnosticModule;
use crate::report::{Confidence, Finding, Severity};

use self::analyze::{Conf, Issue, Sev};
use self::probe::{CertInfo, ServerResp, V10, V11, V12, V13};

pub struct TlsModule;

impl Default for TlsModule {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsModule {
    pub fn new() -> Self {
        TlsModule
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
    let mut f = Finding::new(
        issue.id,
        "tls",
        map_sev(issue.sev),
        issue.title,
        issue.desc,
        evidence,
        None,
    )
    .with_confidence(map_conf(issue.conf));
    if !issue.remediation.is_empty() {
        let steps: Vec<&str> = issue.remediation.iter().map(String::as_str).collect();
        f = f.with_remediation(steps);
    }
    f
}

/// Split "host" or "host:port" (default 443).
fn parse_target(t: &str) -> Option<(String, u16)> {
    let t = t.trim();
    if t.is_empty() {
        return None;
    }
    if let Some((h, p)) = t.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
        && !h.is_empty()
    {
        return Some((h.to_string(), port));
    }
    Some((t.to_string(), 443))
}

/// Probe one (version) against an already-resolved target. Returns the
/// classification and, for the TLS 1.2 probe, the leaf certificate if present.
async fn probe_one(
    host: &str,
    port: u16,
    legacy: u16,
    probe_13: bool,
    per_query: Duration,
) -> (ServerResp, Option<CertInfo>) {
    let hello = probe::client_hello(legacy, probe_13, host);
    let want_cert = !probe_13 && legacy == V12;
    let connect = tokio::time::timeout(per_query, TcpStream::connect((host, port))).await;
    let mut stream = match connect {
        Ok(Ok(s)) => s,
        _ => return (ServerResp::Incomplete, None),
    };
    if tokio::time::timeout(per_query, stream.write_all(&hello)).await.is_err() {
        return (ServerResp::Incomplete, None);
    }

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(per_query, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                // Enough to classify?
                let resp = probe::classify(&buf);
                if matches!(resp, ServerResp::Alert { .. }) {
                    break;
                }
                if matches!(resp, ServerResp::ServerHello { .. }) {
                    if !want_cert {
                        break;
                    }
                    // For the cert probe, stop once ServerHelloDone (14) is seen.
                    let (hs, _) = probe::collect_handshake(&buf);
                    let msgs = probe::parse_messages(&hs);
                    if msgs.iter().any(|(t, _)| *t == 14) {
                        break;
                    }
                }
                if buf.len() > 32768 {
                    break;
                }
            }
            _ => break,
        }
    }

    let resp = probe::classify(&buf);
    let cert = if want_cert && matches!(resp, ServerResp::ServerHello { .. }) {
        let (hs, _) = probe::collect_handshake(&buf);
        probe::parse_messages(&hs)
            .iter()
            .find(|(t, _)| *t == 11)
            .and_then(|(_, body)| probe::first_cert_der(body))
            .and_then(|der| probe::cert_info(&der))
    } else {
        None
    };
    (resp, cert)
}

#[async_trait]
impl DiagnosticModule for TlsModule {
    fn name(&self) -> &'static str {
        "tls"
    }

    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>> {
        if config.tls_targets.is_empty() {
            return Ok(vec![Finding::skipped(
                "tls",
                "No TLS targets provided (use --tls-target host[:port])",
            )]);
        }
        let per_query = Duration::from_secs(config.timeout_secs.max(5));
        let now_secs = chrono::Utc::now().timestamp();
        let mut findings = Vec::new();

        for raw_target in &config.tls_targets {
            let Some((host, port)) = parse_target(raw_target) else {
                continue;
            };
            let label = format!("{host}:{port}");
            eprintln!("[+] tls: probing {label}");

            let mut accepts: Vec<(u16, bool, Option<u16>)> = Vec::new();
            let mut cert: Option<CertInfo> = None;
            let mut any_response = false;

            for (legacy, p13) in [(V10, false), (V11, false), (V12, false), (V12, true)] {
                let (resp, c) = probe_one(&host, port, legacy, p13, per_query).await;
                let probed_version = if p13 { V13 } else { legacy };
                match resp {
                    ServerResp::ServerHello { negotiated, cipher } => {
                        any_response = true;
                        // Trust the negotiated version the server reports.
                        accepts.push((probed_version, negotiated == probed_version, Some(cipher)));
                        if c.is_some() {
                            cert = c;
                        }
                    }
                    ServerResp::Alert { .. } => {
                        any_response = true;
                        accepts.push((probed_version, false, None));
                    }
                    _ => {
                        accepts.push((probed_version, false, None));
                    }
                }
            }

            if !any_response {
                findings.push(Finding::skipped(
                    "tls",
                    &format!("{label}: no TLS response (unreachable, filtered, or not a TLS service)"),
                ));
                continue;
            }

            for issue in analyze::analyze_versions(&label, &accepts) {
                findings.push(issue_to_finding(issue));
            }
            if let Some(ci) = &cert {
                for issue in analyze::analyze_cert(&label, ci, now_secs) {
                    findings.push(issue_to_finding(issue));
                }
            } else {
                findings.push(Finding::skipped(
                    "tls-cert",
                    &format!("{label}: certificate not captured (no cleartext TLS 1.2 handshake)"),
                ));
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_defaults_and_explicit_port() {
        assert_eq!(parse_target("example.com"), Some(("example.com".into(), 443)));
        assert_eq!(parse_target("example.com:8443"), Some(("example.com".into(), 8443)));
        assert_eq!(parse_target("  mail.example.com:25 "), Some(("mail.example.com".into(), 25)));
        assert_eq!(parse_target(""), None);
    }
}
