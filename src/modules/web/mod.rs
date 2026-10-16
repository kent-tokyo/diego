//! Explicit-target external web-server posture checks.
//!
//! The module sends one unauthenticated HTTP `HEAD` request to each URL passed
//! with `--web-target`. If `HEAD` is unsupported, it sends one `GET` request
//! with `Range: bytes=0-0` and never reads a response body. Redirects are not
//! followed. It does not crawl, discover paths, submit forms, authenticate,
//! brute-force, or send exploit payloads.

pub mod analyze;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, RANGE};
use reqwest::{Client, StatusCode, Url, redirect::Policy};

use crate::config::Config;
use crate::modules::DiagnosticModule;
use crate::report::{Confidence, Finding, Outcome, Severity};

use self::analyze::{Conf, Issue, Sev};

pub struct WebModule;

impl Default for WebModule {
    fn default() -> Self {
        Self::new()
    }
}

impl WebModule {
    pub fn new() -> Self {
        Self
    }
}

fn map_severity(severity: Sev) -> Severity {
    match severity {
        Sev::High => Severity::High,
        Sev::Medium => Severity::Medium,
        Sev::Low => Severity::Low,
        Sev::Info => Severity::Info,
    }
}

fn map_confidence(confidence: Conf) -> Confidence {
    match confidence {
        Conf::High => Confidence::High,
        Conf::Medium => Confidence::Medium,
    }
}

fn finding(issue: Issue) -> Finding {
    let outcome = if issue.id == "WEB-RESPONSE-INCONCLUSIVE" {
        Outcome::Inconclusive
    } else {
        Outcome::Confirmed
    };
    let evidence = serde_json::Value::Object(
        issue
            .evidence
            .into_iter()
            .map(|(key, value)| (key.to_string(), serde_json::Value::String(value)))
            .collect(),
    );
    Finding::new(
        issue.id,
        "web",
        map_severity(issue.sev),
        issue.title,
        issue.desc,
        evidence,
        None,
    )
    .with_confidence(map_confidence(issue.conf))
    .with_outcome(outcome)
    .with_remediation(issue.remediation.to_vec())
}

fn observed_header_names(headers: &HeaderMap) -> Vec<String> {
    const RELEVANT: [&str; 9] = [
        "location",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "set-cookie",
        "server",
        "x-powered-by",
    ];
    RELEVANT
        .iter()
        .filter(|name| headers.contains_key(**name))
        .map(|name| (*name).to_string())
        .collect()
}

fn add_probe_evidence(mut finding: Finding, requests: u8, headers: Option<&HeaderMap>) -> Finding {
    if let Some(evidence) = finding.evidence.as_object_mut() {
        evidence.insert("request_count".into(), serde_json::json!(requests));
        if let Some(headers) = headers {
            evidence.insert(
                "observed_header_names".into(),
                serde_json::json!(observed_header_names(headers)),
            );
        }
    }
    finding
}

fn response_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn validate_target(raw: &str) -> anyhow::Result<Url> {
    let url = Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("only http:// and https:// URLs are supported");
    }
    if url.host_str().is_none() {
        anyhow::bail!("URL must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("URLs with embedded credentials are not supported");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("URLs with query parameters or fragments are not supported");
    }
    Ok(url)
}

async fn request_headers(
    client: &Client,
    url: Url,
) -> (reqwest::Result<(StatusCode, HeaderMap)>, u8) {
    let response = match client.head(url.clone()).send().await {
        Ok(response) => response,
        Err(error) => return (Err(error), 1),
    };
    if matches!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_IMPLEMENTED
    ) {
        return (
            client
                .get(url)
                .header(RANGE, "bytes=0-0")
                .send()
                .await
                .map(|response| (response.status(), response.headers().clone())),
            2,
        );
    }
    (Ok((response.status(), response.headers().clone())), 1)
}

/// Run the bounded header checks for one explicitly named HTTP(S) URL.
///
/// This is shared by the CLI module and the localhost UI. It uses one HEAD
/// request (or one range-limited GET fallback), never follows redirects, and
/// does not retain response bodies, cookie values, or credentials.
pub async fn scan_target(raw: &str, timeout_secs: u64) -> Vec<Finding> {
    let url = match validate_target(raw) {
        Ok(url) => url,
        Err(error) => {
            let mut skipped = Finding::skipped("web", &format!("Target rejected: {error}"))
                .with_outcome(Outcome::Unavailable);
            skipped.evidence =
                serde_json::json!({"request_count": 0, "failure_reason": "invalid_target"});
            return vec![skipped];
        }
    };
    let client = match Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(timeout_secs.max(3)))
        .user_agent(concat!(
            "diego/",
            env!("CARGO_PKG_VERSION"),
            " read-only-posture-check"
        ))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            let mut skipped = Finding::skipped(
                "web",
                &format!("Could not initialise HTTP client ({error})"),
            )
            .with_outcome(Outcome::Unavailable);
            skipped.evidence =
                serde_json::json!({"request_count": 0, "failure_reason": "client_initialization"});
            return vec![skipped];
        }
    };
    let target = url.as_str().to_string();
    eprintln!("[+] web: checking {target}");
    let (result, requests) = request_headers(&client, url.clone()).await;
    match result {
        Ok((status, headers)) => {
            let parsed = response_headers(&headers);
            analyze::analyze(&target, url.scheme() == "https", status.as_u16(), &parsed)
                .into_iter()
                .map(|issue| add_probe_evidence(finding(issue), requests, Some(&headers)))
                .collect()
        }
        Err(error) => {
            let reason = if error.is_timeout() {
                "timeout"
            } else if error.is_connect() {
                "connection_failed"
            } else {
                "request_failed"
            };
            let mut skipped =
                Finding::skipped("web", &format!("{target}: request failed ({error})"))
                    .with_outcome(Outcome::Unavailable);
            skipped.evidence = serde_json::json!({
                "target": target, "request_count": requests, "failure_reason": reason,
            });
            vec![skipped]
        }
    }
}

#[async_trait]
impl DiagnosticModule for WebModule {
    fn name(&self) -> &'static str {
        "web"
    }

    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>> {
        if config.web_targets.is_empty() {
            return Ok(vec![Finding::skipped(
                "web",
                "No website URLs provided (use --web-target https://host.example/path)",
            )]);
        }
        let mut findings = Vec::new();
        for raw in &config.web_targets {
            findings.extend(scan_target(raw, config.timeout_secs).await);
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_web_and_credential_urls() {
        assert!(validate_target("ftp://example.test/").is_err());
        assert!(validate_target("https://user:pass@example.test/").is_err());
        assert!(validate_target("https://example.test/?token=secret").is_err());
        assert!(validate_target("https://example.test/path").is_ok());
    }

    #[tokio::test]
    async fn invalid_target_never_creates_a_network_request() {
        let findings = scan_target("ftp://example.test/", 3).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "WEB-SKIP");
    }
}
