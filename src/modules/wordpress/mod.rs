//! Low-impact WordPress posture checks for explicitly named, authorised sites.
//!
//! The module fetches a bounded public prefix of the supplied site root, then
//! sends safe HEAD requests to only three standard WordPress paths: `xmlrpc.php`,
//! `wp-json/`, and `readme.html`. It does not authenticate, enumerate users or
//! plugins, crawl, submit forms, guess paths, send POST requests, or test CVEs.

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

const MAX_BODY_BYTES: usize = 64 * 1024;
const STANDARD_PATHS: [&str; 3] = ["xmlrpc.php", "wp-json/", "readme.html"];

pub struct WordPressModule;

impl Default for WordPressModule {
    fn default() -> Self {
        Self::new()
    }
}

impl WordPressModule {
    pub fn new() -> Self {
        Self
    }
}

fn map_severity(severity: Sev) -> Severity {
    match severity {
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
    let outcome = match issue.id {
        "WP-ROOT-INCONCLUSIVE" | "WP-ENDPOINT-INCONCLUSIVE" | "WP-ROOT-CHECKED" => {
            Outcome::Inconclusive
        }
        _ => Outcome::Exposed,
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
        "wordpress",
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

fn add_probe_evidence(mut finding: Finding, requests: u8, headers: Option<&HeaderMap>) -> Finding {
    let evidence = finding.evidence.as_object_mut();
    if let Some(evidence) = evidence {
        evidence.insert("request_count".into(), serde_json::json!(requests));
        if let Some(headers) = headers {
            let names: Vec<&str> = ["x-pingback", "content-type", "location"]
                .into_iter()
                .filter(|name| headers.contains_key(*name))
                .collect();
            evidence.insert("observed_header_names".into(), serde_json::json!(names));
        }
    }
    finding
}

fn validate_site_root(raw: &str) -> anyhow::Result<Url> {
    let url = Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        anyhow::bail!("a complete http:// or https:// site URL is required");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("URLs with embedded credentials are not supported");
    }
    if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        anyhow::bail!("only a site root without query, fragment, or path is supported");
    }
    Ok(url)
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

async fn bounded_get(client: &Client, url: Url) -> anyhow::Result<(StatusCode, HeaderMap, String)> {
    let mut response = client
        .get(url)
        .header(RANGE, "bytes=0-65535")
        .send()
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    if !status.is_success() {
        return Ok((status, headers, String::new()));
    }
    let mut body = Vec::new();
    while body.len() < MAX_BODY_BYTES {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let remaining = MAX_BODY_BYTES - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    Ok((status, headers, String::from_utf8_lossy(&body).into_owned()))
}

/// Run the bounded public checks for one explicitly named WordPress site root.
///
/// This is shared by the CLI module and the localhost UI. It never follows
/// redirects, authenticates, crawls, sends POST requests, or retains a body.
pub async fn scan_site_root(raw: &str, timeout_secs: u64) -> Vec<Finding> {
    let base = match validate_site_root(raw) {
        Ok(url) => url,
        Err(error) => {
            let mut skipped = Finding::skipped("wordpress", &format!("Target rejected: {error}"))
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
            " wordpress-posture-check"
        ))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            let mut skipped = Finding::skipped(
                "wordpress",
                &format!("Could not initialise HTTP client ({error})"),
            )
            .with_outcome(Outcome::Unavailable);
            skipped.evidence =
                serde_json::json!({"request_count": 0, "failure_reason": "client_initialization"});
            return vec![skipped];
        }
    };
    let target = base.as_str().to_string();
    let mut findings = Vec::new();
    let mut request_count = 1u8;
    eprintln!("[+] wordpress: checking {target}");
    match bounded_get(&client, base.clone()).await {
        Ok((status, headers, body)) => {
            findings.extend(
                analyze::analyze_root(&target, status.as_u16(), &response_headers(&headers), &body)
                    .into_iter()
                    .map(|issue| add_probe_evidence(finding(issue), request_count, Some(&headers))),
            );
            if !status.is_success() {
                return findings;
            }
        }
        Err(error) => {
            let request_error = error.downcast_ref::<reqwest::Error>();
            let reason = if request_error.is_some_and(reqwest::Error::is_timeout) {
                "timeout"
            } else if request_error.is_some_and(reqwest::Error::is_connect) {
                "connection_failed"
            } else {
                "request_failed"
            };
            let mut skipped = Finding::skipped(
                "wordpress",
                &format!("{target}: root request failed ({error})"),
            )
            .with_outcome(Outcome::Unavailable);
            skipped.evidence = serde_json::json!({"target": target, "request_count": request_count, "failure_reason": reason});
            return vec![skipped];
        }
    }
    for path in STANDARD_PATHS {
        request_count += 1;
        let endpoint = base.join(path).expect("fixed relative path is valid");
        match client.head(endpoint).send().await {
            Ok(response) => {
                if let Some(issue) =
                    analyze::analyze_endpoint(&target, path, response.status().as_u16())
                {
                    findings.push(add_probe_evidence(finding(issue), request_count, None));
                }
            }
            Err(error) => {
                let reason = if error.is_timeout() {
                    "timeout"
                } else if error.is_connect() {
                    "connection_failed"
                } else {
                    "request_failed"
                };
                let mut skipped = Finding::skipped(
                    "wordpress",
                    &format!("{target}{path}: request failed ({error})"),
                )
                .with_outcome(Outcome::Unavailable);
                skipped.evidence = serde_json::json!({"target": target, "path": path,
                    "request_count": request_count, "failure_reason": reason});
                findings.push(skipped);
            }
        }
    }
    // The count is per target; repeat it on each finding for standalone JSON
    // consumers and Markdown readers.
    for finding in &mut findings {
        if let Some(evidence) = finding.evidence.as_object_mut() {
            evidence.insert("request_count".into(), serde_json::json!(request_count));
        }
    }
    findings
}

#[async_trait]
impl DiagnosticModule for WordPressModule {
    fn name(&self) -> &'static str {
        "wordpress"
    }

    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>> {
        if config.wordpress_targets.is_empty() {
            return Ok(vec![Finding::skipped(
                "wordpress",
                "No WordPress site roots provided (use --wordpress-target https://site.example/)",
            )]);
        }
        let mut findings = Vec::new();
        for raw in &config.wordpress_targets {
            findings.extend(scan_site_root(raw, config.timeout_secs).await);
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_allows_plain_site_roots() {
        assert!(validate_site_root("https://example.test/").is_ok());
        assert!(validate_site_root("https://example.test/blog/").is_err());
        assert!(validate_site_root("https://example.test/?token=secret").is_err());
        assert!(validate_site_root("ftp://example.test/").is_err());
    }
}
