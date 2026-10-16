//! Pure classification for the explicit-target WordPress posture module.
//!
//! Inputs are public response metadata gathered by `mod.rs`; this module makes
//! no network requests and never stores response bodies or cookie values.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sev {
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conf {
    High,
    Medium,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub id: &'static str,
    pub sev: Sev,
    pub conf: Conf,
    pub title: &'static str,
    pub desc: &'static str,
    pub remediation: &'static [&'static str],
    pub evidence: Vec<(&'static str, String)>,
}

impl Issue {
    fn new(
        id: &'static str,
        sev: Sev,
        conf: Conf,
        title: &'static str,
        desc: &'static str,
        remediation: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            sev,
            conf,
            title,
            desc,
            remediation,
            evidence: vec![],
        }
    }

    fn evidence(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.evidence.push((key, value.into()));
        self
    }
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case(name))
}

fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{name}=");
    let start = lower.find(&needle)? + needle.len();
    let value = tag.get(start..)?.trim_start();
    let quote = value.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let end = value.get(1..)?.find(quote)?;
    value.get(1..1 + end)
}

/// Extract a WordPress generator version from a bounded, public HTML prefix.
/// The version is used only as exposure evidence; this module does not map it
/// to CVEs or make a claim that it is vulnerable.
pub fn generator_version(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(relative_start) = lower.get(offset..)?.find("<meta") {
        let start = offset + relative_start;
        let end = start + lower.get(start..)?.find('>')? + 1;
        let tag = body.get(start..end)?;
        if attribute(tag, "name").is_some_and(|name| name.eq_ignore_ascii_case("generator"))
            && let Some(content) = attribute(tag, "content")
        {
            let version = content
                .trim()
                .strip_prefix("WordPress ")
                .or_else(|| content.trim().strip_prefix("wordpress "))?;
            let version: String = version
                .chars()
                .take_while(|ch| {
                    ch.is_ascii_digit() || matches!(ch, '.' | '-' | 'a'..='z' | 'A'..='Z')
                })
                .collect();
            if !version.is_empty() {
                return Some(version);
            }
        }
        offset = end;
    }
    None
}

pub fn analyze_root(
    target: &str,
    status: u16,
    headers: &[(String, String)],
    body_prefix: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    if let Some(version) = generator_version(body_prefix) {
        issues.push(
            Issue::new(
                "WP-VERSION-EXPOSED",
                Sev::Low,
                Conf::High,
                "WordPress version exposed in public markup",
                "The public response appears to expose a WordPress version. Exposure alone does not prove a vulnerability, but it can simplify version-specific reconnaissance.",
                &["Remove the generator meta tag or ensure the deployed WordPress core is promptly maintained."],
            )
            .evidence("target", target)
            .evidence("version", version),
        );
    }
    if has_header(headers, "x-pingback") {
        issues.push(
            Issue::new(
                "WP-PINGBACK-EXPOSED",
                Sev::Medium,
                Conf::Medium,
                "WordPress pingback endpoint advertised",
                "The response advertises an X-Pingback endpoint. Pingback can be abused for traffic amplification or internal request delivery when it is not needed.",
                &["Disable XML-RPC pingbacks if they are not required, or apply network-layer restrictions."],
            )
            .evidence("target", target),
        );
    }
    if issues.is_empty() {
        issues.push(
            Issue::new(
                "WP-ROOT-CHECKED",
                Sev::Info,
                Conf::High,
                "WordPress root response checked",
                "No WordPress version generator or X-Pingback header was observed in the bounded public response. This is not a complete application-security assessment.",
                &[],
            )
            .evidence("target", target)
            .evidence("status", status.to_string()),
        );
    }
    issues
}

pub fn analyze_endpoint(target: &str, path: &str, status: u16) -> Option<Issue> {
    match path {
        "xmlrpc.php" if status != 404 => Some(
            Issue::new(
                "WP-XMLRPC-EXPOSED",
                Sev::Medium,
                Conf::Medium,
                "WordPress XML-RPC endpoint appears reachable",
                "The standard xmlrpc.php endpoint did not return 404 to a safe HEAD request. This does not confirm that any XML-RPC method is enabled, but the endpoint should be reviewed when unused.",
                &["Disable XML-RPC when it is not needed, or restrict it at the reverse proxy/WAF."],
            )
            .evidence("target", target)
            .evidence("status", status.to_string()),
        ),
        "wp-json/" if (200..300).contains(&status) => Some(
            Issue::new(
                "WP-REST-API-PUBLIC",
                Sev::Info,
                Conf::High,
                "WordPress REST API index is publicly reachable",
                "The public REST API index responded successfully. Public availability is a WordPress default, not by itself a vulnerability; review exposed routes and authentication policy separately.",
                &[],
            )
            .evidence("target", target)
            .evidence("status", status.to_string()),
        ),
        "readme.html" if (200..300).contains(&status) => Some(
            Issue::new(
                "WP-README-EXPOSED",
                Sev::Low,
                Conf::High,
                "WordPress readme.html is publicly reachable",
                "The standard readme.html path responded successfully. It can disclose deployment information and is usually unnecessary in production.",
                &["Remove or deny public access to readme.html in production."],
            )
            .evidence("target", target)
            .evidence("status", status.to_string()),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_version_is_bounded_to_the_version_token() {
        assert_eq!(
            generator_version("<meta name=\"generator\" content=\"WordPress 6.7.1\">"),
            Some("6.7.1".into())
        );
        assert_eq!(generator_version("text mentioning WordPress 6.7.1"), None);
        assert_eq!(generator_version("no generator here"), None);
    }

    #[test]
    fn xmlrpc_non_404_is_a_review_finding() {
        let issue = analyze_endpoint("https://example.test/", "xmlrpc.php", 405).expect("issue");
        assert_eq!(issue.id, "WP-XMLRPC-EXPOSED");
        assert_eq!(issue.sev, Sev::Medium);
    }
}
