//! Pure HTTP response-header analysis for the explicit-target web module.
//!
//! No requests are made here. The transport layer supplies only a response
//! status and header names/values, so detection is deterministic and can be
//! tested without a network connection.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sev {
    High,
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

fn values<'a>(headers: &'a [(String, String)], name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    values(headers, name).next().is_some()
}

fn has_hsts_enforcement(headers: &[(String, String)]) -> bool {
    values(headers, "strict-transport-security").any(|value| {
        value.split(';').any(|directive| {
            let Some((name, age)) = directive.trim().split_once('=') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("max-age")
                && age
                    .trim()
                    .trim_matches('"')
                    .parse::<u64>()
                    .is_ok_and(|age| age > 0)
        })
    })
}

fn csp_has_directive(headers: &[(String, String)], wanted: &str) -> bool {
    values(headers, "content-security-policy").any(|policy| {
        policy.split(';').any(|directive| {
            directive
                .split_whitespace()
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
        })
    })
}

fn has_valid_x_frame_options(headers: &[(String, String)]) -> bool {
    values(headers, "x-frame-options").any(|value| {
        matches!(
            value.trim().to_ascii_uppercase().as_str(),
            "DENY" | "SAMEORIGIN"
        )
    })
}

fn cookie_has_attr(cookie: &str, attr: &str) -> bool {
    cookie
        .split(';')
        .skip(1)
        .any(|part| part.trim().eq_ignore_ascii_case(attr))
}

/// Analyse one response. `is_https` describes the supplied URL, not a redirect
/// destination: redirects are deliberately not followed by the web module.
pub fn analyze(
    target: &str,
    is_https: bool,
    status: u16,
    headers: &[(String, String)],
) -> Vec<Issue> {
    if !is_https {
        let redirects_to_https = (300..400).contains(&status)
            && values(headers, "location")
                .any(|location| location.trim().to_ascii_lowercase().starts_with("https://"));
        return if redirects_to_https {
            vec![Issue::new(
                "WEB-HTTP-REDIRECT-OK",
                Sev::Info,
                Conf::High,
                "HTTP redirects to HTTPS",
                "The explicitly requested HTTP URL redirected to an HTTPS URL. The redirect destination was not followed.",
                &[],
            )
            .evidence("target", target)
            .evidence("status", status.to_string())]
        } else if (200..300).contains(&status) {
            vec![Issue::new(
                "WEB-HTTPS-REDIRECT-MISSING",
                Sev::High,
                Conf::High,
                "HTTP endpoint does not redirect to HTTPS",
                "The explicitly requested HTTP URL did not return a redirect to HTTPS, so clients may use an unencrypted connection.",
                &["Redirect all HTTP requests to the equivalent HTTPS URL."],
            )
            .evidence("target", target)
            .evidence("status", status.to_string())]
        } else {
            vec![Issue::new(
                "WEB-RESPONSE-INCONCLUSIVE",
                Sev::Info,
                Conf::High,
                "HTTP response does not establish redirect policy",
                "The HTTP response was not a successful page or a direct HTTPS redirect. The destination was not followed.",
                &[],
            ).evidence("target", target).evidence("status", status.to_string())]
        };
    }

    if !(200..300).contains(&status) {
        return vec![Issue::new(
            "WEB-RESPONSE-INCONCLUSIVE",
            Sev::Info,
            Conf::High,
            "HTTPS response does not permit a header posture conclusion",
            "The explicitly requested HTTPS URL did not return a successful response. Redirects were not followed; their headers and error-page headers do not establish the destination's posture.",
            &[],
        )
        .evidence("target", target)
        .evidence("status", status.to_string())];
    }

    let mut issues = Vec::new();
    if !has_hsts_enforcement(headers) {
        issues.push(
            Issue::new(
                "WEB-HSTS-NON_ENFORCING",
                Sev::Medium,
                Conf::High,
                "HSTS enforcement missing or disabled",
                "The HTTPS response does not provide a positive Strict-Transport-Security max-age, so browsers are not instructed to prefer HTTPS for later visits.",
                &["Set Strict-Transport-Security with a suitable max-age after verifying HTTPS coverage."],
            )
            .evidence("target", target)
            .evidence("status", status.to_string()),
        );
    }
    let has_csp = values(headers, "content-security-policy").any(|value| !value.trim().is_empty());
    if !has_csp {
        issues.push(
            Issue::new(
                "WEB-CSP-MISSING",
                Sev::Medium,
                Conf::High,
                "Content-Security-Policy header missing",
                "The response does not define a Content-Security-Policy, reducing browser-side mitigation for content injection.",
                &["Deploy a tested Content-Security-Policy, starting with report-only mode where appropriate."],
            )
            .evidence("target", target),
        );
    }
    let has_frame_protection =
        has_valid_x_frame_options(headers) || csp_has_directive(headers, "frame-ancestors");
    if !has_frame_protection {
        issues.push(
            Issue::new(
                "WEB-FRAME-PROTECTION-MISSING",
                Sev::Medium,
                Conf::High,
                "Clickjacking protection header missing",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed in this response.",
                &["Set CSP frame-ancestors or X-Frame-Options according to the intended embedding policy."],
            )
            .evidence("target", target),
        );
    }
    let nosniff = values(headers, "x-content-type-options")
        .any(|value| value.trim().eq_ignore_ascii_case("nosniff"));
    if !nosniff {
        issues.push(
            Issue::new(
                "WEB-NOSNIFF-MISSING",
                Sev::Low,
                Conf::High,
                "X-Content-Type-Options: nosniff missing",
                "The response does not instruct browsers to disable MIME-type sniffing.",
                &["Set X-Content-Type-Options: nosniff on applicable responses."],
            )
            .evidence("target", target),
        );
    }
    if !has_header(headers, "referrer-policy") {
        issues.push(
            Issue::new(
                "WEB-REFERRER-POLICY-MISSING",
                Sev::Low,
                Conf::High,
                "Referrer-Policy header missing",
                "The response does not define a Referrer-Policy, so browser defaults determine how much URL information may be sent to other origins.",
                &["Set a Referrer-Policy appropriate for the application, such as strict-origin-when-cross-origin."],
            )
            .evidence("target", target),
        );
    }

    let cookies: Vec<&str> = values(headers, "set-cookie").collect();
    let missing_secure = cookies
        .iter()
        .filter(|cookie| !cookie_has_attr(cookie, "secure"))
        .count();
    if missing_secure > 0 {
        issues.push(
            Issue::new(
                "WEB-COOKIE-SECURE-MISSING",
                Sev::Medium,
                Conf::High,
                "HTTPS cookie missing Secure attribute",
                "One or more cookies set by this HTTPS response do not include the Secure attribute.",
                &["Set the Secure attribute on cookies that must not be sent over HTTP."],
            )
            .evidence("target", target)
            .evidence("cookie_count", missing_secure.to_string()),
        );
    }
    let missing_httponly = cookies
        .iter()
        .filter(|cookie| !cookie_has_attr(cookie, "httponly"))
        .count();
    if missing_httponly > 0 {
        issues.push(
            Issue::new(
                "WEB-COOKIE-HTTPONLY-MISSING",
                Sev::Low,
                Conf::High,
                "Cookie missing HttpOnly attribute",
                "One or more cookies set by this response do not include HttpOnly. The scanner records only the count, never cookie values.",
                &["Set HttpOnly on cookies that do not need JavaScript access."],
            )
            .evidence("target", target)
            .evidence("cookie_count", missing_httponly.to_string()),
        );
    }

    let disclosure_headers = ["server", "x-powered-by"];
    for name in disclosure_headers {
        if has_header(headers, name) {
            issues.push(
                Issue::new(
                    "WEB-SERVER-DISCLOSURE",
                    Sev::Low,
                    Conf::Medium,
                    "Server technology header exposed",
                    "The response includes a server technology header. This is usually low risk but can aid version-specific reconnaissance.",
                    &["Remove unnecessary Server and X-Powered-By response headers at the application or proxy layer."],
                )
                .evidence("target", target)
                .evidence("header", name),
            );
            break;
        }
    }

    if issues.is_empty() {
        issues.push(
            Issue::new(
                "WEB-HEADERS-OK",
                Sev::Info,
                Conf::High,
                "Checked security headers are present",
                "The checked HTTPS response included the configured baseline of security headers. This does not establish application-level security.",
                &[],
            )
            .evidence("target", target)
            .evidence("status", status.to_string()),
        );
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    #[test]
    fn http_without_https_redirect_is_high() {
        let issues = analyze("http://example.test/", false, 200, &[]);
        assert_eq!(issues[0].id, "WEB-HTTPS-REDIRECT-MISSING");
        assert_eq!(issues[0].sev, Sev::High);
    }

    #[test]
    fn https_header_baseline_has_no_negative_findings() {
        let issues = analyze(
            "https://example.test/",
            true,
            200,
            &headers(&[
                ("Strict-Transport-Security", "max-age=31536000"),
                (
                    "Content-Security-Policy",
                    "default-src 'self'; frame-ancestors 'none'",
                ),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ]),
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "WEB-HEADERS-OK");
    }

    #[test]
    fn error_responses_are_inconclusive_not_header_failures() {
        let issues = analyze("https://example.test/missing", true, 404, &[]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "WEB-RESPONSE-INCONCLUSIVE");
    }

    #[test]
    fn unfollowed_redirects_do_not_claim_destination_header_posture() {
        let https = analyze("https://example.test/", true, 302, &[]);
        assert_eq!(https.len(), 1);
        assert_eq!(https[0].id, "WEB-RESPONSE-INCONCLUSIVE");

        let http = analyze(
            "http://example.test/",
            false,
            302,
            &headers(&[("Location", "/elsewhere")]),
        );
        assert_eq!(http.len(), 1);
        assert_eq!(http[0].id, "WEB-RESPONSE-INCONCLUSIVE");
    }

    #[test]
    fn hsts_requires_a_positive_max_age() {
        let issues = analyze(
            "https://example.test/",
            true,
            200,
            &headers(&[("Strict-Transport-Security", "max-age=0")]),
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.id == "WEB-HSTS-NON_ENFORCING")
        );
    }

    #[test]
    fn framing_protection_requires_a_real_directive_or_valid_xfo() {
        let issues = analyze(
            "https://example.test/",
            true,
            200,
            &headers(&[
                (
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'frame-ancestors'",
                ),
                ("X-Frame-Options", "allow-everything"),
            ]),
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.id == "WEB-FRAME-PROTECTION-MISSING")
        );
    }

    #[test]
    fn cookie_values_are_not_retained() {
        let issues = analyze(
            "https://example.test/",
            true,
            200,
            &headers(&[("Set-Cookie", "session=secret-value; Path=/")]),
        );
        let cookie_issue = issues
            .iter()
            .find(|issue| issue.id == "WEB-COOKIE-SECURE-MISSING")
            .expect("cookie issue");
        assert_eq!(
            cookie_issue.evidence,
            vec![
                ("target", "https://example.test/".into()),
                ("cookie_count", "1".into())
            ]
        );
    }

    #[test]
    fn cookie_attributes_allow_optional_whitespace() {
        assert!(cookie_has_attr("session=value;Secure; HttpOnly", "secure"));
        assert!(cookie_has_attr(
            "session=value;Secure; HttpOnly",
            "httponly"
        ));
    }
}
