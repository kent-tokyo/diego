//! Loopback fixtures exercise the transport boundary without external targets.
use diego::modules::{web, wordpress};
use diego::report::{Outcome, Report, ScanContext, markdown};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

async fn fixture(responses: Vec<String>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let Ok(Ok((mut stream, _))) =
                timeout(Duration::from_millis(500), listener.accept()).await
            else {
                break;
            };
            let mut buf = [0u8; 2048];
            let read = stream.read(&mut buf).await.unwrap();
            requests.push(String::from_utf8_lossy(&buf[..read]).into_owned());
            let _ = stream.write_all(response.as_bytes()).await;
        }
        requests
    });
    (format!("http://{address}/"), server)
}

fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn web_redirect_is_observed_once_without_following_it() {
    let (target, server) = fixture(vec![response(
        "302 Found",
        "Location: https://example.test/\r\n",
        "",
    )])
    .await;
    let findings = web::scan_target(&target, 3).await;
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("HEAD / HTTP/1.1"));
    assert_eq!(findings[0].id, "WEB-HTTP-REDIRECT-OK");
    assert_eq!(findings[0].outcome, Some(Outcome::Confirmed));
    assert_eq!(
        serde_json::to_value(&findings[0]).unwrap()["outcome"],
        "confirmed"
    );
    assert_eq!(findings[0].evidence["request_count"], 1);
    assert_eq!(
        findings[0].evidence["observed_header_names"],
        serde_json::json!(["location"])
    );
    let report = Report::new(
        ScanContext {
            dc_ip: String::new(),
            domain: String::new(),
            username: String::new(),
            privilege_level: "standard_user".into(),
            modules_run: vec!["web".into()],
            duration_secs: 0,
        },
        findings,
    );
    assert!(markdown::generate(&report).contains("**Outcome**: `confirmed`"));
}

#[tokio::test]
async fn web_head_fallback_uses_one_range_get_and_reports_both_requests() {
    let (target, server) = fixture(vec![
        response("405 Method Not Allowed", "", ""),
        response("206 Partial Content", "", "x"),
    ])
    .await;
    let findings = web::scan_target(&target, 3).await;
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("HEAD / HTTP/1.1"));
    assert!(requests[1].starts_with("GET / HTTP/1.1"));
    assert!(
        requests[1]
            .to_ascii_lowercase()
            .contains("range: bytes=0-0")
    );
    assert_eq!(findings[0].evidence["request_count"], 2);
}

#[tokio::test]
async fn web_malformed_reply_is_unavailable_with_reason() {
    let (target, server) = fixture(vec!["not an HTTP response\r\n".into()]).await;
    let findings = web::scan_target(&target, 3).await;
    assert_eq!(server.await.unwrap().len(), 1);
    assert_eq!(findings[0].outcome, Some(Outcome::Unavailable));
    assert_eq!(findings[0].evidence["request_count"], 1);
    assert_eq!(findings[0].evidence["failure_reason"], "request_failed");
}

#[tokio::test]
async fn web_timeout_is_reported_without_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let read = stream.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..read]).starts_with("HEAD / HTTP/1.1"));
        tokio::time::sleep(Duration::from_millis(3200)).await;
    });
    let findings = web::scan_target(&target, 3).await;
    server.await.unwrap();
    assert_eq!(findings[0].outcome, Some(Outcome::Unavailable));
    assert_eq!(findings[0].evidence["request_count"], 1);
    assert_eq!(findings[0].evidence["failure_reason"], "timeout");
}

#[tokio::test]
async fn wordpress_redirect_stops_at_root() {
    let (target, server) = fixture(vec![response("302 Found", "Location: /other/\r\n", "")]).await;
    let findings = wordpress::scan_site_root(&target, 3).await;
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET / HTTP/1.1"));
    assert_eq!(findings[0].id, "WP-ROOT-INCONCLUSIVE");
    assert_eq!(findings[0].outcome, Some(Outcome::Inconclusive));
    assert_eq!(findings[0].evidence["request_count"], 1);
}

#[tokio::test]
async fn wordpress_limits_body_prefix_and_does_not_call_405_exposure() {
    let oversized_body = format!(
        "{}<meta name=\"generator\" content=\"WordPress 9.9\">",
        "x".repeat(65_536)
    );
    let (target, server) = fixture(vec![
        response("200 OK", "Content-Type: text/html\r\n", &oversized_body),
        response("405 Method Not Allowed", "", ""),
        response("404 Not Found", "", ""),
        response("404 Not Found", "", ""),
    ])
    .await;
    let findings = wordpress::scan_site_root(&target, 3).await;
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 4);
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("range: bytes=0-65535")
    );
    assert!(requests[1].starts_with("HEAD /xmlrpc.php HTTP/1.1"));
    assert!(requests[2].starts_with("HEAD /wp-json/ HTTP/1.1"));
    assert!(requests[3].starts_with("HEAD /readme.html HTTP/1.1"));
    assert!(
        !findings
            .iter()
            .any(|finding| finding.id == "WP-VERSION-EXPOSED" || finding.id == "WP-XMLRPC-EXPOSED")
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.id == "WP-ENDPOINT-INCONCLUSIVE"
                && finding.outcome == Some(Outcome::Inconclusive))
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.evidence["request_count"] == 4)
    );
}

#[tokio::test]
async fn rejected_urls_never_echo_secrets_into_findings() {
    for findings in [
        web::scan_target("https://user:secret@example.test/", 3).await,
        wordpress::scan_site_root("https://example.test/?token=secret", 3).await,
    ] {
        let serialised = serde_json::to_string(&findings).unwrap();
        assert!(!serialised.contains("secret"));
        assert_eq!(findings[0].outcome, Some(Outcome::Unavailable));
        assert_eq!(findings[0].evidence["request_count"], 0);
    }
}
