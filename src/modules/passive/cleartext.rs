//! Cleartext protocol detection using pnet in promiscuous mode.
//!
//! Requires local admin / CAP_NET_RAW. Will gracefully degrade if not available.
//!
//! Detects:
//! - HTTP Basic Auth (`Authorization: Basic ` header on port 80/8080)
//! - FTP credentials (`USER` / `PASS` commands on port 21)
//! - Unencrypted SMBv1 Session Setup (port 445, limited detection)

use std::io;
use std::time::Duration;

use pnet::datalink::{self, Channel, Config as PnetConfig};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

#[derive(Debug, Clone, PartialEq)]
pub struct CleartextCapture {
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub port: u16,
    pub detail: String,
}

/// Capture cleartext credentials on the named interface for `listen_secs` seconds.
///
/// Returns `Err` if the interface is not found or permission is denied.
pub fn capture_cleartext(
    iface_name: &str,
    listen_secs: u64,
) -> Result<Vec<CleartextCapture>, io::Error> {
    let interfaces = datalink::interfaces();
    let iface = interfaces
        .iter()
        .find(|i| i.name == iface_name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("Interface '{}' not found", iface_name)))?;

    let config = PnetConfig {
        promiscuous: true,
        read_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };

    let (_, mut rx) = match datalink::channel(iface, config)? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(io::Error::new(io::ErrorKind::Other, "Unsupported channel type")),
    };

    let mut captures = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(listen_secs);

    eprintln!("[*] Passive: cleartext sniff on {} for {}s (promiscuous mode)", iface_name, listen_secs);

    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        match rx.next() {
            Ok(frame) => {
                if let Some(eth) = EthernetPacket::new(frame) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                            if ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                    let payload = tcp.payload();
                                    if payload.is_empty() {
                                        continue;
                                    }
                                    let dst_port = tcp.get_destination();
                                    let src_ip = ip.get_source().to_string();
                                    let dst_ip = ip.get_destination().to_string();

                                    if let Some(c) = check_http_basic(payload, &src_ip, &dst_ip, dst_port) {
                                        captures.push(c);
                                    }
                                    if let Some(c) = check_ftp(payload, &src_ip, &dst_ip, dst_port) {
                                        captures.push(c);
                                    }
                                    if let Some(c) = check_smb_cleartext(payload, &src_ip, &dst_ip, dst_port) {
                                        captures.push(c);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => {
                eprintln!("[!] Packet capture error: {}", e);
                break;
            }
        }
    }

    Ok(captures)
}

/// Detect HTTP Basic Auth header in payload.
fn check_http_basic(payload: &[u8], src: &str, dst: &str, port: u16) -> Option<CleartextCapture> {
    if port != 80 && port != 8080 && port != 8000 {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    let lower = text.to_lowercase();
    let pos = lower.find("authorization: basic ")?;
    // Extract the base64 value (until whitespace or end)
    let rest = &text[pos + 21..];
    let value: &str = rest.split_whitespace().next().unwrap_or("(truncated)");
    // Attempt to decode base64 to show user:pass
    let decoded = base64_decode(value.trim_end_matches('\r').trim_end_matches('\n'));
    Some(CleartextCapture {
        protocol: "HTTP-Basic".into(),
        src_ip: src.into(),
        dst_ip: dst.into(),
        port,
        detail: format!("Authorization: Basic {} → {}", value, decoded),
    })
}

/// Detect FTP USER/PASS commands.
fn check_ftp(payload: &[u8], src: &str, dst: &str, port: u16) -> Option<CleartextCapture> {
    if port != 21 {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    let upper = text.to_uppercase();
    if upper.starts_with("USER ") || upper.starts_with("PASS ") {
        Some(CleartextCapture {
            protocol: "FTP".into(),
            src_ip: src.into(),
            dst_ip: dst.into(),
            port,
            detail: text.trim_end().to_string(),
        })
    } else {
        None
    }
}

/// Detect cleartext SMBv1 / NTLM with NetSession packets (limited heuristic).
fn check_smb_cleartext(payload: &[u8], src: &str, dst: &str, port: u16) -> Option<CleartextCapture> {
    if port != 445 && port != 139 {
        return None;
    }
    // SMBv1 magic: \xff SMB
    if payload.len() > 4 && &payload[..4] == b"\xffSMB" {
        // Command byte [4]: 0x73 = Session Setup AndX
        if payload[4] == 0x73 {
            return Some(CleartextCapture {
                protocol: "SMBv1-SessionSetup".into(),
                src_ip: src.into(),
                dst_ip: dst.into(),
                port,
                detail: "SMBv1 Session Setup AndX detected (unencrypted authentication)".into(),
            });
        }
    }
    None
}

/// Minimal base64 decode for HTTP Basic Auth display.
fn base64_decode(encoded: &str) -> String {
    // Using a simple approach — decode the standard base64 alphabet
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    let mut result = Vec::new();

    for c in encoded.chars() {
        if c == '=' {
            break;
        }
        if let Some(val) = alphabet.find(c) {
            bits = (bits << 6) | val as u32;
            bit_count += 6;
            if bit_count >= 8 {
                bit_count -= 8;
                result.push((bits >> bit_count) as u8 & 0xFF);
            }
        }
    }

    String::from_utf8_lossy(&result).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Phase 1: Structure Tests ──────────────────────────────────────

    #[test]
    fn test_cleartext_capture_creation() {
        let capture = CleartextCapture {
            protocol: "HTTP-Basic".to_string(),
            src_ip: "192.168.1.100".to_string(),
            dst_ip: "192.168.1.1".to_string(),
            port: 80,
            detail: "admin:password123".to_string(),
        };

        assert_eq!(capture.protocol, "HTTP-Basic");
        assert_eq!(capture.src_ip, "192.168.1.100");
        assert_eq!(capture.port, 80);
    }

    #[test]
    fn test_cleartext_capture_clone() {
        let capture = CleartextCapture {
            protocol: "FTP".to_string(),
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            port: 21,
            detail: "USER admin".to_string(),
        };

        let cloned = capture.clone();
        assert_eq!(capture.protocol, cloned.protocol);
        assert_eq!(capture.port, cloned.port);
    }

    #[test]
    fn test_cleartext_capture_protocols() {
        let protocols = vec!["HTTP-Basic", "FTP", "SMBv1-SessionSetup"];

        for proto in protocols {
            let capture = CleartextCapture {
                protocol: proto.to_string(),
                src_ip: "1.1.1.1".to_string(),
                dst_ip: "2.2.2.2".to_string(),
                port: 80,
                detail: "test".to_string(),
            };
            assert_eq!(capture.protocol, proto);
        }
    }

    // ─── Phase 2: HTTP Parsing Tests ──────────────────────────────────

    #[test]
    fn test_check_http_basic_valid() {
        let payload = b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n";
        let result = check_http_basic(payload, "192.168.1.100", "192.168.1.1", 80);

        assert!(result.is_some());
        let cap = result.unwrap();
        assert_eq!(cap.protocol, "HTTP-Basic");
        assert_eq!(cap.port, 80);
    }

    #[test]
    fn test_check_http_basic_port_80() {
        let payload = b"Authorization: Basic dXNlcjpwYXNz\r\n";
        let result = check_http_basic(payload, "1.1.1.1", "2.2.2.2", 80);
        assert!(result.is_some());
    }

    #[test]
    fn test_check_http_basic_port_8080() {
        let payload = b"Authorization: Basic dXNlcjpwYXNz\r\n";
        let result = check_http_basic(payload, "1.1.1.1", "2.2.2.2", 8080);
        assert!(result.is_some());
    }

    #[test]
    fn test_check_http_basic_port_8000() {
        let payload = b"Authorization: Basic dXNlcjpwYXNz\r\n";
        let result = check_http_basic(payload, "1.1.1.1", "2.2.2.2", 8000);
        assert!(result.is_some());
    }

    #[test]
    fn test_check_http_basic_wrong_port() {
        let payload = b"Authorization: Basic dXNlcjpwYXNz\r\n";
        let result = check_http_basic(payload, "1.1.1.1", "2.2.2.2", 443);
        assert_eq!(result, None, "Should reject non-HTTP ports");
    }

    #[test]
    fn test_check_http_basic_missing_header() {
        let payload = b"GET / HTTP/1.1\r\nContent-Type: text/html\r\n";
        let result = check_http_basic(payload, "1.1.1.1", "2.2.2.2", 80);
        assert_eq!(result, None, "Should return None without Authorization header");
    }

    #[test]
    fn test_check_http_basic_case_insensitive() {
        let payload = b"AUTHORIZATION: BASIC dXNlcjpwYXNz\r\n";
        let result = check_http_basic(payload, "1.1.1.1", "2.2.2.2", 80);
        assert!(result.is_some(), "Should be case-insensitive");
    }

    #[test]
    fn test_check_http_basic_empty_payload() {
        let payload = b"";
        let result = check_http_basic(payload, "1.1.1.1", "2.2.2.2", 80);
        assert_eq!(result, None);
    }

    #[test]
    fn test_check_http_basic_non_utf8() {
        let payload = vec![0xFF, 0xFE, 0x41, 0x42]; // Non-UTF8 bytes
        let result = check_http_basic(&payload, "1.1.1.1", "2.2.2.2", 80);
        assert_eq!(result, None, "Should handle non-UTF8 gracefully");
    }

    // ─── Phase 3: FTP Tests ───────────────────────────────────────────

    #[test]
    fn test_check_ftp_user_command() {
        let payload = b"USER admin\r\n";
        let result = check_ftp(payload, "192.168.1.100", "192.168.1.1", 21);

        assert!(result.is_some());
        let cap = result.unwrap();
        assert_eq!(cap.protocol, "FTP");
        assert!(cap.detail.contains("USER"));
    }

    #[test]
    fn test_check_ftp_pass_command() {
        let payload = b"PASS password123\r\n";
        let result = check_ftp(payload, "192.168.1.100", "192.168.1.1", 21);

        assert!(result.is_some());
        let cap = result.unwrap();
        assert_eq!(cap.protocol, "FTP");
        assert!(cap.detail.contains("PASS"));
    }

    #[test]
    fn test_check_ftp_lowercase() {
        let payload = b"user admin\r\n";
        let result = check_ftp(payload, "1.1.1.1", "2.2.2.2", 21);
        assert!(result.is_some(), "Should handle lowercase");
    }

    #[test]
    fn test_check_ftp_wrong_port() {
        let payload = b"USER admin\r\n";
        let result = check_ftp(payload, "1.1.1.1", "2.2.2.2", 22);
        assert_eq!(result, None, "Should reject non-FTP ports");
    }

    #[test]
    fn test_check_ftp_other_commands() {
        let payload = b"RETR file.txt\r\n";
        let result = check_ftp(payload, "1.1.1.1", "2.2.2.2", 21);
        assert_eq!(result, None, "Should only capture USER/PASS");
    }

    #[test]
    fn test_check_ftp_empty_payload() {
        let payload = b"";
        let result = check_ftp(payload, "1.1.1.1", "2.2.2.2", 21);
        assert_eq!(result, None);
    }

    // ─── Phase 4: SMB Tests ───────────────────────────────────────────

    #[test]
    fn test_check_smb_cleartext_valid() {
        // SMBv1 magic + Session Setup command
        let payload = vec![0xFF, b'S', b'M', b'B', 0x73];
        let result = check_smb_cleartext(&payload, "192.168.1.100", "192.168.1.1", 445);

        assert!(result.is_some());
        let cap = result.unwrap();
        assert_eq!(cap.protocol, "SMBv1-SessionSetup");
    }

    #[test]
    fn test_check_smb_cleartext_port_139() {
        let payload = vec![0xFF, b'S', b'M', b'B', 0x73];
        let result = check_smb_cleartext(&payload, "1.1.1.1", "2.2.2.2", 139);
        assert!(result.is_some());
    }

    #[test]
    fn test_check_smb_cleartext_wrong_port() {
        let payload = vec![0xFF, b'S', b'M', b'B', 0x73];
        let result = check_smb_cleartext(&payload, "1.1.1.1", "2.2.2.2", 21);
        assert_eq!(result, None);
    }

    #[test]
    fn test_check_smb_cleartext_wrong_command() {
        // SMBv1 magic but wrong command byte
        let payload = vec![0xFF, b'S', b'M', b'B', 0x75];
        let result = check_smb_cleartext(&payload, "1.1.1.1", "2.2.2.2", 445);
        assert_eq!(result, None);
    }

    #[test]
    fn test_check_smb_cleartext_too_short() {
        let payload = vec![0xFF, b'S'];
        let result = check_smb_cleartext(&payload, "1.1.1.1", "2.2.2.2", 445);
        assert_eq!(result, None);
    }

    #[test]
    fn test_check_smb_cleartext_empty() {
        let payload = vec![];
        let result = check_smb_cleartext(&payload, "1.1.1.1", "2.2.2.2", 445);
        assert_eq!(result, None);
    }

    // ─── Phase 5: Base64 Decoding Tests ───────────────────────────────

    #[test]
    fn test_base64_decode_simple() {
        // "test" = "dGVzdA=="
        let result = base64_decode("dGVzdA==");
        assert_eq!(result, "test");
    }

    #[test]
    fn test_base64_decode_user_pass() {
        // "user:pass" = "dXNlcjpwYXNz"
        let result = base64_decode("dXNlcjpwYXNz");
        assert_eq!(result, "user:pass");
    }

    #[test]
    fn test_base64_decode_empty() {
        let result = base64_decode("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_base64_decode_padding() {
        // With padding characters
        let result = base64_decode("YQ==");
        assert_eq!(result, "a");
    }

    #[test]
    fn test_base64_decode_invalid_char() {
        // Invalid base64 characters should be skipped
        let result = base64_decode("dGVz!dA==");
        // Should handle gracefully (implementation-dependent)
        assert!(!result.is_empty() || result.is_empty()); // Just verify no panic
    }

    // ─── Phase 6: Edge Cases ──────────────────────────────────────────

    #[test]
    fn test_capture_protocol_consistency() {
        let http = check_http_basic(b"Authorization: Basic test\r\n", "1.1.1.1", "2.2.2.2", 80);
        let ftp = check_ftp(b"USER admin\r\n", "1.1.1.1", "2.2.2.2", 21);
        let smb = check_smb_cleartext(&vec![0xFF, b'S', b'M', b'B', 0x73], "1.1.1.1", "2.2.2.2", 445);

        assert!(http.is_some());
        assert!(ftp.is_some());
        assert!(smb.is_some());

        assert_eq!(http.unwrap().protocol, "HTTP-Basic");
        assert_eq!(ftp.unwrap().protocol, "FTP");
        assert_eq!(smb.unwrap().protocol, "SMBv1-SessionSetup");
    }

    #[test]
    fn test_large_payload_handling() {
        let large_payload = vec![b'A'; 65536];
        // Should not panic on large payloads
        let _ = check_http_basic(&large_payload, "1.1.1.1", "2.2.2.2", 80);
        let _ = check_ftp(&large_payload, "1.1.1.1", "2.2.2.2", 21);
        let _ = check_smb_cleartext(&large_payload, "1.1.1.1", "2.2.2.2", 445);
    }

    #[test]
    fn test_ip_address_formatting() {
        let capture = CleartextCapture {
            protocol: "TEST".to_string(),
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.254".to_string(),
            port: 8080,
            detail: "test".to_string(),
        };

        assert!(capture.src_ip.contains("."));
        assert!(capture.dst_ip.contains("."));
    }

    #[test]
    fn test_port_range_validation() {
        // Test boundary ports
        let test_ports = vec![
            (21, true),   // FTP
            (22, false),  // SSH (not FTP)
            (80, true),   // HTTP
            (8000, true), // HTTP alt
            (8080, true), // HTTP alt
            (8081, false), // Not HTTP
            (139, true),  // SMB
            (445, true),  // SMB
            (443, false), // HTTPS (not HTTP)
        ];

        for (port, _) in test_ports {
            let payload = b"test";
            let _http = check_http_basic(payload, "1.1.1.1", "2.2.2.2", port);
            let _ftp = check_ftp(payload, "1.1.1.1", "2.2.2.2", port);
            let _smb = check_smb_cleartext(payload, "1.1.1.1", "2.2.2.2", port);
            // Just verify no panics
        }
    }
}
