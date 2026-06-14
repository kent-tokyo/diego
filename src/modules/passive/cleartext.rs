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

#[derive(Debug, Clone)]
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
