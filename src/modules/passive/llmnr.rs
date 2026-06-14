//! LLMNR (Link-Local Multicast Name Resolution) and NBT-NS passive detection.
//!
//! LLMNR uses UDP port 5355, multicast group 224.0.0.252 (IPv4).
//! NBT-NS uses UDP port 137, broadcast.
//!
//! No raw socket (root) required — standard UDP multicast socket suffices.

use std::collections::HashMap;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct LlmnrCapture {
    pub protocol: String,
    pub source_ip: String,
    pub queried_name: String,
}

/// Listen for LLMNR queries on 224.0.0.252:5355 for `listen_secs` seconds.
///
/// Every observed query means an OS or application is broadcasting
/// unresolved hostname lookups — a prime target for LLMNR poisoning attacks.
pub async fn capture_llmnr(listen_secs: u64) -> Vec<LlmnrCapture> {
    let mut captures = Vec::new();

    let socket = match UdpSocket::bind("0.0.0.0:5355").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] LLMNR: could not bind UDP 5355: {}", e);
            return captures;
        }
    };

    // Join IPv4 multicast group for LLMNR
    if let Err(e) = socket.join_multicast_v4(
        "224.0.0.252".parse().unwrap(),
        "0.0.0.0".parse().unwrap(),
    ) {
        eprintln!("[!] LLMNR: could not join multicast group: {}", e);
        // Continue anyway — we may still receive some packets
    }

    eprintln!("[*] Passive: listening for LLMNR on UDP 5355 for {}s", listen_secs);

    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(listen_secs);

    let mut seen: HashMap<String, bool> = HashMap::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, peer))) => {
                if let Some(name) = parse_llmnr_query(&buf[..n]) {
                    let key = format!("{}:{}", peer.ip(), name);
                    if seen.insert(key, true).is_none() {
                        captures.push(LlmnrCapture {
                            protocol: "LLMNR".into(),
                            source_ip: peer.ip().to_string(),
                            queried_name: name,
                        });
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("[!] LLMNR recv error: {}", e);
                break;
            }
            Err(_) => break, // timeout
        }
    }

    captures
}

/// Listen for NBT-NS broadcast queries on UDP 137.
pub async fn capture_nbtns(listen_secs: u64) -> Vec<LlmnrCapture> {
    let mut captures = Vec::new();

    let socket = match UdpSocket::bind("0.0.0.0:137").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] NBT-NS: could not bind UDP 137 (may need root): {}", e);
            return captures;
        }
    };

    eprintln!("[*] Passive: listening for NBT-NS on UDP 137 for {}s", listen_secs);

    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(listen_secs);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, peer))) => {
                if let Some(name) = parse_nbtns_query(&buf[..n]) {
                    captures.push(LlmnrCapture {
                        protocol: "NBT-NS".into(),
                        source_ip: peer.ip().to_string(),
                        queried_name: name,
                    });
                }
            }
            Ok(Err(e)) => {
                eprintln!("[!] NBT-NS recv error: {}", e);
                break;
            }
            Err(_) => break,
        }
    }

    captures
}

/// Parse an LLMNR query packet (RFC 4795) and return the queried name if it's a query.
///
/// LLMNR packet format (DNS-compatible):
/// - ID (2 bytes), FLAGS (2 bytes), QDCOUNT (2 bytes), ...
/// - Question section: QNAME, QTYPE, QCLASS
fn parse_llmnr_query(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    // FLAGS: bit 15 = QR (0=query, 1=response)
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 != 0 {
        return None; // Response, not a query
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }
    // Parse QNAME (offset 12)
    parse_dns_name(data, 12)
}

/// Parse an NBT-NS query and return the decoded NetBIOS name.
fn parse_nbtns_query(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    // NBT-NS uses DNS-compatible format with a 34-byte encoded name
    let flags = u16::from_be_bytes([data[2], data[3]]);
    // QR=0 means query
    if flags & 0x8000 != 0 {
        return None;
    }
    // Decode NBT name: offset 13 is the 34-byte second-level encoded name
    if data.len() < 13 + 33 {
        return None;
    }
    let raw_len = data[12] as usize;
    if raw_len != 32 || data.len() < 13 + raw_len {
        return None;
    }
    let encoded = &data[13..13 + raw_len];
    let name = decode_nbt_name(encoded);
    Some(name.trim().to_string())
}

/// Parse a DNS-style name from a packet starting at `offset`.
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut safety = 0;

    loop {
        if safety > 20 || offset >= data.len() {
            break;
        }
        safety += 1;
        let len = data[offset] as usize;
        if len == 0 {
            break;
        }
        // Pointer (0xC0 prefix)
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                break;
            }
            let ptr = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            offset = ptr;
            jumped = true;
            continue;
        }
        offset += 1;
        if offset + len > data.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&data[offset..offset + len]).into_owned());
        offset += len;
        let _ = jumped; // suppress warning
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Decode a NetBIOS second-level encoded name (32 nibble-encoded bytes → 16 chars).
fn decode_nbt_name(encoded: &[u8]) -> String {
    let mut name = String::new();
    for chunk in encoded.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let c = (((chunk[0] as u8 - b'A') << 4) | (chunk[1] as u8 - b'A')) as char;
        if c.is_ascii() {
            name.push(c);
        }
    }
    name
}
