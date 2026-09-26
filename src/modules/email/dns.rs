//! Minimal DNS client and wire-format codec.
//!
//! Hand-written in pure Rust (no resolver crate) to match diego's dependency
//! philosophy — the same reason the Kerberos module hand-rolls ASN.1/DER. Only
//! the query types the email-hygiene module needs are supported: A, CNAME, MX,
//! TXT, CAA, DS, DNSKEY, RRSIG. Queries are read-only and go to the operator's
//! own recursive resolver.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub const T_A: u16 = 1;
pub const T_NS: u16 = 2;
pub const T_CNAME: u16 = 5;
pub const T_MX: u16 = 15;
pub const T_TXT: u16 = 16;
pub const T_DS: u16 = 43;
pub const T_RRSIG: u16 = 46;
pub const T_DNSKEY: u16 = 48;
pub const T_CAA: u16 = 257;

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    Txt(String),
    Mx { pref: u16, exchange: String },
    Caa { flags: u8, tag: String, value: String },
    Cname(String),
    A([u8; 4]),
    Ds,
    Dnskey,
    Rrsig,
    Other(u16),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedResponse {
    pub flags: u16,
    /// Authenticated Data bit — set by a validating resolver for DNSSEC-signed data.
    pub ad: bool,
    pub answers: Vec<Record>,
}

impl ParsedResponse {
    /// Convenience: collect all TXT strings in the answer section.
    pub fn txt_strings(&self) -> Vec<String> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Txt(s) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn has_type(&self, rtype: u16) -> bool {
        self.answers.iter().any(|r| r.rtype == rtype)
    }
}

/// Encode a domain name as length-prefixed labels, root-terminated.
pub fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
    out
}

/// Build a recursive query. `dnssec_do` adds an EDNS0 OPT record with the DO bit
/// so a validating resolver returns DNSSEC material / sets the AD flag.
pub fn encode_query(id: u16, name: &str, qtype: u16, dnssec_do: bool) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT (always one OPT record)
    msg.extend_from_slice(&encode_qname(name));
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    // EDNS0 OPT on every query so large answers (e.g. apex TXT with many
    // verification records) arrive in one UDP datagram instead of forcing TCP.
    // The DO bit is set only for the DNSSEC probe.
    msg.push(0); // OPT root name
    msg.extend_from_slice(&41u16.to_be_bytes()); // TYPE=OPT
    msg.extend_from_slice(&4096u16.to_be_bytes()); // advertised UDP payload size
    msg.extend_from_slice(&[0, 0]); // ext-rcode + version
    msg.extend_from_slice(&(if dnssec_do { 0x8000u16 } else { 0u16 }).to_be_bytes()); // DO bit
    msg.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    msg
}

/// Parse a (possibly compressed) domain name; returns the name and the position
/// after the name in the reading stream (after the first pointer, if followed).
fn parse_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut end_pos = start;
    let mut jumps = 0usize;
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= msg.len() {
                return None;
            }
            let off = (((len & 0x3F) as usize) << 8) | (msg[pos + 1] as usize);
            if !jumped {
                end_pos = pos + 2;
            }
            jumped = true;
            jumps += 1;
            if jumps > 64 {
                return None; // pointer-loop guard
            }
            pos = off;
        } else if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        } else {
            let s = pos + 1;
            let e = s + len as usize;
            if e > msg.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&msg[s..e]).to_string());
            pos = e;
        }
    }
    Some((labels.join("."), end_pos))
}

/// Parse a DNS response into its answer records. Returns None on malformed input.
pub fn parse_response(msg: &[u8]) -> Option<ParsedResponse> {
    if msg.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let ad = flags & 0x0020 != 0;
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12;
    for _ in 0..qd {
        let (_n, p) = parse_name(msg, pos)?;
        pos = p + 4; // QTYPE + QCLASS
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        let (name, p) = parse_name(msg, pos)?;
        pos = p;
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return None;
        }
        let rdata = &msg[pos..pos + rdlen];
        let data = match rtype {
            T_TXT => {
                let mut s = String::new();
                let mut i = 0;
                while i < rdata.len() {
                    let l = rdata[i] as usize;
                    i += 1;
                    if i + l > rdata.len() {
                        break;
                    }
                    s.push_str(&String::from_utf8_lossy(&rdata[i..i + l]));
                    i += l;
                }
                RData::Txt(s)
            }
            T_MX => {
                if rdlen < 3 {
                    RData::Other(rtype)
                } else {
                    let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                    let (ex, _) = parse_name(msg, pos + 2)?;
                    RData::Mx { pref, exchange: ex }
                }
            }
            T_CAA => {
                if rdlen < 2 {
                    RData::Other(rtype)
                } else {
                    let cflags = rdata[0];
                    let tl = rdata[1] as usize;
                    if 2 + tl > rdlen {
                        RData::Other(rtype)
                    } else {
                        let tag = String::from_utf8_lossy(&rdata[2..2 + tl]).to_string();
                        let value = String::from_utf8_lossy(&rdata[2 + tl..]).to_string();
                        RData::Caa { flags: cflags, tag, value }
                    }
                }
            }
            T_CNAME => {
                let (c, _) = parse_name(msg, pos)?;
                RData::Cname(c)
            }
            T_A => {
                if rdlen == 4 {
                    RData::A([rdata[0], rdata[1], rdata[2], rdata[3]])
                } else {
                    RData::Other(rtype)
                }
            }
            T_DS => RData::Ds,
            T_DNSKEY => RData::Dnskey,
            T_RRSIG => RData::Rrsig,
            other => RData::Other(other),
        };
        answers.push(Record { name, rtype, data });
        pos += rdlen;
    }
    Some(ParsedResponse { flags, ad, answers })
}

/// Read the first `nameserver` entry from /etc/resolv.conf (Unix).
pub fn system_resolver() -> Option<IpAddr> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver")
            && let Ok(ip) = rest.trim().parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    None
}

/// Perform a single read-only DNS query against `resolver`. Falls back to TCP if
/// the UDP response is truncated (TC bit).
pub async fn query(
    resolver: SocketAddr,
    name: &str,
    qtype: u16,
    dnssec_do: bool,
    per_query: Duration,
) -> anyhow::Result<ParsedResponse> {
    let id: u16 = rand::random();
    let packet = encode_query(id, name, qtype, dnssec_do);
    let bind: SocketAddr = if resolver.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    // UDP with one retry — the first datagram after a cold start occasionally
    // exceeds the deadline before the socket path warms up. Falls back to TCP if
    // the answer is truncated (TC bit).
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        match udp_exchange(&bind, resolver, &packet, per_query).await {
            Ok(buf) => {
                let truncated =
                    buf.len() >= 4 && (u16::from_be_bytes([buf[2], buf[3]]) & 0x0200 != 0);
                if truncated {
                    return query_tcp(resolver, &packet, per_query).await;
                }
                return parse_response(&buf)
                    .ok_or_else(|| anyhow::anyhow!("malformed DNS response for {name}"));
            }
            Err(e) => {
                last_err = Some(e);
                if attempt == 0 {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DNS query failed for {name}")))
}

async fn udp_exchange(
    bind: &SocketAddr,
    resolver: SocketAddr,
    packet: &[u8],
    per_query: Duration,
) -> anyhow::Result<Vec<u8>> {
    let sock = UdpSocket::bind(*bind).await?;
    sock.connect(resolver).await?;
    tokio::time::timeout(per_query, sock.send(packet)).await??;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(per_query, sock.recv(&mut buf)).await??;
    buf.truncate(n);
    Ok(buf)
}

async fn query_tcp(
    resolver: SocketAddr,
    packet: &[u8],
    per_query: Duration,
) -> anyhow::Result<ParsedResponse> {
    let mut stream = tokio::time::timeout(per_query, TcpStream::connect(resolver)).await??;
    let len = (packet.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(packet).await?;
    stream.flush().await?;

    let mut lenbuf = [0u8; 2];
    tokio::time::timeout(per_query, stream.read_exact(&mut lenbuf)).await??;
    let resp_len = u16::from_be_bytes(lenbuf) as usize;
    let mut buf = vec![0u8; resp_len];
    tokio::time::timeout(per_query, stream.read_exact(&mut buf)).await??;
    parse_response(&buf).ok_or_else(|| anyhow::anyhow!("malformed DNS response over TCP"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_response(ad: bool, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes());
        let flags: u16 = 0x8180 | if ad { 0x0020 } else { 0 };
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&encode_qname("example.com"));
        m.extend_from_slice(&T_TXT.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        for (rtype, rdata) in answers {
            m.push(0xC0);
            m.push(12u8); // pointer to question name
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&1u16.to_be_bytes());
            m.extend_from_slice(&300u32.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    fn txt_rdata(s: &str) -> Vec<u8> {
        let mut v = vec![s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    #[test]
    fn qname_roundtrip() {
        let e = encode_qname("mail.example.com");
        assert_eq!(e[0], 4);
        assert_eq!(&e[1..5], b"mail");
        assert_eq!(*e.last().unwrap(), 0);
        let (name, end) = parse_name(&e, 0).unwrap();
        assert_eq!(name, "mail.example.com");
        assert_eq!(end, e.len());
    }

    #[test]
    fn parse_txt_answer_with_compression() {
        let msg = build_response(false, &[(T_TXT, txt_rdata("v=spf1 -all"))]);
        let parsed = parse_response(&msg).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "example.com");
        assert_eq!(parsed.answers[0].data, RData::Txt("v=spf1 -all".into()));
    }

    #[test]
    fn parse_multi_segment_txt() {
        let mut rd = Vec::new();
        rd.push(5u8);
        rd.extend_from_slice(b"v=spf");
        rd.push(6u8);
        rd.extend_from_slice(b"1 -all");
        let msg = build_response(false, &[(T_TXT, rd)]);
        let parsed = parse_response(&msg).unwrap();
        assert_eq!(parsed.answers[0].data, RData::Txt("v=spf1 -all".into()));
    }

    #[test]
    fn parse_caa_answer() {
        let mut rd = vec![0u8, 5u8];
        rd.extend_from_slice(b"issue");
        rd.extend_from_slice(b"letsencrypt.org");
        let msg = build_response(false, &[(T_CAA, rd)]);
        let parsed = parse_response(&msg).unwrap();
        assert_eq!(
            parsed.answers[0].data,
            RData::Caa { flags: 0, tag: "issue".into(), value: "letsencrypt.org".into() }
        );
    }

    #[test]
    fn ad_flag_detected() {
        assert!(parse_response(&build_response(true, &[(T_TXT, txt_rdata("x"))])).unwrap().ad);
        assert!(!parse_response(&build_response(false, &[(T_TXT, txt_rdata("x"))])).unwrap().ad);
    }

    #[test]
    fn malformed_truncated_returns_none() {
        assert!(parse_response(&[0, 1, 2]).is_none());
    }
}
