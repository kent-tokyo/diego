pub mod cleartext;
pub mod llmnr;

use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Config;
use crate::modules::DiagnosticModule;
use crate::report::{Finding, Severity};

use self::llmnr::{capture_llmnr, capture_nbtns};

pub struct PassiveModule;

impl PassiveModule {
    pub fn new() -> Self {
        PassiveModule
    }
}

#[async_trait]
impl DiagnosticModule for PassiveModule {
    fn name(&self) -> &'static str {
        "passive"
    }

    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // Default listen window: 30 seconds or the configured timeout
        let listen_secs = config.timeout_secs.max(30);

        // ── LLMNR / NBT-NS (no root required) ────────────────────────────────
        let (llmnr_caps, nbtns_caps) = tokio::join!(
            capture_llmnr(listen_secs),
            capture_nbtns(listen_secs),
        );

        let all_name_caps: Vec<_> = llmnr_caps
            .into_iter()
            .chain(nbtns_caps.into_iter())
            .collect();

        if !all_name_caps.is_empty() {
            let sources: Vec<serde_json::Value> = all_name_caps
                .iter()
                .map(|c| serde_json::json!({
                    "protocol": c.protocol,
                    "src": c.source_ip,
                    "name": c.queried_name,
                }))
                .collect();
            findings.push(Finding::new(
                "PASSIVE-LLMNR-NBTNS",
                "passive",
                Severity::Medium,
                format!("{} LLMNR/NBT-NS broadcasts observed", all_name_caps.len()),
                "The network is broadcasting LLMNR/NBT-NS name resolution queries. \
                 An attacker running Responder or Inveigh can poison these responses \
                 and capture NTLMv2 challenge-responses for offline cracking.",
                serde_json::json!({ "broadcasts": sources }),
                Some("Run Responder.py to capture NTLMv2 hashes, then crack with Hashcat mode 5600.".into()),
            ));
        } else {
            findings.push(Finding::new(
                "PASSIVE-LLMNR-QUIET",
                "passive",
                Severity::Info,
                "No LLMNR/NBT-NS broadcasts observed",
                "No LLMNR or NBT-NS broadcast queries were observed during the listening window. \
                 This may indicate LLMNR/NBT-NS is disabled (good) or the window was too short.",
                serde_json::Value::Null,
                None,
            ));
        }

        // ── Cleartext protocol detection (requires local admin / CAP_NET_RAW) ─
        if let Some(iface) = &config.interface {
            let iface_clone = iface.clone();
            let listen_secs_clone = listen_secs;
            // pnet is blocking — run on a dedicated thread
            let result = tokio::task::spawn_blocking(move || {
                cleartext::capture_cleartext(&iface_clone, listen_secs_clone)
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking error: {}", e))?;

            match result {
                Ok(caps) if !caps.is_empty() => {
                    let evidence: Vec<serde_json::Value> = caps
                        .iter()
                        .map(|c| serde_json::json!({
                            "protocol": c.protocol,
                            "src": c.src_ip,
                            "dst": c.dst_ip,
                            "port": c.port,
                            "detail": c.detail,
                        }))
                        .collect();
                    findings.push(Finding::new(
                        "PASSIVE-CLEARTEXT",
                        "passive",
                        Severity::Low,
                        format!("{} cleartext credential(s) observed on network", caps.len()),
                        "Unencrypted authentication protocols were observed. \
                         An attacker with network access can passively capture credentials.",
                        serde_json::json!({ "captures": evidence }),
                        Some("Disable FTP/HTTP Basic in favour of SFTP/HTTPS. Enable SMB signing.".into()),
                    ));
                }
                Ok(_) => {
                    findings.push(Finding::skipped("passive-cleartext", "No cleartext credentials observed"));
                }
                Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    eprintln!(
                        "[!] Cleartext detection skipped: permission denied on interface '{}'. \
                         Run as root / grant CAP_NET_RAW.",
                        iface
                    );
                    findings.push(Finding::skipped(
                        "passive-cleartext",
                        "Permission denied — requires root or CAP_NET_RAW for promiscuous mode",
                    ));
                }
                Err(e) => {
                    eprintln!("[!] Cleartext capture error: {}", e);
                }
            }
        } else {
            findings.push(Finding::skipped(
                "passive-cleartext",
                "No network interface specified (use --interface <name> to enable)",
            ));
        }

        Ok(findings)
    }
}
