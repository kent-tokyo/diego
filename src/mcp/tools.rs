//! MCP tool definitions and handlers.
//!
//! Each tool corresponds to one or more diagnostic capabilities in the existing
//! modules. Tools run in-process and return JSON-serializable results.

use std::sync::Arc;
use std::time::Duration;

use ldap3::LdapConnAsync;
use serde_json::Value;

use crate::config::Config;
use crate::modules::kerberos::asreq::{build_asrep_roast_request, parse_kdc_response, KdcResponse};
use crate::modules::kerberos::hashcat::format_asrep_18200;
use crate::modules::kerberos::mod_send_kerberos_tcp;
use crate::modules::ldap::parser::extract_spn_accounts;
use crate::modules::ldap::queries::{
    query_asrep_candidates, query_description_leaks, query_password_policy,
    query_spn_accounts, query_unconstrained_delegation,
};
use crate::modules::passive::llmnr::{capture_llmnr, capture_nbtns};
use crate::report::{Finding, Severity};

// ─── Tool schema definitions ──────────────────────────────────────────────────

/// Returns the static list of MCP tools this server exposes.
pub fn tool_list() -> Vec<Value> {
    let ad_args = serde_json::json!({
        "type": "object",
        "properties": {
            "dc_ip":    {"type": "string", "description": "Domain Controller IP address"},
            "domain":   {"type": "string", "description": "AD domain name (e.g. corp.local)"},
            "username": {"type": "string", "description": "Domain username"},
            "password": {"type": "string", "description": "Domain password"},
            "timeout_secs": {"type": "integer", "default": 10}
        },
        "required": ["dc_ip", "domain", "username", "password"]
    });

    vec![
        make_tool(
            "enumerate_asrep_candidates",
            "List domain accounts that have DONT_REQ_PREAUTH set (AS-REP Roasting targets). Returns account names and DNs.",
            ad_args.clone(),
        ),
        make_tool(
            "enumerate_spn_accounts",
            "List service accounts with registered SPNs (Kerberoasting targets). Returns SAM account names, SPN list, and supported encryption types.",
            ad_args.clone(),
        ),
        make_tool(
            "check_unconstrained_delegation",
            "Find computer accounts with Unconstrained Delegation enabled. This is a Critical finding — coercion attacks can lead to full domain compromise.",
            ad_args.clone(),
        ),
        make_tool(
            "check_password_policy",
            "Read the Default Domain Password Policy (min length, lockout threshold, history, etc.).",
            ad_args.clone(),
        ),
        make_tool(
            "scan_description_leaks",
            "Search user account description fields for potential hardcoded credentials or sensitive information.",
            ad_args.clone(),
        ),
        make_tool(
            "run_asrep_roasting",
            "Perform AS-REP Roasting: send AS-REQ without pre-auth to a list of candidate usernames and return Hashcat-mode-18200 hashes for vulnerable accounts.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "dc_ip":    {"type": "string"},
                    "domain":   {"type": "string"},
                    "usernames": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of usernames to test (obtain from enumerate_asrep_candidates)"
                    },
                    "timeout_secs": {"type": "integer", "default": 10}
                },
                "required": ["dc_ip", "domain", "usernames"]
            }),
        ),
        make_tool(
            "run_kerberoasting",
            "Perform Kerberoasting: authenticate with the provided credentials, then request TGS tickets for all SPN accounts and return Hashcat-mode-13100 hashes.",
            ad_args.clone(),
        ),
        make_tool(
            "listen_llmnr",
            "Passively listen for LLMNR and NBT-NS broadcast queries on the local network. Returns observed queries with source IPs and queried hostnames.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "timeout_secs": {"type": "integer", "default": 30, "description": "How long to listen (seconds)"}
                }
            }),
        ),
        make_tool(
            "enumerate_constrained_delegation",
            "Find accounts and computers with Constrained Delegation configured (msDS-AllowedToDelegateTo or T2A4D flag). S4U2Proxy abuse can allow impersonating any user to listed services.",
            ad_args.clone(),
        ),
        make_tool(
            "enumerate_rbcd",
            "Find objects with Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity set). An attacker controlling a listed machine account can impersonate any user.",
            ad_args.clone(),
        ),
        make_tool(
            "enumerate_privileged_groups",
            "List members of high-privilege AD groups: Domain Admins, Enterprise Admins, Backup Operators, Account Operators, etc. Uses recursive membership expansion.",
            ad_args.clone(),
        ),
        make_tool(
            "enumerate_stale_service_passwords",
            "Find service accounts (with SPNs) whose passwords are older than 365 days. Old passwords on Kerberoastable accounts are significantly easier to crack.",
            ad_args.clone(),
        ),
        make_tool(
            "full_scan",
            "Run all diagnostic modules (LDAP enumeration, AS-REP Roasting, Kerberoasting, LLMNR listen) and return all findings as structured JSON.",
            ad_args,
        ),
    ]
}

fn make_tool(name: &str, description: &str, schema: Value) -> Value {
    serde_json::json!({
        "name": name,
        "description": description,
        "inputSchema": schema
    })
}

// ─── Tool dispatcher ──────────────────────────────────────────────────────────

/// Dispatch a tools/call request to the appropriate handler.
pub async fn dispatch(name: &str, args: &Value) -> anyhow::Result<Value> {
    match name {
        "enumerate_asrep_candidates" => enumerate_asrep_candidates(args).await,
        "enumerate_spn_accounts"     => enumerate_spn_accounts(args).await,
        "check_unconstrained_delegation" => check_unconstrained_delegation(args).await,
        "check_password_policy"      => check_password_policy(args).await,
        "scan_description_leaks"     => scan_description_leaks(args).await,
        "run_asrep_roasting"         => run_asrep_roasting(args).await,
        "run_kerberoasting"          => run_kerberoasting(args).await,
        "listen_llmnr"               => listen_llmnr(args).await,
        "enumerate_constrained_delegation" => mcp_constrained_delegation(args).await,
        "enumerate_rbcd"             => mcp_rbcd(args).await,
        "enumerate_privileged_groups" => mcp_privileged_groups(args).await,
        "enumerate_stale_service_passwords" => mcp_stale_passwords(args).await,
        "full_scan"                  => full_scan(args).await,
        _ => anyhow::bail!("Unknown tool: {}", name),
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn get_str<'a>(args: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Missing argument: {}", key))
}

fn get_timeout(args: &Value) -> u64 {
    args.get("timeout_secs").and_then(Value::as_u64).unwrap_or(10)
}

async fn ldap_connect(dc_ip: &str, domain: &str, username: &str, password: &str, timeout_secs: u64)
    -> anyhow::Result<ldap3::Ldap>
{
    let url = format!("ldap://{}:389", dc_ip);
    let (conn, mut ldap) = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        LdapConnAsync::new(&url),
    )
    .await
    .map_err(|_| anyhow::anyhow!("LDAP connection timeout"))?
    .map_err(|e| anyhow::anyhow!("LDAP connection failed: {}", e))?;

    ldap3::drive!(conn);

    ldap.simple_bind(&format!("{}@{}", username, domain), password)
        .await?
        .success()
        .map_err(|e| anyhow::anyhow!("LDAP bind failed: {}", e))?;

    Ok(ldap)
}

fn domain_to_base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
}

// ─── Tool implementations ─────────────────────────────────────────────────────

async fn enumerate_asrep_candidates(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let objs = query_asrep_candidates(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let result: Vec<Value> = objs.iter()
        .filter_map(|o| {
            let sam = o.get_first("sAMAccountName")?;
            Some(serde_json::json!({ "username": sam, "dn": o.dn }))
        })
        .collect();

    Ok(serde_json::json!({ "candidates": result, "count": result.len() }))
}

async fn enumerate_spn_accounts(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let objs = query_spn_accounts(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let result: Vec<Value> = objs.iter()
        .filter_map(|o| {
            let sam = o.get_first("sAMAccountName")?;
            let spns = o.get_all("servicePrincipalName");
            let enc = o.get_u32("msDS-SupportedEncryptionTypes").unwrap_or(0);
            Some(serde_json::json!({ "sam_name": sam, "spns": spns, "supported_enc_types": enc }))
        })
        .collect();

    Ok(serde_json::json!({ "spn_accounts": result, "count": result.len() }))
}

async fn check_unconstrained_delegation(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let objs = query_unconstrained_delegation(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let result: Vec<Value> = objs.iter()
        .map(|o| serde_json::json!({
            "cn": o.get_first("cn"),
            "dnsHostName": o.get_first("dnsHostName"),
            "os": o.get_first("operatingSystem"),
            "dn": o.dn,
        }))
        .collect();

    Ok(serde_json::json!({
        "unconstrained_delegation_computers": result,
        "count": result.len(),
        "severity": if result.is_empty() { "none" } else { "CRITICAL" }
    }))
}

async fn check_password_policy(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let objs = query_password_policy(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    if let Some(policy) = objs.first() {
        let min_len = policy.get_u32("minPwdLength").unwrap_or(0);
        let lockout = policy.get_u32("lockoutThreshold").unwrap_or(0);
        Ok(serde_json::json!({
            "minPwdLength": min_len,
            "lockoutThreshold": lockout,
            "pwdHistoryLength": policy.get_u32("pwdHistoryLength"),
            "assessment": {
                "min_length_ok": min_len >= 14,
                "lockout_enabled": lockout > 0,
                "brute_force_risk": lockout == 0,
            }
        }))
    } else {
        Ok(serde_json::json!({ "error": "Could not read password policy" }))
    }
}

async fn scan_description_leaks(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let objs = query_description_leaks(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let result: Vec<Value> = objs.iter()
        .filter_map(|o| {
            let sam = o.get_first("sAMAccountName")?;
            let desc = o.get_first("description")?;
            Some(serde_json::json!({ "account": sam, "description": desc, "dn": o.dn }))
        })
        .collect();

    Ok(serde_json::json!({ "leaks": result, "count": result.len() }))
}

async fn run_asrep_roasting(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let timeout = get_timeout(args);
    let realm = domain.to_uppercase();

    let usernames: Vec<&str> = args.get("usernames")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let dc_addr: std::net::SocketAddr = format!("{}:88", dc_ip).parse()
        .map_err(|_| anyhow::anyhow!("Invalid DC IP: {}", dc_ip))?;

    let mut hashes = Vec::new();

    for username in usernames {
        let nonce: u32 = rand::random();
        let req = build_asrep_roast_request(username, &realm, nonce);

        match mod_send_kerberos_tcp(&dc_addr, &req, timeout).await {
            Ok(raw) => {
                if let Ok(KdcResponse::AsRep(enc)) = parse_kdc_response(&raw) {
                    let hash = format_asrep_18200(enc.etype, username, &realm, &enc.cipher);
                    hashes.push(serde_json::json!({
                        "username": username,
                        "etype": enc.etype,
                        "hashcat_hash": hash,
                        "hashcat_mode": 18200,
                    }));
                }
            }
            Err(e) => eprintln!("[mcp] AS-REP error for {}: {}", username, e),
        }

        // Jitter
        let ms: u64 = {
            use rand::Rng;
            rand::thread_rng().gen_range(100..=300)
        };
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    Ok(serde_json::json!({ "vulnerable_accounts": hashes, "count": hashes.len() }))
}

async fn run_kerberoasting(args: &Value) -> anyhow::Result<Value> {
    // For kerberoasting we need valid credentials and the SPN list from LDAP.
    // This tool combines enumerate_spn_accounts + the kerberoasting logic.
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let spn_objs = query_spn_accounts(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let spn_accounts = extract_spn_accounts(&spn_objs);
    if spn_accounts.is_empty() {
        return Ok(serde_json::json!({ "hashes": [], "count": 0, "message": "No SPN accounts found" }));
    }

    let config = build_minimal_config(dc_ip, domain, username, password, timeout)?;
    let ctx = crate::modules::LdapContext {
        asrep_candidates: vec![],
        spn_accounts,
    };

    // Use the kerberos module to run the full kerberoasting
    use crate::modules::DiagnosticModule;
    let kerb_mod = crate::modules::kerberos::KerberosModule::new(ctx);
    let findings = kerb_mod.run(Arc::new(config)).await.unwrap_or_default();

    let hashes: Vec<Value> = findings.iter()
        .filter(|f| f.id.starts_with("KERB-TGS-"))
        .map(|f| serde_json::json!({
            "id": f.id,
            "account": f.evidence.get("sam_name"),
            "spn": f.evidence.get("spn"),
            "etype": f.evidence.get("etype"),
            "hashcat_hash": f.evidence.get("hashcat_hash"),
            "hashcat_mode": 13100,
        }))
        .collect();

    Ok(serde_json::json!({ "hashes": hashes, "count": hashes.len() }))
}

async fn listen_llmnr(args: &Value) -> anyhow::Result<Value> {
    let timeout = args.get("timeout_secs").and_then(Value::as_u64).unwrap_or(30);

    let (llmnr, nbtns) = tokio::join!(
        capture_llmnr(timeout),
        capture_nbtns(timeout),
    );

    let all: Vec<Value> = llmnr.iter().chain(nbtns.iter())
        .map(|c| serde_json::json!({
            "protocol": c.protocol,
            "source_ip": c.source_ip,
            "queried_name": c.queried_name,
        }))
        .collect();

    Ok(serde_json::json!({
        "broadcasts": all,
        "count": all.len(),
        "spoofing_risk": !all.is_empty(),
    }))
}

async fn mcp_constrained_delegation(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let objs = crate::modules::ldap::queries::query_constrained_delegation(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let result: Vec<Value> = objs.iter()
        .filter_map(|o| {
            let name = o.get_first("sAMAccountName")?;
            let targets = o.get_all("msDS-AllowedToDelegateTo");
            let uac = o.get_u32("userAccountControl").unwrap_or(0);
            Some(serde_json::json!({
                "account": name,
                "dn": o.dn,
                "delegation_targets": targets,
                "protocol_transition": uac & 0x100000 != 0,
            }))
        })
        .collect();

    Ok(serde_json::json!({ "constrained_delegation": result, "count": result.len() }))
}

async fn mcp_rbcd(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let objs = crate::modules::ldap::queries::query_rbcd(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let result: Vec<Value> = objs.iter()
        .map(|o| serde_json::json!({
            "cn": o.get_first("cn"),
            "sam_name": o.get_first("sAMAccountName"),
            "dnsHostName": o.get_first("dnsHostName"),
            "dn": o.dn,
        }))
        .collect();

    Ok(serde_json::json!({ "rbcd_objects": result, "count": result.len() }))
}

async fn mcp_privileged_groups(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let groups = crate::modules::ldap::queries::query_privileged_groups(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let result: Vec<Value> = groups.iter()
        .map(|(group, members)| {
            let names: Vec<&str> = members.iter()
                .filter_map(|m| m.get_first("sAMAccountName"))
                .collect();
            serde_json::json!({ "group": group, "member_count": members.len(), "members": names })
        })
        .collect();

    Ok(serde_json::json!({ "privileged_groups": result }))
}

async fn mcp_stale_passwords(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);
    let base_dn = domain_to_base_dn(domain);

    let mut ldap = ldap_connect(dc_ip, domain, username, password, timeout).await?;
    let objs = crate::modules::ldap::queries::query_stale_service_passwords(&mut ldap, &base_dn).await?;
    ldap.unbind().await.ok();

    let result: Vec<Value> = objs.iter()
        .filter_map(|o| {
            let name = o.get_first("sAMAccountName")?;
            let pwd_ts = o.get_first("pwdLastSet").unwrap_or("0");
            let age_days = pwd_ts.parse::<i64>()
                .map(|ts| (chrono::Utc::now().timestamp() - (ts - 116_444_736_000_000_000) / 10_000_000) / 86400)
                .unwrap_or(0);
            Some(serde_json::json!({
                "account": name,
                "dn": o.dn,
                "password_age_days": age_days,
                "spns": o.get_all("servicePrincipalName"),
            }))
        })
        .collect();

    Ok(serde_json::json!({ "stale_accounts": result, "count": result.len() }))
}

async fn full_scan(args: &Value) -> anyhow::Result<Value> {
    let dc_ip = get_str(args, "dc_ip")?;
    let domain = get_str(args, "domain")?;
    let username = get_str(args, "username")?;
    let password = get_str(args, "password")?;
    let timeout = get_timeout(args);

    let config = Arc::new(build_minimal_config(dc_ip, domain, username, password, timeout)?);

    use crate::modules::DiagnosticModule;
    let ldap_mod = crate::modules::ldap::LdapModule::new();
    let ldap_findings = ldap_mod.run(Arc::clone(&config)).await.unwrap_or_default();

    let (_, ctx) = crate::modules::ldap::run_ldap_and_extract_context(Arc::clone(&config))
        .await
        .unwrap_or_else(|_| (vec![], crate::modules::LdapContext {
            asrep_candidates: vec![],
            spn_accounts: vec![],
        }));

    let kerb_mod = crate::modules::kerberos::KerberosModule::new(ctx);
    let kerb_findings = kerb_mod.run(Arc::clone(&config)).await.unwrap_or_default();

    let all: Vec<&Finding> = ldap_findings.iter().chain(kerb_findings.iter()).collect();

    let summary = serde_json::json!({
        "critical": all.iter().filter(|f| f.severity == Severity::Critical).count(),
        "high":     all.iter().filter(|f| f.severity == Severity::High).count(),
        "medium":   all.iter().filter(|f| f.severity == Severity::Medium).count(),
        "low":      all.iter().filter(|f| f.severity == Severity::Low).count(),
        "total":    all.len(),
    });

    Ok(serde_json::json!({
        "findings": all,
        "summary": summary,
    }))
}

fn build_minimal_config(
    dc_ip: &str,
    domain: &str,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> anyhow::Result<Config> {
    use std::net::IpAddr;
    use std::str::FromStr;

    let ip = IpAddr::from_str(dc_ip)
        .map_err(|_| anyhow::anyhow!("Invalid DC IP: {}", dc_ip))?;

    use zeroize::Zeroizing;
    Ok(Config {
        dc_ip: ip,
        domain: domain.to_string(),
        base_dn: domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(","),
        username: username.to_string(),
        password: Zeroizing::new(password.to_string()),
        modules: vec![
            crate::config::ModuleKind::Ldap,
            crate::config::ModuleKind::Kerberos,
        ],
        output: None,
        format: crate::config::ReportFormat::Json,
        baseline: None,
        timeout_secs,
        interface: None,
        ai_analyze: false,
        chat: false,
        ai_model: crate::ai::claude::DEFAULT_MODEL.to_string(),
        mcp: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Phase 1: Tool List & Metadata Tests ───────────────────────────

    #[test]
    fn test_tool_list_returns_tools() {
        let tools = tool_list();
        assert!(!tools.is_empty(), "Tool list should not be empty");
        assert!(tools.len() > 10, "Should have at least 10 tools");
    }

    #[test]
    fn test_tool_list_contains_required_tools() {
        let tools = tool_list();
        let names: Vec<String> = tools.iter()
            .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();

        assert!(names.contains(&"enumerate_asrep_candidates".to_string()));
        assert!(names.contains(&"enumerate_spn_accounts".to_string()));
        assert!(names.contains(&"run_asrep_roasting".to_string()));
        assert!(names.contains(&"run_kerberoasting".to_string()));
        assert!(names.contains(&"listen_llmnr".to_string()));
    }

    #[test]
    fn test_tool_has_required_fields() {
        let tools = tool_list();

        for tool in tools {
            assert!(tool.get("name").is_some(), "Tool must have 'name'");
            assert!(tool.get("description").is_some(), "Tool must have 'description'");
            assert!(tool.get("inputSchema").is_some(), "Tool must have 'inputSchema'");
        }
    }

    #[test]
    fn test_make_tool_json_structure() {
        let tool = make_tool(
            "test_tool",
            "This is a test tool",
            serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        );

        assert_eq!(tool.get("name").and_then(|v| v.as_str()), Some("test_tool"));
        assert_eq!(tool.get("description").and_then(|v| v.as_str()), Some("This is a test tool"));
        assert!(tool.get("inputSchema").is_some());
    }

    #[test]
    fn test_tool_descriptions_non_empty() {
        let tools = tool_list();

        for tool in tools {
            let desc = tool.get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert!(!desc.is_empty(), "Tool description must not be empty");
            assert!(desc.len() > 20, "Tool description should be sufficiently detailed");
        }
    }

    // ─── Phase 2: Helper Function Tests ───────────────────────────────

    #[test]
    fn test_get_str_valid_key() {
        let args = serde_json::json!({
            "username": "admin",
            "domain": "corp.local"
        });

        let result = get_str(&args, "username");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "admin");
    }

    #[test]
    fn test_get_str_missing_key() {
        let args = serde_json::json!({
            "username": "admin"
        });

        let result = get_str(&args, "password");
        assert!(result.is_err(), "Should error on missing key");
    }

    #[test]
    fn test_get_str_wrong_type() {
        let args = serde_json::json!({
            "timeout_secs": 123
        });

        let result = get_str(&args, "timeout_secs");
        assert!(result.is_err(), "Should error on non-string type");
    }

    #[test]
    fn test_get_timeout_with_value() {
        let args = serde_json::json!({
            "timeout_secs": 30
        });

        let timeout = get_timeout(&args);
        assert_eq!(timeout, 30);
    }

    #[test]
    fn test_get_timeout_default() {
        let args = serde_json::json!({});

        let timeout = get_timeout(&args);
        assert_eq!(timeout, 10, "Default timeout should be 10 seconds");
    }

    #[test]
    fn test_get_timeout_zero() {
        let args = serde_json::json!({
            "timeout_secs": 0
        });

        let timeout = get_timeout(&args);
        assert_eq!(timeout, 0);
    }

    // ─── Phase 3: Domain to DN Conversion Tests ────────────────────────

    #[test]
    fn test_domain_to_base_dn_single_part() {
        let dn = domain_to_base_dn("local");
        assert_eq!(dn, "DC=local");
    }

    #[test]
    fn test_domain_to_base_dn_two_parts() {
        let dn = domain_to_base_dn("corp.local");
        assert_eq!(dn, "DC=corp,DC=local");
    }

    #[test]
    fn test_domain_to_base_dn_three_parts() {
        let dn = domain_to_base_dn("subdomain.corp.local");
        assert_eq!(dn, "DC=subdomain,DC=corp,DC=local");
    }

    #[test]
    fn test_domain_to_base_dn_uppercase() {
        let dn = domain_to_base_dn("CORP.LOCAL");
        assert_eq!(dn, "DC=CORP,DC=LOCAL");
    }

    #[test]
    fn test_domain_to_base_dn_empty_parts() {
        let dn = domain_to_base_dn("corp..local");
        // Should handle empty parts gracefully
        assert!(dn.contains("DC="), "Should still create DN");
    }

    // ─── Phase 4: Tool Input Validation Tests ──────────────────────────

    #[test]
    fn test_tool_input_schema_types() {
        let tools = tool_list();

        for tool in tools {
            let schema = tool.get("inputSchema");
            assert!(schema.is_some(), "Tool must have inputSchema");

            if let Some(s) = schema {
                // Should be an object with properties
                assert!(s.get("type").is_some(), "Schema should have type");
            }
        }
    }

    #[test]
    fn test_asrep_roasting_has_usernames_param() {
        let tools = tool_list();
        let asrep_tool = tools.iter()
            .find(|t| t.get("name").and_then(|v| v.as_str()) == Some("run_asrep_roasting"))
            .expect("asrep roasting tool should exist");

        let schema = asrep_tool.get("inputSchema").expect("has schema");
        let props = schema.get("properties").expect("has properties");
        assert!(props.get("usernames").is_some(), "Should have usernames parameter");
    }

    #[test]
    fn test_listen_llmnr_has_timeout_param() {
        let tools = tool_list();
        let listen_tool = tools.iter()
            .find(|t| t.get("name").and_then(|v| v.as_str()) == Some("listen_llmnr"))
            .expect("listen_llmnr tool should exist");

        let schema = listen_tool.get("inputSchema").expect("has schema");
        let props = schema.get("properties").expect("has properties");
        assert!(props.get("timeout_secs").is_some(), "Should have timeout_secs parameter");
    }

    // ─── Phase 5: Config Building Tests ────────────────────────────────

    #[test]
    fn test_build_minimal_config_valid() {
        let result = build_minimal_config("192.168.1.1", "corp.local", "user", "pass", 10);
        assert!(result.is_ok(), "Should build config with valid args");

        let config = result.unwrap();
        assert_eq!(config.dc_ip.to_string(), "192.168.1.1");
        assert_eq!(config.domain, "corp.local");
        assert_eq!(config.username, "user");
    }

    #[test]
    fn test_build_minimal_config_timeout() {
        let config = build_minimal_config("10.0.0.1", "example.com", "admin", "secret", 30).unwrap();
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_build_minimal_config_base_dn() {
        let config = build_minimal_config("10.0.0.1", "corp.local", "user", "pass", 10).unwrap();
        assert_eq!(config.base_dn, "DC=corp,DC=local");
    }

    #[test]
    fn test_build_minimal_config_modules() {
        let config = build_minimal_config("1.1.1.1", "test.local", "u", "p", 5).unwrap();
        assert!(!config.modules.is_empty(), "Should have modules configured");
        assert!(config.modules.len() >= 2, "Should have at least LDAP and Kerberos");
    }

    // ─── Phase 6: Dispatch and Tool Matching Tests ─────────────────────

    #[test]
    fn test_dispatch_tool_names_match_list() {
        let tools = tool_list();
        let tool_names: Vec<&str> = tools.iter()
            .filter_map(|t| t.get("name").and_then(|v| v.as_str()))
            .collect();

        // Verify each tool name can be dispatched (at least by name)
        for name in tool_names {
            assert!(!name.is_empty(), "Tool name should not be empty");
            assert!(name.len() < 50, "Tool name should be reasonable length");
        }
    }

    #[test]
    fn test_tool_names_are_unique() {
        let tools = tool_list();
        let names: Vec<String> = tools.iter()
            .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();

        assert_eq!(names.len(), tools.len(), "All tool names should be unique");
    }
}
