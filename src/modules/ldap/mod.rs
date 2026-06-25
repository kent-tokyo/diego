pub mod analyze;
pub mod filters;
pub mod parser;
pub mod queries;
pub mod severity;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ldap3::LdapConnAsync;

use crate::config::Config;
use crate::modules::{DiagnosticModule, LdapContext};
use crate::report::Finding;

use self::parser::{extract_asrep_candidates, extract_spn_accounts};
use self::queries::{
    jitter, query_asrep_candidates, query_constrained_delegation, query_description_leaks,
    query_password_policy, query_privileged_groups, query_rbcd, query_spn_accounts,
    query_stale_service_passwords, query_unconstrained_delegation,
};

pub struct LdapModule;

impl Default for LdapModule {
    fn default() -> Self {
        Self::new()
    }
}

impl LdapModule {
    pub fn new() -> Self {
        LdapModule
    }
}

#[async_trait]
impl DiagnosticModule for LdapModule {
    fn name(&self) -> &'static str {
        "ldap"
    }

    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>> {
        eprintln!("[*] LDAP: connecting to {}", config.ldap_url());

        let (conn, mut ldap) = tokio::time::timeout(
            Duration::from_secs(config.timeout_secs),
            LdapConnAsync::new(&config.ldap_url()),
        )
        .await
        .map_err(|_| anyhow::anyhow!("LDAP connection timeout"))?
        .map_err(|e| anyhow::anyhow!("LDAP connection failed: {}", e))?;

        // Drive the connection in the background
        ldap3::drive!(conn);

        // Authenticate
        ldap.simple_bind(
            &format!("{}@{}", config.username, config.domain),
            &config.password,
        )
        .await?
        .success()
        .map_err(|e| anyhow::anyhow!("LDAP bind failed: {}", e))?;

        eprintln!("[+] LDAP: authenticated as {}@{}", config.username, config.domain);

        // ── Fetch (I/O) ──────────────────────────────────────────────────────
        eprintln!("[*] LDAP: querying AS-REP Roasting candidates");
        let asrep_objs = match query_asrep_candidates(&mut ldap, &config.base_dn).await {
            Ok(objs) => objs,
            Err(e) => { eprintln!("[!] AS-REP query failed: {}", e); vec![] }
        };
        jitter().await;

        eprintln!("[*] LDAP: querying SPN accounts");
        let spn_objs = match query_spn_accounts(&mut ldap, &config.base_dn).await {
            Ok(objs) => objs,
            Err(e) => { eprintln!("[!] SPN query failed: {}", e); vec![] }
        };
        jitter().await;

        eprintln!("[*] LDAP: querying description fields for credential leaks");
        let desc_objs = match query_description_leaks(&mut ldap, &config.base_dn).await {
            Ok(objs) => objs,
            Err(e) => { eprintln!("[!] Description query failed: {}", e); vec![] }
        };
        jitter().await;

        eprintln!("[*] LDAP: querying unconstrained delegation");
        let deleg_objs = match query_unconstrained_delegation(&mut ldap, &config.base_dn).await {
            Ok(objs) => objs,
            Err(e) => { eprintln!("[!] Delegation query failed: {}", e); vec![] }
        };
        jitter().await;

        eprintln!("[*] LDAP: querying password policy");
        let policy_objs = match query_password_policy(&mut ldap, &config.base_dn).await {
            Ok(objs) => objs,
            Err(e) => { eprintln!("[!] Password policy query failed: {}", e); vec![] }
        };
        jitter().await;

        eprintln!("[*] LDAP: querying constrained delegation");
        let const_deleg_objs = match query_constrained_delegation(&mut ldap, &config.base_dn).await {
            Ok(objs) => objs,
            Err(e) => { eprintln!("[!] Constrained delegation query failed: {}", e); vec![] }
        };
        jitter().await;

        eprintln!("[*] LDAP: querying RBCD (Resource-Based Constrained Delegation)");
        let rbcd_objs = match query_rbcd(&mut ldap, &config.base_dn).await {
            Ok(objs) => objs,
            Err(e) => { eprintln!("[!] RBCD query failed: {}", e); vec![] }
        };
        jitter().await;

        eprintln!("[*] LDAP: querying privileged group members");
        let priv_groups = match query_privileged_groups(&mut ldap, &config.base_dn).await {
            Ok(g) => g,
            Err(e) => { eprintln!("[!] Privileged groups query failed: {}", e); vec![] }
        };
        jitter().await;

        eprintln!("[*] LDAP: querying stale service account passwords");
        let stale_pwd_objs = match query_stale_service_passwords(&mut ldap, &config.base_dn).await {
            Ok(objs) => objs,
            Err(e) => { eprintln!("[!] Stale password query failed: {}", e); vec![] }
        };

        ldap.unbind().await?;

        // ── Analyze (pure) — see analyze.rs / tests/detection_tests.rs ────────
        let now = chrono::Utc::now().timestamp();
        let domain = &config.domain;
        let mut findings = Vec::new();
        // Order matches the original push order so that same-severity findings
        // keep their previous relative order after the stable severity sort.
        findings.extend(analyze::build_asrep_findings(&asrep_objs, domain));
        findings.extend(analyze::build_spn_findings(&spn_objs, domain));
        findings.extend(analyze::build_description_leak_findings(&desc_objs, domain));
        findings.extend(analyze::build_unconstrained_findings(&deleg_objs, domain));
        findings.extend(analyze::build_constrained_findings(&const_deleg_objs, domain));
        findings.extend(analyze::build_rbcd_findings(&rbcd_objs, domain));
        findings.extend(analyze::build_privileged_group_findings(&priv_groups, domain));
        findings.extend(analyze::build_stale_password_findings(&stale_pwd_objs, domain, now));
        findings.extend(analyze::build_password_policy_findings(&policy_objs, domain));

        Ok(findings)
    }
}

/// Extract LdapContext from LDAP findings (for consumption by KerberosModule).
pub async fn run_ldap_and_extract_context(config: Arc<Config>) -> anyhow::Result<(Vec<Finding>, LdapContext)> {
    let (conn, mut ldap) = tokio::time::timeout(
        Duration::from_secs(config.timeout_secs),
        LdapConnAsync::new(&config.ldap_url()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("LDAP connection timeout"))?
    .map_err(|e| anyhow::anyhow!("LDAP connection failed: {}", e))?;

    ldap3::drive!(conn);

    ldap.simple_bind(
        &format!("{}@{}", config.username, config.domain),
        &config.password,
    )
    .await?
    .success()
    .map_err(|e| anyhow::anyhow!("LDAP bind failed: {}", e))?;

    let asrep_objs = query_asrep_candidates(&mut ldap, &config.base_dn).await.unwrap_or_default();
    jitter().await;
    let spn_objs = query_spn_accounts(&mut ldap, &config.base_dn).await.unwrap_or_default();

    ldap.unbind().await.ok();

    let asrep_candidates = extract_asrep_candidates(&asrep_objs);
    let spn_accounts = extract_spn_accounts(&spn_objs);

    let ctx = LdapContext { asrep_candidates, spn_accounts };
    Ok((vec![], ctx))
}
