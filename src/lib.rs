// Public library interface — used by integration tests in tests/
use std::sync::Arc;
use std::time::Instant;

pub mod ai;
pub mod config;
pub mod error;
pub mod modules;
pub mod mcp;
pub mod report;
pub mod utils;

use config::{Config, ModuleKind, RunMode};
use modules::{
    kerberos::KerberosModule,
    ldap::{run_ldap_and_extract_context, LdapModule},
    passive::PassiveModule,
    DiagnosticModule, LdapContext,
};
use report::{make_scan_context, Report};

/// Run the configured diagnostics and return a report.
///
/// This is the reusable library boundary for embedders. It follows the same
/// module ordering and concurrency as the CLI, and applies audit redaction
/// before returning so callers cannot accidentally bypass safe mode.
pub async fn run_scan(config: Arc<Config>) -> anyhow::Result<Report> {
    let start = Instant::now();
    let mut all_findings = Vec::new();
    let mut modules_run = Vec::new();

    let ldap_ctx: LdapContext;
    if config.modules.contains(&ModuleKind::Ldap) || config.modules.contains(&ModuleKind::Kerberos) {
        modules_run.push("ldap".to_string());
        match run_ldap_and_extract_context(Arc::clone(&config)).await {
            Ok((_unused, ctx)) => {
                if config.modules.contains(&ModuleKind::Ldap) {
                    match LdapModule::new().run(Arc::clone(&config)).await {
                        Ok(findings) => all_findings.extend(findings),
                        Err(error) => eprintln!("[!] LDAP module error: {}", error),
                    }
                }
                ldap_ctx = ctx;
            }
            Err(error) => {
                eprintln!("[!] LDAP context extraction failed: {}", error);
                ldap_ctx = LdapContext { asrep_candidates: vec![], spn_accounts: vec![] };
            }
        }
    } else {
        ldap_ctx = LdapContext { asrep_candidates: vec![], spn_accounts: vec![] };
    }

    let run_kerberos = config.modules.contains(&ModuleKind::Kerberos);
    let run_passive = config.modules.contains(&ModuleKind::Passive);
    match (run_kerberos, run_passive) {
        (true, true) => {
            modules_run.extend(["kerberos".to_string(), "passive".to_string()]);
            let kerberos_module = KerberosModule::new(ldap_ctx);
            let passive_module = PassiveModule::new();
            let (kerberos, passive) = tokio::join!(
                kerberos_module.run(Arc::clone(&config)),
                passive_module.run(Arc::clone(&config)),
            );
            if let Ok(findings) = kerberos { all_findings.extend(findings); }
            if let Ok(findings) = passive { all_findings.extend(findings); }
        }
        (true, false) => {
            modules_run.push("kerberos".to_string());
            if let Ok(findings) = KerberosModule::new(ldap_ctx).run(Arc::clone(&config)).await {
                all_findings.extend(findings);
            }
        }
        (false, true) => {
            modules_run.push("passive".to_string());
            if let Ok(findings) = PassiveModule::new().run(Arc::clone(&config)).await {
                all_findings.extend(findings);
            }
        }
        (false, false) => {}
    }

    let mut report = Report::new(make_scan_context(&config, modules_run, start), all_findings);
    if !(config.mode == RunMode::Full && config.export_hashes) {
        for finding in &mut report.findings {
            report::redact_evidence(&mut finding.evidence);
        }
    }
    Ok(report)
}
