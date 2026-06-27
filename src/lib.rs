// Public library interface — used by integration tests in tests/
pub mod ai;
pub mod config;
pub mod error;
pub mod modules;
pub mod mcp;
pub mod report;
pub mod utils;

#[cfg(feature = "python")]
mod python;

use std::sync::Arc;
use std::time::Instant;

use modules::{
    DiagnosticModule, LdapContext,
    kerberos::KerberosModule,
    ldap::{run_ldap_and_extract_context, LdapModule},
    passive::PassiveModule,
};
use config::ModuleKind;
use report::{make_scan_context, Report};

/// Run a full diagnostic scan and return the assembled Report.
///
/// Orchestrates: LDAP → Kerberos + Passive (concurrent) → Report.
/// Does not include AI analysis, baseline diff, or output — callers handle those.
pub async fn run_scan(config: Arc<config::Config>) -> anyhow::Result<Report> {
    let start = Instant::now();
    let mut all_findings = Vec::new();
    let mut modules_run: Vec<String> = Vec::new();

    // LDAP runs first: needed by both the LDAP module and Kerberos (for LdapContext)
    let ldap_ctx: LdapContext;
    if config.modules.contains(&ModuleKind::Ldap) || config.modules.contains(&ModuleKind::Kerberos) {
        modules_run.push("ldap".into());
        match run_ldap_and_extract_context(Arc::clone(&config)).await {
            Ok((_unused, ctx)) => {
                if config.modules.contains(&ModuleKind::Ldap) {
                    let ldap_mod = LdapModule::new();
                    if let Ok(f) = ldap_mod.run(Arc::clone(&config)).await {
                        all_findings.extend(f);
                    }
                }
                ldap_ctx = ctx;
            }
            Err(_) => {
                ldap_ctx = LdapContext { asrep_candidates: vec![], spn_accounts: vec![] };
            }
        }
    } else {
        ldap_ctx = LdapContext { asrep_candidates: vec![], spn_accounts: vec![] };
    }

    // Kerberos + Passive run concurrently
    let run_kerberos = config.modules.contains(&ModuleKind::Kerberos);
    let run_passive  = config.modules.contains(&ModuleKind::Passive);
    match (run_kerberos, run_passive) {
        (true, true) => {
            modules_run.push("kerberos".into());
            modules_run.push("passive".into());
            let kerb_mod    = KerberosModule::new(ldap_ctx);
            let passive_mod = PassiveModule::new();
            let (kr, pr) = tokio::join!(
                kerb_mod.run(Arc::clone(&config)),
                passive_mod.run(Arc::clone(&config)),
            );
            if let Ok(f) = kr { all_findings.extend(f); }
            if let Ok(f) = pr { all_findings.extend(f); }
        }
        (true, false) => {
            modules_run.push("kerberos".into());
            let kerb_mod = KerberosModule::new(ldap_ctx);
            if let Ok(f) = kerb_mod.run(Arc::clone(&config)).await { all_findings.extend(f); }
        }
        (false, true) => {
            modules_run.push("passive".into());
            let passive_mod = PassiveModule::new();
            if let Ok(f) = passive_mod.run(Arc::clone(&config)).await { all_findings.extend(f); }
        }
        (false, false) => {}
    }

    let scan_ctx = make_scan_context(&config, modules_run, start);
    Ok(Report::new(scan_ctx, all_findings))
}
