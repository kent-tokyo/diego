use std::sync::Arc;
use std::time::Instant;

use clap::Parser;

use diego::ai;
use diego::config::{Cli, Config, ModuleKind};
use diego::mcp;
use diego::modules::{
    kerberos::KerberosModule,
    ldap::{run_ldap_and_extract_context, LdapModule},
    passive::PassiveModule,
    DiagnosticModule, LdapContext,
};
use diego::report::{self, make_scan_context, Report};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // ── MCP server mode ───────────────────────────────────────────────────────
    if cli.mcp {
        mcp::run().await;
        return Ok(());
    }

    // ── MCP init: write Claude Desktop config snippet ─────────────────────────
    if cli.mcp_init {
        let binary_path = std::env::current_exe()
            .unwrap_or_else(|_| std::path::PathBuf::from("diego"))
            .display()
            .to_string();
        let config_json = serde_json::json!({
            "mcpServers": {
                "diego": {
                    "command": binary_path,
                    "args": ["--mcp"],
                    "description": "Domain Intranet Elusive Guardian & Offensive-Scouter — Non-privileged AD security diagnostic agent"
                }
            }
        });
        println!("{}", serde_json::to_string_pretty(&config_json)?);
        eprintln!("[+] Add the above JSON to your Claude Desktop config file:");
        eprintln!("    macOS: ~/Library/Application Support/Claude/claude_desktop_config.json");
        eprintln!("    Windows: %APPDATA%\\Claude\\claude_desktop_config.json");
        return Ok(());
    }

    // ── CLI scan mode ─────────────────────────────────────────────────────────
    let config = Arc::new(Config::from_cli(cli)?);
    let start = Instant::now();

    eprintln!("[+] diego v{} — target: {} ({})", env!("CARGO_PKG_VERSION"), config.domain, config.dc_ip);
    eprintln!("[+] Modules: {:?}", config.modules);

    let mut all_findings = Vec::new();
    let mut modules_run: Vec<String> = Vec::new();

    // ── LDAP: always runs first (feeds Kerberos) ──────────────────────────────
    let ldap_ctx: LdapContext;

    if config.modules.contains(&ModuleKind::Ldap) || config.modules.contains(&ModuleKind::Kerberos) {
        eprintln!("[*] Running LDAP module");
        modules_run.push("ldap".into());

        match run_ldap_and_extract_context(Arc::clone(&config)).await {
            Ok((_unused, ctx)) => {
                if config.modules.contains(&ModuleKind::Ldap) {
                    let ldap_mod = LdapModule::new();
                    match ldap_mod.run(Arc::clone(&config)).await {
                        Ok(f) => all_findings.extend(f),
                        Err(e) => eprintln!("[!] LDAP module error: {}", e),
                    }
                }
                ldap_ctx = ctx;
            }
            Err(e) => {
                eprintln!("[!] LDAP context extraction failed: {}", e);
                ldap_ctx = LdapContext { asrep_candidates: vec![], spn_accounts: vec![] };
            }
        }
    } else {
        ldap_ctx = LdapContext { asrep_candidates: vec![], spn_accounts: vec![] };
    }

    // ── Kerberos + Passive: run concurrently ──────────────────────────────────
    let run_kerberos = config.modules.contains(&ModuleKind::Kerberos);
    let run_passive  = config.modules.contains(&ModuleKind::Passive);

    match (run_kerberos, run_passive) {
        (true, true) => {
            eprintln!("[*] Running Kerberos + Passive modules (concurrent)");
            modules_run.push("kerberos".into());
            modules_run.push("passive".into());
            let kerb_mod    = KerberosModule::new(ldap_ctx);
            let passive_mod = PassiveModule::new();
            let (kr, pr) = tokio::join!(
                kerb_mod.run(Arc::clone(&config)),
                passive_mod.run(Arc::clone(&config)),
            );
            if let Ok(f) = kr { all_findings.extend(f); } else if let Err(e) = kr { eprintln!("[!] Kerberos error: {}", e); }
            if let Ok(f) = pr { all_findings.extend(f); } else if let Err(e) = pr { eprintln!("[!] Passive error: {}", e); }
        }
        (true, false) => {
            eprintln!("[*] Running Kerberos module");
            modules_run.push("kerberos".into());
            let kerb_mod = KerberosModule::new(ldap_ctx);
            match kerb_mod.run(Arc::clone(&config)).await {
                Ok(f)  => all_findings.extend(f),
                Err(e) => eprintln!("[!] Kerberos error: {}", e),
            }
        }
        (false, true) => {
            eprintln!("[*] Running Passive module");
            modules_run.push("passive".into());
            let passive_mod = PassiveModule::new();
            match passive_mod.run(Arc::clone(&config)).await {
                Ok(f)  => all_findings.extend(f),
                Err(e) => eprintln!("[!] Passive error: {}", e),
            }
        }
        (false, false) => {}
    }

    // ── Build report ──────────────────────────────────────────────────────────
    let scan_ctx = make_scan_context(&config, modules_run, start);
    let mut report = Report::new(scan_ctx, all_findings);

    eprintln!(
        "[+] Scan complete ({:.1}s): {} findings ({} Critical, {} High, {} Medium)",
        start.elapsed().as_secs_f32(),
        report.summary.total,
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
    );

    // ── Baseline diff ─────────────────────────────────────────────────────────
    if let Some(path) = &config.baseline {
        let data = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read baseline {}: {}", path.display(), e))?;
        let baseline: Report = serde_json::from_str(&data)
            .map_err(|e| anyhow::anyhow!("Failed to parse baseline JSON {}: {}", path.display(), e))?;
        let d = report::diff::compute_diff(&report, &baseline);
        eprintln!(
            "[+] Baseline diff: {} new, {} resolved, {} severity-changed, {} unchanged",
            d.new.len(), d.resolved.len(), d.severity_changed.len(), d.unchanged_count,
        );
        report = report.with_diff(d);
    }

    // ── AI analysis ───────────────────────────────────────────────────────────
    if config.ai_analyze {
        match ai::ClaudeClient::new(None, Some(config.ai_model.clone())) {
            Ok(client) => {
                eprintln!("[*] Running Claude AI analysis (model: {})...", config.ai_model);
                match client.analyze_report(&report).await {
                    Ok(analysis) => {
                        eprintln!("[+] AI analysis complete.");
                        report = report.with_ai_analysis(analysis);
                    }
                    Err(e) => eprintln!("[!] AI analysis failed: {}", e),
                }
            }
            Err(e) => eprintln!("[!] Could not initialize Claude client: {}", e),
        }
    }

    // ── Output report ─────────────────────────────────────────────────────────
    report.write(&config).await?;

    // ── Interactive AI chat ───────────────────────────────────────────────────
    if config.chat {
        match ai::ClaudeClient::new(None, Some(config.ai_model.clone())) {
            Ok(client) => {
                ai::chat::run_chat(&client, &report).await?;
            }
            Err(e) => eprintln!("[!] Could not start chat: {}", e),
        }
    }

    Ok(())
}
