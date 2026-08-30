use std::sync::Arc;
use std::time::Instant;

use clap::Parser;

use diego::ai;
use diego::config::{Cli, Config};
use diego::mcp;
use diego::run_scan;
use diego::report::{self, Report};
use diego::report::fleet::{FleetReport, ScanPlan, TargetResult};
use diego::report::governance::GovernanceConfig;

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

    // ── Multi-domain plan mode ───────────────────────────────────────────────
    if let Some(plan_path) = &cli.plan {
        let data = std::fs::read_to_string(plan_path)
            .map_err(|e| anyhow::anyhow!("Failed to read scan plan {}: {}", plan_path.display(), e))?;
        let plan: ScanPlan = serde_json::from_str(&data)
            .map_err(|e| anyhow::anyhow!("Failed to parse scan plan {}: {}", plan_path.display(), e))?;
        plan.validate()?;
        let username = cli.username.as_ref().ok_or_else(|| anyhow::anyhow!("--username is required with --plan"))?;
        if cli.password.is_none() && std::env::var("DIEGO_PASSWORD").is_err() {
            return Err(anyhow::anyhow!("--password or DIEGO_PASSWORD is required with --plan"));
        }
        eprintln!("[+] Executing {} selected target(s) sequentially (scope: {})", plan.selected_targets().len(), plan.scope);
        let mut results = Vec::new();
        for target in plan.selected_targets() {
            let mut target_cli = cli.clone();
            target_cli.plan = None;
            target_cli.mcp = false;
            target_cli.dc = Some(target.dc.clone());
            target_cli.domain = Some(target.domain.clone());
            target_cli.username = Some(username.clone());
            let result = match Config::from_cli(target_cli) {
                Ok(config) => match run_scan(Arc::new(config)).await {
                    Ok(report) => TargetResult { id: target.id, domain: target.domain, dc: target.dc, status: "completed".into(), report: Some(report), error: None },
                    Err(error) => TargetResult { id: target.id, domain: target.domain, dc: target.dc, status: "failed".into(), report: None, error: Some(error.to_string()) },
                },
                Err(error) => TargetResult { id: target.id, domain: target.domain, dc: target.dc, status: "failed".into(), report: None, error: Some(error.to_string()) },
            };
            results.push(result);
        }
        let fleet = FleetReport::new(&plan, results);
        let json = serde_json::to_string_pretty(&fleet)?;
        if let Some(output) = &cli.output { std::fs::write(output, &json)?; }
        println!("{}", json);
        return Ok(());
    }

    // ── CLI scan mode ─────────────────────────────────────────────────────────
    let config = Arc::new(Config::from_cli(cli)?);
    eprintln!("[+] diego v{} — target: {} ({})", env!("CARGO_PKG_VERSION"), config.domain, config.dc_ip);
    eprintln!("[+] Modules: {:?}", config.modules);
    let start = Instant::now();
    let mut report = run_scan(Arc::clone(&config)).await?;
    let mut baseline_for_governance: Option<Report> = None;

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
        baseline_for_governance = Some(baseline);
    }

    if let Some(finding_id) = &config.explain {
        match report.findings.iter().find(|finding| finding.id.eq_ignore_ascii_case(finding_id)) {
            Some(finding) => println!("{}", report::explain::render(finding)),
            None => return Err(anyhow::anyhow!("Finding ID not present in this scan: {}", finding_id)),
        }
        return Ok(());
    }

    if let Some(path) = &config.governance_output {
        let governance_config = if let Some(config_path) = &config.governance_config {
            let data = std::fs::read_to_string(config_path).map_err(|e| anyhow::anyhow!("Failed to read governance config {}: {}", config_path.display(), e))?;
            serde_json::from_str(&data).map_err(|e| anyhow::anyhow!("Failed to parse governance config {}: {}", config_path.display(), e))?
        } else {
            GovernanceConfig::default()
        };
        let assessment = report::governance::assess(&report, baseline_for_governance.as_ref(), &governance_config);
        std::fs::write(path, serde_json::to_string_pretty(&assessment)?)?;
        eprintln!("[+] Governance assessment written to {}", path.display());
    }

    if config.exposure_graph {
        println!("{}", serde_json::to_string_pretty(&report::exposure::build(&report))?);
        return Ok(());
    }

    if let Some(ids) = &config.simulate_remediation {
        let ids: Vec<String> = ids.split(',').map(str::trim).filter(|id| !id.is_empty()).map(String::from).collect();
        println!("{}", serde_json::to_string_pretty(&report::exposure::simulate(&report, &ids))?);
        return Ok(());
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
