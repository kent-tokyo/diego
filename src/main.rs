use std::sync::Arc;
use std::time::Instant;

use clap::Parser;

use diego::ai;
use diego::config::{Cli, Config};
use diego::mcp;
use diego::report::fleet::{
    PlanCheckpoint, FleetReport, PlanTarget, ScanPlan, TargetResult,
};
use diego::report::governance::GovernanceConfig;
use diego::report::{self, Report};
use diego::run_scan;

async fn run_plan_target(target: PlanTarget, cli: Cli, username: String) -> TargetResult {
    let mut target_cli = cli;
    target_cli.plan = None;
    target_cli.mcp = false;
    target_cli.dc = Some(target.dc.clone());
    target_cli.domain = Some(target.domain.clone());
    target_cli.username = Some(username);

    match Config::from_cli(target_cli) {
        Ok(config) => match run_scan(Arc::new(config)).await {
            Ok(report) => TargetResult {
                id: target.id,
                domain: target.domain,
                dc: target.dc,
                status: "completed".into(),
                attack_path: Some(report::attack_path::build(&report)),
                report: Some(report),
                error: None,
            },
            Err(error) => TargetResult {
                id: target.id,
                domain: target.domain,
                dc: target.dc,
                status: "failed".into(),
                report: None,
                attack_path: None,
                error: Some(error.to_string()),
            },
        },
        Err(error) => TargetResult {
            id: target.id,
            domain: target.domain,
            dc: target.dc,
            status: "failed".into(),
            report: None,
            attack_path: None,
            error: Some(error.to_string()),
        },
    }
}

fn write_plan_state(
    path: &std::path::Path,
    plan: &ScanPlan,
    fleet: &FleetReport,
) -> anyhow::Result<()> {
    let checkpoint = PlanCheckpoint::new(plan, fleet)?;
    let data = serde_json::to_string_pretty(&checkpoint)?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, data)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

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

    // ── Offline plan validation ──────────────────────────────────────────────
    if cli.plan_validate {
        let plan_path = cli
            .plan
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--plan is required with --plan-validate"))?;
        let data = std::fs::read_to_string(plan_path).map_err(|error| {
            anyhow::anyhow!("Failed to read scan plan {}: {error}", plan_path.display())
        })?;
        let plan: ScanPlan = serde_json::from_str(&data).map_err(|error| {
            anyhow::anyhow!("Failed to parse scan plan {}: {error}", plan_path.display())
        })?;
        plan.validate()?;
        let selected = plan.selected_targets();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "valid": true,
                "scope": plan.scope,
                "maxParallel": plan.max_parallel,
                "selectedTargets": selected,
            }))?
        );
        return Ok(());
    }

    // ── Multi-domain plan mode ───────────────────────────────────────────────
    if let Some(plan_path) = &cli.plan {
        let data = std::fs::read_to_string(plan_path).map_err(|e| {
            anyhow::anyhow!("Failed to read scan plan {}: {}", plan_path.display(), e)
        })?;
        let plan: ScanPlan = serde_json::from_str(&data).map_err(|e| {
            anyhow::anyhow!("Failed to parse scan plan {}: {}", plan_path.display(), e)
        })?;
        plan.validate()?;
        let plan_started = Instant::now();
        let username = cli
            .username
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--username is required with --plan"))?;
        if cli.password.is_none() && std::env::var("DIEGO_PASSWORD").is_err() {
            return Err(anyhow::anyhow!(
                "--password or DIEGO_PASSWORD is required with --plan"
            ));
        }
        let mut selected_targets = plan.selected_targets();
        let mut results = Vec::new();
        if let Some(state_path) = &cli.plan_state
            && state_path.exists()
        {
            let state_data = std::fs::read_to_string(state_path).map_err(|error| {
                anyhow::anyhow!(
                    "Failed to read plan checkpoint {}: {error}",
                    state_path.display()
                )
            })?;
            let checkpoint: PlanCheckpoint = serde_json::from_str(&state_data).map_err(|error| {
                anyhow::anyhow!(
                    "Failed to parse plan checkpoint {}: {error}",
                    state_path.display()
                )
            })?;
            checkpoint.verify(&plan)?;
            let completed_ids: std::collections::HashSet<String> = checkpoint
                .fleet
                .results
                .iter()
                .filter(|result| result.status == "completed")
                .map(|result| result.id.clone())
                .collect();
            results = checkpoint
                .fleet
                .results
                .into_iter()
                .filter(|result| result.status == "completed")
                .collect();
            selected_targets.retain(|target| !completed_ids.contains(&target.id));
            eprintln!(
                "[+] Resuming from {} completed target(s) in {}",
                completed_ids.len(),
                state_path.display()
            );
        }
        eprintln!(
            "[+] Executing {} selected target(s) with max_parallel={} (scope: {})",
            selected_targets.len(),
            plan.max_parallel,
            plan.scope
        );
        for batch in selected_targets.chunks(plan.max_parallel) {
            let mut handles = Vec::with_capacity(batch.len());
            for target in batch.iter().cloned() {
                handles.push(tokio::spawn(run_plan_target(
                    target,
                    cli.clone(),
                    username.clone(),
                )));
            }
            for handle in handles {
                results.push(
                    handle
                        .await
                        .map_err(|error| anyhow::anyhow!("plan target task failed: {error}"))?,
                );
            }
            if let Some(state_path) = &cli.plan_state {
                let checkpoint = FleetReport::with_duration(
                    &plan,
                    results.clone(),
                    plan_started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                );
                write_plan_state(state_path, &plan, &checkpoint)?;
            }
        }
        let fleet = FleetReport::with_duration(
            &plan,
            results,
            plan_started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        );
        let json = serde_json::to_string_pretty(&fleet)?;
        if let Some(output) = &cli.output {
            std::fs::write(output, &json)?;
            eprintln!("[+] Fleet report written to {}", output.display());
        } else {
            println!("{}", json);
        }
        return Ok(());
    }

    // ── CLI scan mode ─────────────────────────────────────────────────────────
    let config = Arc::new(Config::from_cli(cli)?);
    eprintln!(
        "[+] diego v{} — target: {} ({})",
        env!("CARGO_PKG_VERSION"),
        config.domain,
        config.dc_ip
    );
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
        let baseline: Report = serde_json::from_str(&data).map_err(|e| {
            anyhow::anyhow!("Failed to parse baseline JSON {}: {}", path.display(), e)
        })?;
        let d = report::diff::compute_diff(&report, &baseline);
        eprintln!(
            "[+] Baseline diff: {} new, {} resolved, {} severity-changed, {} unchanged",
            d.new.len(),
            d.resolved.len(),
            d.severity_changed.len(),
            d.unchanged_count,
        );
        report = report.with_diff(d);
        baseline_for_governance = Some(baseline);
    }

    if let Some(finding_id) = &config.explain {
        match report
            .findings
            .iter()
            .find(|finding| finding.id.eq_ignore_ascii_case(finding_id))
        {
            Some(finding) => println!("{}", report::explain::render(finding)),
            None => {
                return Err(anyhow::anyhow!(
                    "Finding ID not present in this scan: {}",
                    finding_id
                ));
            }
        }
        return Ok(());
    }

    if let Some(path) = &config.governance_output {
        let governance_config = if let Some(config_path) = &config.governance_config {
            let data = std::fs::read_to_string(config_path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read governance config {}: {}",
                    config_path.display(),
                    e
                )
            })?;
            serde_json::from_str(&data).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to parse governance config {}: {}",
                    config_path.display(),
                    e
                )
            })?
        } else {
            GovernanceConfig::default()
        };
        let assessment = report::governance::assess(
            &report,
            baseline_for_governance.as_ref(),
            &governance_config,
        );
        std::fs::write(path, serde_json::to_string_pretty(&assessment)?)?;
        eprintln!("[+] Governance assessment written to {}", path.display());
    }

    if let Some(path) = &config.sarif_output {
        std::fs::write(path, report::sarif::generate(&report)?)?;
        eprintln!("[+] SARIF report written to {}", path.display());
    }

    if let Some(path) = &config.webhook_output {
        std::fs::write(path, report::webhook::generate(&report)?)?;
        eprintln!("[+] Webhook event written to {}", path.display());
    }

    let attack_path_output = match config.format {
        diego::config::ReportFormat::Markdown => report::attack_path::generate_markdown(&report),
        _ => report::attack_path::generate_json(&report)?,
    };
    if let Some(path) = &config.attack_path_output {
        std::fs::write(path, &attack_path_output)?;
        eprintln!("[+] Attack-path summary written to {}", path.display());
    }

    if config.attack_path && config.attack_path_output.is_none() {
        println!("{}", attack_path_output);
        return Ok(());
    }

    if config.exposure_graph {
        println!(
            "{}",
            serde_json::to_string_pretty(&report::exposure::build(&report))?
        );
        return Ok(());
    }

    if let Some(ids) = &config.simulate_remediation {
        let ids: Vec<String> = ids
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(String::from)
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&report::exposure::simulate(&report, &ids))?
        );
        return Ok(());
    }

    // ── AI analysis ───────────────────────────────────────────────────────────
    if config.ai_analyze {
        match ai::ClaudeClient::new(None, Some(config.ai_model.clone())) {
            Ok(client) => {
                eprintln!(
                    "[*] Running Claude AI analysis (model: {})...",
                    config.ai_model
                );
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
