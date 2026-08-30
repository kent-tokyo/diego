use std::sync::Arc;
use std::time::Instant;

use clap::Parser;

use diego::ai;
use diego::config::{Cli, Config};
use diego::mcp;
use diego::run_scan;
use diego::report::{self, Report};

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
    eprintln!("[+] diego v{} — target: {} ({})", env!("CARGO_PKG_VERSION"), config.domain, config.dc_ip);
    eprintln!("[+] Modules: {:?}", config.modules);
    let start = Instant::now();
    let mut report = run_scan(Arc::clone(&config)).await?;

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
