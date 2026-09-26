use std::io::{self, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use zeroize::Zeroizing;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "diego",
    about = "Domain Intranet Elusive Guardian & Offensive-Scouter\nNon-privileged Active Directory security diagnostic agent"
)]
pub struct Cli {
    /// Domain Controller IP address (required for CLI mode)
    #[arg(long)]
    pub dc: Option<String>,

    /// Domain name (e.g. corp.local)
    #[arg(long)]
    pub domain: Option<String>,

    /// Username for authentication
    #[arg(long)]
    pub username: Option<String>,

    /// Password for authentication
    #[arg(
        long,
        required_unless_present_any = ["mcp", "plan_validate"]
    )]
    pub password: Option<String>,

    /// Modules to run: kerberos, ldap, passive, all
    #[arg(long, default_value = "all")]
    pub modules: String,

    /// Output file path
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Output format: json, markdown, or html
    #[arg(long, default_value = "json")]
    pub format: String,

    /// Path to a prior diego JSON report to diff against (baseline comparison)
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Per-query timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Network interface for passive listening
    #[arg(long)]
    pub interface: Option<String>,

    // ── AI flags ─────────────────────────────────────────────────────────────
    /// Analyze scan results with Claude API after scanning
    #[arg(long)]
    pub ai_analyze: bool,

    /// Enter interactive AI chat mode after scan (implies --ai-analyze)
    #[arg(long)]
    pub chat: bool,

    /// Claude model to use for AI analysis
    #[arg(long, default_value = crate::ai::claude::DEFAULT_MODEL)]
    pub ai_model: String,

    // ── Safe mode ─────────────────────────────────────────────────────────────
    /// Run mode: audit (default) redacts crackable hashes; full keeps raw evidence
    #[arg(long, value_enum, default_value = "audit")]
    pub mode: RunMode,

    /// Include crackable hash material in the report (requires --mode full)
    #[arg(long)]
    pub export_hashes: bool,

    /// Explain one finding ID after the scan, including evidence provenance
    #[arg(long, value_name = "FINDING_ID")]
    pub explain: Option<String>,

    /// Emit the bounded finding exposure graph as JSON after the scan
    #[arg(long)]
    pub exposure_graph: bool,

    /// Simulate remediation by comma-separated finding IDs (no directory changes)
    #[arg(long, value_name = "FINDING_IDS")]
    pub simulate_remediation: Option<String>,

    /// JSON governance policy for local scoring and ownership metadata
    #[arg(long)]
    pub governance_config: Option<PathBuf>,

    /// Write a local governance assessment JSON sidecar
    #[arg(long)]
    pub governance_output: Option<PathBuf>,

    /// Write a SARIF 2.1.0 findings sidecar for CI/security-platform ingestion
    #[arg(long)]
    pub sarif_output: Option<PathBuf>,
    /// Write an evidence-safe scan.completed webhook/SIEM event sidecar
    #[arg(long)]
    pub webhook_output: Option<PathBuf>,

    /// Emit the bounded defensive attack-path summary as JSON or Markdown
    #[arg(long)]
    pub attack_path: bool,

    /// Write the bounded defensive attack-path summary to a local sidecar
    #[arg(long)]
    pub attack_path_output: Option<PathBuf>,

    /// JSON multi-domain execution plan (credentials remain CLI/env supplied)
    #[arg(long)]
    pub plan: Option<PathBuf>,

    /// Validate a plan locally without credentials or network access
    #[arg(long)]
    pub plan_validate: bool,

    /// Local checkpoint file for resumable multi-domain plan execution
    #[arg(long, value_name = "PATH")]
    pub plan_state: Option<PathBuf>,

    // ── MCP mode ─────────────────────────────────────────────────────────────
    /// Run as an MCP (Model Context Protocol) server over stdio
    #[arg(long)]
    pub mcp: bool,

    /// Write a Claude Desktop MCP configuration snippet to stdout and exit
    #[arg(long)]
    pub mcp_init: bool,
}

/// Output mode: audit (default) hides crackable hash material; full+export-hashes enables it.
#[derive(Clone, Debug, PartialEq, clap::ValueEnum)]
pub enum RunMode {
    Audit,
    Full,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ModuleKind {
    Kerberos,
    Ldap,
    Passive,
}

#[derive(Clone, Debug)]
pub enum ReportFormat {
    Json,
    Markdown,
    Html,
}

#[derive(Debug)]
pub struct Config {
    pub dc_ip: IpAddr,
    pub domain: String,
    pub base_dn: String,
    pub username: String,
    pub password: Zeroizing<String>, // Credentials zeroized on drop
    pub modules: Vec<ModuleKind>,
    pub output: Option<PathBuf>,
    pub format: ReportFormat,
    pub baseline: Option<PathBuf>,
    pub timeout_secs: u64,
    pub interface: Option<String>,
    // AI
    pub ai_analyze: bool,
    pub chat: bool,
    pub ai_model: String,
    // Safe mode
    pub mode: RunMode,
    pub export_hashes: bool,
    pub explain: Option<String>,
    pub exposure_graph: bool,
    pub simulate_remediation: Option<String>,
    pub governance_config: Option<PathBuf>,
    pub governance_output: Option<PathBuf>,
    pub sarif_output: Option<PathBuf>,
    pub webhook_output: Option<PathBuf>,
    pub attack_path: bool,
    pub attack_path_output: Option<PathBuf>,
    // MCP
    pub mcp: bool,
}

impl Config {
    pub fn from_cli(cli: Cli) -> anyhow::Result<Self> {
        let dc_str = cli
            .dc
            .ok_or_else(|| anyhow::anyhow!("--dc is required in CLI mode"))?;
        let dc_ip = IpAddr::from_str(&dc_str)
            .map_err(|_| anyhow::anyhow!("Invalid DC IP address: {}", dc_str))?;

        let domain = cli
            .domain
            .ok_or_else(|| anyhow::anyhow!("--domain is required in CLI mode"))?;
        let base_dn = domain_to_base_dn(&domain);
        let modules = parse_modules(&cli.modules);

        let format = match cli.format.to_lowercase().as_str() {
            "markdown" | "md" => ReportFormat::Markdown,
            "html" | "htm" => ReportFormat::Html,
            _ => ReportFormat::Json,
        };

        let username = cli
            .username
            .ok_or_else(|| anyhow::anyhow!("--username is required in CLI mode"))?;

        // Password resolution: CLI → environment → interactive prompt.
        // Keytab and Kerberos-cache authentication require GSSAPI/SASL support,
        // which diego does not implement yet.
        let password = if let Some(pwd) = cli.password {
            // Explicitly provided
            eprintln!("[+] Using password from --password");
            Zeroizing::new(pwd)
        } else if let Ok(pwd) = std::env::var("DIEGO_PASSWORD") {
            // Environment variable
            eprintln!("[+] Using password from $DIEGO_PASSWORD");
            Zeroizing::new(pwd)
        } else {
            // Interactive prompt
            eprint!("Password: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            Zeroizing::new(input.trim().to_string())
        };

        if cli.export_hashes && cli.mode != RunMode::Full {
            eprintln!("[!] --export-hashes has no effect without --mode full");
        }

        Ok(Config {
            dc_ip,
            domain,
            base_dn,
            username,
            password,
            modules,
            output: cli.output,
            format,
            baseline: cli.baseline,
            timeout_secs: cli.timeout,
            interface: cli.interface,
            ai_analyze: cli.ai_analyze || cli.chat,
            chat: cli.chat,
            ai_model: cli.ai_model,
            mode: cli.mode,
            export_hashes: cli.export_hashes,
            explain: cli.explain,
            exposure_graph: cli.exposure_graph,
            simulate_remediation: cli.simulate_remediation,
            governance_config: cli.governance_config,
            governance_output: cli.governance_output,
            sarif_output: cli.sarif_output,
            webhook_output: cli.webhook_output,
            attack_path: cli.attack_path,
            attack_path_output: cli.attack_path_output,
            mcp: cli.mcp,
        })
    }

    pub fn ldap_url(&self) -> String {
        format!("ldap://{}:389", self.dc_ip)
    }

    pub fn dc_addr_port88(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.dc_ip, 88)
    }

    pub fn realm(&self) -> String {
        self.domain.to_uppercase()
    }
}

pub fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_modules(s: &str) -> Vec<ModuleKind> {
    if s.eq_ignore_ascii_case("all") {
        return vec![ModuleKind::Ldap, ModuleKind::Kerberos, ModuleKind::Passive];
    }
    s.split(',')
        .filter_map(|m| match m.trim().to_lowercase().as_str() {
            "kerberos" | "kerb" => Some(ModuleKind::Kerberos),
            "ldap" => Some(ModuleKind::Ldap),
            "passive" | "pass" => Some(ModuleKind::Passive),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_base_dn() {
        assert_eq!(domain_to_base_dn("corp.local"), "DC=corp,DC=local");
        assert_eq!(
            domain_to_base_dn("ad.example.com"),
            "DC=ad,DC=example,DC=com"
        );
    }

    #[test]
    fn test_parse_modules_all() {
        let mods = parse_modules("all");
        assert!(mods.contains(&ModuleKind::Kerberos));
        assert!(mods.contains(&ModuleKind::Ldap));
        assert!(mods.contains(&ModuleKind::Passive));
    }

    #[test]
    fn test_parse_modules_subset() {
        let mods = parse_modules("ldap,kerberos");
        assert!(mods.contains(&ModuleKind::Ldap));
        assert!(mods.contains(&ModuleKind::Kerberos));
        assert!(!mods.contains(&ModuleKind::Passive));
    }

    fn parse_format(s: &str) -> ReportFormat {
        match s.to_lowercase().as_str() {
            "markdown" | "md" => ReportFormat::Markdown,
            "html" | "htm" => ReportFormat::Html,
            _ => ReportFormat::Json,
        }
    }

    #[test]
    fn test_parse_format() {
        assert!(matches!(parse_format("html"), ReportFormat::Html));
        assert!(matches!(parse_format("HTM"), ReportFormat::Html));
        assert!(matches!(parse_format("md"), ReportFormat::Markdown));
        assert!(matches!(parse_format("markdown"), ReportFormat::Markdown));
        assert!(matches!(parse_format("json"), ReportFormat::Json));
        assert!(matches!(parse_format("nonsense"), ReportFormat::Json));
    }

    #[test]
    fn parses_attack_path_sidecar_flag() {
        let cli = Cli::try_parse_from([
            "diego",
            "--dc",
            "10.0.0.1",
            "--domain",
            "corp.local",
            "--username",
            "jdoe",
            "--password",
            "secret",
            "--attack-path-output",
            "path.json",
        ])
        .unwrap();
        assert_eq!(cli.attack_path_output, Some(PathBuf::from("path.json")));
    }
}
