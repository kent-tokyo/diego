use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use zeroize::ZeroizeOnDrop;

#[derive(Parser, Debug)]
#[command(
    name = "diego",
    about = "Domain Intranet Elusive Guardian & Offensive-Scouter\nNon-privileged Active Directory security diagnostic agent"
)]
pub struct Cli {
    /// Domain Controller IP address (required for CLI mode)
    #[arg(long, required_unless_present = "mcp")]
    pub dc: Option<String>,

    /// Domain name (e.g. corp.local)
    #[arg(long, required_unless_present = "mcp")]
    pub domain: Option<String>,

    /// Username for authentication
    #[arg(long, required_unless_present = "mcp")]
    pub username: Option<String>,

    /// Password for authentication
    #[arg(long, required_unless_present = "mcp")]
    pub password: Option<String>,

    /// Modules to run: kerberos, ldap, passive, all
    #[arg(long, default_value = "all")]
    pub modules: String,

    /// Output file path
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Output format: json or markdown
    #[arg(long, default_value = "json")]
    pub format: String,

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

    // ── MCP mode ─────────────────────────────────────────────────────────────

    /// Run as an MCP (Model Context Protocol) server over stdio
    #[arg(long)]
    pub mcp: bool,

    /// Write a Claude Desktop MCP configuration snippet to stdout and exit
    #[arg(long)]
    pub mcp_init: bool,
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
}

#[derive(Clone, Debug)]
pub struct Config {
    pub dc_ip: IpAddr,
    pub domain: String,
    pub base_dn: String,
    pub username: String,
    pub password: String,
    pub modules: Vec<ModuleKind>,
    pub output: Option<PathBuf>,
    pub format: ReportFormat,
    pub timeout_secs: u64,
    pub interface: Option<String>,
    // AI
    pub ai_analyze: bool,
    pub chat: bool,
    pub ai_model: String,
    // MCP
    pub mcp: bool,
}

impl Config {
    pub fn from_cli(cli: Cli) -> anyhow::Result<Self> {
        let dc_str = cli.dc.ok_or_else(|| anyhow::anyhow!("--dc is required in CLI mode"))?;
        let dc_ip = IpAddr::from_str(&dc_str)
            .map_err(|_| anyhow::anyhow!("Invalid DC IP address: {}", dc_str))?;

        let domain = cli.domain.ok_or_else(|| anyhow::anyhow!("--domain is required in CLI mode"))?;
        let base_dn = domain_to_base_dn(&domain);
        let modules = parse_modules(&cli.modules);

        let format = match cli.format.to_lowercase().as_str() {
            "markdown" | "md" => ReportFormat::Markdown,
            _ => ReportFormat::Json,
        };

        Ok(Config {
            dc_ip,
            domain,
            base_dn,
            username: cli.username.unwrap_or_default(),
            password: cli.password.unwrap_or_default(),
            modules,
            output: cli.output,
            format,
            timeout_secs: cli.timeout,
            interface: cli.interface,
            ai_analyze: cli.ai_analyze || cli.chat,
            chat: cli.chat,
            ai_model: cli.ai_model,
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
        assert_eq!(domain_to_base_dn("ad.example.com"), "DC=ad,DC=example,DC=com");
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
}
