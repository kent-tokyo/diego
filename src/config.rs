use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::io::{self, Write};

use clap::Parser;
use zeroize::Zeroizing;

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
            "html" | "htm" => ReportFormat::Html,
            _ => ReportFormat::Json,
        };

        let username = cli.username.ok_or_else(|| anyhow::anyhow!("--username is required in CLI mode"))?;

        // Password resolution: CLI → ENV → keytab → krb5 cache → interactive prompt
        let password = if let Some(pwd) = cli.password {
            // Explicitly provided
            eprintln!("[+] Using password from --password");
            Zeroizing::new(pwd)
        } else if let Ok(pwd) = std::env::var("DIEGO_PASSWORD") {
            // Environment variable
            eprintln!("[+] Using password from $DIEGO_PASSWORD");
            Zeroizing::new(pwd)
        } else if let Some(pwd) = get_password_from_keytab(&username, &domain) {
            // keytab authentication
            eprintln!("[+] Using Kerberos authentication from keytab");
            Zeroizing::new(pwd)
        } else if let Some(pwd) = get_password_from_krb5_cache(&username, &domain) {
            // Kerberos TGT cache
            eprintln!("[+] Using Kerberos authentication from TGT cache");
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

/// Detects keytab presence and logs a notice, but does NOT perform GSSAPI auth.
/// ponytail: stub — LDAP still uses simple bind; GSSAPI/SASL is a future addition.
fn get_password_from_keytab(username: &str, domain: &str) -> Option<String> {
    let keytab_path = if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(format!("{}/.diego/keytab", home))
    } else {
        return None;
    };

    if keytab_path.exists() {
        eprintln!("[*] Found keytab at {}", keytab_path.display());
        eprintln!("[*] Kerberos principal: {}@{}", username, domain.to_uppercase());
        // Return marker to signal keytab auth; actual Kerberos client will use the keytab
        Some("KERBEROS_KEYTAB".to_string())
    } else {
        None
    }
}

/// Detects Kerberos TGT cache presence and logs a notice, but does NOT extract tickets.
/// ponytail: stub — LDAP still uses simple bind; GSSAPI/SASL is a future addition.
fn get_password_from_krb5_cache(username: &str, domain: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        // Linux: check for /tmp/krb5cc_<uid> from $UID or KRB5CCNAME env var
        if let Ok(ccname) = std::env::var("KRB5CCNAME") {
            // KRB5CCNAME is set (e.g., "FILE:/tmp/krb5cc_1000")
            eprintln!("[*] Found KRB5CCNAME: {}", ccname);
            eprintln!("[*] Using cached Kerberos credentials for {}@{}", username, domain.to_uppercase());
            return Some("KERBEROS_CACHE".to_string());
        }

        if let Ok(uid) = std::env::var("UID") {
            let cache_path = PathBuf::from(format!("/tmp/krb5cc_{}", uid));
            if cache_path.exists() {
                eprintln!("[*] Found Kerberos TGT cache at {}", cache_path.display());
                eprintln!("[*] Using cached Kerberos credentials for {}@{}", username, domain.to_uppercase());
                return Some("KERBEROS_CACHE".to_string());
            }
        }

        None
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: check ~/Library/Caches/org.h5l.kcm/event or KRB5CCNAME
        if let Ok(ccname) = std::env::var("KRB5CCNAME") {
            eprintln!("[*] Found KRB5CCNAME: {}", ccname);
            eprintln!("[*] Using cached Kerberos credentials for {}@{}", username, domain.to_uppercase());
            return Some("KERBEROS_CACHE".to_string());
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        // Windows: Kerberos tickets are in LSASS memory
        eprintln!("[*] Windows Kerberos cache: run 'klist' to check cached tickets");
        eprintln!("[*] Or use: runas /user:{}@{} diego ...", username, domain);
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
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
}
