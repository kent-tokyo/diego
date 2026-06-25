pub mod diff;
pub mod html;
pub mod json;
pub mod markdown;
pub mod sample;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

use crate::config::{Config, ReportFormat};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// How sure diego is that a finding is a true positive — distinct from how
/// damaging it would be (`Severity`).
///
/// - `High`   — deterministic evidence (a captured hash, a UAC flag bit, an
///   explicit delegation attribute). Effectively no false-positive risk.
/// - `Medium` — heuristic detection (e.g. keyword match in a description
///   field, a spray-feasibility estimate). Plausible but warrants review.
/// - `Low`    — circumstantial / inferred; treat as a lead, not a conclusion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    #[default]
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::High => write!(f, "HIGH"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub module: String,
    pub severity: Severity,
    /// Confidence that this finding is a true positive (default `High`).
    /// `#[serde(default)]` so baseline reports written by older diego builds
    /// (which lack this field) still deserialize for `--baseline` diffs.
    #[serde(default)]
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub evidence: serde_json::Value,
    pub attack_path_hint: Option<String>,
    pub timestamp: DateTime<Utc>,

    // ── AI-first fields ───────────────────────────────────────────────────────
    /// Plain-English context for LLM consumption — why this is dangerous and
    /// what it means to an attacker. Empty string if not explicitly set.
    pub llm_context: String,
    /// Ordered list of concrete remediation steps.
    pub remediation_steps: Vec<String>,
    /// MITRE ATT&CK technique ID (e.g. "T1558.004").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_id: Option<String>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        module: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence: serde_json::Value,
        attack_path_hint: Option<String>,
    ) -> Self {
        Finding {
            id: id.into(),
            module: module.into(),
            severity,
            confidence: Confidence::High,
            title: title.into(),
            description: description.into(),
            evidence,
            attack_path_hint,
            timestamp: Utc::now(),
            llm_context: String::new(),
            remediation_steps: Vec::new(),
            mitre_id: None,
        }
    }

    /// Builder: set the LLM context string.
    pub fn with_llm_context(mut self, ctx: impl Into<String>) -> Self {
        self.llm_context = ctx.into();
        self
    }

    /// Builder: set concrete remediation steps.
    pub fn with_remediation(mut self, steps: Vec<&str>) -> Self {
        self.remediation_steps = steps.into_iter().map(String::from).collect();
        self
    }

    /// Builder: set a MITRE ATT&CK technique ID.
    pub fn with_mitre(mut self, id: impl Into<String>) -> Self {
        self.mitre_id = Some(id.into());
        self
    }

    /// Builder: set detection confidence (defaults to `High`).
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Create an INFO-level finding indicating a module was skipped.
    pub fn skipped(module: &str, reason: &str) -> Self {
        Finding::new(
            format!("{}-SKIP", module.to_uppercase()),
            module,
            Severity::Info,
            format!("Module {} skipped", module),
            reason,
            serde_json::Value::Null,
            None,
        )
    }
}

// ─── Scan context ─────────────────────────────────────────────────────────────

/// Metadata about the scan itself — included in the report so an LLM
/// can reason about privilege level, scope, and timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    pub dc_ip: String,
    pub domain: String,
    pub username: String,
    /// Always "standard_user" — diego never requires admin rights.
    pub privilege_level: String,
    pub modules_run: Vec<String>,
    pub duration_secs: u64,
}

// ─── AI analysis ──────────────────────────────────────────────────────────────

/// Structured output produced by the Claude API analysis pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysis {
    pub model: String,
    /// Narrative describing the overall attack surface.
    pub attack_narrative: String,
    /// Ordered steps from standard user to Domain Admin.
    pub critical_path: Vec<String>,
    /// Top-priority fixes the defender should take immediately.
    pub immediate_actions: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

// ─── Report ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub domain: String,
    pub generated_at: DateTime<Utc>,
    pub scan_context: ScanContext,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_analysis: Option<AiAnalysis>,
    /// Comparison against a prior baseline report, if `--baseline` was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<diff::ReportDiff>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

impl Report {
    pub fn new(scan_context: ScanContext, mut findings: Vec<Finding>) -> Self {
        findings.sort_by(|a, b| a.severity.cmp(&b.severity));

        let summary = Summary {
            critical: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            high: findings.iter().filter(|f| f.severity == Severity::High).count(),
            medium: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            low: findings.iter().filter(|f| f.severity == Severity::Low).count(),
            info: findings.iter().filter(|f| f.severity == Severity::Info).count(),
            total: findings.len(),
        };

        let domain = scan_context.domain.clone();

        Report {
            tool: "diego".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            domain,
            generated_at: Utc::now(),
            scan_context,
            findings,
            summary,
            ai_analysis: None,
            diff: None,
        }
    }

    pub fn with_ai_analysis(mut self, analysis: AiAnalysis) -> Self {
        self.ai_analysis = Some(analysis);
        self
    }

    pub fn with_diff(mut self, diff: diff::ReportDiff) -> Self {
        self.diff = Some(diff);
        self
    }

    pub async fn write(&self, config: &Arc<Config>) -> anyhow::Result<()> {
        let content = match config.format {
            ReportFormat::Json => json::generate(self)?,
            ReportFormat::Markdown => markdown::generate(self),
            ReportFormat::Html => html::generate(self),
        };

        match &config.output {
            Some(path) => {
                tokio::fs::write(path, &content).await?;
                eprintln!("[+] Report written to {}", path.display());
            }
            None => println!("{}", content),
        }
        Ok(())
    }
}

/// Helper to build a ScanContext from config + measured duration.
pub fn make_scan_context(config: &Config, modules_run: Vec<String>, start: Instant) -> ScanContext {
    ScanContext {
        dc_ip: config.dc_ip.to_string(),
        domain: config.domain.clone(),
        username: config.username.clone(),
        privilege_level: "standard_user".into(),
        modules_run,
        duration_secs: start.elapsed().as_secs(),
    }
}
