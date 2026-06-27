pub mod diff;
pub mod html;
pub mod json;
pub mod markdown;
pub mod sample;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

use crate::config::{Config, ReportFormat, RunMode};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let emit_hashes = config.mode == RunMode::Full && config.export_hashes;
        let content = if emit_hashes {
            match config.format {
                ReportFormat::Json => json::generate(self)?,
                ReportFormat::Markdown => markdown::generate(self),
                ReportFormat::Html => html::generate(self),
            }
        } else {
            let mut redacted = self.clone();
            for f in &mut redacted.findings {
                redact_evidence(&mut f.evidence);
            }
            match config.format {
                ReportFormat::Json => json::generate(&redacted)?,
                ReportFormat::Markdown => markdown::generate(&redacted),
                ReportFormat::Html => html::generate(&redacted),
            }
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

const REDACTED: &str = "[REDACTED — use --mode full --export-hashes]";

/// Recursively replace sensitive evidence keys with a redaction marker.
///
/// Denylist keys:
/// - `hashcat_hash` — AS-REP / TGS-REP crackable hashes from the Kerberos module
/// - `hash` — legacy key used in sample data (normalised to hashcat_hash in future)
/// - `detail` — cleartext capture credential strings (generic name but only used in
///   passive/cleartext findings where it holds captured FTP/HTTP passwords)
pub fn redact_evidence(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if matches!(key.as_str(), "hashcat_hash" | "hash" | "detail") {
                    *v = serde_json::Value::String(REDACTED.into());
                } else {
                    redact_evidence(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_evidence(v);
            }
        }
        _ => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_asrep_finding() -> Finding {
        Finding::new(
            "KRB-ASREP-test",
            "kerberos",
            Severity::Critical,
            "AS-REP Roastable Account",
            "test",
            serde_json::json!({
                "account": "svc_test",
                "hashcat_hash": "$krb5asrep$23$svc_test@TEST.LOCAL:deadbeef",
                "hashcat_mode": 18200,
            }),
            None,
        )
    }

    #[test]
    fn redact_evidence_removes_hash_in_audit_mode() {
        let mut f = fake_asrep_finding();
        redact_evidence(&mut f.evidence);
        let serialized = serde_json::to_string(&f.evidence).unwrap();
        assert!(!serialized.contains("deadbeef"), "hash must not appear in audit output");
        assert!(serialized.contains(REDACTED), "redaction marker must be present");
    }

    #[test]
    fn redact_evidence_removes_detail_in_nested_capture() {
        let mut val = serde_json::json!({
            "captures": [
                { "protocol": "FTP", "src": "1.2.3.4", "detail": "PASS secret123" }
            ]
        });
        redact_evidence(&mut val);
        let s = serde_json::to_string(&val).unwrap();
        assert!(!s.contains("secret123"));
        assert!(s.contains(REDACTED));
    }

    #[test]
    fn redact_evidence_preserves_non_sensitive_keys() {
        let mut val = serde_json::json!({ "account": "jdoe", "lockout_threshold": 10 });
        redact_evidence(&mut val);
        let s = serde_json::to_string(&val).unwrap();
        assert!(s.contains("jdoe"));
        assert!(s.contains("10"));
    }
}
