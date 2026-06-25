use super::{Report, Severity};

pub fn generate(report: &Report) -> String {
    let mut out = String::new();

    out.push_str(&format!("# Diego Security Report — {}\n\n", report.domain));
    out.push_str(&format!(
        "_Generated: {} | Scanned as: `{}` (standard user) | DC: `{}`_\n\n",
        report.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        report.scan_context.username,
        report.scan_context.dc_ip,
    ));

    // ── AI Analysis (if present) ──────────────────────────────────────────────
    if let Some(ai) = &report.ai_analysis {
        out.push_str("## AI Analysis\n\n");
        out.push_str(&format!("_Model: {}_\n\n", ai.model));
        out.push_str("### Attack Narrative\n\n");
        out.push_str(&ai.attack_narrative);
        out.push_str("\n\n");

        if !ai.critical_path.is_empty() {
            out.push_str("### Critical Attack Path (Standard User → Domain Admin)\n\n");
            for (i, step) in ai.critical_path.iter().enumerate() {
                out.push_str(&format!("{}. {}\n", i + 1, step));
            }
            out.push('\n');
        }

        if !ai.immediate_actions.is_empty() {
            out.push_str("### Immediate Actions Required\n\n");
            for action in &ai.immediate_actions {
                out.push_str(&format!("- [ ] {}\n", action));
            }
            out.push('\n');
        }
        out.push_str("---\n\n");
    }

    // ── Baseline Diff (if present) ────────────────────────────────────────────
    if let Some(d) = &report.diff {
        out.push_str("## Baseline Diff\n\n");
        out.push_str(&format!(
            "_Compared against baseline from {}_\n\n",
            d.baseline_generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        ));
        out.push_str(&format!("🆕 **New ({})**\n\n", d.new.len()));
        for e in &d.new {
            out.push_str(&format!("- [{}] {} (`{}`)\n", e.severity, e.title, e.id));
        }
        out.push_str(&format!("\n✅ **Resolved ({})**\n\n", d.resolved.len()));
        for e in &d.resolved {
            out.push_str(&format!("- [{}] {} (`{}`)\n", e.severity, e.title, e.id));
        }
        out.push_str(&format!("\n⚠️ **Severity Changed ({})**\n\n", d.severity_changed.len()));
        for c in &d.severity_changed {
            out.push_str(&format!("- {} (`{}`): {} → {}\n", c.title, c.id, c.from, c.to));
        }
        out.push_str(&format!("\n_Unchanged: {}_\n\n", d.unchanged_count));
        out.push_str("---\n\n");
    }

    // ── Executive Summary ─────────────────────────────────────────────────────
    out.push_str("## Executive Summary\n\n");
    out.push_str(&format!(
        "| Severity | Count |\n|----------|-------|\n| Critical | {} |\n| High     | {} |\n| Medium   | {} |\n| Low      | {} |\n| Info     | {} |\n\n",
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info,
    ));

    if report.summary.critical > 0 || report.summary.high > 0 {
        out.push_str("### Attack Path Overview\n\n");
        for f in report.findings.iter().filter(|f| {
            f.severity == Severity::Critical || f.severity == Severity::High
        }) {
            if let Some(hint) = &f.attack_path_hint {
                out.push_str(&format!("- **[{}] {}**: {}\n", f.severity, f.title, hint));
            }
        }
        out.push('\n');
    }

    // ── Findings ──────────────────────────────────────────────────────────────
    out.push_str("## Findings\n\n");

    for f in &report.findings {
        let icon = match f.severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Info => "🔵",
        };
        out.push_str(&format!(
            "### {} [{} / Confidence: {}] {} ({})\n\n",
            icon, f.severity, f.confidence, f.title, f.id
        ));
        out.push_str(&format!("**Module**: `{}`", f.module));
        if let Some(mitre) = &f.mitre_id {
            out.push_str(&format!(" | **MITRE**: [{mitre}](https://attack.mitre.org/techniques/{}/)", mitre.replace('.', "/")));
        }
        out.push_str("\n\n");
        out.push_str(&format!("{}\n\n", f.description));

        if !f.evidence.is_null() {
            out.push_str("**Evidence**:\n\n```json\n");
            out.push_str(&serde_json::to_string_pretty(&f.evidence).unwrap_or_default());
            out.push_str("\n```\n\n");
        }

        if let Some(hint) = &f.attack_path_hint {
            out.push_str(&format!("> **Attack Path**: {}\n\n", hint));
        }

        if !f.remediation_steps.is_empty() {
            out.push_str("**Remediation**:\n\n");
            for step in &f.remediation_steps {
                out.push_str(&format!("- [ ] {}\n", step));
            }
            out.push('\n');
        }

        out.push_str("---\n\n");
    }

    out
}
