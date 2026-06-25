//! Self-contained HTML report generator.
//!
//! Produces a single HTML file with inline CSS and JS — no external fonts, CDNs,
//! or network fetches, so it renders in air-gapped environments.
//!
//! Security: findings contain attacker-controlled strings (e.g. AD `description`
//! fields). Every dynamic value is HTML-escaped via [`esc`] and rendered
//! server-side into the DOM. We deliberately do NOT embed findings as a JSON
//! data-island inside `<script>` (plain escaping does not prevent `</script>`
//! breakout). The inline JS only sorts/filters pre-rendered `<tr>` rows by their
//! static `data-*` attributes, so there is no sink where report data reaches JS.

use super::{Confidence, Report, Severity};

/// HTML-escape a string. `&` must be replaced first.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn sev_class(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Numeric rank for severity sort (lower = more severe).
fn sev_rank(sev: &Severity) -> u8 {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn conf_class(c: &Confidence) -> &'static str {
    match c {
        Confidence::High => "chigh",
        Confidence::Medium => "cmedium",
        Confidence::Low => "clow",
    }
}

/// Numeric rank for confidence sort (lower = higher confidence).
fn conf_rank(c: &Confidence) -> u8 {
    match c {
        Confidence::High => 0,
        Confidence::Medium => 1,
        Confidence::Low => 2,
    }
}

const STYLE: &str = r#"
:root { --bg:#0f1115; --panel:#181b22; --border:#2a2f3a; --text:#e6e8ec; --muted:#9aa3b2;
  --critical:#d32f2f; --high:#f57c00; --medium:#fbc02d; --low:#388e3c; --info:#1976d2; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; line-height:1.5; }
.wrap { max-width:1100px; margin:0 auto; padding:32px 20px 80px; }
h1 { font-size:1.6rem; margin:0 0 4px; }
h2 { font-size:1.2rem; margin:32px 0 12px; border-bottom:1px solid var(--border); padding-bottom:6px; }
.meta { color:var(--muted); font-size:.9rem; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin:16px 0; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 18px; min-width:110px; }
.card .n { font-size:1.8rem; font-weight:700; }
.card .l { color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; }
.card.critical .n { color:var(--critical); } .card.high .n { color:var(--high); }
.card.medium .n { color:var(--medium); } .card.low .n { color:var(--low); } .card.info .n { color:var(--info); }
.badge { display:inline-block; padding:2px 8px; border-radius:6px; font-size:.72rem; font-weight:700;
  color:#fff; text-transform:uppercase; letter-spacing:.03em; }
.badge.critical { background:var(--critical); } .badge.high { background:var(--high); }
.badge.medium { background:var(--medium); color:#222; } .badge.low { background:var(--low); } .badge.info { background:var(--info); }
.conf { display:inline-block; padding:2px 7px; border-radius:6px; font-size:.7rem; font-weight:600; border:1px solid var(--border); }
.conf.chigh { color:#9ae6b4; border-color:#2f6f4f; } .conf.cmedium { color:#fbd38d; border-color:#7a5a23; } .conf.clow { color:#a0aec0; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px 18px; margin:12px 0; }
.controls { margin:12px 0; display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
.controls button { background:var(--panel); color:var(--text); border:1px solid var(--border);
  border-radius:6px; padding:6px 12px; cursor:pointer; font-size:.85rem; }
.controls button.active { border-color:var(--info); color:#fff; }
table { width:100%; border-collapse:collapse; margin-top:8px; font-size:.9rem; }
th, td { text-align:left; padding:10px; border-bottom:1px solid var(--border); vertical-align:top; }
th { cursor:pointer; color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; user-select:none; }
th:hover { color:var(--text); }
tr.detail td { background:#12141a; color:var(--muted); }
pre { background:#0b0d11; border:1px solid var(--border); border-radius:8px; padding:12px; overflow:auto; font-size:.8rem; }
a { color:#5aa0ff; }
ul { margin:6px 0; padding-left:20px; }
.diff-grp { margin:8px 0; }
.diff-grp .t { font-weight:700; margin-bottom:4px; }
.muted { color:var(--muted); }
"#;

const SCRIPT: &str = r#"
function filterSev(sev, btn){
  document.querySelectorAll('#controls button').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('tr.frow').forEach(function(r){
    var show = (sev==='all') || (r.getAttribute('data-severity')===sev);
    r.style.display = show ? '' : 'none';
    var d = r.nextElementSibling;
    if (d && d.classList.contains('detail')) d.style.display = (show && d.dataset.open==='1') ? '' : 'none';
  });
}
function sortBy(col){
  var tb = document.querySelector('#findings tbody');
  var rows = Array.prototype.slice.call(tb.querySelectorAll('tr.frow'));
  rows.sort(function(a,b){
    if(col==='severity'){ return (+a.dataset.rank) - (+b.dataset.rank); }
    if(col==='confidence'){ return (+a.dataset.confrank) - (+b.dataset.confrank); }
    return (a.dataset[col]||'').localeCompare(b.dataset[col]||'');
  });
  rows.forEach(function(r){ var d=r.nextElementSibling; tb.appendChild(r); if(d&&d.classList.contains('detail')) tb.appendChild(d); });
}
function toggleDetail(id){
  var d = document.getElementById('d-'+id);
  if(!d) return;
  var open = d.dataset.open==='1';
  d.dataset.open = open ? '0':'1';
  d.style.display = open ? 'none':'';
}
"#;

pub fn generate(report: &Report) -> String {
    let mut o = String::new();
    o.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
    o.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    o.push_str(&format!("<title>Diego Security Report — {}</title>\n", esc(&report.domain)));
    o.push_str("<style>");
    o.push_str(STYLE);
    o.push_str("</style></head><body><div class=\"wrap\">\n");

    // ── Header ────────────────────────────────────────────────────────────────
    o.push_str(&format!("<h1>Diego Security Report — {}</h1>\n", esc(&report.domain)));
    o.push_str(&format!(
        "<div class=\"meta\">Generated: {} &middot; Scanned as <code>{}</code> (standard user) &middot; DC: <code>{}</code> &middot; diego v{}</div>\n",
        report.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        esc(&report.scan_context.username),
        esc(&report.scan_context.dc_ip),
        esc(&report.version),
    ));

    // ── Baseline diff (if present) ──────────────────────────────────────────────
    if let Some(d) = &report.diff {
        o.push_str("<h2>Baseline Diff</h2>\n<div class=\"panel\">\n");
        o.push_str(&format!(
            "<div class=\"muted\">Compared against baseline from {}</div>\n",
            d.baseline_generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        ));
        let group = |title: &str, items: String| -> String {
            format!("<div class=\"diff-grp\"><div class=\"t\">{title}</div>{items}</div>")
        };
        let entries = |list: &[super::diff::DiffEntry]| -> String {
            if list.is_empty() {
                "<div class=\"muted\">none</div>".to_string()
            } else {
                let mut s = String::from("<ul>");
                for e in list {
                    s.push_str(&format!(
                        "<li><span class=\"badge {}\">{}</span> {} <span class=\"muted\">({})</span></li>",
                        sev_class(&e.severity), e.severity, esc(&e.title), esc(&e.id)
                    ));
                }
                s.push_str("</ul>");
                s
            }
        };
        o.push_str(&group(&format!("🆕 New ({})", d.new.len()), entries(&d.new)));
        o.push_str(&group(&format!("✅ Resolved ({})", d.resolved.len()), entries(&d.resolved)));
        let changed = if d.severity_changed.is_empty() {
            "<div class=\"muted\">none</div>".to_string()
        } else {
            let mut s = String::from("<ul>");
            for c in &d.severity_changed {
                s.push_str(&format!(
                    "<li>{} <span class=\"muted\">({})</span>: <span class=\"badge {}\">{}</span> → <span class=\"badge {}\">{}</span></li>",
                    esc(&c.title), esc(&c.id), sev_class(&c.from), c.from, sev_class(&c.to), c.to
                ));
            }
            s.push_str("</ul>");
            s
        };
        o.push_str(&group(&format!("⚠️ Severity changed ({})", d.severity_changed.len()), changed));
        o.push_str(&format!("<div class=\"muted\">Unchanged: {}</div>\n", d.unchanged_count));
        o.push_str("</div>\n");
    }

    // ── Severity summary cards ──────────────────────────────────────────────────
    o.push_str("<h2>Summary</h2>\n<div class=\"cards\">\n");
    for (label, n, cls) in [
        ("Critical", report.summary.critical, "critical"),
        ("High", report.summary.high, "high"),
        ("Medium", report.summary.medium, "medium"),
        ("Low", report.summary.low, "low"),
        ("Info", report.summary.info, "info"),
    ] {
        o.push_str(&format!(
            "<div class=\"card {cls}\"><div class=\"n\">{n}</div><div class=\"l\">{label}</div></div>\n"
        ));
    }
    o.push_str("</div>\n");

    // ── AI analysis (if present) ────────────────────────────────────────────────
    if let Some(ai) = &report.ai_analysis {
        o.push_str("<h2>AI Analysis</h2>\n<div class=\"panel\">\n");
        o.push_str(&format!("<div class=\"muted\">Model: {}</div>\n", esc(&ai.model)));
        o.push_str("<h3>Attack Narrative</h3>\n");
        o.push_str(&format!("<p>{}</p>\n", esc(&ai.attack_narrative).replace('\n', "<br>")));
        if !ai.critical_path.is_empty() {
            o.push_str("<h3>Critical Attack Path</h3>\n<ol>");
            for step in &ai.critical_path {
                o.push_str(&format!("<li>{}</li>", esc(step)));
            }
            o.push_str("</ol>\n");
        }
        if !ai.immediate_actions.is_empty() {
            o.push_str("<h3>Immediate Actions</h3>\n<ul>");
            for a in &ai.immediate_actions {
                o.push_str(&format!("<li>{}</li>", esc(a)));
            }
            o.push_str("</ul>\n");
        }
        o.push_str("</div>\n");
    }

    // ── Attack path overview ────────────────────────────────────────────────────
    if report.summary.critical > 0 || report.summary.high > 0 {
        o.push_str("<h2>Attack Path Overview</h2>\n<div class=\"panel\"><ul>\n");
        for f in report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
        {
            if let Some(hint) = &f.attack_path_hint {
                o.push_str(&format!(
                    "<li><span class=\"badge {}\">{}</span> <strong>{}</strong>: {}</li>\n",
                    sev_class(&f.severity), f.severity, esc(&f.title), esc(hint)
                ));
            }
        }
        o.push_str("</ul></div>\n");
    }

    // ── Findings table ──────────────────────────────────────────────────────────
    o.push_str("<h2>Findings</h2>\n");
    o.push_str("<div class=\"controls\" id=\"controls\">\n");
    o.push_str("<span class=\"muted\">Filter:</span>\n");
    o.push_str("<button class=\"active\" onclick=\"filterSev('all',this)\">All</button>\n");
    for (label, cls) in [
        ("Critical", "critical"),
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Info", "info"),
    ] {
        o.push_str(&format!("<button onclick=\"filterSev('{cls}',this)\">{label}</button>\n"));
    }
    o.push_str("</div>\n");

    o.push_str("<table id=\"findings\"><thead><tr>");
    o.push_str("<th onclick=\"sortBy('severity')\">Severity</th>");
    o.push_str("<th onclick=\"sortBy('confidence')\">Confidence</th>");
    o.push_str("<th onclick=\"sortBy('title')\">Title</th>");
    o.push_str("<th onclick=\"sortBy('module')\">Module</th>");
    o.push_str("<th>MITRE</th></tr></thead><tbody>\n");

    for (i, f) in report.findings.iter().enumerate() {
        let cls = sev_class(&f.severity);
        let mitre = match &f.mitre_id {
            Some(m) => format!(
                "<a href=\"https://attack.mitre.org/techniques/{}/\" target=\"_blank\" rel=\"noopener\">{}</a>",
                esc(&m.replace('.', "/")),
                esc(m)
            ),
            None => "—".to_string(),
        };
        let ccls = conf_class(&f.confidence);
        o.push_str(&format!(
            "<tr class=\"frow\" data-severity=\"{cls}\" data-rank=\"{rank}\" data-confidence=\"{ccls}\" data-confrank=\"{crank}\" data-title=\"{title}\" data-module=\"{module}\" onclick=\"toggleDetail({i})\">\
             <td><span class=\"badge {cls}\">{sev}</span></td><td><span class=\"conf {ccls}\">{conf}</span></td><td>{title}</td><td><code>{module}</code></td><td>{mitre}</td></tr>\n",
            cls = cls,
            rank = sev_rank(&f.severity),
            ccls = ccls,
            crank = conf_rank(&f.confidence),
            conf = f.confidence,
            sev = f.severity,
            title = esc(&f.title),
            module = esc(&f.module),
            mitre = mitre,
            i = i,
        ));

        // Detail row (collapsed by default).
        let mut detail = String::new();
        detail.push_str(&format!("<div class=\"muted\">ID: {}</div>", esc(&f.id)));
        detail.push_str(&format!("<p>{}</p>", esc(&f.description).replace('\n', "<br>")));
        if !f.evidence.is_null() {
            let ev = serde_json::to_string_pretty(&f.evidence).unwrap_or_default();
            detail.push_str(&format!("<pre>{}</pre>", esc(&ev)));
        }
        if let Some(hint) = &f.attack_path_hint {
            detail.push_str(&format!("<p><strong>Attack path:</strong> {}</p>", esc(hint)));
        }
        if !f.remediation_steps.is_empty() {
            detail.push_str("<p><strong>Remediation:</strong></p><ul>");
            for s in &f.remediation_steps {
                detail.push_str(&format!("<li>{}</li>", esc(s)));
            }
            detail.push_str("</ul>");
        }
        o.push_str(&format!(
            "<tr class=\"detail\" id=\"d-{i}\" data-open=\"0\" style=\"display:none\"><td colspan=\"5\">{detail}</td></tr>\n"
        ));
    }
    o.push_str("</tbody></table>\n");

    // ── Appendix ────────────────────────────────────────────────────────────────
    o.push_str("<h2>Appendix</h2>\n<div class=\"panel\">\n");
    o.push_str("<h3>Scan Context</h3>\n<ul>\n");
    let sc = &report.scan_context;
    o.push_str(&format!("<li>Domain: <code>{}</code></li>\n", esc(&sc.domain)));
    o.push_str(&format!("<li>Domain Controller: <code>{}</code></li>\n", esc(&sc.dc_ip)));
    o.push_str(&format!("<li>Authenticated as: <code>{}</code> ({})</li>\n", esc(&sc.username), esc(&sc.privilege_level)));
    o.push_str(&format!("<li>Modules run: {}</li>\n", esc(&sc.modules_run.join(", "))));
    o.push_str(&format!("<li>Duration: {}s</li>\n", sc.duration_secs));
    o.push_str(&format!("<li>Tool: diego v{}</li>\n", esc(&report.version)));
    o.push_str("</ul>\n");
    if let Some(d) = &report.diff {
        o.push_str(&format!(
            "<h3>Baseline</h3>\n<p>Diffed against a baseline generated {}.</p>\n",
            d.baseline_generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        ));
    }
    o.push_str("<h3>Methodology &amp; Confidence</h3>\n<ul>\n");
    o.push_str("<li>All operations are read-only LDAP and Kerberos queries; no directory writes, no OS command execution.</li>\n");
    o.push_str("<li>Randomised jitter is applied between requests to smooth timing/volume (it does not change per-request behavioural signatures).</li>\n");
    o.push_str("<li><strong>Confidence</strong>: <span class=\"conf chigh\">HIGH</span> = deterministic evidence (captured hash, UAC flag, explicit attribute); <span class=\"conf cmedium\">MEDIUM</span> = heuristic (e.g. description keyword match), review recommended; <span class=\"conf clow\">LOW</span> = circumstantial.</li>\n");
    o.push_str("<li>Detection note: avoiding .NET/PowerShell removes host-based telemetry, but DC-side sensors (e.g. Defender for Identity) can still observe Kerberoasting/AS-REP behaviour.</li>\n");
    o.push_str("</ul>\n</div>\n");

    o.push_str("<script>");
    o.push_str(SCRIPT);
    o.push_str("</script>\n");
    o.push_str("</div></body></html>\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, Report, ScanContext, Severity};

    fn ctx() -> ScanContext {
        ScanContext {
            dc_ip: "10.0.0.1".into(),
            domain: "corp.local".into(),
            username: "jdoe".into(),
            privilege_level: "standard_user".into(),
            modules_run: vec!["ldap".into()],
            duration_secs: 1,
        }
    }

    #[test]
    fn esc_handles_all_five_chars() {
        assert_eq!(esc("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&#39;f");
        // Ampersand must be escaped first (no double-escaping).
        assert_eq!(esc("<"), "&lt;");
    }

    #[test]
    fn output_is_wellformed_html() {
        let report = Report::new(ctx(), vec![]);
        let html = generate(&report);
        assert!(html.starts_with("<!DOCTYPE html"));
        assert!(html.contains("corp.local"));
        assert!(html.trim_end().ends_with("</html>"));
    }

    #[test]
    fn xss_in_finding_is_escaped() {
        // A malicious AD description must not survive as live markup.
        let payload = "<script>alert(1)</script>";
        let f = Finding::new(
            "EVIL-1",
            "ldap",
            Severity::High,
            payload,
            payload,
            serde_json::json!({ "desc": payload }),
            Some(payload.to_string()),
        );
        let report = Report::new(ctx(), vec![f]);
        let html = generate(&report);
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn renders_confidence_column_and_appendix() {
        use crate::report::Confidence;
        let f = Finding::new(
            "LDAP-DESC-LEAK-X",
            "ldap",
            Severity::High,
            "Potential credential in description",
            "heuristic match",
            serde_json::Value::Null,
            None,
        )
        .with_confidence(Confidence::Medium);
        let report = Report::new(ctx(), vec![f]);
        let html = generate(&report);
        // Confidence column header + the per-finding MEDIUM badge.
        assert!(html.contains("sortBy('confidence')"));
        assert!(html.contains("data-confidence=\"cmedium\""));
        assert!(html.contains("<span class=\"conf cmedium\">MEDIUM</span>"));
        // Appendix with scan context.
        assert!(html.contains("<h2>Appendix</h2>"));
        assert!(html.contains("Scan Context"));
    }
}
