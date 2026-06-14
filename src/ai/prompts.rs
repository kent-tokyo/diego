//! System prompts and finding-to-prompt converters for Claude API calls.

use crate::report::Report;

/// Build the system prompt for the initial analysis pass.
pub fn analysis_system_prompt(domain: &str) -> String {
    format!(
        r#"You are a senior penetration tester and Active Directory security expert.
You are analyzing output from "diego" — a non-privileged AD diagnostic tool that operates
with only standard domain user credentials (no admin rights) against domain '{domain}'.

Your role:
1. Synthesize the findings into a coherent attack narrative from an attacker's perspective
2. Identify the shortest path from a standard domain user to Domain Admin
3. Provide specific, environment-aware remediation steps for the most critical issues
4. Be technically precise — reference exact account names and techniques where evidence supports it

Output format (respond in JSON only, no markdown):
{{
  "attack_narrative": "<2-4 paragraph narrative describing the overall attack surface and most dangerous findings>",
  "critical_path": ["<step 1>", "<step 2>", "..."],
  "immediate_actions": ["<top priority fix 1>", "<top priority fix 2>", "..."]
}}

Severity order: CRITICAL > HIGH > MEDIUM > LOW > INFO.
Focus on CRITICAL and HIGH findings for the attack path. Be concise and actionable."#,
        domain = domain
    )
}

/// Build the user message for the analysis pass — serializes the full report as JSON context.
pub fn analysis_user_message(report: &Report) -> anyhow::Result<String> {
    let report_json = serde_json::to_string_pretty(report)?;
    Ok(format!(
        "Analyze the following diego security scan results for domain '{domain}'.\n\nScan results:\n```json\n{json}\n```",
        domain = report.domain,
        json = report_json
    ))
}

/// System prompt for the interactive chat REPL.
pub fn chat_system_prompt(domain: &str, report_json: &str) -> String {
    format!(
        r#"You are a senior penetration tester and Active Directory security expert.
You previously analyzed a diego security scan against domain '{domain}'.
The full scan report is provided below for reference.

Answer the user's questions accurately and concisely. When referencing specific findings,
cite the finding ID (e.g. KERB-ASREP-ALICE) and explain the technical details.
If asked for remediation steps, be specific and actionable.
If asked for attack techniques, explain them for defensive/educational purposes.

Scan report:
```json
{report}
```"#,
        domain = domain,
        report = report_json
    )
}
