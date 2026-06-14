//! Interactive AI chat REPL.
//!
//! After a scan + AI analysis, enters a stdin loop where the user can ask
//! follow-up questions about the findings in natural language.
//! Claude's responses are streamed to the terminal in real time.

use std::io::{self, BufRead, Write};

use super::claude::{ClaudeClient, Message};
use super::prompts::chat_system_prompt;
use crate::report::Report;

/// Run the interactive REPL. Exits on Ctrl+C, EOF, or the user typing "exit"/"quit".
pub async fn run_chat(client: &ClaudeClient, report: &Report) -> anyhow::Result<()> {
    let report_json = serde_json::to_string_pretty(report)
        .unwrap_or_else(|_| "{}".into());
    let system = chat_system_prompt(&report.domain, &report_json);

    let mut history: Vec<Message> = Vec::new();

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  Diego AI Chat  —  domain: {}  ", report.domain);
    eprintln!("║  Type your question, or 'exit' / Ctrl+C to quit.        ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    let stdin = io::stdin();
    loop {
        print!("Diego AI> ");
        io::stdout().flush()?;

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break,             // EOF (Ctrl+D)
            Ok(_) => {}
            Err(e) => {
                eprintln!("[!] stdin error: {}", e);
                break;
            }
        }

        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if matches!(input.to_lowercase().as_str(), "exit" | "quit" | "q") {
            break;
        }

        history.push(Message::user(input));

        print!("\n[Claude]: ");
        io::stdout().flush()?;

        match client.stream_message(&system, &history).await {
            Ok(response) => {
                history.push(Message::assistant(&response));
                eprintln!();
            }
            Err(e) => {
                eprintln!("[!] Claude API error: {}", e);
                // Remove the user message so the history stays clean
                history.pop();
            }
        }
    }

    eprintln!("[+] Chat session ended.");
    Ok(())
}
