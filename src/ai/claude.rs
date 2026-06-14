//! Claude API HTTP client.
//!
//! Supports two modes:
//! - `analyze_report`: non-streaming, returns AiAnalysis
//! - `stream_message`: streaming SSE, yields text chunks for REPL display

use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::report::{AiAnalysis, Report};

use super::prompts::{analysis_system_prompt, analysis_user_message};

pub const DEFAULT_MODEL: &str = "claude-sonnet-4-6";
const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_TOKENS: u32 = 4096;

// ─── Wire types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

impl Message {
    pub fn user(content: impl Into<String>) -> Self {
        Message { role: "user".into(), content: content.into() }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Message { role: "assistant".into(), content: content.into() }
    }
}

#[derive(Serialize)]
struct ApiRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: &'a [Message],
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
}

#[derive(Deserialize)]
struct ApiResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: String,
}

// Streaming SSE event structs
#[derive(Deserialize)]
struct StreamDelta {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
}

#[derive(Deserialize)]
struct StreamEvent {
    #[serde(rename = "type")]
    kind: String,
    delta: Option<StreamDelta>,
}

// ─── Client ───────────────────────────────────────────────────────────────────

pub struct ClaudeClient {
    api_key: Zeroizing<String>, // API key zeroized on drop
    pub model: String,
    client: reqwest::Client,
}

impl ClaudeClient {
    /// Create a client. Reads `ANTHROPIC_API_KEY` if `api_key` is None.
    pub fn new(api_key: Option<String>, model: Option<String>) -> anyhow::Result<Self> {
        let key = api_key
            .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
            .ok_or_else(|| anyhow::anyhow!(
                "No Anthropic API key found. Set ANTHROPIC_API_KEY environment variable."
            ))?;

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_str(&key)?);
        headers.insert("anthropic-version", HeaderValue::from_static(ANTHROPIC_VERSION));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;

        Ok(ClaudeClient {
            api_key: Zeroizing::new(key),
            model: model.unwrap_or_else(|| DEFAULT_MODEL.into()),
            client,
        })
    }

    /// Non-streaming: analyze the scan report and return structured AiAnalysis.
    pub async fn analyze_report(&self, report: &Report) -> anyhow::Result<AiAnalysis> {
        let system = analysis_system_prompt(&report.domain);
        let user_msg = analysis_user_message(report)?;

        let body = ApiRequest {
            model: &self.model,
            max_tokens: MAX_TOKENS,
            system: &system,
            messages: &[Message::user(&user_msg)],
            stream: false,
        };

        let resp = self.client
            .post(ANTHROPIC_API_URL)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Claude API error {}: {}", status, text);
        }

        let api_resp: ApiResponse = resp.json().await?;
        let raw_text = api_resp.content.first()
            .map(|c| c.text.as_str())
            .unwrap_or("")
            .trim();

        // Strip markdown code fences if present
        let json_str = raw_text
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        #[derive(Deserialize)]
        struct AnalysisJson {
            attack_narrative: String,
            critical_path: Vec<String>,
            immediate_actions: Vec<String>,
        }

        let parsed: AnalysisJson = serde_json::from_str(json_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse Claude response as JSON: {}\nRaw: {}", e, json_str))?;

        Ok(AiAnalysis {
            model: self.model.clone(),
            attack_narrative: parsed.attack_narrative,
            critical_path: parsed.critical_path,
            immediate_actions: parsed.immediate_actions,
            generated_at: chrono::Utc::now(),
        })
    }

    /// Streaming: send a message and stream the response text to stdout, returning the full text.
    pub async fn stream_message(
        &self,
        system: &str,
        messages: &[Message],
    ) -> anyhow::Result<String> {
        let body = ApiRequest {
            model: &self.model,
            max_tokens: MAX_TOKENS,
            system,
            messages,
            stream: true,
        };

        let resp = self.client
            .post(ANTHROPIC_API_URL)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Claude API error {}: {}", status, text);
        }

        let mut stream = resp.bytes_stream();
        let mut full_text = String::new();
        let mut buffer = String::new();

        while let Some(chunk) = stream.next().await {
            let bytes = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&bytes));

            // Parse SSE lines: "data: {...}"
            loop {
                if let Some(newline_pos) = buffer.find('\n') {
                    let line = buffer[..newline_pos].trim().to_string();
                    buffer = buffer[newline_pos + 1..].to_string();

                    if let Some(data) = line.strip_prefix("data: ") {
                        if data == "[DONE]" {
                            break;
                        }
                        if let Ok(event) = serde_json::from_str::<StreamEvent>(data) {
                            if event.kind == "content_block_delta" {
                                if let Some(delta) = event.delta {
                                    if delta.kind == "text_delta" {
                                        if let Some(text) = delta.text {
                                            print!("{}", text);
                                            use std::io::Write;
                                            std::io::stdout().flush().ok();
                                            full_text.push_str(&text);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        }

        println!(); // newline after stream ends
        Ok(full_text)
    }
}
