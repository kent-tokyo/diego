//! MCP server — JSON-RPC 2.0 over stdio.
//!
//! Protocol: https://spec.modelcontextprotocol.io/specification/
//! Transport: newline-delimited JSON on stdin/stdout.
//!
//! Handled methods:
//!   initialize        → return capabilities
//!   tools/list        → return tool schemas
//!   tools/call        → execute a tool and return result
//!   ping              → return empty response
//! All others → method-not-found error

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::tools;

// ─── JSON-RPC types ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RpcRequest {
    // Part of the JSON-RPC 2.0 envelope; deserialized for completeness.
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize)]
struct RpcSuccess {
    jsonrpc: &'static str,
    id: Value,
    result: Value,
}

#[derive(Serialize)]
struct RpcError {
    jsonrpc: &'static str,
    id: Value,
    error: RpcErrorBody,
}

#[derive(Serialize)]
struct RpcErrorBody {
    code: i32,
    message: String,
}

fn success(id: Value, result: Value) -> String {
    serde_json::to_string(&RpcSuccess { jsonrpc: "2.0", id, result }).unwrap()
}

fn error(id: Value, code: i32, message: impl Into<String>) -> String {
    serde_json::to_string(&RpcError {
        jsonrpc: "2.0",
        id,
        error: RpcErrorBody { code, message: message.into() },
    })
    .unwrap()
}

// ─── Server main loop ─────────────────────────────────────────────────────────

/// Run the MCP server. Reads JSON-RPC requests from stdin and writes responses to stdout.
/// Blocking — run inside `#[tokio::main]`.
pub async fn run() {
    eprintln!("[mcp] diego MCP server started (stdio transport)");

    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(_) => break,
        };

        let request: RpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let msg = error(Value::Null, -32700, format!("Parse error: {}", e));
                writeln!(stdout.lock(), "{}", msg).ok();
                continue;
            }
        };

        let id = request.id.clone().unwrap_or(Value::Null);
        let response = handle(request).await;

        let out = match response {
            Ok(result) => success(id, result),
            Err(e) => error(id, -32603, format!("{}", e)),
        };

        writeln!(stdout.lock(), "{}", out).ok();
        stdout.lock().flush().ok();
    }

    eprintln!("[mcp] diego MCP server stopped");
}

// ─── Request handler ──────────────────────────────────────────────────────────

async fn handle(req: RpcRequest) -> anyhow::Result<Value> {
    match req.method.as_str() {
        "initialize" => Ok(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "diego",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Non-privileged Active Directory security diagnostic agent"
            }
        })),

        "initialized" => Ok(Value::Object(Default::default())),

        "ping" => Ok(Value::Object(Default::default())),

        "tools/list" => Ok(serde_json::json!({
            "tools": tools::tool_list()
        })),

        "tools/call" => {
            let params = req.params.unwrap_or(Value::Object(Default::default()));
            let tool_name = params.get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("Missing 'name' in tools/call params"))?;
            let args = params.get("arguments").cloned().unwrap_or(Value::Object(Default::default()));

            let result = tools::dispatch(tool_name, &args).await
                .map_err(|e| anyhow::anyhow!("Tool '{}' failed: {}", tool_name, e))?;

            // MCP tool result format: content array
            Ok(serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&result)?
                }],
                "isError": false
            }))
        }

        _ => anyhow::bail!("Method not found: {}", req.method),
    }
}
