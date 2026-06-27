//! PyO3 Python bindings for diego.
//!
//! Activated by `--features python` (maturin uses this automatically via pyproject.toml).
//! Entry point: `diego.scan(dc, domain, username, password, modules="all") -> dict`

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use zeroize::Zeroizing;

use crate::config::{Config, ReportFormat, parse_modules, domain_to_base_dn};

// ─── serde_json::Value → Python object ────────────────────────────────────────

fn val_to_py(py: Python<'_>, val: &serde_json::Value) -> PyObject {
    match val {
        serde_json::Value::Null => py.None(),
        serde_json::Value::Bool(b) => {
            pyo3::types::PyBool::new(py, *b).to_owned().into_any().unbind()
        }
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py).unwrap().into_any().unbind()
            } else if let Some(f) = n.as_f64() {
                f.into_pyobject(py).unwrap().into_any().unbind()
            } else {
                py.None()
            }
        }
        serde_json::Value::String(s) => s.as_str().into_pyobject(py).unwrap().into_any().unbind(),
        serde_json::Value::Array(arr) => {
            let list = PyList::new(py, arr.iter().map(|v| val_to_py(py, v))).unwrap();
            list.into_any().unbind()
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, val_to_py(py, v)).unwrap();
            }
            dict.into_any().unbind()
        }
    }
}

// ─── Config builder ────────────────────────────────────────────────────────────

fn build_config(
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    modules: &str,
    timeout: u64,
) -> anyhow::Result<Config> {
    Ok(Config {
        dc_ip: IpAddr::from_str(dc)
            .map_err(|_| anyhow::anyhow!("Invalid DC IP address: {dc}"))?,
        domain: domain.to_string(),
        base_dn: domain_to_base_dn(domain),
        username: username.to_string(),
        password: Zeroizing::new(password.to_string()),
        modules: parse_modules(modules),
        output: None,
        format: ReportFormat::Json,
        baseline: None,
        timeout_secs: timeout,
        interface: None,
        ai_analyze: false,
        chat: false,
        ai_model: crate::ai::claude::DEFAULT_MODEL.to_string(),
        mcp: false,
    })
}

// ─── Python-exposed functions ──────────────────────────────────────────────────

/// Run a diego AD diagnostic scan and return a Python dict matching the JSON report schema.
///
/// Args:
///     dc (str): Domain Controller IP address.
///     domain (str): Domain name, e.g. "corp.local".
///     username (str): Domain username.
///     password (str): Password (use DIEGO_PASSWORD env var instead where possible).
///     modules (str): Comma-separated modules to run: "ldap", "kerberos", "passive", or "all".
///     timeout (int): Per-query timeout in seconds (default: 10).
///
/// Returns:
///     dict: Report matching docs/report.schema.json — keys: tool, version, domain,
///           generated_at, scan_context, findings, summary.
#[pyfunction]
#[pyo3(signature = (dc, domain, username, password, modules="all", timeout=10))]
fn scan(
    py: Python<'_>,
    dc: &str,
    domain: &str,
    username: &str,
    password: &str,
    modules: &str,
    timeout: u64,
) -> PyResult<PyObject> {
    let config = build_config(dc, domain, username, password, modules, timeout)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    // tokio::Runtime::block_on keeps pyo3-asyncio out of scope while still
    // running async Rust. Python callers get a regular synchronous return value.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let report = rt
        .block_on(crate::run_scan(Arc::new(config)))
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let json_val = serde_json::to_value(&report)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    Ok(val_to_py(py, &json_val))
}

/// Return the diego version string.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ─── Module registration ───────────────────────────────────────────────────────

#[pymodule]
fn diego(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
