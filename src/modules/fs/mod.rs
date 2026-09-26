//! Local file-permission posture module (Surface C).
//!
//! Read-only, unprivileged self-audit of paths the operator explicitly names
//! (`--fs-path`). It inspects only Unix permission bits on files/directories the
//! current user can already stat, flagging over-permissive private keys and
//! credential files, world-writable files/dirs, and loose `.ssh`/`.gnupg`
//! permissions. It never reads file contents, never follows symlinks, never
//! executes OS commands, and never escalates. Bounded by depth and entry count.

pub mod analyze;

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Config;
use crate::modules::DiagnosticModule;
use crate::report::{Confidence, Finding, Severity};

use self::analyze::{Conf, Issue, Sev};

const MAX_DEPTH: usize = 8;
const MAX_ENTRIES: usize = 50_000;

pub struct FsModule;

impl Default for FsModule {
    fn default() -> Self {
        Self::new()
    }
}

impl FsModule {
    pub fn new() -> Self {
        FsModule
    }
}

fn map_sev(s: Sev) -> Severity {
    match s {
        Sev::Critical => Severity::Critical,
        Sev::High => Severity::High,
        Sev::Medium => Severity::Medium,
        Sev::Low => Severity::Low,
        Sev::Info => Severity::Info,
    }
}

fn map_conf(c: Conf) -> Confidence {
    match c {
        Conf::High => Confidence::High,
        Conf::Medium => Confidence::Medium,
        Conf::Low => Confidence::Low,
    }
}

fn issue_to_finding(issue: Issue) -> Finding {
    let evidence = if issue.evidence.is_empty() {
        serde_json::Value::Null
    } else {
        let map: serde_json::Map<String, serde_json::Value> = issue
            .evidence
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        serde_json::Value::Object(map)
    };
    let mut f = Finding::new(
        issue.id,
        "fs",
        map_sev(issue.sev),
        issue.title,
        issue.desc,
        evidence,
        None,
    )
    .with_confidence(map_conf(issue.conf));
    if !issue.remediation.is_empty() {
        let steps: Vec<&str> = issue.remediation.iter().map(String::as_str).collect();
        f = f.with_remediation(steps);
    }
    f
}

#[cfg(unix)]
fn walk(root: &std::path::Path, findings: &mut Vec<Finding>) {
    use std::os::unix::fs::PermissionsExt;

    fn visit(
        path: &std::path::Path,
        depth: usize,
        seen: &mut usize,
        findings: &mut Vec<Finding>,
    ) {
        if depth > MAX_DEPTH || *seen >= MAX_ENTRIES {
            return;
        }
        // symlink_metadata does not follow symlinks.
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return;
        };
        if meta.file_type().is_symlink() {
            return; // never follow symlinks
        }
        *seen += 1;
        let mode = meta.permissions().mode();
        let is_dir = meta.is_dir();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        for issue in analyze::classify(&path.to_string_lossy(), name, mode, is_dir) {
            findings.push(issue_to_finding(issue));
        }
        if is_dir
            && let Ok(rd) = std::fs::read_dir(path)
        {
            for entry in rd.flatten() {
                visit(&entry.path(), depth + 1, seen, findings);
            }
        }
    }

    let mut seen = 0usize;
    visit(root, 0, &mut seen, findings);
}

#[async_trait]
impl DiagnosticModule for FsModule {
    fn name(&self) -> &'static str {
        "fs"
    }

    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>> {
        if config.fs_paths.is_empty() {
            return Ok(vec![Finding::skipped(
                "fs",
                "No paths provided (use --fs-path <dir|file>[,<dir|file>])",
            )]);
        }

        #[cfg(not(unix))]
        {
            return Ok(vec![Finding::skipped(
                "fs",
                "File-permission posture checks are only implemented for Unix hosts",
            )]);
        }

        #[cfg(unix)]
        {
            let mut findings = Vec::new();
            for raw in &config.fs_paths {
                let path = std::path::Path::new(raw);
                if !path.exists() {
                    findings.push(Finding::skipped("fs", &format!("Path not found: {raw}")));
                    continue;
                }
                eprintln!("[+] fs: scanning {raw}");
                walk(path, &mut findings);
            }
            if findings.is_empty() {
                findings.push(Finding::skipped(
                    "fs",
                    "No permission issues found in the scanned paths",
                ));
            }
            Ok(findings)
        }
    }
}
