//! Generate sample reports (HTML / Markdown / JSON) from a synthetic fixture.
//!
//! Useful for previewing the report UI and producing README screenshots without
//! needing a live domain. Usage:
//!
//!     cargo run --example sample_report -- /tmp/diego_sample.html
//!
//! The output format is inferred from the file extension (.html/.md/.json).
//! The fixture itself lives in `diego::report::sample::sample_report` so the
//! example, golden test, and schema test all share one source of truth.

use diego::report::{html, json, markdown, sample::sample_report};

fn main() {
    let report = sample_report();

    let path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/diego_sample.html".into());
    let content = if path.ends_with(".md") {
        markdown::generate(&report)
    } else if path.ends_with(".json") {
        json::generate(&report).expect("json")
    } else {
        html::generate(&report)
    };
    std::fs::write(&path, content).expect("write report");
    eprintln!("[+] Sample report written to {path}");
}
