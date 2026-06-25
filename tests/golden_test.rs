//! Golden test: the serialized sample report must not change shape unexpectedly.
//!
//! This guards against accidental drift in the report schema, finding count,
//! severity/confidence values, and ordering when refactoring. Wall-clock
//! timestamp fields are normalised away so the comparison is deterministic.
//!
//! Scope: this is a *format* golden over a synthetic fixture
//! (`diego::report::sample::sample_report`). It does not exercise live
//! detection logic end-to-end (that needs a mock DC — see ROADMAP corpus item).
//!
//! To update intentionally: regenerate and re-normalise the golden, e.g.
//!   cargo run --example sample_report -- /tmp/s.json
//! then write the timestamp-normalised JSON to tests/golden/sample-report.json.

use diego::report::{json, sample::sample_report};
use serde_json::Value;

const VOLATILE: &[&str] = &["generated_at", "timestamp", "baseline_generated_at"];

/// Recursively replace wall-clock timestamp fields with a fixed marker.
fn normalize(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if VOLATILE.contains(&k.as_str()) {
                    *val = Value::String("<normalized>".into());
                } else {
                    normalize(val);
                }
            }
        }
        Value::Array(arr) => arr.iter_mut().for_each(normalize),
        _ => {}
    }
}

#[test]
fn sample_report_matches_golden() {
    let actual_str = json::generate(&sample_report()).expect("serialize sample report");
    let mut actual: Value = serde_json::from_str(&actual_str).expect("actual is valid JSON");
    normalize(&mut actual);

    let mut golden: Value =
        serde_json::from_str(include_str!("golden/sample-report.json")).expect("golden is valid JSON");
    normalize(&mut golden); // idempotent; tolerant if golden ever carries real timestamps

    assert_eq!(
        actual, golden,
        "\nReport output drifted from tests/golden/sample-report.json.\n\
         If this change is intentional, regenerate the golden (see this file's header).\n"
    );
}
