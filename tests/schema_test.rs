//! Validates that diego's JSON report conforms to the published schema
//! (docs/report.schema.json). The schema is diego's output contract for anyone
//! parsing reports in CI or downstream tooling; this test keeps the two in sync.

use diego::report::{json, sample::sample_report};
use serde_json::Value;

#[test]
fn schema_itself_is_valid() {
    let schema: Value =
        serde_json::from_str(include_str!("../docs/report.schema.json")).expect("schema is valid JSON");
    // Compiling the schema fails if it is not a well-formed JSON Schema.
    jsonschema::validator_for(&schema).expect("report.schema.json must be a valid JSON Schema");
}

#[test]
fn sample_report_conforms_to_schema() {
    let schema: Value =
        serde_json::from_str(include_str!("../docs/report.schema.json")).expect("schema is valid JSON");
    let validator = jsonschema::validator_for(&schema).expect("compile schema");

    let report: Value =
        serde_json::from_str(&json::generate(&sample_report()).expect("serialize")).expect("report JSON");

    if let Err(error) = validator.validate(&report) {
        panic!(
            "report does not conform to docs/report.schema.json at `{}`: {}",
            error.instance_path(),
            error
        );
    }
}
