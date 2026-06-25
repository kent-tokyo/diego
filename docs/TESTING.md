# Testing layers

diego's tests are organised into layers, each guarding a different property.
Knowing which layer a test belongs to tells you what a failure means — and what
is **not** yet covered.

| Layer | File(s) | Guards | Does **not** guard |
|-------|---------|--------|--------------------|
| **Golden** | `tests/golden_test.rs` + `tests/golden/sample-report.json` | The serialized report's *shape* — finding count, fields, severity/confidence, ordering — does not drift unexpectedly (timestamps normalised). | Whether findings are *correct* for real input. |
| **Detection** | `tests/detection_tests.rs` | Detection *logic*: a synthetic `LdapObject` produces the expected finding (id, severity, confidence), and benign input does **not** (false-positive guard). | A live Domain Controller; the LDAP fetch/filter layer. |
| **Integration** | `tests/ldap_integration_tests.rs`, `tests/mock_kdc.rs` | LDAP filter strings / OID constants; Kerberos KDC response parsing (AS-REP flow, malformed input). | The end-to-end fetch→analyze path against a directory. |
| **Schema** | `tests/schema_test.rs` + `docs/report.schema.json` | The JSON report conforms to the published schema (the integration contract). | Semantic correctness of values. |
| **Unit** | `#[cfg(test)]` in `src/**` (e.g. `parser.rs`, `severity.rs`) | Small pure helpers (attribute parsing, severity mapping). | Cross-module behaviour. |

## What is not yet covered

There is **no live-DC end-to-end test** — diego is not yet run against a real or
mocked directory in CI. The detection layer exercises the analysis logic over
representative objects, and the integration layer covers filters and KDC
parsing, but the full fetch→analyze path against directory data is a roadmap
item. See [ROADMAP.md](../ROADMAP.md) ("Reproduction corpus → live-path
detection tests"). Performance benchmarks are also pending a lab environment
(methodology only in [BENCHMARKS.md](BENCHMARKS.md)).

## Running

```bash
cargo test --all                       # everything
cargo test --test detection_tests      # one layer
cargo clippy --all -- -D warnings      # lints (CI gate)
cargo audit                            # advisories (CI gate)
```

## Updating the golden snapshot

If you intentionally change report output, regenerate and re-normalise the
golden (see the header of `tests/golden_test.rs`):

```bash
cargo run --example sample_report -- /tmp/s.json
# write the timestamp-normalised JSON to tests/golden/sample-report.json
```

The sample fixture lives in `src/report/sample.rs`, shared by the example and
the golden/schema tests so they cannot drift apart.
