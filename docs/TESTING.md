# Testing layers

Each layer guards a different property. A passing layer does not prove the
behaviour named in its final column.

| Layer | File(s) | Guards | Does **not** guard |
|-------|---------|--------|--------------------|
| **Golden** | `tests/golden_test.rs` + `tests/golden/sample-report.json` | The serialized report's *shape* — finding count, fields, severity/confidence, ordering — does not drift unexpectedly (timestamps normalised). | Whether findings are *correct* for real input. |
| **Detection** | `tests/detection_tests.rs` | Detection *logic*: a synthetic `LdapObject` produces the expected finding (id, severity, confidence), and benign input does **not** (false-positive guard). | A live Domain Controller; the LDAP fetch/filter layer. |
| **Integration** | `tests/ldap_integration_tests.rs`, `tests/mock_kdc.rs` | LDAP filter strings / OID constants; Kerberos KDC response parsing (AS-REP flow, malformed input). | The end-to-end fetch→analyze path against a directory. |
| **Web-header unit** | `src/modules/web/analyze.rs` | Explicit HTTP/HTTPS target validation plus deterministic status, HSTS, framing-policy, security-header, redirect, and cookie-attribute classification. | A live server's configuration, redirect destination, page body, or application behaviour. |
| **WordPress unit** | `src/modules/wordpress/analyze.rs` | Bounded public WordPress exposure classification and exact site-root validation. | Plugin/user enumeration, authentication, CVE applicability, or exploitability. |
| **Local UI unit** | `src/web_ui.rs` | Local-only Web/WordPress UI copy, language-selector coverage, and JSON error response shape. | Browser rendering, a live local listener, or a real external site. |
| **Schema** | `tests/schema_test.rs` + `docs/report.schema.json` | The JSON report conforms to the published schema (the integration contract). | Semantic correctness of values. |
| **Unit** | `#[cfg(test)]` in `src/**` (e.g. `parser.rs`, `severity.rs`) | Small pure helpers (attribute parsing, severity mapping). | Cross-module behaviour. |

## What is not yet covered

There is **no live-DC or live-external-target end-to-end test** in CI. The
detection layer uses representative objects; integration tests cover LDAP
filters and KDC parsing; Web/WordPress/UI tests cover only bounded parsing and
local response contracts. Plan validation, bounded execution, and checkpoint
tamper rejection run locally. Benchmarks remain methodology only in
[BENCHMARKS.md](BENCHMARKS.md).

## Running

```bash
cargo test --all                       # everything
cargo test --test detection_tests      # one layer
cargo clippy --all -- -D warnings      # lints (CI gate)
cargo run -- --plan docs/sample-scan-plan.json --plan-validate
```

CI also runs RustSec audit. Run `cargo audit` locally when the tool is
installed.

## Updating the golden snapshot

If you intentionally change report output, regenerate and re-normalise the
golden (see the header of `tests/golden_test.rs`):

```bash
cargo run --example sample_report -- /tmp/s.json
# write the timestamp-normalised JSON to tests/golden/sample-report.json
```

The sample fixture lives in `src/report/sample.rs`, shared by the example and
the golden/schema tests so they cannot drift apart.
