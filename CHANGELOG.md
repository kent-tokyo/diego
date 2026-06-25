# Changelog

All notable changes to diego are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Published JSON Schema** for the report (`docs/report.schema.json`) — the
  integration contract for downstream/CI consumers — with a test validating the
  sample output against it.
- **Golden test** (`tests/golden_test.rs`) guarding the serialized report
  against accidental shape/finding-count drift (timestamps normalised).
- **Contributor front-door:** `CONTRIBUTING.md`, `SECURITY.md` (coordinated
  vulnerability disclosure), GitHub issue/PR templates.
- **`ROADMAP.md`** stating the 0.2.x stabilisation focus and honestly parking
  lab-dependent and deferred items.

### Added
- **Detection tests** (`tests/detection_tests.rs`): assert "directory object →
  expected finding" (id, severity, confidence) over synthetic `LdapObject`
  fixtures, including a false-positive guard for description-field heuristics.

### Changed
- Extracted the sample-report fixture into `diego::report::sample::sample_report`
  so the example, golden test, and schema test share one source of truth.
- Split the LDAP module into fetch (`queries.rs`) and pure analysis
  (`modules/ldap/analyze.rs`), making detection logic unit-testable.
- The CLI binary (`main.rs`) now consumes the `diego` library crate instead of
  re-declaring its modules, removing the binary-only `#![allow(dead_code)]` and
  the double-compilation it papered over.

## [0.2.0] - 2026-06-25

### Added
- **HTML report** (`--format html`): a single self-contained file (inline CSS/JS,
  no CDN — works air-gapped) with a severity summary, attack-path overview, a
  sortable/filterable findings table, and an audit-style **Appendix** (scan
  context, methodology, confidence legend, detection notes).
- **Baseline diff** (`--baseline <prior.json>`): classifies findings as new,
  resolved, or severity-changed against a prior JSON report. Matching is by
  stable finding ID; output is surfaced in JSON, Markdown, and HTML.
- **Confidence scoring**: every finding carries a `confidence` (High/Medium/Low)
  distinct from severity. Deterministic detections stay High; heuristic ones
  (e.g. description-field keyword matches) are Medium.
- **Sample reports & live demo**: `docs/sample-report.html`,
  `docs/sample-findings.json`, and a screenshot, generated reproducibly by
  `cargo run --example sample_report`. Published via GitHub Pages.
- **Project docs**: `CHANGELOG.md`, `docs/THREAT_MODEL.md`, `docs/BENCHMARKS.md`,
  and an architecture diagram in the README.

### Changed
- **README honesty pass** (4 languages): the comparison table and OPSEC claims
  now distinguish host-based EDR avoidance (real) from DC-side behavioural
  detection (e.g. Microsoft Defender for Identity), which still applies
  regardless of client language. Added a "Detection considerations" section.
- Migrated the HTTP stack (`reqwest`) from native-tls to **rustls-tls**.

### Fixed
- **CI is green again.** All four previously-failing jobs were repaired:
  Clippy (`-D warnings`), the Linux musl static build, the Windows build
  (Npcap SDK for `pnet` linking), and the Security Audit action reference.

### Security
- Removed the OpenSSL (`openssl-sys`) dependency by moving to rustls, easing
  static / musl / Alpine builds and shrinking the native attack surface.

## [0.1.1] - 2026-06-14

### Added
- Multi-method password-less authentication (env var, keytab, TGT cache,
  interactive prompt) and multi-language README support.

## [0.1.0] - 2026-06-14

### Added
- Initial release: unprivileged AD diagnostics — AS-REP Roasting, Kerberoasting,
  LDAP enumeration, LLMNR/NBT-NS passive monitoring, Claude API analysis, and
  MCP server mode.

[0.2.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.2.0
[0.1.1]: https://github.com/kent-tokyo/diego/releases/tag/v0.1.1
[0.1.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.1.0
