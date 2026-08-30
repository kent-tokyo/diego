# Changelog

All notable changes to diego are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2026-08-30

### Added
- SARIF 2.1.0 sidecar output via `--sarif <path>` for CI and security-platform ingestion.
- Typed Finding-to-SARIF mapping with severity, confidence, MITRE ID, timestamps, and remediation guidance.
- Contract tests ensuring SARIF output preserves audit-mode boundaries and omits raw evidence.

## [0.9.0] - 2026-08-30

### Added
- Bounded exposure graph object evidence with provenance, confidence, and observation time.
- Remediation-candidate nodes and impact edges for defensive prioritisation.
- Explicit unknown reachability and protected-asset boundaries; no BloodHound-compatible export.

## [0.8.0] - 2026-08-30

### Added
- Local configurable severity scoring and governance assessment output.
- Finding ownership, ticket, due date, suppression, and exception metadata.
- Baseline-aware fixed/regressed state evaluation and SHA-256 policy fingerprint.

## [0.7.0] - 2026-08-30

### Added
- JSON multi-domain execution plans with explicit scope, enablement, and exclusions.
- Bounded aggregate fleet reports with per-target success/failure visibility.
- Credential-free plan format; credentials remain supplied by CLI or `DIEGO_PASSWORD`.

## [0.6.0] - 2026-08-30

### Added
- Bounded exposure graph with explicit provenance, missing-data boundaries,
  and standard-user assessment scope.
- Read-only remediation simulation for selected finding IDs.

### Changed
- Exposure paths are labelled as assessment paths, not exploitation paths or
  complete BloodHound-compatible graph data.

## [0.5.0] - 2026-08-30

### Added
- Detector metadata for required permissions, collection source, expected
  false positives, and confidence rationale.
- `--explain <finding-id>` for safe, operator-facing evidence provenance and
  remediation details.

### Changed
- Finding explanations use the same audit-mode redaction boundary as reports.

## [0.4.0] - 2026-08-30

### Added
- Reusable `diego::run_scan` library API with the same module orchestration as
  the CLI and safe-mode redaction at the API boundary.
- Synthetic, redacted LDAP JSON corpus and load-and-analyze regression tests.

### Changed
- CLI scan orchestration now uses the public library API, preventing drift
  between embedded and command-line usage.
- Roadmap now tracks v0.4.0 evidence and lab-validation milestones.

## [0.3.0] - 2026-08-30

### Added
- **Defensive-by-default hash output:** CLI reports and MCP full scans redact
  crackable AS-REP/TGS material by default. Explicit `--mode full
  --export-hashes` (or MCP `export_hashes: true`) is required to emit it.
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

### Documentation
- README intro (4 languages) reframed to lead with the defensive / authorised-use
  posture, removing residual "post-exploitation" wording so it matches the
  tagline.
- Added `docs/TESTING.md` (golden / detection / integration / schema test layers
  and what each does **not** guard) and `docs/DESIGN-safe-mode.md` (the safety
  contract for defensive-by-default `--mode audit` / `--export-hashes`).
- ROADMAP: expanded the reproduction-corpus item into concrete staged milestones
  (fixture format → load-and-analyze tests → mock LDAP) and listed safe mode.

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

[0.6.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.6.0
[0.7.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.7.0
[0.8.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.8.0
[0.9.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.9.0
[0.10.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.10.0
[0.5.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.5.0
[0.4.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.4.0
[0.3.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.3.0
[0.2.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.2.0
[0.1.1]: https://github.com/kent-tokyo/diego/releases/tag/v0.1.1
[0.1.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.1.0
