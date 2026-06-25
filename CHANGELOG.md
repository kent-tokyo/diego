# Changelog

All notable changes to diego are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
