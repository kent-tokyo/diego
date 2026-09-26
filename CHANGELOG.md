# Changelog

All notable changes to diego are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.22.0] - 2026-09-26

### Documentation
- Corrected credential guidance: keytab and Kerberos-cache detection are not
  supported authentication methods.
- Consolidated MCP, testing, benchmark, and operator documentation around the
  current v0.22.0 boundaries.

### Security
- Removed sensitive account, SPN, credential-cache, and hash values from
  diagnostic and test-failure logs.
- Removed unsupported keytab and Kerberos-cache password fallbacks; authentication
  now uses an explicitly supplied password, `DIEGO_PASSWORD`, or an interactive
  prompt.

### Added
- Added `--plan-validate` for credential-free, network-free scan plan validation.
- Added normalized validation output showing scope, bounded parallelism, and selected targets.

## [0.21.0] - 2026-08-31

### Added
- Added SHA-256 integrity protection and plan fingerprints to local Fleet checkpoints.
- Added checkpoint schema validation to reject tampering or reuse with changed plans.

## [0.20.0] - 2026-08-31

### Added
- Added local `--plan-state <path>` checkpoints for resumable multi-domain execution.
- Added plan/target identity validation so checkpoints cannot be applied to a changed plan.

## [0.19.0] - 2026-08-31

### Added
- Enabled bounded multi-domain execution using the scan plan's `max_parallel` setting while preserving deterministic target order and per-target failures.
- Added the configured concurrency limit to FleetReport execution metadata.

## [0.18.0] - 2026-08-31

### Added
- Added bounded FleetReport execution metrics for selected, completed, and failed targets plus elapsed milliseconds.
- Added offline contract coverage for fleet execution-state accounting.

## [0.17.0] - 2026-08-31

### Added
- Added bounded per-target `attackPath` summaries to multi-domain `FleetReport` output.
- Added contract coverage confirming attack-path redaction and omission for failed targets.

## [0.16.0] - 2026-08-31

### Added
- Added `--attack-path-output <path>` for offline JSON/Markdown attack-path sidecars while preserving the normal report output.
- Added CLI coverage for separating the bounded path summary from the primary report stream.

## [0.15.0] - 2026-08-31

### Added
- Webhook/SIEM events now include resolved baseline findings with `baselineState: absent` for lifecycle-complete triage.
- Added contract coverage for current and resolved event records without raw evidence.

## [0.14.0] - 2026-08-31

### Added
- Added deterministic defensive attack-path output via `--attack-path` in JSON or Markdown.
- Added `diego.attack-path.v1` contract coverage with explicit standard-user and protected-asset boundaries.

### Changed
- Rewrote the README files to match the current CLI, report, baseline, governance,
  SARIF, webhook, exposure-graph, and MCP implementations.
- Removed obsolete stealth/attack-narrative wording and shortened operator docs.

### Removed
- Removed internal agent instructions, task notes, and the superseded safe-mode
  design sketch from the public repository.

## Earlier 0.x releases (0.1.0–0.13.0)

- Foundation: read-only LDAP, Kerberos, and passive diagnostics; JSON,
  Markdown, and HTML reporting; baseline comparison and confidence scoring.
- Safety and contracts: audit-default evidence redaction, report schema,
  golden/detection tests, and contributor/security guidance.
- Operations: reusable library API, finding explanations, bounded exposure and
  remediation views, governance, multi-domain plans, SARIF, and webhook output.

Use the repository's tags and GitHub releases for the full historical notes.

[0.14.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.14.0
[0.15.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.15.0
[0.16.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.16.0
[0.17.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.17.0
[0.18.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.18.0
[0.19.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.19.0
[0.20.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.20.0
[0.21.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.21.0
[0.22.0]: https://github.com/kent-tokyo/diego/releases/tag/v0.22.0
