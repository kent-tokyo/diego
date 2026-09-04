# diego roadmap

The roadmap prioritises evidence quality, defensive operations, and honest
limits. diego does not promise stealth, exploitation, lateral movement, or a
complete BloodHound export.

## Current status: v0.22.0

Completed and covered locally:

- Read-only LDAP, Kerberos, and passive diagnostics for standard domain users.
- Audit-safe JSON, Markdown, and HTML reports with explicit hash export.
- Stable findings, severity/confidence, provenance, remediation, baseline diff,
  governance, SARIF, webhook, MCP, exposure graph, and defensive path output.
- Multi-domain plans with bounded `max_parallel` execution and per-target paths.
- Resumable local checkpoints with plan fingerprints and SHA-256 integrity checks.
- Credential-free, network-free plan validation via `--plan-validate`.

## Next priorities

### v0.23 — Measurement and operator feedback

- Add report-level counters for LDAP/Kerberos requests and module failures.
- Record bounded resource observations where the host can provide them safely.
- Add controlled fixture coverage for partial responses and plan resume flows.

Exit gate: counters are defined, deterministic in tests, absent when unavailable,
and documented as local observations rather than directory-wide coverage.

### v0.24 — Reproducible support evidence

- Document the Linux, Windows, LDAP, Kerberos, and passive-monitoring support
  matrix.
- Add anonymised representative corpus cases and malformed-input coverage.
- Keep benchmark results separate from methodology until a controlled lab run.

Exit gate: every supported claim links to a local test, fixture, or explicitly
labelled lab measurement.

### v1.0 — Independent verification

Requires independent review of protocol handling, credential lifecycle,
redaction, read-only guarantees, report compatibility, controlled benchmarks,
and the support matrix. Comparative claims must include negative results and
reproducible conditions.

## Permanent non-goals

diego will not execute attacks, dump credentials, crack hashes, move laterally,
persist, guarantee detection evasion, or make unauthorised directory changes.
