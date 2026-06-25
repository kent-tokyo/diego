# Contributing to diego

Thanks for your interest. diego is an **unprivileged, read-only** Active
Directory diagnostic tool; contributions should preserve that posture.

## Ground rules

- **OPSEC constraint (enforced by CI):** no `std::process::Command` anywhere in
  `src/`. All behaviour is pure network protocol interaction. The `opsec-lint`
  CI job fails the build if this is violated.
- **Read-only:** no writes to the directory; no exploitation/persistence. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for goals and non-goals.
- **Authorisation:** only test against directories you own or are explicitly
  authorised to assess.

## Development

```bash
cargo build
cargo test --all
cargo clippy --all -- -D warnings   # CI gate: warnings are errors
cargo audit                         # optional locally; runs in CI
```

CI must be green on all platforms (Linux musl, Windows, plus test/clippy/audit/
coverage) before a PR is merged.

## Adding a detector / finding

1. Add the LDAP query (or Kerberos/passive logic) — e.g. a `query_*` function in
   `src/modules/ldap/queries.rs` (fetch only).
2. Turn results into `Finding`s in the module's `run` (e.g.
   `src/modules/ldap/mod.rs`), using `Finding::new(...)` with a **stable id**
   derived from an object identifier (sAMAccountName, CN, SPN) — not a loop
   index — so baseline diffs stay stable.
3. Set severity, and use `.with_confidence(...)` for heuristic detections
   (default is `High`; use `Medium`/`Low` for keyword/inference-based findings).
   Add `.with_mitre(...)` and `.with_remediation(...)` where applicable.
4. If you change the report's JSON shape, update `docs/report.schema.json`.

## Updating the golden test

`tests/golden_test.rs` snapshots the sample report. If you intentionally change
report output, regenerate and re-normalise the golden:

```bash
cargo run --example sample_report -- /tmp/s.json
# write the timestamp-normalised JSON to tests/golden/sample-report.json
```

The fixture lives in `src/report/sample.rs` (shared by the example and tests).

## Pull requests

- Keep commits focused; conventional-commit style is appreciated
  (`feat(report): ...`, `ci: ...`, `docs: ...`).
- Update `CHANGELOG.md` under `[Unreleased]`.
- Make sure `cargo test --all` and `cargo clippy --all -- -D warnings` pass.

## Reporting security issues

Please do **not** open public issues for vulnerabilities — see
[SECURITY.md](SECURITY.md).
