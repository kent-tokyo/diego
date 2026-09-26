# Contributing to diego

Thanks for your interest. diego is an **unprivileged, read-only** Active
Directory diagnostic tool; contributions should preserve that posture.

## Ground rules

- **No OS commands:** `std::process::Command` is forbidden in `src/`; CI checks
  this directly. Network diagnostics and passive capture are allowed.
- **Read-only:** no writes to the directory; no exploitation/persistence. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for goals and non-goals.
- **Authorisation:** only test against directories you own or are explicitly
  authorised to assess.

## Development

```bash
cargo build
cargo test --all
cargo clippy --all -- -D warnings   # CI gate: warnings are errors
```

CI runs tests, Clippy, the OS-command check, RustSec audit, Linux musl, Windows,
and best-effort coverage. Run `cargo audit` locally only when it is installed.

The test suite is layered (golden / detection / integration / schema / unit) —
see [docs/TESTING.md](docs/TESTING.md) for what each layer guards and what is not
yet covered.

## Adding a detector / finding

1. Add a read-only LDAP, Kerberos, or passive query and turn results into
   `Finding`s with a stable object-derived ID.
2. Set severity, confidence, MITRE mapping, and remediation where appropriate.
3. Update `docs/report.schema.json` and the golden fixture when the JSON
   contract changes.

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
