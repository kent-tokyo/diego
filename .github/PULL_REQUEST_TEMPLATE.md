<!-- Thanks for contributing! See CONTRIBUTING.md. -->

## Summary

<!-- What does this change and why? -->

## Checklist

- [ ] `cargo test --all` passes
- [ ] `cargo clippy --all -- -D warnings` passes
- [ ] No `std::process::Command` added (OPSEC constraint)
- [ ] Operations remain read-only / unprivileged
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (if user-facing)
- [ ] `docs/report.schema.json` + golden updated (if report output changed)
