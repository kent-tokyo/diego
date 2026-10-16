# diego

Read-only security diagnostics for authorised defenders and assessors. diego
uses standard-user access where applicable and writes JSON, Markdown, or
self-contained HTML reports. It does not modify a directory, execute OS
commands, crack hashes, exploit hosts, or move laterally.

## Current release

**v0.24.0** is the published release. It includes Active Directory diagnostics,
credential-free email/TLS/file-permission checks, bounded Web and WordPress
posture checks, and a loopback-only Web UI.

## What it checks

| Surface | Scope |
|---|---|
| Active Directory | Read-only LDAP and Kerberos diagnostics with standard domain-user credentials; optional passive local-interface observation. |
| Email DNS | SPF, DMARC, common DKIM selectors, MTA-STS, TLS-RPT, CAA, and bounded DNSSEC checks over public DNS. |
| TLS | Accepted TLS versions, negotiated cipher, and basic certificate validity for endpoints named with `--tls-target`. |
| File permissions | Unix permission bits for named files and directories; contents and symlinks are not read. |
| Web headers | HTTPS redirect, response security headers, framing policy, and cookie attributes for exact URLs named with `--web-target`. |
| WordPress | Bounded public posture for exact site roots: generator exposure, X-Pingback, XML-RPC, REST index, and `readme.html`. |

External Web checks are deliberately narrow: one unauthenticated request per
URL, plus a range-limited GET only when HEAD is unsupported. They do not follow
redirects, crawl, discover paths, authenticate, submit forms, enumerate users
or plugins, verify CVEs, or send attack payloads. HTTPS error responses are
inconclusive, not missing-header findings.

## Quick start

```bash
cargo build --release
./target/release/diego --dc 10.0.0.1 --domain corp.local \
  --username jdoe --modules all --format json --output report.json
```

Supply a password with `--password` or `DIEGO_PASSWORD`; otherwise diego prompts
for one. Keytab and Kerberos-cache authentication are not supported yet. The
default `audit` mode removes crackable hash material from reports. Only an
authorised assessment that needs that material should use both `--mode full`
and `--export-hashes`.

Released, credential-free checks need only their explicit inputs:

```bash
# Public email DNS
./target/release/diego --modules email --domain example.com --format json
# Named TLS endpoints; no port discovery
./target/release/diego --modules tls \
  --tls-target www.example.com:443,mail.example.com:443 --format json
# Named local paths; permission bits only
./target/release/diego --modules fs \
  --fs-path ~/.ssh,~/.aws --format json
```

Web and WordPress checks require an exact, authorised target:

```bash
./target/release/diego --modules web \
  --web-target https://www.example.com/security --format json

./target/release/diego --modules wordpress \
  --wordpress-target https://www.example.com/ --format json
```

`--web-ui` starts the same two checks through a browser form on
`127.0.0.1:8787`. It accepts one target at a time, requires an authorisation
acknowledgement, stores no results, and never binds to a remote interface.
The interface switches between English, Japanese, Simplified Chinese, and
Traditional Chinese; raw diagnostic evidence is preserved in the report.

## Common options

| Option | Purpose |
|---|---|
| `--modules <LIST>` | Run `kerberos`, `ldap`, `passive`, `email`, `tls`, `fs`, `web`, `wordpress`, or `all` |
| `--dns-resolver <ADDR>` / `--dkim-selectors <LIST>` | Email DNS resolver and selector controls |
| `--tls-target <LIST>` / `--fs-path <LIST>` | Explicit TLS endpoints or local paths |
| `--web-target <LIST>` / `--wordpress-target <LIST>` | Explicit Web URLs or WordPress roots |
| `--web-ui` / `--web-ui-port <PORT>` | Local-only Web/WordPress UI (default 8787) |
| `--format <FORMAT>` / `--output <PATH>` | Primary `json`, `markdown`, or `html` output |
| `--baseline <PATH>` / `--explain <ID>` | Baseline comparison and finding provenance |
| `--plan <PATH>` / `--plan-validate` / `--plan-state <PATH>` | Bounded multi-domain execution, offline validation, and integrity-protected checkpoints |
| `--sarif-output <PATH>` / `--webhook-output <PATH>` | Evidence-safe integration sidecars |
| `--mcp` / `--mcp-init` | MCP stdio mode or client configuration |

## Output safety and detection

Audit output is the default. Raw hash material is an explicit full-mode opt-in,
and sidecars contain summaries rather than raw evidence. diego is read-only,
not invisible: directory-side monitoring can observe LDAP and Kerberos
activity. Jitter changes timing; it does not hide the request pattern.

## Development

```bash
cargo test --all
cargo clippy --all -- -D warnings
```

## Documentation

- [Roadmap](ROADMAP.md) — release status and next gates
- [Threat model](docs/THREAT_MODEL.md) — supported scope and non-goals
- [Testing](docs/TESTING.md) — coverage boundaries
- [Benchmarks](docs/BENCHMARKS.md) — lab methodology; no measured results yet
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)
- [Report schema](docs/report.schema.json), [sample report](docs/sample-report.html), and [sample JSON](docs/sample-findings.json)
- [Changelog](CHANGELOG.md)

## License

MIT License. Copyright (c) 2026 kent-tokyo. You may use, modify, and
redistribute diego under the terms in [LICENSE](LICENSE); copies and substantial
portions must retain this copyright and permission notice.
