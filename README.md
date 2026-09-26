# diego

Read-only Active Directory diagnostics for authorised defenders and assessors.
diego runs from a standard domain-user context and produces JSON, Markdown, or
self-contained HTML reports. It does not modify the directory, execute OS
commands, crack hashes, exploit hosts, or move laterally.

## Current release

**v0.23.0** adds credential-free, read-only posture diagnostics for email
authentication, explicitly named TLS endpoints, and operator-named local paths.
These surfaces run without a Domain Controller and do not execute commands,
read file contents, scan ports, or attempt authentication.

## Capabilities

- LDAP: delegation, RBCD, privileged groups, SPNs, stale service passwords,
  description leaks, password policy, and related read-only findings.
- Kerberos: AS-REP and TGS requests with audit-safe evidence handling.
- Passive observation: LLMNR/NBT-NS and cleartext-protocol indicators on a
  selected local interface.
- Email & domain authentication hygiene (Surface A): SPF, DMARC, DKIM (common
  selectors), MTA-STS, TLS-RPT, CAA, and a bounded DNSSEC check — over public
  DNS only, needing no credentials and no Domain Controller.
- TLS transport hygiene (Surface B): for explicitly named endpoints, which of
  TLS 1.0/1.1/1.2/1.3 are accepted, the negotiated cipher, and certificate
  validity (expired/expiring/self-signed). Read-only, no port scanning, no
  exploit probes, no credentials.
- Local file-permission posture (Surface C): for paths you name, over-permissive
  private keys and credential files, world-writable files/directories, and loose
  .ssh/.gnupg permissions — inspecting permission bits only (never file
  contents), never following symlinks, unprivileged and read-only (Unix).
- Reports and integrations: JSON, Markdown, HTML, baseline diff, explanations,
  bounded exposure graph, remediation simulation, governance, SARIF, webhook,
  MCP stdio, and multi-domain plans.
- Optional Claude analysis and chat, requiring `ANTHROPIC_API_KEY`.

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

The email module is read-only and needs neither credentials nor a Domain
Controller — only a domain and a resolver:

```bash
./target/release/diego --modules email --domain example.com \
  --dns-resolver 1.1.1.1 --format json --output email.json
```

The TLS module is read-only and probes only the endpoints you name (no port
scanning); it needs no credentials and no Domain Controller:

```bash
./target/release/diego --modules tls --domain n/a \
  --tls-target www.example.com:443,mail.example.com:443 --format json
```

The file-permission module scans only the paths you name, reads permission
bits (not contents), and needs no credentials:

```bash
./target/release/diego --modules fs --domain n/a \
  --fs-path ~/.ssh,~/.aws --format json
```

## Common options

| Option | Purpose |
|---|---|
| `--modules <LIST>` | Run `kerberos`, `ldap`, `passive`, `email`, `tls`, `fs`, or `all` |
| `--dns-resolver <ADDR>` | Resolver for `email` checks (ip or ip:port; default: system) |
| `--dkim-selectors <LIST>` | Comma-separated DKIM selectors for `email` (default: common set) |
| `--tls-target <LIST>` | Comma-separated `host[:port]` endpoints for the `tls` module |
| `--fs-path <LIST>` | Comma-separated files/dirs for the `fs` permission-posture module |
| `--format <FORMAT>` | Write `json`, `markdown`, or `html` |
| `--output <PATH>` | Write the primary report to a file |
| `--baseline <PATH>` | Compare the current report with a prior report |
| `--explain <ID>` | Explain a finding and its provenance |
| `--exposure-graph` | Emit a bounded exposure graph |
| `--simulate-remediation <IDS>` | Simulate removing findings locally |
| `--sarif-output <PATH>` | Write a SARIF 2.1.0 sidecar |
| `--webhook-output <PATH>` | Write an evidence-safe webhook sidecar |
| `--attack-path` / `--attack-path-output <PATH>` | Emit a bounded defensive path summary |
| `--plan <PATH>` | Execute a multi-domain plan whose target metadata has no credentials |
| `--plan-validate` | Validate a plan without credentials or network access |
| `--plan-state <PATH>` | Save and resume an integrity-protected local checkpoint |
| `--mcp` / `--mcp-init` | Run MCP stdio mode or print its client configuration |

## Multi-domain plans

A plan contains target metadata only. Executing it still requires `--username`
and either `--password` or `DIEGO_PASSWORD`. Targets execute in bounded batches
controlled by `max_parallel`; FleetReport retains each target's status, report,
bounded `attackPath`, and aggregate severity counts.

Validate a plan before supplying credentials:

```bash
diego --plan docs/sample-scan-plan.json --plan-validate
```

For a resumable run, write a local checkpoint after each batch:

```bash
diego --plan docs/sample-scan-plan.json --plan-state fleet-state.json \
  --username jdoe --password "$DIEGO_PASSWORD" --modules ldap --output fleet.json
```

Re-running the same command skips completed targets and retries failed or
unfinished targets. The checkpoint is rejected when its SHA-256 checksum or
plan fingerprint is invalid, or when the plan's scope, target ID, domain, or DC
metadata has changed.

## Output safety and detection

Audit output is the default. Raw hash material is an explicit full-mode opt-in,
and sidecars are designed to contain summaries rather than raw evidence.
diego is read-only and does not claim to be invisible: LDAP enumeration,
AS-REP roasting, and especially RC4 Kerberoasting remain observable to
directory-side monitoring. Jitter may smooth request timing, but it does not
remove the behavioural signature of a request.

## Development

```bash
cargo test --all
cargo clippy --all -- -D warnings
cargo package --allow-dirty --no-verify
```

The project forbids `std::process::Command` in `src/`. Offline commands work
only when their dependencies are already cached. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [docs/TESTING.md](docs/TESTING.md).

## Documentation

- [Threat model](docs/THREAT_MODEL.md) — goals, non-goals, detection, and limits
- [Roadmap](ROADMAP.md) — current status and next gates
- [Security policy](SECURITY.md) — private vulnerability reporting
- [Testing](docs/TESTING.md) — test layers and coverage boundaries
- [Benchmarks](docs/BENCHMARKS.md) — reproducible lab methodology
- [Report schema](docs/report.schema.json) — JSON contract
- [Changelog](CHANGELOG.md)
- [Sample report](docs/sample-report.html) and [sample JSON](docs/sample-findings.json)

## License

MIT License. Copyright (c) 2026 kent-tokyo. You may use, modify, and
redistribute diego under the terms in [LICENSE](LICENSE); copies and substantial
portions must retain this copyright and permission notice.
