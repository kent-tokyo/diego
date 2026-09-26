# diego

Read-only Active Directory diagnostics for authorised defenders and assessors.
diego runs from a standard domain-user context and produces JSON, Markdown, or
self-contained HTML reports. It does not modify the directory, execute OS
commands, crack hashes, exploit hosts, or move laterally.

## Current release

The working tree targets **v0.22.0**. Recent releases added bounded multi-domain
execution, resumable local checkpoints, checkpoint integrity validation, and
credential-free plan validation. Registry publication is intentionally paused;
the current development workflow is local and offline.

## Capabilities

- LDAP: delegation, RBCD, privileged groups, SPNs, stale service passwords,
  description leaks, password policy, and related read-only findings.
- Kerberos: AS-REP and TGS requests with audit-safe evidence handling.
- Passive observation: LLMNR/NBT-NS and cleartext-protocol indicators on a
  selected local interface.
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

## Common options

| Option | Purpose |
|---|---|
| `--modules <LIST>` | Run `kerberos`, `ldap`, `passive`, or `all` |
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

MIT
