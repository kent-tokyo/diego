# diego roadmap

The roadmap prioritises evidence quality, defensive operations, and honest
limits. diego does not promise stealth, exploitation, lateral movement, or a
complete BloodHound export.

## Current status: v0.23.0

Completed and covered locally:

- Read-only LDAP, Kerberos, and passive diagnostics for standard domain users.
- Audit-safe JSON, Markdown, and HTML reports with explicit hash export.
- Stable findings, severity/confidence, provenance, remediation, baseline diff,
  governance, SARIF, webhook, MCP, exposure graph, and defensive path output.
- Multi-domain plans with bounded `max_parallel` execution and per-target paths.
- Resumable local checkpoints with plan fingerprints and SHA-256 integrity checks.
- Credential-free, network-free plan validation via `--plan-validate`.

## Near-term (Active Directory track)

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

## Direction: unprivileged, multi-surface diagnostics (exploratory, post-1.0)

diego today diagnoses one surface — on-premises Active Directory. The same
operating principles (read-only, standard-user privilege, no OS-command
execution, honest limits) generalise to other security surfaces that an
unprivileged user or a low-privilege endpoint can *legitimately observe*. The
objective is broader **posture assessment**, never broader attack capability:
each surface only reports misconfigurations that are visible from a context the
operator already holds, and every surface inherits the Permanent non-goals
below.

Design constraints that gate every candidate surface:

- **No new privilege.** If a check needs administrator/root, a privileged API,
  or credential material the operator was not already given, it is out of scope.
- **No active exploitation.** Observation and standards-conformant queries only —
  no fuzzing, no exploit probes, no auth-bypass attempts, no OS commands.
- **Least-intrusive default.** Every surface ships behind its own module flag,
  defaults to the quietest behaviour, and documents exactly what privilege and
  network position it assumes.
- **One findings model.** Shared finding schema, severity x confidence,
  provenance, and remediation across all surfaces, so reports, baseline diff,
  SARIF, and MCP stay uniform.
- **Deterministic tests.** Fixture-based coverage; findings absent (not guessed)
  when the underlying data is unavailable.

### Candidate surfaces

**Surface A — Email & domain authentication hygiene (passive, public DNS).**
*Pilot landed (unreleased): the `email` module.* SPF, DMARC, DKIM, MTA-STS,
TLS-RPT, CAA, and a bounded DNSSEC check read from public DNS only. Fully
passive, no credentials, no target-side footprint, reusing the existing
findings/report pipeline. Chosen as the first pilot for lowest privilege and
lowest risk. Remaining before release: an anonymised fixture corpus and the
support-matrix entry required by the v0.24 gate.

**Surface B — Reachable-endpoint transport hygiene (read-only).**
*Pilot landed (unreleased): the `tls` module.* For endpoints the operator names
explicitly (`--tls-target host[:port]`): which of TLS 1.0/1.1/1.2/1.3 are
accepted (per-version ClientHello probes), the negotiated cipher (3DES/RC4
flagged), and certificate validity (expired/expiring/self-signed) read from the
cleartext TLS 1.2 Certificate message. No port scanning, no handshake
completion, no exploit probes. Remaining before release: weak-cipher
enumeration (offering legacy suites), full chain/hostname validation, and the
support-matrix entry required by the v0.24 gate.

**Surface C — Local endpoint configuration posture (unprivileged, local).**
*Pilot landed (unreleased): the `fs` module.* For operator-named paths
(`--fs-path`): over-permissive private keys and credential files, world-writable
files/directories, and loose `.ssh`/`.gnupg` permissions — inspecting Unix
permission bits only, never reading file contents, never following symlinks,
never executing OS commands, never escalating (consistent with the existing
no-`std::process::Command` rule). Remaining before release: content-based
cleartext-secret indicators (with careful value redaction — the more sensitive
item, deliberately deferred), Windows ACL support, and the support-matrix entry
required by the v0.24 gate.

**Surface D — Cloud identity posture (read-only, future).**
Entra ID / cloud IAM misconfigurations a standard user can enumerate through the
provider's own read APIs. Flagged out-of-scope in the threat model today; a
candidate direction, not a commitment.

Exit gate for the expansion as a whole: each shipped surface is behind its own
flag, is read-only and unprivileged by construction, has deterministic fixture
tests, states its privilege/network assumptions in the docs, and maps cleanly
onto the shared findings model.

## Permanent non-goals

diego will not — on any surface, existing or new — execute attacks, crack
hashes, exploit vulnerabilities, move laterally, persist, guarantee detection
evasion, or make unauthorised changes. Adding a diagnostic surface never adds an
offensive capability: a new surface may only add read-only observation from a
context the operator already holds. Any check that cannot be performed
read-only and unprivileged is out of scope by definition. diego also does not
promise a complete identity graph or BloodHound CE export.
