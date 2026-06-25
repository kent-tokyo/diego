# diego — Threat Model

This document states what diego is and is not designed to do, so operators and
defenders can reason about it accurately. It is deliberately conservative:
where a capability is limited, we say so.

## Goals

- Provide **unprivileged, read-only** Active Directory security diagnostics from
  a standard domain-user session — surfacing exploitable misconfigurations
  (AS-REP roastable accounts, Kerberoastable SPNs, unconstrained/constrained
  delegation, RBCD, weak password policy, credential leaks in descriptions).
- Emit **prioritised, actionable findings** (severity × confidence, MITRE
  mapping, remediation steps) in machine- and human-readable formats
  (JSON / Markdown / HTML / MCP).
- Run as a **single static binary** with no .NET/PowerShell/Python runtime,
  reducing host-based EDR telemetry from interpreter/runtime artefacts.
- Be **honest about detection**: see Detection Assumptions below.

## Non-goals

- **Not an exploitation framework.** diego does not execute code on remote
  hosts, move laterally, dump LSASS, perform DCSync, or persist. It requests and
  captures hashes for *offline* analysis; it does not crack them.
- **Not a detection-evasion guarantee.** Jitter smooths timing/volume; it does
  not hide the behavioural signature of a request (see below).
- **Not a full graph collector.** diego collects *findings*, not the complete
  identity graph (ACLs, sessions, SIDs, full group membership). This is why a
  valid BloodHound CE export is **not** offered today — a partial graph would
  mislead more than it helps.
- **Not a substitute for authorisation.** Use only where you are permitted to
  run AD diagnostics.

## Detection assumptions

diego is **OPSEC-friendly, not invisible.** Two distinct layers:

1. **Host-based detection of the tool** — *reduced.* As a pure-Rust binary, it
   produces no .NET CLR / PowerShell / Python runtime artefacts, so ETW / AMSI /
   Script Block Logging signals that catch Rubeus/PowerView/Impacket on the
   foothold do not fire.
2. **DC-side detection of the behaviour** — *still applies.* LDAP enumeration,
   Kerberoasting (especially RC4 `etype 23` TGS requests), and AS-REP roasting
   are exactly what directory-side sensors such as **Microsoft Defender for
   Identity** detect, **regardless of client language**. RC4 Kerberoasting in
   particular is a loud, well-signatured event.

Treat "low host telemetry" and "undetectable" as different claims — diego makes
only the former.

## Supported environments

- **Operator host:** Linux or Windows; single static binary (musl static build
  for Linux). macOS for development.
- **Privilege:** standard domain user. No administrator rights at any stage.
- **Target:** on-premises Active Directory reachable over LDAP (389) and
  Kerberos (88); passive monitoring requires a local interface in the broadcast
  domain.
- **Out of scope today:** Entra ID / Azure / AWS / GCP identity (a possible
  future direction, not implemented).

## Limitations / known gaps

- **Not collected:** object SIDs, full `memberOf` graph, ACLs (GenericAll etc.),
  active sessions, local-admin relationships, GPO/OU/Container objects.
- **Heuristic findings** (e.g. credential-in-description) are reported at
  **Medium confidence** and require human review; deterministic findings
  (captured hashes, UAC flags) are High confidence.
- **Offline only** for hash material — no cracking is performed or assisted.
- **Performance at scale** is not yet benchmarked against a large lab forest;
  see [BENCHMARKS.md](BENCHMARKS.md) (results pending).

## Responsible use

diego is intended for authorised security diagnostics, CTFs, lab research, and
defensive baselining. Running it against directories you do not own or are not
explicitly authorised to assess may be illegal.
