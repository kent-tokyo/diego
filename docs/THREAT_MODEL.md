# diego — Threat Model

diego accepts only unprivileged, read-only, bounded checks for authorised
operators.

## Goals

- Diagnose AD configuration with standard domain-user access, and inspect
  public email DNS, named TLS endpoints, and named Unix paths without
  credentials where possible.
- The unreleased Web and WordPress modules accept only exact, authorised
  targets with a small documented request bound.
- Emit prioritised findings and state detection and coverage limits plainly.

## Non-goals

- No exploitation, remote code execution, lateral movement, persistence,
  credential cracking, or unauthorised change. Audit output redacts crackable
  material unless an authorised operator explicitly requests full export.
- No port scan, path discovery, redirect following, crawl, authentication, form
  submission, WordPress user/plugin enumeration, CVE verification, or attack
  payload. The UI is loopback-only, single-target, acknowledged, and stateless.
- No detection-evasion guarantee or complete identity graph/BloodHound export.
  Use diego only with authorisation.

## Detection assumptions

A Rust binary avoids interpreter-runtime artefacts, but is **not invisible**.
Directory monitoring can observe LDAP/Kerberos activity; external Web checks can
appear in server, CDN, WAF, and network logs. Jitter changes timing, not the
request pattern.

## Supported environments

- **Host and privilege:** Linux or Windows, standard domain user; macOS is for
  development. Passive monitoring needs a local interface in the broadcast
  domain.
- **Inputs:** AD uses LDAP/Kerberos; email, TLS, Web, and WordPress checks need
  explicit inputs. Cloud identity is out of scope.

## Limitations / known gaps

- No full identity graph, ACL/session/local-admin/GPO collection, or
  keytab/TGT authentication.
- Heuristic findings need human review. Web/WordPress findings describe posture,
  not CVE applicability or exploitability.
- Scale performance is unmeasured; see [BENCHMARKS.md](BENCHMARKS.md).

## Responsible use

Use only for authorised security diagnostics, CTFs, lab research, or defensive
baselining.
