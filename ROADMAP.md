# diego Roadmap

This roadmap is organized around a single product thesis: diego should be the
most trustworthy way to measure the **read-only, standard-user blast radius**
of an Active Directory environment. It is not a promise of invisibility and it
is not an exploitation roadmap. Every phase is for authorised defensive
assessment, with explicit evidence, safety controls, and reproducible results.

## Competitive strategy

The market already has strong point solutions:

| Alternative | Strength to respect | diego's target advantage |
|---|---|---|
| PingCastle | Broad AD health checks, maturity reporting, domain consolidation | A single Rust binary, stronger evidence lineage, safe-mode defaults, and deterministic machine-readable output |
| BloodHound CE/Enterprise | Identity graph and attack-path exploration | A smaller, read-only exposure assessment that can run from an ordinary endpoint and explain findings without pretending to be a complete graph |
| Purple Knight and similar auditors | Curated AD security checks and operator-friendly findings | Cross-platform offline operation, privacy-preserving reports, and tests that prove each detector against fixtures |
| Continuous monitoring platforms | Ongoing change detection and enterprise workflow | A low-friction baseline and verification agent that can feed existing SIEM/ticketing workflows without requiring a SaaS control plane |

The advantage must be demonstrated, not asserted. The primary scorecard is:

- time from download to first useful report;
- coverage of high-impact, standard-user-visible misconfigurations;
- finding precision, confidence, and evidence completeness;
- peak memory, query count, and network footprint in a published lab;
- percentage of remediations verified by a later baseline;
- zero secret leakage in audit-mode output.

## Phase 0 — Trust, scope, and release gate (v0.4.x)

**Goal:** make the existing feature set safe to evaluate and easy to trust.

- Finish the mock LDAP fetch path and representative AD lab validation.
- Define a versioned finding contract: stable IDs, severity, confidence,
  evidence, remediation, source attributes, and collection timestamp.
- Make authorisation, read-only behaviour, safe mode, and detection assumptions
  visible in CLI help and every report.
- Add a threat-model review to every new detector; reject checks that require
  privilege escalation, code execution, credential dumping, or exploit logic.
- Publish benchmark methodology and reproducible redacted fixtures.

**Exit criteria:** all v0.4 findings have fixture coverage; audit-mode reports
pass schema and secret-scanning tests; benchmark results are published; the CLI
and report formats are stable enough for external users.

## Phase 1 — Evidence-first detection engine (v0.5)

**Goal:** beat broad scanners on explainability and operator confidence.

Status: core metadata and `--explain` support are implemented; detector
expansion and mutation testing remain for follow-up releases.

- Add stable finding IDs and evidence bundles with redaction by default.
- ✅ Add detector metadata: required permissions, LDAP/Kerberos queries, expected
  false positives, confidence rationale, and remediation references.
- Expand read-only detectors for trusts, SID history, privileged group paths,
  delegation variants, stale objects, password policy, and certificate-related
  exposure where the data is available to a standard user.
- Add deterministic fixture-driven tests, golden reports, and mutation tests for
  parser boundaries and unsafe inputs.
- ✅ Support `--explain <finding-id>` so an operator can trace finding → evidence →
  remediation without reading source code.

**Exit criteria:** every finding is traceable to evidence; no detector silently
falls back to an unsupported assumption; regression tests cover malformed and
partial directory data.

## Phase 2 — Exposure graph, without misleading completeness (v0.6)

**Goal:** provide useful prioritisation between a flat audit and a full graph
platform.

- Collect only the object identifiers and relationships needed to connect
  diego's own findings; document the exact graph boundary.
- Generate a bounded “why this matters” exposure chain from the current user
  context to protected groups, clearly labelled as an assessment path rather
  than an exploit path.
- Export an explicitly scoped interoperability format for downstream graph
  tools; never advertise a partial export as a full BloodHound replacement.
- Add remediation simulation: show which findings disappear when a selected
  control is corrected, without changing the directory.

**Exit criteria:** path explanations are reproducible from the same input;
incomplete data is surfaced; graph output contains provenance and privacy
controls; no active exploitation or lateral movement is added.

## Phase 3 — Baseline, verification, and drift (v0.7)

**Goal:** turn a one-time assessment into measurable risk reduction.

- Version and sign baseline snapshots; support encrypted export for transfer.
- Add baseline diff with suppression rationale, expiry, owner, and ticket ID.
- Add “fixed / regressed / unknown” verification and remediation SLAs.
- Provide scheduled, operator-controlled runs through the host's normal task
  scheduler; keep collection read-only and document expected DC telemetry.
- Emit compact JSON suitable for SIEM, CI, and ticketing ingestion.

**Exit criteria:** a team can run recurring assessments, identify real drift,
verify a fix, and retain an auditable history without a cloud dependency.

## Phase 4 — Deployment and integration moat (v0.8)

**Goal:** make diego cheaper to adopt than a larger platform.

- Ship signed, reproducible Windows and Linux binaries plus a static Linux
  artifact where dependencies allow it.
- Provide offline operation, proxy/TLS configuration, least-data collection,
  and documented air-gapped transfer workflows.
- Stabilise the library API and MCP interface with capability discovery and
  audit-mode guarantees.
- Add integrations for generic webhooks, SARIF, and common SIEM ingestion;
  keep vendor-specific adapters optional and narrowly scoped.
- Publish a support matrix for AD versions, trusts, TLS modes, and failure
  behaviour.

**Exit criteria:** installation, authentication, scan, report, and export work
in a disconnected lab; integrations are contract-tested; upgrade and rollback
procedures are documented.

## Phase 5 — Validation and ecosystem (v0.9 / 1.0)

**Goal:** convert technical differentiation into credible adoption.

- Run an independent review of protocol handling, secret lifecycle, and report
  redaction.
- Publish a benchmark against representative forest sizes, with query counts,
  runtime, memory, and finding agreement—not marketing-only scores.
- Publish detector contribution guidelines and a reviewed extension API.
- Map findings to CIS, Microsoft security baselines, and MITRE ATT&CK with
  scope and confidence labels; do not claim compliance certification.
- Establish a public compatibility and release policy, including deprecation
  rules for report schemas.

**1.0 exit criteria:** reproducible release artifacts, independent security
review completed, documented performance envelope, stable schema/API policy,
and a measured remediation workflow from baseline to verified closure.

## Deferred until the core moat is proven

- Native GSSAPI LDAP bind if it can be delivered without sacrificing the
  cross-platform/static build target.
- Entra ID or other cloud identity providers after on-premises AD coverage and
  data-boundary controls are mature.
- A plugin architecture after the detector contract is stable and there is a
  demonstrated contributor need.
- Full BloodHound-compatible graph collection, because partial graph data can
  create false confidence.

## Non-goals

diego will not become an exploitation framework, credential-dumping tool,
lateral-movement tool, persistence mechanism, or detection-evasion guarantee.
It will not run commands on target hosts, crack captured hashes, or make
unauthorised changes to Active Directory.
