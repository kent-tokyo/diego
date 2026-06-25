# diego Roadmap

This roadmap is deliberately honest about what is done, what is parked, and
*why*. diego is past its initial feature push; the near-term focus is
**stabilisation and evidence**, not new surface area.

## Now — 0.2.x: stabilisation (near feature-freeze)

Priority is bug fixes, issue triage, and real-user feedback over new features.

- ✅ Green CI on all platforms (Linux musl, Windows, clippy, security audit).
- ✅ Honest README / Threat Model (host-based vs DC-side detection).
- ✅ HTML report, baseline diff, confidence scoring, audit appendix.
- ✅ Output contract: published JSON Schema (`docs/report.schema.json`) +
  golden test guarding report drift.
- ✅ Contributor front-door: CONTRIBUTING, SECURITY, issue/PR templates.
- ⏳ Triage incoming issues; patch releases (0.2.1, 0.2.2, …) as fixes land.

## Needs a lab environment (cannot be produced from this repo alone)

- **Real-environment evaluation.** Run against a representative forest
  (e.g. Windows Server 2022, ~10k users, multi-domain) and fill in the results
  table in [docs/BENCHMARKS.md](docs/BENCHMARKS.md) (runtime, peak RSS, query
  counts). Methodology is already published; only numbers are pending.
- **Reproduction corpus.** A redacted LDAP dump / mock domain fixture so issues
  can be reproduced deterministically in CI without a live DC. This would also
  let the golden test cover live detection logic end-to-end (today it covers
  report *format* over a synthetic fixture, not detection).

## Future design (not yet — intentionally deferred)

- **Plugin architecture.** Refactor detectors behind a `trait Detector` and a
  `detectors/` directory once the detector count grows (it is ~13 today; this is
  premature now). Lowers the barrier for external contributors.
- **BloodHound export.** Requires first collecting object SIDs and full group
  membership; a partial graph from current findings would mislead, so it stays
  deferred. See THREAT_MODEL.md (Limitations).
- **CIS "Mapped Controls".** Map findings to CIS / Microsoft Security Baseline /
  MITRE ATT&CK as a partial, clearly-scoped mapping — not a full compliance
  claim.
- **Cloud identity** (Entra ID / AWS / GCP IAM): a possible long-term direction,
  not committed.

## Non-goals

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): diego is not an exploitation
framework, not a detection-evasion guarantee, and not a full graph collector.
