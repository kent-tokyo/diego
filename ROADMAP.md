# diego Roadmap

This roadmap is deliberately honest about what is done, what is parked, and
*why*. diego is past its initial feature push; the near-term focus is
**stabilisation and evidence**, not new surface area.

## Completed — v0.3.0

- ✅ LDAP/Kerberos/passive diagnostics and JSON/Markdown/HTML reports.
- ✅ Baseline diff, confidence scoring, audit appendix, and JSON Schema.
- ✅ Safe mode: hash material is redacted unless explicitly exported.
- ✅ Cross-platform CI, dependency auditing, and crates.io publication.

## Now — v0.4.0

The focus is reproducible evidence and a stable analysis boundary before adding
more protocol surface area.

- ✅ Add a synthetic, redacted LDAP JSON corpus and load-and-analyze regression tests.
- ⏳ Exercise the LDAP fetch path with a lightweight mock server.
- ⏳ Publish a reusable library scan API without weakening safe-mode guarantees.
- ⏳ Validate runtime, memory, and query counts in a representative AD lab.

## Needs a lab environment (cannot be produced from this repo alone)

- **Real-environment evaluation.** Run against a representative forest
  (e.g. Windows Server 2022, ~10k users, multi-domain) and fill in the results
  table in [docs/BENCHMARKS.md](docs/BENCHMARKS.md) (runtime, peak RSS, query
  counts). Methodology is already published; only numbers are pending.
- **Reproduction corpus → live-path detection tests (v0.4.0).** Today
  `tests/detection_tests.rs` calls `analyze::build_*` with hand-built
  `LdapObject`s. To cover the full fetch→analyze path deterministically without
  a live DC, in stages:
  1. **Define a fixture format**: recorded/redacted LDAP responses as JSON
     (`SearchEntry` → `LdapObject`), stored under `tests/corpus/`.
  2. **Load-and-analyze tests**: read those fixtures and run them through
     `analyze::build_*`, asserting findings — one step more realistic than the
     current synthetic-object calls.
  3. **(stretch) Lightweight mock LDAP server** so the filter/fetch side
     (`queries.rs`) is exercised end-to-end too.

  Status: the **analysis** side and recorded JSON boundary are covered; the
  fetch layer still needs a mock server and lab validation.

## Future design (not yet — intentionally deferred)

- ✅ **Safe mode (`--mode audit` / `--export-hashes`).** Implemented in 0.3.0:
  audit mode (the default) redacts crackable hash material from all report
  formats; hash output requires explicit `--mode full --export-hashes`. MCP tool
  responses are always audit-mode. See [docs/DESIGN-safe-mode.md](docs/DESIGN-safe-mode.md).
- **GSSAPI / Kerberos bind.** `~/.diego/keytab` and TGT cache detection are
  implemented (config.rs), but the LDAP layer still uses simple bind. Native
  GSSAPI auth (via ldap3 SASL or libgssapi-krb5 bindings) is deferred — it
  requires a cross-platform native-lib dependency that breaks the static musl
  build. Target: after v0.4 lab validation once a rustls-compatible SASL path
  is available.
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
