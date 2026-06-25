# diego — Benchmarks

> **Status: not yet measured.** The methodology and harness below are defined,
> but the result tables are placeholders pending a controlled lab run against a
> representative forest. We do not publish fabricated numbers — see the project's
> stance on claims vs. evidence in the README's *Detection considerations* and
> [THREAT_MODEL.md](THREAT_MODEL.md).

## Why this document exists

"How fast is it / how heavy is it at scale?" is a fair adoption question. Rather
than quote unverified figures, this page pins down *how* we will measure so the
numbers, once produced, are reproducible and comparable.

## What we measure

| Metric | Definition |
|--------|------------|
| Elapsed (wall clock) | `--modules all` end-to-end, excluding interactive prompts |
| Peak RSS | Maximum resident memory during the run |
| LDAP queries issued | Count of distinct LDAP requests sent to the DC |
| Kerberos requests | AS-REQ / TGS-REQ counts |
| Findings produced | Total, and per severity/confidence |

Jitter is **disabled or fixed** for benchmarking (it adds deliberate sleeps and
would otherwise dominate wall-clock); the configured jitter range is recorded
alongside results so timings are interpretable.

## Test matrix (planned)

| Scenario | Users | Computers | Domains | Notes |
|----------|-------|-----------|---------|-------|
| Small    | ~500  | ~100      | 1       | Single DC baseline |
| Medium   | ~10k  | ~2k       | 1       | Typical mid-size org |
| Large    | ~10k  | ~2k       | 5       | Multi-domain forest |

## Reproduction

```bash
# Build the optimised binary
cargo build --release

# Measure elapsed + peak RSS (Linux: /usr/bin/time -v; macOS: /usr/bin/time -l)
/usr/bin/time -v ./target/release/diego \
  --dc <DC_IP> --domain <DOMAIN> --username <USER> \
  --modules ldap,kerberos \
  --format json --output run.json

# Findings breakdown
jq '.summary' run.json
```

Record: diego version (`diego --version` / Cargo.toml), DC OS/version, network
RTT to the DC, and the jitter setting used.

## Results

| Scenario | diego version | Elapsed | Peak RSS | LDAP queries | Findings |
|----------|---------------|---------|----------|--------------|----------|
| Small    | —             | TBD     | TBD      | TBD          | TBD      |
| Medium   | —             | TBD     | TBD      | TBD          | TBD      |
| Large    | —             | TBD     | TBD      | TBD          | TBD      |

_Results will be filled in from a controlled lab run. Until then, treat the
table as **unmeasured**, not zero._

## Contributing measurements

If you run diego against a lab forest, a PR adding a row (with the environment
details above) is welcome. Please do not submit numbers from production
directories or environments you are not authorised to test.
