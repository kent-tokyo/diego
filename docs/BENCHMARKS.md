# diego — Benchmarks

> **Status: no measurements are published.** Use this method only in a
> controlled, authorised lab. Until a run records its conditions and raw
> results, diego makes no performance or coverage claim.

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

## Planned lab matrix

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

Record the diego version, DC OS/version, network RTT, jitter setting, module
selection, and a redacted environment description.

## Results

No result table is maintained until a controlled lab run can include the
version, environment, command, raw measurements, and redaction rationale.
Unmeasured performance is not zero performance.

## Contributing measurements

If you run diego against a lab forest, a PR adding a row (with the environment
details above) is welcome. Please do not submit numbers from production
directories or environments you are not authorised to test.
