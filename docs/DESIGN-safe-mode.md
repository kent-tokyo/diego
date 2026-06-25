# Design sketch: safe mode (`--mode audit` / `--export-hashes`)

> **Status: design only — not implemented.** This records the intended design so
> it can be reviewed before any code is written. Tracked in
> [ROADMAP.md](../ROADMAP.md).

## Motivation

diego is positioned as a **defensive** AD diagnostic tool, but some of its
output is dual-use: AS-REP Roasting and Kerberoasting findings can include
**crackable hash material** (`$krb5asrep$…`, `$krb5tgs$…`). For an auditor who
only needs to know *"this account is roastable"*, emitting the hash is
unnecessary and raises the blast radius if a report leaks.

The goal: make the **defensive output the default**, and gate offensive output
behind an explicit, visible opt-in — so the safe thing is the easy thing.

## Proposed modes

| Mode | Flag | Emits findings? | Emits hash material? |
|------|------|-----------------|----------------------|
| **Audit** (proposed default) | `--mode audit` | Yes (incl. "roastable", severity, remediation) | **No** — hash fields omitted/redacted |
| **Full** | `--mode full` | Yes | Only if `--export-hashes` is *also* given |

- `--export-hashes` is a no-op (or an error) without `--mode full`, so exporting
  crackable material always requires a deliberate, legible combination.
- In audit mode, a roastable account still produces its finding; the `evidence`
  simply omits the `hash`/`hash_value` field (e.g. replaced with
  `"redacted": true`) so downstream tooling can tell it was intentionally
  withheld.

## Implementation notes (for later)

- **Where to gate:** prefer filtering at the **report layer** (strip hash fields
  from `Finding.evidence` when not in full+export mode) rather than skipping
  capture in the Kerberos module — this keeps one code path and one place to
  audit. Capture can stay; emission is what's gated.
- **Config:** add a `mode` enum and `export_hashes: bool` to `Config`
  (`src/config.rs`); thread into `Report::write` / the formatters, or apply a
  redaction pass on the `Report` before output.
- **MCP:** the `run_asrep_roasting` / `run_kerberoasting` tools would respect the
  same gate; consider an explicit tool argument mirroring `--export-hashes`.

## Backwards compatibility

Today's default emits hashes. Switching the default to `audit` is a behaviour
change, so it should land on a minor bump (≥ 0.3.0) with a clear CHANGELOG note
and a one-line migration ("pass `--mode full --export-hashes` for the previous
behaviour").

## Relationship to the Threat Model

This reinforces [THREAT_MODEL.md](THREAT_MODEL.md): diego does not crack hashes
and is for authorised assessment. A defensive-by-default output mode makes that
posture the path of least resistance rather than just a documented intent.
