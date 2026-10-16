# diego roadmap

diego prioritises evidence, clear operator boundaries, and safe defaults. It
does not promise stealth, exploitation, lateral movement, a complete identity
graph, or a BloodHound export.

## Current status: v0.24.0 is released

The published release provides standard-user Active Directory diagnostics,
credential-free email/TLS/file-permission checks, bounded Web/WordPress
posture checks, a local multilingual Web UI, audit-safe reports, and bounded
multi-domain plans. Everything below is planned work.

## Next: v0.25 — evidence and deterministic coverage

The published `web`, `wordpress`, and loopback-only Web UI features remain
unauthenticated, non-crawling posture checks. Web targets are exact URLs;
WordPress targets are exact site roots; the UI takes one acknowledged target
and stores nothing. `tls`, `web`, `wordpress`, and `fs` do not need a
placeholder AD domain.

**Release gate**

1. Publish a support matrix with platform, privilege, network position, and
   known limits for every surface.
2. Add fixtures for successful, unavailable, malformed, partial, and
   inconclusive responses.
3. Add deterministic module outcomes and request/failure counters; keep
   benchmark claims unpublished until an authorised lab run is reproducible.

## After v0.25

- Improve TLS result fidelity only after fixture-backed chain and hostname
  validation.
- Improve report ergonomics without weakening audit-default redaction.
- Consider Windows ACL posture only if it remains unprivileged, read-only,
  explicitly scoped, and fixture-tested.

Cloud identity enumeration is not committed work; it needs a separate threat
model and API/consent review.

## v1.0 — independent verification

v1.0 requires independent review of protocol handling, credential lifecycle,
redaction, read-only guarantees, report compatibility, support coverage, and
benchmark methodology. The detailed scope and permanent non-goals are in the
[threat model](docs/THREAT_MODEL.md).
