# Changelog

All notable changes to diego are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.24.0] - 2026-10-16

### Added
- Bounded, explicit-target Web-header posture checks for HTTPS redirect,
  security headers, framing policy, and cookie attributes. The module makes one
  unauthenticated request per URL (with a range-limited fallback only when HEAD
  is unsupported); it does not follow redirects, crawl, authenticate, or send
  attack payloads.
- Bounded public WordPress posture checks for explicitly named site roots:
  generator exposure, X-Pingback, XML-RPC, REST index, and `readme.html`.
  These checks do not log in, enumerate users or plugins, verify CVEs, or send
  POST requests.
- A local-only (`127.0.0.1`) browser UI for the bounded Web and WordPress
  checks. It supports English, Japanese, Simplified Chinese, and Traditional
  Chinese; requires an operator acknowledgement; handles one target at a time;
  and does not retain results or expose a remote listener.

### Changed
- Endpoint-only and local-path modules no longer require a placeholder AD
  domain. Email remains domain-based; AD modules retain their domain and
  credential requirements.

## [0.23.0] - 2026-09-26

### Added
- Credential-free email DNS, explicit TLS, and Unix file-permission posture
  modules. They do not require a Domain Controller or credentials.
- Bounded multi-domain plans, resumable integrity-protected checkpoints, and
  offline plan validation.

### Changed
- Audit output redacts sensitive evidence by default. Password input is explicit
  (`--password`, `DIEGO_PASSWORD`, or prompt); keytab/TGT-cache login is not
  supported.

## Earlier 0.x releases

- Foundation: read-only LDAP, Kerberos, and passive diagnostics; JSON,
  Markdown, and HTML reporting; baseline comparison and confidence scoring.
- Safety and contracts: audit-default evidence redaction, report schema,
  golden/detection tests, and contributor/security guidance.
- Operations: reusable library API, finding explanations, bounded exposure and
  remediation views, governance, multi-domain plans, SARIF, and webhook output.

For tagged release notes, see the [GitHub releases](https://github.com/kent-tokyo/diego/releases).
