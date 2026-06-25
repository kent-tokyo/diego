# Security Policy

## Scope

diego is a defensive/diagnostic security tool. This policy covers vulnerabilities
**in diego itself** — for example:

- memory-safety or panic issues in protocol parsing (Kerberos ASN.1, LDAP,
  packet handling);
- a crafted server response or directory value that causes a crash or, in the
  HTML report, escapes HTML escaping (XSS in the generated report);
- credential handling defects (e.g. secrets not zeroized).

It does **not** cover misconfigurations in *your* Active Directory — diego's job
is to help you find those.

## Reporting a vulnerability

Please report privately rather than opening a public issue:

- Preferred: GitHub **Security Advisories** → "Report a vulnerability" on the
  repository (Security tab).
- Alternatively, open a minimal issue asking for a private contact channel
  **without** disclosing details.

Please include: affected version (`diego --version`), platform, a description,
and a reproduction (a redacted packet/LDAP value is ideal).

## Coordinated disclosure

We aim to acknowledge reports promptly and work on a fix before public
disclosure. We will credit reporters who wish to be named. Please give us
reasonable time to release a patch before disclosing publicly.

## Supported versions

diego is pre-1.0; security fixes target the latest released `0.x` line.
