# DIEGO - Domain Intranet Elusive Guardian & Offensive-Scouter

Non-privileged Active Directory security diagnostic agent, written in Pure Rust.

---

**DIEGO** is a post-exploitation reconnaissance and security diagnostic agent for Active Directory environments. It operates entirely with standard domain user credentials, produces no noisy network artefacts, and ships as a single static binary.

## Key Pillars

- **Unprivileged** — Works with standard domain user credentials only. No administrator rights required at any stage.
- **Stealth (OPSEC-friendly)** — Issues only legitimate AD queries. No aggressive scanning. Configurable jitter between requests blends with normal domain traffic.
- **Portable** — Single static binary with zero runtime dependencies. Drop and run on any target host.
- **Pure Rust** — No .NET CLR, no PowerShell, no Python interpreter. Every protocol interaction — Kerberos ASN.1 framing, LDAP, RC4-HMAC — is implemented in pure Rust (RustCrypto). This eliminates the ETW / AMSI / Script Block Logging attack surface that EDR products monitor most aggressively.
- **AI-First** — Claude API integration synthesises scan output into a coherent attack narrative. MCP server mode allows LLM clients to orchestrate individual diagnostic tools directly.

---

## Quick Start

```bash
# CLI mode — run all diagnostic modules
diego --dc 10.0.0.1 --domain corp.local --username jdoe --password P@ss

# With AI analysis (requires ANTHROPIC_API_KEY)
diego --dc 10.0.0.1 --domain corp.local --username jdoe --password P@ss --ai-analyze

# Interactive AI chat after scan
diego ... --ai-analyze --chat

# MCP server mode (for Claude Desktop / MCP clients)
diego --mcp
```

---

## Diagnostic Modules

### Kerberos — `Asn1Kerberos`

Interacts directly with the KDC over port 88 using raw ASN.1/Kerberos frames.

- **AS-REP Roasting** — identifies accounts with Kerberos pre-authentication disabled and captures AS-REP hashes
- **Kerberoasting** — requests TGS tickets for all SPN-bearing accounts
- All hashes are emitted in Hashcat-compatible format (`$krb5asrep$`, `$krb5tgs$`)

### LDAP — `LdapQuery`

Performs read-only LDAP queries against the domain controller.

- AD topology enumeration (domain, forest, sites, trusts)
- Description field credential leak detection
- Unconstrained delegation discovery
- Password policy extraction (lockout threshold, minimum length, complexity)

### Passive — `PassiveListen`

Monitors local network traffic without sending any packets.

- LLMNR / NBT-NS broadcast detection → identifies hosts susceptible to name-poisoning attacks
- Cleartext protocol monitoring (LDAP, HTTP, FTP, Telnet)

### AI Analysis

Requires `ANTHROPIC_API_KEY`.

- Claude-powered attack narrative from raw scan results
- Critical path to Domain Admin synthesis
- Prioritised remediation recommendations
- Interactive chat mode for follow-up investigation

---

## MCP Server Mode

When started with `diego --mcp`, the binary exposes a Model Context Protocol server. MCP-compatible clients (Claude Desktop, custom LLM agents) can invoke individual diagnostic tools directly.

| Tool | Description |
|------|-------------|
| `enumerate_asrep_candidates` | List accounts with pre-auth disabled |
| `enumerate_spn_accounts` | List accounts with registered SPNs |
| `enumerate_constrained_delegation` | Find accounts/computers with S4U2Self→S4U2Proxy delegation |
| `enumerate_rbcd` | Find objects with Resource-Based Constrained Delegation |
| `enumerate_privileged_groups` | List members of high-privilege groups (DA/EA/Backup Ops etc.) |
| `enumerate_stale_service_passwords` | Find SPN accounts with passwords >365 days old |
| `check_unconstrained_delegation` | Find computers/accounts with unconstrained delegation |
| `check_password_policy` | Retrieve domain password and lockout policy + spray estimation |
| `scan_description_leaks` | Search AD descriptions for embedded credentials |
| `run_asrep_roasting` | Capture AS-REP hashes for offline cracking |
| `run_kerberoasting` | Capture TGS hashes for offline cracking |
| `listen_llmnr` | Passive LLMNR/NBT-NS broadcast monitor |
| `full_scan` | Run all modules and return consolidated JSON report |

---

## Comparison with Similar Tools

| Feature | **diego** | BloodHound / SharpHound | Impacket (GetUserSPNs etc.) | PowerView | Rubeus | PingCastle |
|---------|-----------|-------------------------|-----------------------------|-----------|--------|------------|
| Language / runtime | Rust — single static binary | C# (.NET) + Python | Python 3 | PowerShell | C# (.NET) | C# (.NET) |
| **Pure Rust / no C runtime** | **Yes** | No (.NET CLR) | No (CPython) | No (PS runtime) | No (.NET CLR) | No (.NET CLR) |
| Privilege required | **Standard user only** | Local admin on endpoints | Domain user (some ops need admin) | Domain user | Domain user | Domain admin recommended |
| Detectable by EDR | **Low** — no .NET/PS/Python | High — .NET reflection, AMSI | Medium | High — AMSI / Script Block Logging | High — .NET, known signatures | Medium |
| Active scanning / noise | **No** — read-only LDAP + Kerberos only | Yes — SMB, RPC, massive LDAP dump | Moderate | Moderate | Yes | Yes — extensive LDAP/RPC |
| Jitter / OPSEC throttling | **Yes** | No | No | No | No | No |
| AS-REP Roasting | **Yes** | No (data only) | Yes (`GetNPUsers.py`) | No | **Yes** | No |
| Kerberoasting | **Yes** | No (data only) | Yes (`GetUserSPNs.py`) | No | **Yes** | No |
| Unconstrained Delegation | **Yes** | **Yes** | Partial | **Yes** | No | **Yes** |
| Password Policy | **Yes** | No | No | **Yes** | No | **Yes** |
| Description credential leak | **Yes** | No | No | Partial | No | No |
| LLMNR/NBT-NS detection | **Yes** | No | No | No | No | No |
| Cleartext protocol detection | **Yes** | No | No | No | No | No |
| Cross-platform (Linux) | **Yes** | No | **Yes** | No | No | No |
| AI analysis (Claude API) | **Yes** | No | No | No | No | No |
| MCP server mode | **Yes** | No | No | No | No | No |
| Structured JSON output | **Yes** | **Yes** (Neo4j) | Partial | No | Partial | No (HTML) |
| Zero install / drop-and-run | **Yes** | No | No | No | No | No |

### Summary

- **BloodHound** is the gold standard for attack path visualisation, but requires local admin for SharpHound collection and generates significant noise (SMB, RPC, LDAP bulk dumps). It does not perform active exploitation like Roasting.
- **Impacket** covers Roasting well but requires a Python environment on the attacker machine and cannot run on the foothold host itself.
- **Rubeus** is the most capable Kerberos attack tool but is .NET-only, Windows-only, and heavily signatured by EDR.
- **PowerView** is powerful for LDAP enumeration but PowerShell is the most scrutinised execution environment in modern SOCs.
- **PingCastle** is the closest to diego in intent (domain health check) but requires elevated privileges, produces only HTML, and has no stealth posture.
- **diego** occupies the gap: a single binary that runs from a standard user session on Linux or Windows, avoids EDR-triggering runtimes, and feeds findings directly into an AI for narrative synthesis.

---

## Build

```bash
cargo build --release

# Static Linux binary (requires musl target)
cargo build --release --target x86_64-unknown-linux-musl
```

The release profile applies LTO, single codegen unit, and binary stripping to minimise size and maximise performance.

---

## OPSEC Notes

- No OS command execution at any point — all operations are pure network protocol interactions.
- Randomised jitter is applied between LDAP and Kerberos requests to avoid uniform timing signatures.
- All queries are functionally identical to those issued by standard Windows domain workstations and domain management tools.
- No writes to the directory; all operations are strictly read-only.

---

## License

MIT
