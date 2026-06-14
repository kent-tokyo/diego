# Diego — TODO

## Done

### Core (v0.1)
- [x] Project skeleton: Cargo.toml (edition 2024), config, error, module trait (`DiagnosticModule`)
- [x] Manual DER encoder (`asreq.rs`) — no rasn-kerberos API dependency
- [x] Kerberos crypto: inline MD4 (RFC 1320), RC4-HMAC (RFC 4757), inline RC4 — pure Rust, zero C
- [x] Kerberos module: AS-REP Roasting (AS-REQ/AS-REP), Kerberoasting (TGT acquisition + TGS-REQ)
- [x] Hashcat output: mode 18200 (AS-REP) + mode 13100 (TGS)
- [x] LDAP module: 9 queries with jitter (AS-REP candidates, SPNs, description leaks, unconstrained delegation, constrained delegation, RBCD, privileged groups, stale passwords, password policy)
- [x] Passive module: LLMNR/NBT-NS multicast UDP + pnet promiscuous cleartext detection
- [x] Report engine: JSON + Markdown with `llm_context`, `remediation_steps`, `mitre_id` per Finding
- [x] `ScanContext` + `AiAnalysis` in Report for LLM-optimised output

### AI-First (v0.2)
- [x] `--ai-analyze`: Claude API non-streaming analysis → structured `AiAnalysis` (attack narrative, critical path, immediate actions)
- [x] `--chat`: streaming SSE REPL with conversation history
- [x] `--mcp`: MCP server over stdio, JSON-RPC 2.0, 13 tools
- [x] `--mcp-init`: writes Claude Desktop `claude_desktop_config.json` snippet

### Feature enhancements (v0.3)
- [x] LDAP-CONST-DELEG: Constrained Delegation (msDS-AllowedToDelegateTo + T2A4D flag)
- [x] LDAP-RBCD: Resource-Based Constrained Delegation
- [x] LDAP-PRIVESC-GROUP: recursive privileged group membership (DA/EA/Backup Ops etc.)
- [x] LDAP-STALE-PWD: service accounts with passwords >365 days old
- [x] Password spray estimation in policy finding (safe rate vs lockout threshold)
- [x] Pure Rust pillar in README + comparison table

### Testing & CI (v0.3)
- [x] Unit tests: MD4 RFC 1320 vectors, ntlm_hash, DER int, RC4 roundtrip, Hashcat format, LDAP parser, config
- [x] Integration test: mock KDC (TcpListener) — AS-REP Roasting + PREAUTH_REQUIRED (`tests/mock_kdc.rs`)
- [x] `src/lib.rs` for integration test crate access
- [x] `.github/workflows/ci.yml`: test / OPSEC lint / musl static binary / Windows / Clippy
- [x] `.gitignore`, `Cargo.toml` metadata (repository, keywords, categories)

## Backlog

- [ ] AES Kerberos (etype 17/18) — pre-auth + AS-REP decryption; needs `sha1`, `pbkdf2`, `aes` (RustCrypto)
- [ ] DCSync ACL check — parse `nTSecurityDescriptor` binary (Windows DACL format) for replication rights
- [ ] `--mcp-proxy` mode — relay MCP calls to a remote diego instance over SSH/SOCKS
- [ ] musl cross-compile config for macOS → Linux (`.cargo/config.toml` + `brew install FiloSottile/musl-cross/musl-cross`)
- [ ] Constrained Delegation / RBCD added to MCP `enumerate_constrained_delegation` and `enumerate_rbcd` tools (done) — add to `full_scan` aggregation
