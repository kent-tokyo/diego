# diego — Agent Specification

diego is a next-generation, Rust-based security diagnostic agent that simulates a "post-initial-compromise foothold" inside an intranet (specifically in Active Directory environments). Using only standard unprivileged user credentials, it rapidly and covertly detects critical misconfigurations across an entire domain.

---

## 1. Background and Purpose

Conventional intranet diagnostic tools written in Go or Python suffer from several practical problems: heavy third-party library dependencies, aggressive packet transmission (active scanning) that triggers EDR/IDS alerts, and the operational overhead of requiring administrator privileges. diego is built around three core principles:

- **Unprivileged approach** — No administrator rights are used at any point. The tool measures the "blast radius" achievable by a new employee or a compromised endpoint PC using only their default, non-elevated credentials.
- **Stealth (OPSEC-friendly)** — No bulk scanning is performed. All diagnostics rely exclusively on queries that conform to the legitimate specifications of AD (Kerberos/LDAP).
- **Portability** — A single binary that runs immediately on the target environment (Windows or Linux) with zero dependencies.

---

## 2. Core Functionality Architecture

The agent is composed of four independent diagnostic modules orchestrated by an asynchronous execution engine (tokio).

```
                    +---------------------------------------+
                    |          diego (Single Binary)        |
                    +---------------------------------------+
                                        |
                 +----------------------+----------------------+
                 | (Async Execution Engine via Tokio)          |
                 v                      v                      v
        +-----------------+    +-----------------+    +-----------------+
        |  Asn1Kerberos   |    |    LdapQuery    |    |  PassiveListen  |
        |    (Module)     |    |    (Module)     |    |    (Module)     |
        +-----------------+    +-----------------+    +-----------------+
                 |                      |                      |
      [Kerberoasting / AS-REP]   [AD Topology / ACL]    [LLMNR/NBT-NS/SMB]
                 |                      |                      |
                 +----------------------+----------------------+
                                        |
                                        v
                        +-------------------------------+
                        |   Structured JSON/Markdown    |
                        |            Report             |
                        +-------------------------------+
```

### Module 1 — Asn1Kerberos (Kerberos Misconfiguration Diagnostics)

**Overview:** Constructs the Kerberos protocol (ASN.1 binary structures) in pure Rust without any external C library dependencies, then communicates directly with the Domain Controller (DC) over TCP/UDP port 88.

**Diagnostics performed:**

- **AS-REP Roasting** — Enumerates accounts that have pre-authentication disabled (`DONT_REQ_PREAUTH`), identifying them by username.
- **Kerberoasting** — Requests TGS (Ticket-Granting Service) tickets for all service accounts (SPNs) in the domain using standard user privileges. Checks the encryption strength of returned hashes (RC4, AES, etc.) and extracts them in offline-cracking format (Hashcat-compatible).

### Module 2 — LdapQuery (AD Structure and Permission Misconfiguration Visualization)

**Overview:** Uses the LDAP read access granted to all domain users by default to enumerate all objects in the domain asynchronously at high speed.

**Diagnostics performed:**

- **Over-privileged attribute discovery** — Scans publicly readable attributes (such as `description`) for hardcoded passwords.
- **Unconstrained Delegation** — Identifies computers with delegation settings enabled that could lead to credential theft (impersonation attacks).
- **Password Policy** — Retrieves minimum password length and account lockout thresholds to evaluate resistance to brute-force attacks.

### Module 3 — PassiveListen (Passive Network Diagnostics)

**Overview:** Rather than sending packets, this module runs resident and passively captures passing network traffic (promiscuous mode).

**Diagnostics performed:**

- **LLMNR / NBT-NS broadcast detection** — Detects packets from middleware or OS components broadcasting for non-existent hostnames (measures the domain's exposure to attacker spoofing attacks).
- **Cleartext Protocol Detector** — Passively monitors the local network segment for unencrypted credentials in transit (HTTP Basic Auth, FTP, unencrypted SMB).

---

## 3. Technology Stack (Key Crates)

Selected to minimize "reinventing the wheel" while keeping the implementation in pure Rust:

| Crate | Role | Rationale |
|---|---|---|
| `tokio` | Async runtime | Non-blocking, high-throughput processing of large numbers of LDAP queries and network I/O operations. |
| `rasn` / `rasn-kerberos` | ASN.1 codec | Safe and strict parsing and serialization of raw ASN.1 binary data exchanged with the Kerberos KDC. |
| `ldap3` | LDAP client | Pure-Rust LDAP protocol implementation for fast bulk retrieval of AD objects. |
| `pnet` (`libpnet`) | Packet analysis | Zero-copy, high-speed parsing of Layer 2/3 packets in the PassiveListen module. |
| `serde` & `serde_json` | Serialization | Outputs diagnostic results as structured data for easy integration with existing SIEM tools and reporting pipelines. |

---

## 4. OPSEC Guidelines (EDR / Detection Evasion)

Implementation rules for diego to avoid standing out inside an intranet:

### No OS-Command Execution (`std::process::Command` is prohibited)

Executing OS commands such as `net user` or `whoami` immediately triggers alerts in modern EDR solutions (CrowdStrike, Microsoft Defender for Endpoint, etc.). All data retrieval must be accomplished either by calling Win32 APIs directly (`windows-sys`) or through network sockets (LDAP/Kerberos).

### Jitter & Throttling

Concentrating LDAP queries or SPN requests within a short window causes anomaly detection in the Domain Controller's event logs (e.g., Event ID 4769). A random delay (jitter) must be inserted between queries so that diagnostic traffic blends in with normal business traffic.

---

## 5. Roadmap

- [ ] **Phase 1: Foundation** — Set up the tokio runtime and implement basic AD enumeration via `ldap3` using standard user credentials.
- [ ] **Phase 2: Kerberos Implementation** — Use `rasn` to build AS-REP / Kerberoasting packet mocks and conduct communication tests against a DC.
- [ ] **Phase 3: Passive Capabilities** — Add LLMNR/NBT-NS passive capture functionality using `pnet`.
- [ ] **Phase 4: Reporting** — Implement output of "shortest attack path to Domain Admin" hints from scan results in Markdown/JSON format.
