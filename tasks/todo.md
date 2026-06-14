# DIEGO — Development Tasks

**Project:** Domain Intranet Elusive Guardian & Offensive-Scouter  
**Current Version:** 0.1.2  
**Last Updated:** 2025-06-14

---

## 📊 Test Coverage Progress

| Metric | Progress | Details |
|--------|----------|---------|
| Total Tests | 238 / ∞ | lib: 216, bin: 207, integration: 15 |
| Code Coverage | ~36-37% | 654/1,899 LOC |
| Target | 50%+ | Focus on AI + MCP modules |

---

## ✅ Completed Sessions

### Session 1: Phase 1 & 2 Security Fixes + CI
- **Focus:** Kerberos protocol foundation (AS-REQ, AS-REP, TGS-REP)
- **Tests Added:** 85 tests
- **Coverage:** 20.91%
- **Status:** ✅ Complete

### Session 2: TGS-REP & LDAP Query Tests
- **Focus:** Kerberos response parsing, LDAP enumeration
- **Tests Added:** 61 new → 146 total
- **Coverage:** 28.65%
- **Status:** ✅ Complete

### Session 3: LLMNR/NBT-NS Passive Monitoring
- **Focus:** Broadcast-based name resolution detection
- **Tests Added:** 27 new → 173 total
- **Coverage:** 31.54%
- **Status:** ✅ Complete

### Session 4: Cleartext Credential Capture
- **Focus:** HTTP, FTP, SMTP, Telnet cleartext protocols
- **Tests Added:** 33 new → 206 total
- **Coverage:** 34.44%
- **Status:** ✅ Complete

### Session 5: MCP Tools Infrastructure Tests
- **Focus:** Tool registration, metadata, helper functions
- **Tests Added:** 32 new → 238 total
- **Coverage:** ~36-37% (estimated)
- **Status:** ✅ Complete

---

## 🔄 Next Sessions (Planned)

### Session 6: Claude API Client + Report Generation
- **Files:** `src/ai/claude.rs` (76 LOC) + `src/report/markdown.rs` (76 LOC)
- **Estimated Tests:** 20-30
- **Target Coverage:** 40%+
- **Status:** 📋 Planned

### Session 7: LDAP Advanced Queries
- **Files:** Constrained delegation, RBCD, privilege groups
- **Estimated Tests:** 25-35
- **Target Coverage:** 45%+
- **Status:** 📋 Planned

### Session 8: Full Integration Tests
- **Focus:** End-to-end LDAP/Kerberos workflows
- **Estimated Tests:** 15-20
- **Target Coverage:** 50%+
- **Status:** 📋 Planned

---

## 📝 Documentation Status

| Task | Status | Notes |
|------|--------|-------|
| README.md — CLI Examples | ✅ | 10 practical examples |
| README.md — Feature Comparison | ✅ | vs 6 competing tools |
| README_ja.md — Japanese | ✅ | Full translation |
| README_ja.md — CLI Examples | ✅ | Japanese examples |
| Support Additional Languages | 📋 | French, Spanish, German, Chinese |
| CONTRIBUTING.md | 📋 | Development guide |
| SECURITY.md | 📋 | Responsible disclosure |
| CHANGELOG.md | 📋 | Release notes |

---

## 🎯 Implementation Checklist

### Core Tests (Sessions 1-5)
- [x] Kerberos protocol (AS-REP, TGS)
- [x] LDAP enumeration
- [x] Passive monitoring (LLMNR, cleartext)
- [x] MCP tool infrastructure

### Remaining (Sessions 6-8)
- [ ] Claude API client
- [ ] Report generation (Markdown)
- [ ] Advanced LDAP queries
- [ ] End-to-end integration

### Nice-to-Have
- [ ] AES Kerberoasting
- [ ] DCSync ACL checking
- [ ] Password spray
- [ ] Static binary (musl)
- [ ] CI/CD pipeline

---

## 🔐 Security Checklist

- [x] No command execution
- [x] Credential zeroization
- [x] Request jitter
- [x] Read-only LDAP
- [x] Pure Rust (no .NET/PS/Python)
- [ ] Static binary builds
- [ ] Minimal dependencies
- [ ] EDR evasion testing

---

## 📦 Release Roadmap

**v0.1.2** (Current)
- CLI usage examples
- Japanese documentation
- MCP tool tests

**v0.2.0** (Target)
- 50%+ coverage
- Sessions 6-8 complete
- Claude API integration
- Report generation

---

## 🔗 Resources

- Repo: https://github.com/kent-tokyo/diego
- Crates: https://crates.io/crates/diego
- License: MIT

---

## Session 5b: Password-Less Authentication Implementation ✅

**Features Added:**
1. ✅ Environment variable ($DIEGO_PASSWORD)
2. ✅ Kerberos keytab (~/.diego/keytab)
3. ✅ Kerberos TGT cache detection (KRB5CCNAME, /tmp/krb5cc_*)
4. ✅ Interactive prompt (fallback)

**Files Modified:**
- src/config.rs: Added credential resolution logic
- README.md: Added password resolution documentation
- README_ja.md: Japanese translation of password docs

**Priority Order:**
1. CLI --password argument (explicit)
2. $DIEGO_PASSWORD environment variable
3. Keytab authentication (~/.diego/keytab)
4. Kerberos TGT cache
5. Interactive stdin prompt

**OPSEC Benefits:**
- No password on command line (avoids shell history)
- Supports cached Kerberos credentials (realistic AD breach scenario)
- Keytab support for automated/scripted deployments
