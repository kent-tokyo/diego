# DIEGO — Development Tasks

**Project:** Domain Intranet Elusive Guardian & Offensive-Scouter  
**Current Version:** 0.1.3 (in progress)  
**Last Updated:** 2025-06-14

---

## 📊 Test Coverage Progress

| Metric | Progress | Details |
|--------|----------|---------|
| Total Tests | 238 / ∞ | lib: 216, bin: 207, integration: 15 |
| Code Coverage | ~36-37% | 654/1,899 LOC |
| Target | 50%+ | Focus on AI + MCP modules |

---

## ✅ Completed Features

### Core Implementation (Sessions 1-5)
- [x] **Session 1:** Kerberos protocol (AS-REP, TGS) — 85 tests, 20.91% coverage
- [x] **Session 2:** LDAP enumeration + TGS-REP — 61 new tests, 28.65% coverage
- [x] **Session 3:** LLMNR/NBT-NS passive monitoring — 27 new tests, 31.54% coverage
- [x] **Session 4:** Cleartext credential capture — 33 new tests, 34.44% coverage
- [x] **Session 5:** MCP tools infrastructure — 32 new tests, ~36-37% coverage

### Documentation & Features (Post-Session 5)
- [x] CLI usage examples (10 practical examples)
- [x] Japanese README translation (README_ja.md)
- [x] Multi-language README framework
- [x] Password-less authentication support:
  - Environment variable ($DIEGO_PASSWORD)
  - Kerberos keytab (~/.diego/keytab)
  - Kerberos TGT cache detection (KRB5CCNAME, /tmp/krb5cc_*)
  - Interactive fallback prompt

---

## 🔄 In Progress / Next

### Session 6: Claude API Client + Report Generation Tests
- **Files:** `src/ai/claude.rs` (76 LOC) + `src/report/markdown.rs` (76 LOC)
- **Focus:**
  - Claude API client initialization
  - Attack narrative synthesis
  - Markdown report formatting
  - Interactive chat
- **Estimated Tests:** 20-30
- **Target Coverage:** 40%+
- **Status:** 📋 Planned

### Session 7: LDAP Advanced Queries
- **Files:** Constrained delegation, RBCD, privilege groups, stale passwords
- **Estimated Tests:** 25-35
- **Target Coverage:** 45%+
- **Status:** 📋 Planned

### Session 8: Full Integration Tests
- **Focus:** End-to-end LDAP/Kerberos/AI workflows
- **Estimated Tests:** 15-20
- **Target Coverage:** 50%+
- **Status:** 📋 Planned

---

## 📝 Documentation Status

| Task | Status | Details |
|------|--------|---------|
| README.md — Feature overview | ✅ | Key pillars, comparison table |
| README.md — CLI usage examples | ✅ | 10 practical examples |
| README.md — Password resolution | ✅ | 4 credential methods |
| README_ja.md — Japanese translation | ✅ | Full Japanese docs |
| README_ja.md — CLI examples (Japanese) | ✅ | 10 examples in Japanese |
| README_ja.md — Password docs (Japanese) | ✅ | Japanese credential guide |
| README_zh.md — Simplified Chinese | 📋 | In progress |
| README_zh_TW.md — Traditional Chinese | 📋 | Planned |
| README_fr.md — French | 📋 | Planned |
| README_es.md — Spanish | 📋 | Planned |
| README_de.md — German | 📋 | Planned |
| CONTRIBUTING.md | 📋 | Development guide |
| SECURITY.md | 📋 | Responsible disclosure |
| CHANGELOG.md | 📋 | Release notes |

---

## 🎯 Implementation Checklist

### Testing (Sessions 1-8)
- [x] Kerberos protocol tests
- [x] LDAP enumeration tests
- [x] Passive monitoring tests
- [x] MCP tool infrastructure tests
- [ ] Claude API client tests
- [ ] Report generation tests
- [ ] Advanced LDAP queries tests
- [ ] End-to-end integration tests

### Features
- [x] AS-REP Roasting
- [x] Kerberoasting
- [x] LDAP topology enumeration
- [x] Password policy extraction
- [x] Unconstrained delegation detection
- [x] LLMNR/NBT-NS passive monitoring
- [x] Cleartext protocol capture
- [x] MCP server mode
- [x] Password-less authentication
- [ ] Claude API integration
- [ ] Attack narrative synthesis
- [ ] Interactive chat mode
- [ ] Constrained delegation detection
- [ ] RBCD detection
- [ ] Privilege group enumeration
- [ ] Stale password detection

### Documentation
- [x] English README (CLI examples, password methods)
- [x] Japanese README (full translation)
- [ ] Chinese (Simplified) README
- [ ] Chinese (Traditional) README
- [ ] French README
- [ ] Spanish README
- [ ] German README
- [ ] CONTRIBUTING guide
- [ ] SECURITY policy

---

## 🧪 Test Infrastructure

| Component | Status | Tests |
|-----------|--------|-------|
| Unit tests (lib) | ✅ | 216 tests |
| Binary tests | ✅ | 207 tests |
| Integration tests | ✅ | 15 tests |
| Total | ✅ | 238 tests |

---

## 🔐 OPSEC Features Implemented

- [x] No command execution (pure protocols)
- [x] Credential zeroization
- [x] Request jitter (100-500ms)
- [x] Read-only LDAP
- [x] Pure Rust (no .NET/PS/Python)
- [x] Password-less auth (keytab, TGT cache)
- [x] Environment variable for credentials
- [ ] Static binary builds (musl)
- [ ] Minimal dependencies

---

## 📦 Release Roadmap

**v0.1.3** (Current)
- Password-less authentication
- Multi-language README support
- CLI examples and documentation

**v0.2.0** (Target)
- 50%+ code coverage
- Claude API client
- Report generation (Markdown)
- Interactive chat mode
- Advanced LDAP queries
- Full integration tests

**v0.3.0** (Future)
- Static binary (musl)
- CI/CD pipeline
- AES Kerberoasting
- DCSync ACL checking

---

## 🌍 Supported Languages

| Language | Status | File |
|----------|--------|------|
| English | ✅ | README.md |
| Japanese | ✅ | README_ja.md |
| Simplified Chinese | 📋 | README_zh.md |
| Traditional Chinese | 📋 | README_zh_TW.md |
| French | 📋 | README_fr.md |
| Spanish | 📋 | README_es.md |
| German | 📋 | README_de.md |

---

## 🔗 Resources

- **Repository:** https://github.com/kent-tokyo/diego
- **Crates.io:** https://crates.io/crates/diego
- **Documentation:** See README.md and language variants
- **License:** MIT

---

## 📞 Contact & Support

- **Issue Tracker:** GitHub Issues
- **Author:** kent-tokyo <kent-tokyo@users.noreply.github.com>
- **Email:** ke.tanabe@gmail.com
