"""
diego Python SDK — basic usage example.

Install:
    pip install maturin
    maturin develop --features python   # builds and installs in current virtualenv

Usage:
    DIEGO_PASSWORD=P@ssw0rd python examples/scan.py
"""

import os
import json
import diego  # built by maturin develop

DC       = os.getenv("DIEGO_DC",       "10.0.0.1")
DOMAIN   = os.getenv("DIEGO_DOMAIN",   "corp.local")
USERNAME = os.getenv("DIEGO_USERNAME", "jdoe")
PASSWORD = os.getenv("DIEGO_PASSWORD", "")

if not PASSWORD:
    import getpass
    PASSWORD = getpass.getpass("Password: ")

print(f"[*] diego {diego.version()} — scanning {DOMAIN} ({DC})")

report = diego.scan(
    dc=DC,
    domain=DOMAIN,
    username=USERNAME,
    password=PASSWORD,
    modules="ldap",   # "all" | "ldap" | "kerberos" | "passive"
    timeout=10,
)

summary = report["summary"]
print(f"[+] {summary['total']} findings — "
      f"Critical:{summary['critical']} High:{summary['high']} "
      f"Medium:{summary['medium']} Low:{summary['low']}")

# Print all findings sorted by severity
for finding in report["findings"]:
    sev = finding["severity"]
    confidence = finding.get("confidence", "?")
    print(f"  [{sev}/{confidence}] {finding['id']} — {finding['title']}")

# Filter to actionable findings only
critical_high = [
    f for f in report["findings"]
    if f["severity"] in ("CRITICAL", "HIGH")
]
if critical_high:
    print(f"\n[!] {len(critical_high)} Critical/High finding(s) require attention:")
    print(json.dumps(critical_high, indent=2, default=str))
