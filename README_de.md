# DIEGO - Domain Intranet Elusive Guardian & Offensive-Scouter

Nicht-privilegierter Active-Directory-Sicherheits-Diagnose-Agent, geschrieben in reinem Rust.

---

**DIEGO** ist ein Post-Exploitation-Reconnaissance- und Security-Diagnose-Agent für Active-Directory-Umgebungen. Er arbeitet ausschließlich mit Standard-Domänenbenutzerdaten, erzeugt keine lauten Netzwerkentitäten und wird als einzelne statische Binärdatei bereitgestellt.

## Kernprinzipien

- **Unprivileged** — Funktioniert nur mit Standard-Domänenbenutzerdaten. Verwaltungsrechte sind in keinem Stadium erforderlich.
- **Stealth (OPSEC-freundlich)** — Gibt nur legitime AD-Anfragen aus. Kein aggressives Scanning. Konfigurierbare Zufallsverzögerung zwischen Anfragen vermischt sich mit normalem Domänenverkehr.
- **Portabel** — Einzelne statische Binärdatei ohne Laufzeitabhängigkeiten. Einfach auf jedem Zielhost platzieren und ausführen.
- **Pure Rust** — Keine .NET CLR, kein PowerShell, kein Python-Interpreter. Jede Protokollinteraktion — Kerberos ASN.1 Framing, LDAP, RC4-HMAC — ist in reinem Rust (RustCrypto) implementiert. Dies eliminiert die ETW / AMSI / Script Block Logging Angriffsfläche, die EDR-Produkte am aggressivsten überwachen.
- **AI-First** — Claude API Integration synthetisiert Scan-Ausgabe in kohärente Angriffs-Narrative. MCP-Servermodus ermöglicht es LLM-Clients, einzelne Diagnose-Tools direkt zu orchestrieren.

---

## Schnellstart

```bash
# CLI-Modus — alle Diagnose-Module ausführen
# Passwort kann weggelassen werden; diego versucht: Umgebungsvariable → keytab → TGT Cache → interaktive Eingabe
diego --dc 10.0.0.1 --domain corp.local --username jdoe

# Mit explizitem Passwort (am wenigsten sicher; verwenden Sie stattdessen Umgebungsvariable, um Shell-Verlauf zu vermeiden)
diego --dc 10.0.0.1 --domain corp.local --username jdoe --password P@ss

# Mit KI-Analyse (erfordert ANTHROPIC_API_KEY)
diego --dc 10.0.0.1 --domain corp.local --username jdoe --ai-analyze

# Interaktiver KI-Chat nach dem Scan
diego ... --ai-analyze --chat

# MCP-Servermodus (für Claude Desktop / MCP-Clients)
diego --mcp
```

### Passwort-Auflösung (Prioritätsreihenfolge)

Wenn das Passwort nicht mit `--password` angegeben ist, versucht diego diese Methoden in der folgenden Reihenfolge:

1. **`$DIEGO_PASSWORD` Umgebungsvariable** — Am OPSEC-freundlichsten für Skripte
   ```bash
   export DIEGO_PASSWORD="P@ssw0rd"
   diego --dc 10.0.0.1 --domain corp.local --username jdoe
   ```

2. **Kerberos Keytab** — `~/.diego/keytab` (kein Passwort erforderlich)
   ```bash
   # Keytab einrichten (erfordert kinit oder ktutil)
   ktutil: addent -password -p user@CORP.LOCAL -k 1 -e aes256-cts-hmac-sha1-96
   ktutil: write_kt ~/.diego/keytab
   
   # Dann ohne Passwort ausführen
   diego --dc 10.0.0.1 --domain corp.local --username jdoe
   ```

3. **Kerberos TGT Cache** — `KRB5CCNAME` Umgebungsvariable oder `/tmp/krb5cc_*` (kein Passwort erforderlich)
   ```bash
   # Wenn bereits im Kerberos-Realm angemeldet:
   klist  # Gecachte Tickets überprüfen
   diego --dc 10.0.0.1 --domain corp.local --username jdoe
   ```

4. **Interaktive Eingabe** — Fallback, wenn oben nichts verfügbar ist
   ```
   $ diego --dc 10.0.0.1 --domain corp.local --username jdoe
   Passwort: █████████
   ```

---

## Diagnose-Module

### Kerberos — `Asn1Kerberos`

Interagiert direkt mit dem KDC über Port 88 mit rohen ASN.1/Kerberos Frames.

- **AS-REP Roasting** — Identifiziert Konten mit deaktivierter Kerberos-Vorauthentifizierung und erfasst AS-REP Hashes
- **Kerberoasting** — Fordert TGS-Tickets für alle SPN-tragenden Konten an
- Alle Hashes werden in Hashcat-kompatiblem Format ausgegeben (`$krb5asrep$`, `$krb5tgs$`)

### LDAP — `LdapQuery`

Führt schreibgeschützte LDAP-Abfragen gegen den Domänencontroller durch.

- AD-Topologie-Aufzählung (Domäne, Wald, Standorte, Vertrauensbeziehungen)
- Erkennung von Anmeldedaten-Lecks in Beschreibungsfeldern
- Entdeckung unbeschränkter Delegierung
- Extrahierung von Passwortrichtlinien (Sperrschwelle, Mindestlänge, Komplexität)

### Passiv — `PassiveListen`

Überwacht lokalen Netzwerkverkehr ohne Pakete zu senden.

- LLMNR / NBT-NS Broadcast-Erkennung → identifiziert Hosts anfällig für Name-Poisoning-Attacken
- Überwachung von Cleartext-Protokollen (LDAP, HTTP, FTP, Telnet)

### KI-Analyse

Erfordert `ANTHROPIC_API_KEY`.

- Claude-betriebene Angriffs-Narrative aus Rohdaten
- Kritischer Pfad zur Domain Admin Synthese
- Priorisierte Abhilfemaßnahmen
- Interaktiver Chat-Modus für Nachfrage-Ermittlung

---

## MCP-Servermodus

Bei Start mit `diego --mcp` exponiert die Binärdatei einen Model Context Protocol Server. MCP-kompatible Clients (Claude Desktop, Custom LLM Agents) können einzelne Diagnose-Tools direkt aufrufen.

| Tool | Beschreibung |
|------|-------------|
| `enumerate_asrep_candidates` | Konten mit deaktivierter Vorauthentifizierung auflisten |
| `enumerate_spn_accounts` | Konten mit registrierten SPNs auflisten |
| `enumerate_constrained_delegation` | Konten/Computer mit S4U2Self→S4U2Proxy Delegierung finden |
| `enumerate_rbcd` | Objekte mit ressourcengestützter eingeschränkter Delegierung finden |
| `enumerate_privileged_groups` | Mitglieder von hochprivilegierten Gruppen auflisten |
| `enumerate_stale_service_passwords` | SPN-Konten mit Passwörtern >365 Tage alt finden |
| `check_unconstrained_delegation` | Computer/Konten mit unbeschränkter Delegierung finden |
| `check_password_policy` | Domänen-Passwort- und Sperrichtlinie abrufen |
| `scan_description_leaks` | Nach eingebetteten Anmeldedaten in AD-Beschreibungen suchen |
| `run_asrep_roasting` | AS-REP Hashes für Offline-Knacken erfassen |
| `run_kerberoasting` | TGS Hashes für Offline-Knacken erfassen |
| `listen_llmnr` | Passiver LLMNR/NBT-NS Broadcast Monitor |
| `full_scan` | Alle Module ausführen und konsolidierten JSON-Report zurückgeben |

---

## Vergleich mit ähnlichen Tools

| Feature | **diego** | BloodHound / SharpHound | Impacket (GetUserSPNs, etc.) | PowerView | Rubeus | PingCastle |
|---------|-----------|-------------------------|-----------------------------|-----------|--------|------------|
| Sprache / Laufzeit | Rust — einzelne statische Binärdatei | C# (.NET) + Python | Python 3 | PowerShell | C# (.NET) | C# (.NET) |
| **Pure Rust / keine C Laufzeit** | **Ja** | Nein (.NET CLR) | Nein (CPython) | Nein (PS Laufzeit) | Nein (.NET CLR) | Nein (.NET CLR) |
| Erforderliche Rechte | **Nur Standard-User** | Lokaler Admin auf Endpoints | Domain User | Domain User | Domain User | Domain Admin empfohlen |
| Von EDR erkennbar | **Niedrig** — kein .NET/PS/Python | Hoch — .NET Reflection, AMSI | Mittel | Hoch — AMSI / Script Block Logging | Hoch — .NET, bekannte Signaturen | Mittel |
| Aktives Scanning / Lärm | **Nein** — nur Read LDAP + Kerberos | Ja — SMB, RPC, massive LDAP Dumps | Mittel | Mittel | Ja | Ja — umfangreich LDAP/RPC |
| Jitter / OPSEC Drosselung | **Ja** | Nein | Nein | Nein | Nein | Nein |

---

## Bauen

```bash
cargo build --release

# Statische Linux-Binärdatei (erfordert musl Target)
cargo build --release --target x86_64-unknown-linux-musl
```

---

## OPSEC Hinweise

- Keine OS-Befehlsausführung zu irgendeinem Zeitpunkt — alle Operationen sind pure Netzwerkprotokoll-Interaktionen.
- Randomisierte Jitter wird zwischen LDAP- und Kerberos-Anfragen angewendet, um einheitliche Timing-Signaturen zu vermeiden.
- Alle Abfragen sind funktional identisch mit denen, die von Standard-Windows-Domänen-Workstations und Domänenverwaltungstools ausgegeben werden.
- Keine Schreibvorgänge im Verzeichnis; alle Operationen sind streng schreibgeschützt.

---

## Lizenz

MIT
