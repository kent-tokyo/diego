# DIEGO - Domain Intranet Elusive Guardian & Offensive-Scouter

Agent de diagnostic de sécurité Active Directory sans privilèges, écrit en Rust pur.

---

**DIEGO** est un agent de reconnaissance post-exploitation et diagnostic de sécurité pour les environnements Active Directory. Il fonctionne entièrement avec les credentials standard d'un utilisateur du domaine, ne produit aucun artefact réseau bruyant, et s'exécute en tant que binaire statique unique.

## Piliers Clés

- **Sans Privilèges** — Fonctionne uniquement avec les credentials standard d'un utilisateur du domaine. Aucun droit administrateur requis à aucun stade.
- **Discrétion (Compatible OPSEC)** — Émet uniquement des requêtes AD légitimes. Pas de scanning agressif. Gigue configurable entre les requêtes se fond dans le trafic normal du domaine.
- **Portable** — Binaire statique unique sans dépendances runtime. Déposez et exécutez sur n'importe quel hôte cible.
- **Rust Pur** — Aucune CLR .NET, aucun PowerShell, aucun interpréteur Python. Chaque interaction de protocole — encadrement ASN.1 Kerberos, LDAP, RC4-HMAC — est implémentée en Rust pur (RustCrypto). Cela élimine la surface d'attaque ETW / AMSI / Script Block Logging que les produits EDR surveillent le plus agressivement.
- **Centré sur l'IA** — L'intégration API Claude synthétise la sortie de balayage en un récit d'attaque cohérent. Le mode serveur MCP permet aux clients LLM d'orchestrer les outils de diagnostic individuels directement.

---

## Démarrage Rapide

```bash
# Mode CLI — exécuter tous les modules de diagnostic
# Le mot de passe peut être omis ; diego essayera : variable env → keytab → cache TGT → prompt interactif
diego --dc 10.0.0.1 --domain corp.local --username jdoe

# Avec mot de passe explicite (moins sécurisé ; évite l'historique shell avec var env à la place)
diego --dc 10.0.0.1 --domain corp.local --username jdoe --password P@ss

# Avec analyse IA (nécessite ANTHROPIC_API_KEY)
diego --dc 10.0.0.1 --domain corp.local --username jdoe --ai-analyze

# Chat IA interactif après balayage
diego ... --ai-analyze --chat

# Mode serveur MCP (pour Claude Desktop / clients MCP)
diego --mcp
```

### Résolution de Mot de Passe (Ordre de Priorité)

Lorsque le mot de passe n'est pas fourni avec `--password`, diego essaie ces méthodes dans l'ordre :

1. **Variable d'environnement `$DIEGO_PASSWORD`** — Plus compatible OPSEC pour les scripts
   ```bash
   export DIEGO_PASSWORD="P@ssw0rd"
   diego --dc 10.0.0.1 --domain corp.local --username jdoe
   ```

2. **Keytab Kerberos** — `~/.diego/keytab` (aucun mot de passe nécessaire)
   ```bash
   # Configurer keytab (nécessite kinit ou ktutil)
   ktutil: addent -password -p user@CORP.LOCAL -k 1 -e aes256-cts-hmac-sha1-96
   ktutil: write_kt ~/.diego/keytab
   
   # Puis exécuter sans mot de passe
   diego --dc 10.0.0.1 --domain corp.local --username jdoe
   ```

3. **Cache TGT Kerberos** — Variable env `KRB5CCNAME` ou `/tmp/krb5cc_*` (aucun mot de passe nécessaire)
   ```bash
   # Si déjà connecté au domaine Kerberos :
   klist  # Vérifier les tickets en cache
   diego --dc 10.0.0.1 --domain corp.local --username jdoe
   ```

4. **Prompt Interactif** — Secours si aucun des éléments ci-dessus n'est disponible
   ```
   $ diego --dc 10.0.0.1 --domain corp.local --username jdoe
   Mot de passe: █████████
   ```

---

## Modules de Diagnostic

### Kerberos — `Asn1Kerberos`

Interagit directement avec le KDC sur le port 88 en utilisant des trames ASN.1/Kerberos brutes.

- **Attaque AS-REP** — Identifie les comptes avec pré-authentification Kerberos désactivée et capture les hashs AS-REP
- **Kerberoasting** — Demande les tickets TGS pour tous les comptes porteurs de SPN
- Tous les hashs sont émis en format compatible Hashcat (`$krb5asrep$`, `$krb5tgs$`)

### LDAP — `LdapQuery`

Effectue des requêtes LDAP en lecture seule contre le contrôleur de domaine.

- Énumération de la topologie AD (domaine, forêt, sites, trusts)
- Détection des fuites de credentials dans les champs de description
- Découverte de la délégation non contrainte
- Extraction de la politique de mot de passe (seuil de verrouillage, longueur minimale, complexité)

### Passif — `PassiveListen`

Surveille le trafic réseau local sans envoyer aucun paquet.

- Détection de transmission LLMNR / NBT-NS → identifie les hôtes susceptibles d'empoisonnement de noms
- Surveillance de protocole en clair (LDAP, HTTP, FTP, Telnet)

### Analyse IA

Nécessite `ANTHROPIC_API_KEY`.

- Récit d'attaque alimenté par Claude à partir des résultats de balayage bruts
- Synthèse du chemin critique vers l'administrateur de domaine
- Recommandations de remédiation priorisées
- Mode chat interactif pour l'investigation de suivi

---

## Mode Serveur MCP

Lorsqu'il démarre avec `diego --mcp`, le binaire expose un serveur Model Context Protocol. Les clients compatibles MCP (Claude Desktop, agents LLM personnalisés) peuvent invoquer les outils de diagnostic individuels directement.

| Outil | Description |
|------|-------------|
| `enumerate_asrep_candidates` | Énumérer les comptes avec pré-auth désactivée |
| `enumerate_spn_accounts` | Énumérer les comptes avec SPN enregistrés |
| `enumerate_constrained_delegation` | Découvrir les comptes/ordinateurs avec délégation restreinte S4U2Self→S4U2Proxy |
| `enumerate_rbcd` | Découvrir les objets avec délégation restreinte basée sur les ressources |
| `enumerate_privileged_groups` | Énumérer les membres des groupes à haut privilège |
| `enumerate_stale_service_passwords` | Découvrir les comptes SPN avec mots de passe >365 jours |
| `check_unconstrained_delegation` | Découvrir les ordinateurs/comptes avec délégation sans contrainte |
| `check_password_policy` | Récupérer les politiques de mot de passe et de verrouillage du domaine |
| `scan_description_leaks` | Rechercher les credentials intégrés dans les descriptions AD |
| `run_asrep_roasting` | Capturer les hashs AS-REP pour déchiffrement hors ligne |
| `run_kerberoasting` | Capturer les hashs TGS pour déchiffrement hors ligne |
| `listen_llmnr` | Moniteur de transmission LLMNR/NBT-NS passif |
| `full_scan` | Exécuter tous les modules et renvoyer un rapport JSON consolidé |

---

## Comparaison avec des Outils Similaires

| Caractéristique | **diego** | BloodHound / SharpHound | Impacket (GetUserSPNs, etc.) | PowerView | Rubeus | PingCastle |
|---------|-----------|-------------------------|-----------------------------|-----------|--------|------------|
| Langage / runtime | Rust — binaire statique unique | C# (.NET) + Python | Python 3 | PowerShell | C# (.NET) | C# (.NET) |
| **Rust Pur / pas de runtime C** | **Oui** | Non (.NET CLR) | Non (CPython) | Non (runtime PS) | Non (.NET CLR) | Non (.NET CLR) |
| Privilèges requis | **Utilisateur standard uniquement** | Admin local sur les points de terminaison | Utilisateur de domaine | Utilisateur de domaine | Utilisateur de domaine | Admin de domaine recommandé |
| Détectable par EDR | **Bas** — pas de .NET/PS/Python | Haut — réflexion .NET, AMSI | Moyen | Haut — AMSI / Script Block Logging | Haut — .NET, signatures connues | Moyen |
| Scan actif / bruit | **Non** — LDAP + Kerberos lecture seule | Oui — SMB, RPC, dumps LDAP massifs | Modéré | Modéré | Oui | Oui — LDAP/RPC étendu |
| Gigue / limitation OPSEC | **Oui** | Non | Non | Non | Non | Non |

---

## Construire

```bash
cargo build --release

# Binaire Linux statique (nécessite la cible musl)
cargo build --release --target x86_64-unknown-linux-musl
```

---

## Notes OPSEC

- Aucune exécution de commande OS à aucun moment — toutes les opérations sont des interactions de protocole réseau pur.
- La gigue aléatoire est appliquée entre les requêtes LDAP et Kerberos pour éviter les signatures de synchronisation uniformes.
- Toutes les requêtes sont fonctionnellement identiques à celles émises par les stations de travail de domaine Windows standard et les outils de gestion de domaine.
- Aucune écriture dans l'annuaire ; toutes les opérations sont strictement en lecture seule.

---

## Licence

MIT
