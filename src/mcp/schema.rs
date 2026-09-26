use serde_json::Value;

/// Returns the static list of MCP tools this server exposes.
pub(super) fn tool_list() -> Vec<Value> {
    let ad_args = serde_json::json!({
        "type": "object",
        "properties": {
            "dc_ip":    {"type": "string", "description": "Domain Controller IP address"},
            "domain":   {"type": "string", "description": "AD domain name (e.g. corp.local)"},
            "username": {"type": "string", "description": "Domain username"},
            "password": {"type": "string", "description": "Domain password"},
            "timeout_secs": {"type": "integer", "default": 10}
        },
        "required": ["dc_ip", "domain", "username", "password"]
    });

    vec![
        make_tool(
            "enumerate_asrep_candidates",
            "List domain accounts that have DONT_REQ_PREAUTH set (AS-REP Roasting targets). Returns account names and DNs.",
            ad_args.clone(),
        ),
        make_tool(
            "enumerate_spn_accounts",
            "List service accounts with registered SPNs (Kerberoasting targets). Returns SAM account names, SPN list, and supported encryption types.",
            ad_args.clone(),
        ),
        make_tool(
            "check_unconstrained_delegation",
            "Find computer accounts with Unconstrained Delegation enabled. This is a Critical finding — coercion attacks can lead to full domain compromise.",
            ad_args.clone(),
        ),
        make_tool(
            "check_password_policy",
            "Read the Default Domain Password Policy (min length, lockout threshold, history, etc.).",
            ad_args.clone(),
        ),
        make_tool(
            "scan_description_leaks",
            "Search user account description fields for potential hardcoded credentials or sensitive information.",
            ad_args.clone(),
        ),
        make_tool(
            "run_asrep_roasting",
            "Perform AS-REP Roasting: send AS-REQ without pre-auth to a list of candidate usernames and return Hashcat-mode-18200 hashes for vulnerable accounts.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "dc_ip":    {"type": "string"},
                    "domain":   {"type": "string"},
                    "usernames": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of usernames to test (obtain from enumerate_asrep_candidates)"
                    },
                    "timeout_secs": {"type": "integer", "default": 10}
                },
                "required": ["dc_ip", "domain", "usernames"]
            }),
        ),
        make_tool(
            "run_kerberoasting",
            "Perform Kerberoasting: authenticate with the provided credentials, then request TGS tickets for all SPN accounts and return Hashcat-mode-13100 hashes.",
            ad_args.clone(),
        ),
        make_tool(
            "listen_llmnr",
            "Passively listen for LLMNR and NBT-NS broadcast queries on the local network. Returns observed queries with source IPs and queried hostnames.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "timeout_secs": {"type": "integer", "default": 30, "description": "How long to listen (seconds)"}
                }
            }),
        ),
        make_tool(
            "enumerate_constrained_delegation",
            "Find accounts and computers with Constrained Delegation configured (msDS-AllowedToDelegateTo or T2A4D flag). S4U2Proxy abuse can allow impersonating any user to listed services.",
            ad_args.clone(),
        ),
        make_tool(
            "enumerate_rbcd",
            "Find objects with Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity set). An attacker controlling a listed machine account can impersonate any user.",
            ad_args.clone(),
        ),
        make_tool(
            "enumerate_privileged_groups",
            "List members of high-privilege AD groups: Domain Admins, Enterprise Admins, Backup Operators, Account Operators, etc. Uses recursive membership expansion.",
            ad_args.clone(),
        ),
        make_tool(
            "enumerate_stale_service_passwords",
            "Find service accounts (with SPNs) whose passwords are older than 365 days. Old passwords on Kerberoastable accounts are significantly easier to crack.",
            ad_args.clone(),
        ),
        make_tool(
            "full_scan",
            "Run all diagnostic modules (LDAP enumeration, AS-REP Roasting, Kerberoasting, LLMNR listen) and return all findings as structured JSON.",
            ad_args,
        ),
    ]
}

pub(super) fn make_tool(name: &str, description: &str, schema: Value) -> Value {
    serde_json::json!({
        "name": name,
        "description": description,
        "inputSchema": schema
    })
}
