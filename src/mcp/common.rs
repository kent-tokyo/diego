use std::time::Duration;

use ldap3::LdapConnAsync;
use serde_json::Value;

pub(super) fn get_str<'a>(args: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Missing argument: {}", key))
}

pub(super) fn get_timeout(args: &Value) -> u64 {
    args.get("timeout_secs")
        .and_then(Value::as_u64)
        .unwrap_or(10)
}

pub(super) struct AdRequest {
    pub(super) dc_ip: String,
    pub(super) domain: String,
    pub(super) username: String,
    pub(super) password: String,
    pub(super) timeout_secs: u64,
}

impl AdRequest {
    pub(super) fn from_args(args: &Value) -> anyhow::Result<Self> {
        Ok(Self {
            dc_ip: get_str(args, "dc_ip")?.to_string(),
            domain: get_str(args, "domain")?.to_string(),
            username: get_str(args, "username")?.to_string(),
            password: get_str(args, "password")?.to_string(),
            timeout_secs: get_timeout(args),
        })
    }

    pub(super) fn base_dn(&self) -> String {
        domain_to_base_dn(&self.domain)
    }

    pub(super) async fn connect(&self) -> anyhow::Result<ldap3::Ldap> {
        ldap_connect(
            &self.dc_ip,
            &self.domain,
            &self.username,
            &self.password,
            self.timeout_secs,
        )
        .await
    }
}

async fn ldap_connect(
    dc_ip: &str,
    domain: &str,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> anyhow::Result<ldap3::Ldap> {
    let url = format!("ldap://{}:389", dc_ip);
    let (conn, mut ldap) =
        tokio::time::timeout(Duration::from_secs(timeout_secs), LdapConnAsync::new(&url))
            .await
            .map_err(|_| anyhow::anyhow!("LDAP connection timeout"))?
            .map_err(|e| anyhow::anyhow!("LDAP connection failed: {}", e))?;

    ldap3::drive!(conn);

    ldap.simple_bind(&format!("{}@{}", username, domain), password)
        .await?
        .success()
        .map_err(|e| anyhow::anyhow!("LDAP bind failed: {}", e))?;

    Ok(ldap)
}

pub(super) fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) const TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x1000000;

pub(super) fn has_protocol_transition(uac: u32) -> bool {
    uac & TRUSTED_TO_AUTH_FOR_DELEGATION != 0
}
