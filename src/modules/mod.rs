pub mod kerberos;
pub mod ldap;
pub mod passive;

use async_trait::async_trait;
use std::sync::Arc;

use crate::config::Config;
use crate::report::Finding;

#[async_trait]
pub trait DiagnosticModule: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, config: Arc<Config>) -> anyhow::Result<Vec<Finding>>;
}

/// Data extracted by LdapModule and passed to KerberosModule
#[derive(Debug, Clone)]
pub struct LdapContext {
    pub asrep_candidates: Vec<String>,
    pub spn_accounts: Vec<SpnAccount>,
}

#[derive(Debug, Clone)]
pub struct SpnAccount {
    pub sam_name: String,
    pub spns: Vec<String>,
    /// msDS-SupportedEncryptionTypes bitmask (0 = unknown/legacy = RC4 supported)
    pub supported_enc_types: u32,
    /// pwdLastSet as Windows FILETIME (100-ns intervals since 1601-01-01); None if unset
    pub pwd_last_set: Option<i64>,
    /// adminCount=1 indicates the account was/is in a privileged group and has protected ACL
    pub admin_count: u32,
}
