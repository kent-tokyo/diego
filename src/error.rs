use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiegoError {
    #[error("Kerberos error: {0}")]
    Kerberos(String),

    #[error("LDAP error: {0}")]
    Ldap(String),

    #[error("Network I/O error: {0}")]
    Network(#[from] std::io::Error),

    #[error("ASN.1 encode error: {0}")]
    AsnEncode(String),

    #[error("ASN.1 decode error: {0}")]
    AsnDecode(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Timeout after {0}s")]
    Timeout(u64),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}
