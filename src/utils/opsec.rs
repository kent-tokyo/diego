//! OPSEC utilities: jitter, nonce generation, timing.

use std::time::Duration;

pub const JITTER_MIN_MS: u64 = 100;
pub const JITTER_MAX_MS: u64 = 500;

/// Generate a random nonce for Kerberos AS-REQ.
pub fn generate_nonce() -> u32 {
    rand::random()
}

/// Generate a random jitter value in milliseconds.
pub fn generate_jitter_ms(min_ms: u64, max_ms: u64) -> u64 {
    use rand::Rng;
    rand::thread_rng().gen_range(min_ms..=max_ms)
}

/// Sleep for a random duration (OPSEC jitter).
pub async fn sleep_jitter(min_ms: u64, max_ms: u64) {
    let ms = generate_jitter_ms(min_ms, max_ms);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Sleep for default jitter duration (100-500ms).
pub async fn sleep_jitter_default() {
    sleep_jitter(JITTER_MIN_MS, JITTER_MAX_MS).await;
}
