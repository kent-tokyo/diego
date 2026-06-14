/// Windows FILETIME to Unix timestamp conversions.
/// FILETIME is 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
/// Unix time is seconds since 1970-01-01 00:00:00 UTC.

pub const WINDOWS_EPOCH_DELTA: i64 = 116_444_736_000_000_000;
pub const FILETIME_SCALE: i64 = 10_000_000;

/// Convert Windows FILETIME (100-ns intervals) to Unix seconds.
pub fn filetime_to_unix_secs(filetime: i64) -> anyhow::Result<i64> {
    filetime
        .checked_sub(WINDOWS_EPOCH_DELTA)
        .and_then(|v| v.checked_div(FILETIME_SCALE))
        .ok_or_else(|| anyhow::anyhow!("Timestamp conversion overflow"))
}

/// Convert Unix seconds back to Windows FILETIME.
pub fn unix_secs_to_filetime(unix_secs: i64) -> anyhow::Result<i64> {
    unix_secs
        .checked_mul(FILETIME_SCALE)
        .and_then(|v| v.checked_add(WINDOWS_EPOCH_DELTA))
        .ok_or_else(|| anyhow::anyhow!("Timestamp conversion overflow"))
}

/// Calculate age in days from a Windows FILETIME string.
pub fn filetime_age_days(filetime_str: &str) -> anyhow::Result<i64> {
    let filetime = filetime_str.parse::<i64>()?;
    let unix_secs = filetime_to_unix_secs(filetime)?;
    let now_secs = chrono::Utc::now().timestamp();
    Ok((now_secs - unix_secs) / 86400)
}

/// Generate a Windows FILETIME N days in the past.
pub fn days_ago_to_windows_filetime(days: u64) -> anyhow::Result<i64> {
    let now_secs = chrono::Utc::now().timestamp();
    let days_secs = (days as i64)
        .checked_mul(86400)
        .ok_or_else(|| anyhow::anyhow!("Days calculation overflow"))?;
    let past_secs = now_secs
        .checked_sub(days_secs)
        .ok_or_else(|| anyhow::anyhow!("Timestamp underflow"))?;
    unix_secs_to_filetime(past_secs)
}
