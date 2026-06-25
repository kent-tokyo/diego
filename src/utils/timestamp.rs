//! Windows FILETIME to Unix timestamp conversions.
//! FILETIME is 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
//! Unix time is seconds since 1970-01-01 00:00:00 UTC.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_conversion_roundtrip() {
        // Windows epoch: Jan 1, 1970 00:00:00 UTC = 116444736000000000 as FILETIME
        let unix_secs = 0i64; // Unix epoch
        let filetime = unix_secs_to_filetime(unix_secs).unwrap();
        let back = filetime_to_unix_secs(filetime).unwrap();
        assert_eq!(back, unix_secs, "Roundtrip conversion must preserve value");
    }

    #[test]
    fn test_filetime_known_value() {
        // 2024-01-01 00:00:00 UTC ≈ 1704067200 Unix seconds
        let unix_secs = 1704067200i64;
        let filetime = unix_secs_to_filetime(unix_secs).unwrap();
        let back = filetime_to_unix_secs(filetime).unwrap();
        assert_eq!(back, unix_secs, "Known timestamp must roundtrip");
    }

    #[test]
    fn test_filetime_overflow_forward() {
        // Very large Unix timestamp (year 3000+)
        let huge_unix = i64::MAX / FILETIME_SCALE;
        let result = unix_secs_to_filetime(huge_unix);
        assert!(result.is_err(), "Very large timestamp should overflow");
    }

    #[test]
    fn test_filetime_overflow_backward() {
        // Windows FILETIME that results in division overflow (before subtraction)
        // This is actually hard to trigger since checked_sub handles large values.
        // Instead, test that we handle the subtraction correctly for near-max values.
        let near_max_filetime = i64::MAX - 100;
        let result = filetime_to_unix_secs(near_max_filetime);
        // This should succeed, since near-max minus a constant gives a valid result
        assert!(result.is_ok(), "Near-max FILETIME should handle subtraction");
    }

    #[test]
    fn test_filetime_negative_unix() {
        // Before Unix epoch (but after Windows epoch) — should work
        let negative_unix = -86400i64; // 1 day before Unix epoch
        let filetime = unix_secs_to_filetime(negative_unix).unwrap();
        let back = filetime_to_unix_secs(filetime).unwrap();
        assert_eq!(back, negative_unix, "Pre-Unix-epoch timestamp should work");
    }

    #[test]
    fn test_days_ago_roundtrip() {
        // Calculate N days ago, convert back, check age
        let days = 100u64;
        let filetime = days_ago_to_windows_filetime(days).unwrap();
        let age = filetime_age_days(&filetime.to_string()).unwrap();
        // Allow ±1 day for clock skew during test execution
        assert!(age >= days as i64 - 1 && age <= days as i64 + 1,
            "Age calculation for {}-day-old timestamp should be within ±1 day", days);
    }

    #[test]
    fn test_days_ago_overflow() {
        // Very large number of days should overflow
        let days = (i64::MAX as u64) / 86400 + 1000;
        let result = days_ago_to_windows_filetime(days);
        assert!(result.is_err(), "Huge days value should overflow");
    }

    #[test]
    fn test_filetime_age_days_parsing() {
        // Create a FILETIME for 365 days ago
        let filetime = days_ago_to_windows_filetime(365).unwrap();
        let age = filetime_age_days(&filetime.to_string()).unwrap();
        assert!(age >= 364 && age <= 366, "365-day-old timestamp should report ~365 days");
    }

    #[test]
    fn test_filetime_age_days_invalid_string() {
        // Malformed FILETIME string should fail
        assert!(filetime_age_days("not a number").is_err());
        assert!(filetime_age_days("").is_err());
    }
}
