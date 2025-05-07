// === utils.rs ===

use chrono::Utc;

/// Returns the current UTC timestamp in milliseconds.
pub fn now_millis() -> u128 {
    Utc::now().timestamp_millis() as u128
}

/// Validates whether a data payload is acceptable (non-empty, not too large).
pub fn valid_data_payload(data: &str) -> bool {
    !data.trim().is_empty() && data.len() <= 1024
}
