// === cryptography.rs ===

use sha2::{Digest, Sha256};

/// Calculates a SHA-256 hash from block contents
pub fn calculate_hash(index: u64, timestamp: u128, prev_hash: &str, data: &str, nonce: u64) -> String {
    let input = format!("{}{}{}{}{}", index, timestamp, prev_hash, data, nonce);
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)
}

/// Verifies proof-of-work: hash must start with "0000"
pub fn verify_pow(hash: &str) -> bool {
    hash.starts_with("0000")
}
