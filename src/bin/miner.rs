// === miner.rs ===

use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct Tip {
    index: u64,
    hash: String,
}

#[tokio::main]
async fn main() {
    let node_url = std::env::var("NODE_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let api_key = std::env::var("API_KEY").unwrap_or_else(|_| "secretkey".into());

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 1. Fetch latest tip block
    let tip: Tip = client
        .get(format!("{}/tip", node_url))
        .send()
        .await
        .expect("Failed to get tip")
        .json()
        .await
        .expect("Failed to parse tip");

    // 2. Mine block
    let index = tip.index + 1;
    let prev_hash = tip.hash;
    let data = "hello from miner";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    let mut nonce = 0u64;
    let block_hash = loop {
        let input = format!("{}{}{}{}{}", index, timestamp, prev_hash, data, nonce);
        let hash = format!("{:x}", Sha256::digest(input.as_bytes()));
        if hash.starts_with("0000") {
            break hash;
        }
        nonce += 1;
    };

    println!("🧱 Mined block with hash: {}", block_hash);

    // 3. Submit to /mine
    let res = client
        .post(format!("{}/mine", node_url))
        .header("x-api-key", api_key)
        .json(&json!(data))
        .send()
        .await;

    match res {
        Ok(r) => println!("✅ Submitted via /mine: {}", r.status()),
        Err(e) => println!("❌ Failed to submit mined block via /mine: {}", e),
    }
}
