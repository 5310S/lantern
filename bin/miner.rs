use reqwest::Client;
use serde::{Deserialize, Serialize};
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
    let node_url = "https://localhost:8080";
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 1. Fetch latest tip block
    let tip: Tip = client
        .get(format!("{}/tip", node_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // 2. Mine manually if API unavailable or rate-limited
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

    // 3. Try POST /mine if access key available
    let res = client
        .post(format!("{}/mine", node_url))
        .header("x-api-key", "secretkey")
        .json(&data)
        .send()
        .await;

    match res {
        Ok(r) => println!("✅ Submitted via /mine: {}", r.status()),
        Err(e) => println!("❌ Failed to submit mined block via /mine: {}", e),
    }
}
