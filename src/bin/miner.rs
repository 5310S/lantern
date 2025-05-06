use reqwest::Client;
use sha2::{Digest, Sha256};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

fn calculate_hash(index: u64, timestamp: i64, data: &str, prev_hash: &str, nonce: u64) -> String {
    let input = format!("{index}{timestamp}{data}{prev_hash}{nonce}");
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

#[tokio::main]
async fn main() {
    let index = 1;
    let data = "hello miner";
    let prev_hash = "<PUT_LAST_HASH_HERE>"; // <<< replace
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

    let mut nonce = 0;
    let mut hash;

    loop {
        hash = calculate_hash(index, timestamp, data, prev_hash, nonce);
        if hash.starts_with("00") {
            break;
        }
        nonce += 1;
    }

    println!("✅ Mined block with nonce {} and hash {}", nonce, hash);

    let block = json!({
        "index": index,
        "timestamp": timestamp,
        "data": data,
        "previous_hash": prev_hash,
        "hash": hash,
        "nonce": nonce
    });

    let client = Client::builder().danger_accept_invalid_certs(true).build().unwrap();
    let res = client
        .post("https://localhost:8080/block")
        .json(&block)
        .send()
        .await
        .unwrap();

    println!("📡 Submitted block: {}", res.status());
}
