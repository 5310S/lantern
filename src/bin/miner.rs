use reqwest::Client;
use sha2::{Digest, Sha256};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

fn calculate_hash(index: u64, timestamp: i64, data: &str, prev_hash: &str, nonce: u64) -> String {
    let input = format!("{}{}{}{}{}", index, timestamp, data, prev_hash, nonce);
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

#[tokio::main]
async fn main() {
    let node_url = "https://localhost:8080";
    let client = Client::builder().danger_accept_invalid_certs(true).build().unwrap();

    // Step 1: Fetch latest block tip
    let tip = client.get(format!("{}/tip", node_url)).send().await.unwrap().text().await.unwrap();
    let (index, prev_hash) = {
        let mut lines = tip.lines();
        let idx = lines.next().unwrap().split('=').nth(1).unwrap().trim().parse::<u64>().unwrap();
        let hash = lines.next().unwrap().split('=').nth(1).unwrap().trim().to_string();
        (idx + 1, hash)
    };

    let data = "hello from miner";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut nonce = 0;
    let hash;

    loop {
        let candidate = calculate_hash(index, timestamp, data, &prev_hash, nonce);
        if candidate.starts_with("00") {
            hash = candidate;
            break;
        }
        nonce += 1;
    }

    println!("✅ Mined block: nonce={}, hash={}", nonce, hash);

    let block = json!({
        "index": index,
        "timestamp": timestamp,
        "data": data,
        "previous_hash": prev_hash,
        "hash": hash,
        "nonce": nonce
    });

    let res = client.post(format!("{}/block", node_url)).json(&block).send().await.unwrap();
    println!("📡 Submitted block: {}", res.status());
}
