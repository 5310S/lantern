// === networking.rs ===

use crate::blockchain::{Block, Blockchain};
use crate::storage;
use lazy_static::lazy_static;
use reqwest::Client;
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

lazy_static! {
    static ref KNOWN_PEERS: Mutex<HashSet<String>> = Mutex::new({
        let initial = storage::load_peers();
        println!("📥 Loaded {} persisted peers", initial.len());
        initial.into_iter().collect()
    });
    static ref MY_IP: String = detect_public_ip();
}

pub fn detect_public_ip() -> String {
    reqwest::blocking::get("https://api.ipify.org")
        .and_then(|res| res.text())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

pub fn add_peer(peer_url: &str) {
    if peer_url.contains(&*MY_IP) {
        println!("🔍 Skipping self peer: {}", peer_url);
        return;
    }
    KNOWN_PEERS.lock().unwrap().insert(peer_url.to_string());
}

pub fn register_peer(peer: String) -> bool {
    if peer.contains(&*MY_IP) {
        println!("🔍 Ignored self-peer: {}", peer);
        return false;
    }
    let mut peers = KNOWN_PEERS.lock().unwrap();
    let added = peers.insert(peer.clone());
    if added {
        println!("🔗 Registered peer: {}", &peer);
        storage::save_peers(&peers.iter().cloned().collect::<Vec<_>>());
    }
    added
}

pub fn get_peers() -> Vec<String> {
    KNOWN_PEERS.lock().unwrap().iter().cloned().collect()
}

pub async fn sync_with_peers(chain: Arc<Mutex<Blockchain>>) {
    async fn result(peer: String, chain: Arc<Mutex<Blockchain>>, client: &Client) -> Result<(), reqwest::Error> {
        let url = format!("{}/chain", peer);
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(remote_chain) = resp.json::<Blockchain>().await {
                    let mut local = chain.lock().unwrap();
                    if local.sync(remote_chain.clone()) {
                        println!("✅ Synced with {}", peer);
                        return Ok(());
                    } else {
                        println!("ℹ️ Chain from {} not longer than local", peer);
                    }
                }
                Ok(())
            }
            Ok(resp) => {
                println!("⚠️ Failed to sync from {}: {}", peer, resp.status());
                Ok(())
            }
            Err(e) => {
                println!("❌ Error contacting {}: {}", peer, e);
                Err(e)
            }
        }
    }
    let peers = KNOWN_PEERS.lock().unwrap().clone();
    let client = Client::new();

    for peer in peers {
        for attempt in 1..=3 {
            if result(peer.clone(), chain.clone(), &client).await.is_ok() {
                break;
            }
            println!("🔁 Retrying sync with {} (attempt {})", peer, attempt);
            sleep(Duration::from_secs(2)).await;
        }
    }
}

pub fn broadcast_block(block: &Block) {
    let peers = KNOWN_PEERS.lock().unwrap().clone();
    let client = reqwest::blocking::Client::new();
    for peer in peers {
        let url = format!("{}/block", peer);
        match client.post(&url).json(block).send() {
            Ok(resp) => println!("📡 Block broadcasted to {}: {}", peer, resp.status()),
            Err(e) => println!("⚠️ Broadcast to {} failed: {}", peer, e),
        }
    }
}
