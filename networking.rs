// === networking.rs ===

use crate::blockchain::Block;
use crate::storage;
use lazy_static::lazy_static;
use reqwest::blocking::Client;
use std::collections::HashSet;
use std::sync::Mutex;

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
        broadcast_new_peer(&peer);
    }
    added
}

pub fn get_peers() -> Vec<String> {
    KNOWN_PEERS.lock().unwrap().iter().cloned().collect()
}

pub fn broadcast_block(block: &Block) {
    let peers = KNOWN_PEERS.lock().unwrap().clone();
    let client = Client::new();
    for peer in peers {
        let url = format!("{}/block", peer);
        match client.post(&url).json(&block).send() {
            Ok(resp) => println!("📡 Block broadcasted to {}: {}", peer, resp.status()),
            Err(e) => println!("⚠️ Broadcast to {} failed: {}", peer, e),
        }
    }
}

pub fn broadcast_new_peer(peer: &str) {
    let peers = KNOWN_PEERS.lock().unwrap().clone();
    let client = Client::new();
    for other in peers {
        if other == *peer {
            continue;
        }
        let url = format!("{}/add_peer", other);
        match client.post(&url).json(&peer).send() {
            Ok(resp) => println!("📨 Peer announced to {}: {}", other, resp.status()),
            Err(e) => println!("⚠️ Could not announce peer to {}: {}", other, e),
        }
    }
}
