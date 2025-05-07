use crate::blockchain::Blockchain;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

const PEER_FILE: &str = "peers.txt";
const CHAIN_FILE: &str = "chain.json";

pub fn save_peers(peers: &[String]) {
    if let Ok(mut file) = File::create(PEER_FILE) {
        for peer in peers {
            let _ = writeln!(file, "{}", peer);
        }
    }
}

pub fn load_peers() -> Vec<String> {
    let mut content = String::new();
    if let Ok(mut file) = File::open(PEER_FILE) {
        if file.read_to_string(&mut content).is_ok() {
            return content
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

pub fn save_chain(chain: &Blockchain) {
    if let Ok(json) = serde_json::to_string_pretty(chain) {
        let _ = fs::write(CHAIN_FILE, json);
    }
}

pub fn load_chain() -> Option<Blockchain> {
    if let Ok(content) = fs::read_to_string(CHAIN_FILE) {
        if let Ok(chain) = serde_json::from_str(&content) {
            return Some(chain);
        }
    }
    None
}
