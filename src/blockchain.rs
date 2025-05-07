// === blockchain.rs ===

use crate::cryptography::{calculate_hash, verify_pow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u128,
    pub prev_hash: String,
    pub hash: String,
    pub data: String,
    pub nonce: u64,
}

impl Block {
    pub fn new(index: u64, timestamp: u128, prev_hash: String, data: String, nonce: u64) -> Self {
        let hash = calculate_hash(index, timestamp, &prev_hash, &data, nonce);
        Block {
            index,
            timestamp,
            prev_hash,
            hash,
            data,
            nonce,
        }
    }

    pub fn new_dummy() -> Self {
        Block::new(0, 0, "0".into(), "GENESIS".into(), 0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
}

impl Blockchain {
    pub fn new() -> Self {
        Blockchain {
            blocks: vec![Block::new_dummy()],
        }
    }

    pub fn tip(&self) -> &Block {
        self.blocks.last().expect("Chain should have at least genesis")
    }

    pub fn add_block(&mut self, block: Block) -> bool {
        let tip = self.tip();
        if block.prev_hash != tip.hash {
            println!("❌ Rejected block: prev_hash mismatch");
            return false;
        }
        if !verify_pow(&block.hash) {
            println!("❌ Rejected block: PoW invalid");
            return false;
        }
        self.blocks.push(block);
        true
    }

    pub fn mine_block(&mut self, data: String) -> Block {
        let tip = self.tip();
        let index = tip.index + 1;
        let timestamp = chrono::Utc::now().timestamp_millis() as u128;
        let prev_hash = tip.hash.clone();
        let mut nonce = 0;
        loop {
            let hash = calculate_hash(index, timestamp, &prev_hash, &data, nonce);
            if verify_pow(&hash) {
                return Block {
                    index,
                    timestamp,
                    prev_hash,
                    hash,
                    data,
                    nonce,
                };
            }
            nonce += 1;
        }
    }

    pub fn sync(&mut self, other: Blockchain) -> bool {
        if other.blocks.len() > self.blocks.len() {
            self.blocks = other.blocks;
            true
        } else {
            false
        }
    }
}
