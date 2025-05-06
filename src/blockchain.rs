

use crate::cryptography::calculate_hash;
use crate::storage::Storage;
use crate::utils::get_current_timestamp;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: i64,
    pub data: String,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
}

pub struct Blockchain {
    pub storage: Storage,
}

impl Blockchain {
    pub fn new() -> Self {
        let mut blockchain = Blockchain {
            storage: Storage::new(),
        };
        blockchain.create_genesis_block();
        blockchain
    }

    fn create_genesis_block(&mut self) {
        let mut genesis = Block {
            index: 0,
            timestamp: get_current_timestamp(),
            data: "Genesis Block".to_string(),
            previous_hash: String::new(),
            hash: String::new(),
            nonce: 0,
        };
        genesis.hash = calculate_hash(&format!("{}{}{}{}{}", genesis.index, genesis.timestamp, genesis.data, genesis.previous_hash, genesis.nonce));
        self.storage.add_block(genesis);
    }

    pub fn add_block(&mut self, data: String) {
        let last_block = self.storage.get_blocks().last().expect("Blockchain should have at least one block");
        let mut nonce = 0;
        let timestamp = get_current_timestamp();
        loop {
            let block = Block {
                index: last_block.index + 1,
                timestamp,
                data: data.clone(),
                previous_hash: last_block.hash.clone(),
                hash: String::new(),
                nonce,
            };
            let hash = calculate_hash(&format!("{}{}{}{}{}", block.index, block.timestamp, block.data, block.previous_hash, block.nonce));
            if hash.starts_with("00") {
                let mut final_block = block;
                final_block.hash = hash;
                self.storage.add_block(final_block);
                break;
            }
            nonce += 1;
        }
    }

    pub fn get_chain(&self) -> &Vec<Block> {
        self.storage.get_blocks()
    }
}
