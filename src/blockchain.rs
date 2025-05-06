use crate::cryptography::calculate_hash;
use crate::storage::Storage;
use crate::utils::get_current_timestamp;

#[derive(Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: i64,
    pub data: String,
    pub previous_hash: String,
    pub hash: String,
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
        let genesis = Block {
            index: 0,
            timestamp: get_current_timestamp(),
            data: "Genesis Block".to_string(),
            previous_hash: String::new(),
            hash: String::new(),
        };
        let hash = calculate_hash(&format!("{}{}{}{}", genesis.index, genesis.timestamp, genesis.data, genesis.previous_hash));
        let mut genesis = genesis;
        genesis.hash = hash;
        self.storage.add_block(genesis);
    }

    pub fn add_block(&mut self, data: String) {
        let last_block = self.storage.get_blocks().last().expect("Blockchain should have at least one block");
        let new_block = Block {
            index: last_block.index + 1,
            timestamp: get_current_timestamp(),
            data,
            previous_hash: last_block.hash.clone(),
            hash: String::new(),
        };
        let hash = calculate_hash(&format!("{}{}{}{}", new_block.index, new_block.timestamp, new_block.data, new_block.previous_hash));
        let mut new_block = new_block;
        new_block.hash = hash;
        self.storage.add_block(new_block);
    }

    pub fn get_chain(&self) -> &Vec<Block> {
        self.storage.get_blocks()
    }
}