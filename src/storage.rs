use crate::blockchain::Block;

pub struct Storage {
    pub blocks: Vec<Block>,
}

impl Storage {
    pub fn new() -> Self {
        Storage { blocks: Vec::new() }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn get_blocks(&self) -> &Vec<Block> {
        &self.blocks
    }
}
