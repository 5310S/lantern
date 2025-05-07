// === prune.rs ===

use crate::blockchain::Blockchain;

/// Retains the most recent `retain_count` blocks in the blockchain.
pub fn prune_chain(chain: &mut Blockchain, retain_count: usize) {
    if chain.blocks.len() > retain_count {
        let drop_count = chain.blocks.len() - retain_count;
        chain.blocks.drain(0..drop_count);
        println!("🧹 Pruned {} blocks, {} remain", drop_count, chain.blocks.len());
    }
}
