

mod blockchain;
mod cryptography;
mod networking;
mod storage;
mod utils;

use blockchain::Blockchain;
use networking::start_network;
use std::sync::{Arc, Mutex};

fn main() {
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));
    start_network(blockchain);
}

