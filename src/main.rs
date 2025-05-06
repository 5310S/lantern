mod blockchain;
mod cryptography;
mod networking;
mod storage;
mod utils;

use blockchain::Blockchain;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));
    networking::start_https_server(blockchain).await;
}
