pub mod blockchain;
pub mod cryptography;
pub mod networking;
pub mod prune;
pub mod rate_limit;
pub mod routes;
pub mod server;
pub mod storage;
pub mod utils;

pub fn start() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Runtime::new()?.block_on(async {
        server::run().await
    })
}
