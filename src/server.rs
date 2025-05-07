// === server.rs ===

use crate::blockchain::Blockchain;
use crate::rate_limit::rate_limited;
use crate::routes::build_routes;
use crate::storage::{load_chain, save_chain};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task;
use warp::{Filter, filters::BoxedFilter};

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let chain = Arc::new(Mutex::new(load_chain().unwrap_or_else(Blockchain::new)));
    let chain_status = chain.clone();
    let chain_for_filter = chain.clone();

    let rate_limiter = rate_limited().untuple_one().boxed();


    let routes = build_routes(chain_status, rate_limiter).with(warp::log::custom(|info| {
        println!("📥 {} {} {}", info.method(), info.path(), info.status());
    }));

    let chain_clone_2 = chain.clone();
task::spawn(async move {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        crate::networking::sync_with_peers(chain_clone_2.clone()).await;
    }
});


    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
    Ok(())
}
