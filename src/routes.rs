// === routes.rs ===

use crate::blockchain::Blockchain;
use crate::networking::{broadcast_block, get_peers, register_peer};
use crate::prune::prune_chain;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use warp::Filter;

pub fn build_routes(
    chain: Arc<Mutex<Blockchain>>,
    rate_limiter: impl Filter<Extract = (), Error = warp::Rejection> + Clone + Send + Sync + 'static,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let chain_status = chain.clone();
    let chain_for_filter = chain.clone();
    let chain_filter = warp::any().map(move || chain_for_filter.clone());
    

    let api_key: &'static str = Box::leak(Box::new(env::var("API_KEY").unwrap_or_else(|_| "secretkey".into())));
    let protected = warp::header::exact("x-api-key", api_key);

    let status = warp::path("status").map(move || {
        let c = chain_status.lock().unwrap();
        let tip = c.tip();
        warp::reply::json(&serde_json::json!({ "index": tip.index, "hash": tip.hash }))
    });

    let tip = warp::path("tip").and(chain_filter.clone()).map(|chain: Arc<Mutex<Blockchain>>| {
        let c = chain.lock().unwrap();
        warp::reply::json(&*c.tip())
    });

    let peers = warp::path("peers").and(warp::get()).map(|| {
        warp::reply::json(&get_peers())
    });

    let add_peer = warp::path("add_peer")
        .and(warp::post())
        .and(warp::body::json())
        .map(|peer: String| {
            let added = register_peer(peer);
            warp::reply::json(&serde_json::json!({ "added": added }))
        });

    let summary = warp::path!("chain" / "summary")
        .and(chain_filter.clone())
        .map(|chain: Arc<Mutex<Blockchain>>| {
            let c = chain.lock().unwrap();
            warp::reply::json(&serde_json::json!({
                "length": c.blocks.len(),
                "tip_index": c.tip().index,
                "tip_hash": c.tip().hash
            }))
        });

    let block_lookup = warp::path!("block" / String)
        .and(warp::query::<HashMap<String, String>>())
        .and(chain_filter.clone())
        .map(|hash: String, params: HashMap<String, String>, chain: Arc<Mutex<Blockchain>>| {
            let c = chain.lock().unwrap();
            let filtered = if let Some(f) = params.get("contains") {
                c.blocks.iter().find(|b| b.hash == hash && b.data.contains(f))
            } else {
                c.blocks.iter().find(|b| b.hash == hash)
            };
            match filtered {
                Some(b) => warp::reply::json(b),
                None => warp::reply::json(&serde_json::json!({ "error": "Block not found or filtered out" })),
            }
        });

    let mine = warp::path("mine")
        .and(warp::post())
        .and(warp::body::json())
        .and(chain_filter.clone())
        .map(|data: String, chain: Arc<Mutex<Blockchain>>| {
            if data.trim().is_empty() || data.len() > 1024 {
                return warp::reply::json(&serde_json::json!({ "error": "Invalid data payload" }));
            }
            let mut c = chain.lock().unwrap();
            let block = c.mine_block(data);
            broadcast_block(&block);
            let added = c.add_block(block.clone());
            warp::reply::json(&serde_json::json!({ "added": added, "hash": block.hash }))
        });

    let prune = warp::path("prune")
        .and(warp::post())
        .and(chain_filter.clone())
        .map(|chain: Arc<Mutex<Blockchain>>| {
            let mut c = chain.lock().unwrap();
            let len_before = c.blocks.len();
            prune_chain(&mut c, 100);
            let len_after = c.blocks.len();
            warp::reply::json(&serde_json::json!({ "pruned_from": len_before, "to": len_after }))
        });

    let health_check = warp::path("health").map(|| {
        warp::reply::json(&serde_json::json!({ "status": "ok" }))
    });

    let redis_health = warp::path("health_redis").map(|| {
        warp::reply::json(&serde_json::json!({ "redis": "handled by rate_limit.rs" }))
    });

    let rate_stats = warp::path("rate_debug").map(|| {
        warp::reply::json(&serde_json::json!({ "note": "Handled in-memory or Redis via rate_limit.rs" }))
    });

    let secured_mine = protected.clone().and(rate_limiter.clone()).and(mine);
    let secured_prune = protected.and(prune);

    status
        .or(tip)
        .or(peers)
        .or(add_peer)
        .or(summary)
        .or(block_lookup)
        .or(secured_mine)
        .or(secured_prune)
        .or(health_check)
        .or(redis_health)
        .or(rate_stats)
}






