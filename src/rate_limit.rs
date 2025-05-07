// === rate_limit.rs ===

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::{Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use lazy_static::lazy_static;
use redis::{AsyncCommands, Client};
use warp::filters::BoxedFilter;
use warp::Filter;

#[derive(Debug)]
struct RateLimitRejection;
impl warp::reject::Reject for RateLimitRejection {}

lazy_static! {
    static ref REDIS_CLIENT: Client = Client::open(env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into())).unwrap();
    static ref MEM_LIMITS: Mutex<HashMap<String, (AtomicUsize, Instant)>> = Mutex::new(HashMap::new());
}

pub fn rate_limited() -> BoxedFilter<((),)> {
    warp::filters::addr::remote()
        .and_then(|addr: Option<SocketAddr>| async move {
            let ip = addr.map(|a| a.ip().to_string()).unwrap_or("unknown".into());
            let key = format!("rate:{}", ip);

            match REDIS_CLIENT.get_async_connection().await {
                Ok(mut con) => {
                    let count: u32 = con.incr(&key, 1).await.unwrap_or(0);
                    if count == 1 {
                        let _ : () = con.expire(
                            &key,
                            env::var("RATE_WINDOW_SECS").unwrap_or("60".into()).parse().unwrap_or(60)
                        ).await.unwrap_or(());
                    }
                    let limit: u32 = env::var("RATE_LIMIT").unwrap_or("10".into()).parse().unwrap_or(10);
                    if count > limit {
                        return Err(warp::reject::custom(RateLimitRejection));
                    }
                    Ok(())
                }
                Err(_) => fallback_in_memory(&ip),
            }
        })
        .boxed()
}

fn fallback_in_memory(ip: &str) -> Result<(), warp::Rejection> {
    let now = Instant::now();
    let mut m = MEM_LIMITS.lock().unwrap();
    let e = m.entry(ip.to_string()).or_insert_with(|| (AtomicUsize::new(0), now));

    if now.duration_since(e.1) > Duration::from_secs(60) {
        e.0.store(1, Ordering::Relaxed);
        e.1 = now;
        return Ok(());
    }

    if e.0.fetch_add(1, Ordering::Relaxed) > 10 {
        return Err(warp::reject::custom(RateLimitRejection));
    }

    Ok(())
}
