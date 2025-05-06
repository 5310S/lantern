mod blockchain;
mod cryptography;
mod networking;
mod storage;
mod utils;

use blockchain::Blockchain;
use networking::start_network;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc as SyncArc;
use std::thread;
use std::time::Duration;

fn main() {
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));
    start_network(blockchain);

    println!("Node ready at 0.0.0.0:8080");

    let running = SyncArc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\nShutting down...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }
}
