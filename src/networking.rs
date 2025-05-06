use crate::blockchain::Blockchain;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use reqwest;

const PEERS: [&str; 2] = ["47.17.52.8:8080", "82.25.86.57:8080"];

struct Peer {
    addr: String,
    stream: TcpStream,
}

type SharedPeers = Arc<Mutex<Vec<Peer>>>;

pub fn start_network(blockchain: Arc<Mutex<Blockchain>>) {
    let peers: SharedPeers = Arc::new(Mutex::new(Vec::new()));
    let blockchain_clone = Arc::clone(&blockchain);
    let peers_clone = Arc::clone(&peers);

    thread::spawn(move || {
        listen_for_connections(blockchain_clone, peers_clone);
    });

    maintain_peer_connections(Arc::clone(&peers));
    spawn_chat_input_thread(peers);
}

fn listen_for_connections(_blockchain: Arc<Mutex<Blockchain>>, peers: SharedPeers) {
    let listener = TcpListener::bind("0.0.0.0:8080").expect("Failed to bind to port 8080");
    println!("Listening for connections on port 8080...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                println!("Accepted connection from: {}", addr);
                peers.lock().unwrap().push(Peer { addr, stream: stream.try_clone().unwrap() });
                thread::spawn(move || handle_connection(stream));
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
}

fn get_public_ip() -> Option<IpAddr> {
    let response = reqwest::blocking::get("https://api.ipify.org").ok()?;
    let ip_str = response.text().ok()?;
    ip_str.parse().ok()
}

fn maintain_peer_connections(peers: SharedPeers) {
    let public_ip = get_public_ip().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    thread::spawn(move || loop {
        for &peer in PEERS.iter() {
            if let Some(ip_part) = peer.split(':').next() {
                if let Ok(peer_ip) = ip_part.parse::<IpAddr>() {
                    if peer_ip == public_ip {
                        println!("Skipping self-connection to {}", peer);
                        continue;
                    }
                }
            }

            let already_connected = {
                peers.lock().unwrap().iter().any(|p| p.addr == peer)
            };

            if !already_connected {
                match TcpStream::connect(peer) {
                    Ok(mut stream) => {
                        println!("Connected to peer: {}", peer);
                        let _ = stream.write_all(b"HANDSHAKE\n");
                        peers.lock().unwrap().push(Peer {
                            addr: peer.to_string(),
                            stream: stream.try_clone().unwrap(),
                        });

                        let peer_clone = stream.try_clone().unwrap();
                        thread::spawn(move || handle_connection(peer_clone));
                    }
                    Err(e) => eprintln!("Retry: Failed to connect to peer {}: {}", peer, e),
                }
            }
        }

        thread::sleep(Duration::from_secs(10));
    });
}

fn handle_connection(stream: TcpStream) {
    let peer_addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());
    println!("New connection from: {}", peer_addr);

    let reader = BufReader::new(&stream);
    for line in reader.lines() {
        match line {
            Ok(message) => {
                println!("Received from {}: {}", peer_addr, message);
                if message.trim() == "HANDSHAKE" {
                    let _ = stream.try_clone().unwrap().write_all(b"HANDSHAKE_ACK\n");
                }
            }
            Err(_) => break,
        }
    }
}

fn spawn_chat_input_thread(peers: SharedPeers) {
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let msg = line.unwrap_or_default();
            let mut to_remove = vec![];

            let mut peers_guard = peers.lock().unwrap();
            for (i, peer) in peers_guard.iter_mut().enumerate() {
                if peer.stream.write_all(format!("CHAT:{}\n", msg).as_bytes()).is_err() {
                    to_remove.push(i);
                }
            }

            // Optionally remove failed peers
            for &i in to_remove.iter().rev() {
                peers_guard.remove(i);
            }
        }
    });
}
