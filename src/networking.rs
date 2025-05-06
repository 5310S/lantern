use crate::blockchain::Blockchain;
use local_ip_address::local_ip;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const PEERS: [&str; 2] = ["47.17.52.8:8000", "82.25.86.57:8000"];

type SharedPeers = Arc<Mutex<Vec<TcpStream>>>;

pub fn start_network(blockchain: Arc<Mutex<Blockchain>>) {
    let peers: SharedPeers = Arc::new(Mutex::new(Vec::new()));
    let blockchain_clone = Arc::clone(&blockchain);
    let peers_clone = Arc::clone(&peers);

    thread::spawn(move || {
        listen_for_connections(blockchain_clone, peers_clone);
    });

    connect_to_peers(peers);
}

fn listen_for_connections(_blockchain: Arc<Mutex<Blockchain>>, peers: SharedPeers) {
    let listener = TcpListener::bind("0.0.0.0:8000").expect("Failed to bind to port 8000");
    println!("Listening for connections on port 8000...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("Accepted connection from: {}", stream.peer_addr().unwrap());
                peers.lock().unwrap().push(stream.try_clone().unwrap());
                thread::spawn(move || handle_connection(stream));
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
}

fn connect_to_peers(peers: SharedPeers) {
    let local_ip = local_ip().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    for &peer in PEERS.iter() {
        if let Some(ip_part) = peer.split(':').next() {
            if let Ok(peer_ip) = ip_part.parse::<IpAddr>() {
                if peer_ip == local_ip {
                    println!("Skipping self-connection to {}", peer);
                    continue;
                }
            }
        }

        match TcpStream::connect(peer) {
            Ok(mut stream) => {
                println!("Connected to peer: {}", peer);
                let _ = stream.write_all(b"HANDSHAKE\n");
                peers.lock().unwrap().push(stream.try_clone().unwrap());

                let peer_clone = stream.try_clone().unwrap();
                thread::spawn(move || handle_connection(peer_clone));
            }
            Err(e) => eprintln!("Failed to connect to peer {}: {}", peer, e),
        }
    }

    let peers_writer = Arc::clone(&peers);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(10));
        let peers_guard = peers_writer.lock().unwrap();
        for peer in peers_guard.iter() {
            let _ = peer.try_clone().unwrap().write_all(b"PING\n");
        }
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