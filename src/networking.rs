use crate::blockchain::{Block, Blockchain};
use std::sync::{Arc, Mutex};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc as SyncArc;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;
use std::convert::Infallible;
use reqwest::Client;
use crate::utils::get_current_timestamp;
use serde_json;

static PEERS: &[&str] = &[
    "https://47.17.52.8:8080",
    "https://82.25.86.57:8080"
];

pub async fn connect_to_peers(blockchain: Arc<Mutex<Blockchain>>) {

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let chain = blockchain.lock().unwrap().get_chain().clone();
    let body = serde_json::to_vec(&chain).unwrap();

    let local_ip = match reqwest::get("https://api.ipify.org").await {
        Ok(resp) => match resp.text().await {
            Ok(ip) => {
                println!("🌐 Detected public IP: {}", ip);
                ip
            },
            Err(_) => {
                eprintln!("⚠️ Failed to parse public IP.");
                return;
            }
        },
        Err(_) => {
            eprintln!("⚠️ Failed to fetch public IP.");
            return;
        }
    };

    for peer in PEERS {
        if let Ok(url) = reqwest::Url::parse(peer) {
            if let Some(host) = url.host_str() {
                if host == local_ip {
                    println!("🔍 Detected public IP as {} — skipping peer {} (this is me)", local_ip, peer);
                    continue;
                }
            }
        }
        match client.post(format!("{}/sync", peer)).body(body.clone()).send().await {
            Ok(res) => {
            println!("✅ Synced with {}: {}", peer, res.status());
            if let Ok(text) = res.text().await {
                println!("📨 Peer response: {}", text);
            }
        },
            Err(_) => println!("🔄 {} not available. Will try again later.", peer),
        }
    }
}

pub async fn start_https_server(blockchain: Arc<Mutex<Blockchain>>) {
    // DEBUG: Add 3 fake blocks here instead of inside the async spawn
    let fake_blocks = {
        let mut bc = blockchain.lock().unwrap();
        let mut last = bc.get_chain().last().unwrap().clone();
        for i in 1..=3 {
            let new_block = Block {
                index: last.index + 1,
                timestamp: get_current_timestamp(),
                data: format!("fake block {}", i),
                previous_hash: last.hash.clone(),
                hash: format!("fakehash-{}", i),
                nonce: 0,
            };
            bc.storage.blocks.push(new_block.clone());
            last = new_block;
        }
    };

    let sync_blockchain = blockchain.clone();
    tokio::spawn(async move {
        loop {
            connect_to_peers(sync_blockchain.clone()).await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
    let tls_config = load_tls_config();
    let tls_acceptor = TlsAcceptor::from(SyncArc::new(tls_config));

    let listener = TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("Failed to bind HTTPS port");

    let incoming = TcpListenerStream::new(listener)
        .then(|conn| {
            let tls_acceptor = tls_acceptor.clone();
            async move {
                match conn {
                    Ok(tcp) => tls_acceptor.accept(tcp).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
                    Err(e) => Err(e),
                }
            }
        });

    let make_service = make_service_fn(move |_| {
        let blockchain = Arc::clone(&blockchain);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let blockchain = Arc::clone(&blockchain);
                async move { handle_https_request(req, blockchain).await }
            }))
        }
    });

    let server = Server::builder(hyper::server::accept::from_stream(incoming))
        .serve(make_service);

    println!("HTTPS server listening on https://0.0.0.0:8080");
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

fn load_tls_config() -> ServerConfig {
    use crate::utils::get_current_timestamp;
    use crate::blockchain::Block;
    use std::path::Path;

    if !Path::new("cert.pem").exists() || !Path::new("key.pem").exists() {
        println!("🔧 Generating self-signed TLS certificate...");
        std::process::Command::new("openssl")
            .args(&["req", "-x509", "-newkey", "rsa:2048", "-keyout", "key.pem", "-out", "cert.pem", "-days", "365", "-nodes", "-subj", "/CN=localhost"])
            .status()
            .expect("failed to invoke openssl");
    }

    let cert_file = &mut BufReader::new(File::open("cert.pem").expect("cert.pem not found"));
    let key_file = &mut BufReader::new(File::open("key.pem").expect("key.pem not found"));

    let cert_chain = certs(cert_file)
        .expect("Failed to read cert.pem")
        .into_iter()
        .map(Certificate)
        .collect();

    let mut keys = pkcs8_private_keys(key_file).expect("Failed to read key.pem");
    assert!(!keys.is_empty(), "No private keys found");
    let key = PrivateKey(keys.remove(0));

    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("invalid TLS config")
}

async fn handle_https_request(
    req: Request<Body>,
    blockchain: Arc<Mutex<Blockchain>>,
) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::POST && req.uri().path() == "/sync" {
        let (parts, body_stream) = req.into_parts();
        let body = hyper::body::to_bytes(body_stream).await.unwrap();
        if let Ok(chain) = serde_json::from_slice::<Vec<Block>>(&body) {
            let mut bc = blockchain.lock().unwrap();
            if chain.len() > bc.get_chain().len() {
            bc.storage.blocks = chain;
            if let Some(addr) = parts.headers.get("host") {
                println!("✅ Chain replaced via /sync from peer: {}", addr.to_str().unwrap_or("?"));
            } else {
                println!("✅ Chain replaced via /sync");
            }
        } else {
            if let Some(addr) = parts.headers.get("host") {
                println!("ℹ️  Received /sync from peer: {}, but local chain is longer or equal.", addr.to_str().unwrap_or("?"));
            } else {
                println!("ℹ️  Received /sync but local chain is longer or equal.");
            }
        }
            return Ok(Response::new(Body::from("Chain received")));
        } else {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid chain format"))
                .unwrap());
        }
    }
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => Ok(Response::new(Body::from("OK"))),
        (&Method::GET, "/version") => Ok(Response::new(Body::from("v1.0.0"))),
        (&Method::GET, "/height") => {
            let chain = blockchain.lock().unwrap();
            Ok(Response::new(Body::from(chain.get_chain().len().to_string())))
        }
        (&Method::GET, "/valid") => {
            let chain = blockchain.lock().unwrap();
            let valid = chain.get_chain().windows(2).all(|w| w[1].previous_hash == w[0].hash);
            Ok(Response::new(Body::from(valid.to_string())))
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap()),
    }
}
