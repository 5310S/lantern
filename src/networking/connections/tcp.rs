use std::net::TcpStream;


// to a server


pub async fn connection() -> Result<(), Box<dyn std::error::Error>> {
    // (2) Await the future and unwrap the Result:
    let my_ip = get_ip().await?;

    let peer_addr = if my_ip == "47.17.52.8" {
        "82.25.86.57:8080"
    } else {
        "47.17.52.8:8080"
    };

    println!("Connecting to {peer_addr}...");

    // (3) Use an async TcpStream connect (e.g. from Tokio)
    let stream = tokio::net::TcpStream::connect(peer_addr).await;
    match stream {
        Ok(_) => println!("Connected to the server!"),
        Err(e) => eprintln!("Couldn't connect to the server: {}", e),
    }

    Ok(())


}

async fn get_ip() -> Result<String, reqwest::Error> {

    let ip= reqwest::get("https://api.ipify.org")
    .await?
    .text()
    .await?;
println!("My public IP is: {}", ip);
Ok(ip)
}


