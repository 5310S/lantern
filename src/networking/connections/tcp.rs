use std::net::TcpStream;

// to a server
pub fn connection() {


if let Ok(stream) = TcpStream::connect("82.25.86.57:8080") {
    println!("Connect to the server!");
} else {
    println!("Couldn't connect to the server.");
}


}


