use std::io::prelude::*;
use std::net::TcpStream;

mod networking;

fn main() -> std::io::Result<()> {

let a = networking::connections::tcp::connection();





    Ok(())

} // the stream is closed here