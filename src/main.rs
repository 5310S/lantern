// Cargo.toml
// [dependencies]
// tokio = { version = "1", features = ["full"] }

use std::error::Error;
mod networking;

#[tokio::main]                      // ← this turns main into async + starts the runtime
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello");
    // actually run your connection future:
    networking::connections::tcp::connection().await?;
    // if connection() returns something (e.g. TcpStream), capture it:
    // let stream = networking::connections::tcp::connection().await?;
    Ok(())
}
