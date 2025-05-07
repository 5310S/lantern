fn main() {
    if let Err(e) = weave_node::start() {
        eprintln!("❌ Failed to start node: {}", e);
    }
}
