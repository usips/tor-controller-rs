//! Example: Basic connection and authentication
//!
//! This example demonstrates how to connect to Tor and authenticate.
//!
//! Run with: cargo run --example basic

use tor_controller::{Result, TorClient};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging (optional)
    tracing_subscriber::fmt::init();

    println!("Connecting to Tor control port...");

    // Connect to the default control port (127.0.0.1:9051)
    let mut client = TorClient::connect_default().await?;
    println!("Connected!");

    // Get protocol info to see available auth methods
    let protocol_info = client.protocol_info().await?;
    println!("Tor version: {:?}", protocol_info.tor_version);
    println!("Auth methods: {:?}", protocol_info.auth_methods);

    if let Some(ref cookie) = protocol_info.cookie_file {
        println!("Cookie file: {}", cookie);
    }

    // Auto-authenticate using the best available method
    println!("\nAuthenticating...");
    client.auto_authenticate().await?;
    println!("Authentication successful!");

    // Get Tor version
    let version = client.get_version().await?;
    println!("\nTor version: {}", version);

    // Get some basic info
    if let Ok(traffic_read) = client.get_info("traffic/read").await {
        println!("Traffic read: {} bytes", traffic_read);
    }

    if let Ok(traffic_written) = client.get_info("traffic/written").await {
        println!("Traffic written: {} bytes", traffic_written);
    }

    // Get circuit status
    let circuits = client.get_circuit_status().await?;
    println!("\nActive circuits: {}", circuits.len());

    for circuit in circuits.iter().take(5) {
        println!(
            "  Circuit {}: {:?} ({} hops)",
            circuit.id.0,
            circuit.status,
            circuit.path.len()
        );
    }

    // Close the connection gracefully
    client.quit().await?;
    println!("\nDisconnected.");

    Ok(())
}
