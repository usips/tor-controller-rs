//! Example: New identity (circuit rotation)
//!
//! This example demonstrates how to request a new identity from Tor,
//! which clears and rebuilds all circuits.
//!
//! Run with: cargo run --example new_identity

use tor_controller::{Signal, TorClient, Result};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Connecting to Tor control port...");
    let mut client = TorClient::connect_default().await?;
    client.auto_authenticate().await?;
    println!("Connected and authenticated!\n");

    // Get current circuit status
    let circuits_before = client.get_circuit_status().await?;
    println!("Current circuits: {}", circuits_before.len());

    // Request new identity
    println!("\nRequesting new identity (NEWNYM signal)...");
    client.signal(Signal::NewNym).await?;
    println!("New identity requested!");

    // Note: There's a rate limit on NEWNYM (typically 10 seconds between requests)
    // Tor will queue the request if called too frequently

    // Wait a moment for circuits to change
    println!("\nWaiting 2 seconds for circuit changes...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Get new circuit status
    let circuits_after = client.get_circuit_status().await?;
    println!("Circuits after NEWNYM: {}", circuits_after.len());

    // Display circuit details
    println!("\nCircuit details:");
    for circuit in circuits_after.iter().take(5) {
        let path: Vec<String> = circuit
            .path
            .iter()
            .map(|s| format!("{}", s))
            .collect();
        
        println!(
            "  Circuit {}: {:?}",
            circuit.id.0,
            circuit.status,
        );
        if !path.is_empty() {
            println!("    Path: {}", path.join(" -> "));
        }
    }

    client.quit().await?;
    println!("\nDone!");

    Ok(())
}
