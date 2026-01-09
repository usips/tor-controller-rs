//! Example: Create an onion service
//!
//! This example demonstrates how to create and manage onion (hidden) services.
//!
//! Run with: cargo run --example onion_service

use tor_control::{TorClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Connecting to Tor control port...");
    let mut client = TorClient::connect_default().await?;
    client.auto_authenticate().await?;
    println!("Connected and authenticated!\n");

    // Create a new onion service
    // This will create a .onion address that maps virtual port 80 to local port 8080
    println!("Creating onion service...");
    
    let service = client.add_onion(
        &[
            (80, Some("127.0.0.1:8080")),   // Virtual port 80 -> local 8080
            (443, Some("127.0.0.1:8443")),  // Virtual port 443 -> local 8443
        ],
        None,              // Generate a new key (None = NEW:BEST)
        &[],               // No special flags
    ).await?;

    println!("Onion service created!");
    println!("  Address: {}", service.address);
    println!("  URL: http://{}", service.address);

    if let Some(ref key) = service.private_key {
        println!("  Private key: {}... (save this to recreate the service)", &key[..50.min(key.len())]);
    }

    println!("\nYour service is now reachable at the onion address above.");
    println!("Make sure you have a web server running on 127.0.0.1:8080");
    println!("\nPress Enter to delete the service and exit...");

    // Wait for user input
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    // Delete the onion service
    println!("Deleting onion service...");
    client.del_onion(&service.address.service_id()).await?;
    println!("Onion service deleted.");

    client.quit().await?;
    println!("Disconnected.");

    Ok(())
}
