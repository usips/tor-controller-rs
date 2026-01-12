//! Configuration management example for tor-controller.
//!
//! This example demonstrates how to query and modify Tor's runtime configuration
//! using the GETCONF, SETCONF, RESETCONF, and SAVECONF commands.
//!
//! Run with: cargo run --example config
//!
//! Requires a running Tor instance with control port enabled.

use tor_controller::{Result, TorClient};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("tor_controller=debug")
        .init();

    println!("Connecting to Tor control port...");
    let mut client = TorClient::connect_default().await?;
    client.auto_authenticate().await?;
    println!("Connected and authenticated!\n");

    // ========================================
    // Reading Configuration
    // ========================================
    println!("=== Reading Configuration ===\n");

    // Get a single configuration value
    let socks_port = client.get_conf("SocksPort").await?;
    println!("SocksPort: {:?}", socks_port);

    let control_port = client.get_conf("ControlPort").await?;
    println!("ControlPort: {:?}", control_port);

    let data_dir = client.get_conf("DataDirectory").await?;
    println!("DataDirectory: {:?}", data_dir);

    // Get multiple configuration values at once
    let configs = client
        .get_conf_multi(&[
            "SocksPort",
            "ControlPort",
            "ORPort",
            "DirPort",
            "MaxCircuitDirtiness",
            "CircuitBuildTimeout",
            "LearnCircuitBuildTimeout",
        ])
        .await?;

    println!("\nMultiple config values:");
    for (key, values) in &configs {
        println!("  {}: {:?}", key, values);
    }

    // ========================================
    // Modifying Configuration
    // ========================================
    println!("\n=== Modifying Configuration ===\n");

    // Get the current value
    let original = client.get_conf("MaxCircuitDirtiness").await?;
    println!("Original MaxCircuitDirtiness: {:?}", original);

    // Set a new value
    println!("Setting MaxCircuitDirtiness to 600 seconds...");
    client.set_conf("MaxCircuitDirtiness", "600").await?;

    // Verify the change
    let new_value = client.get_conf("MaxCircuitDirtiness").await?;
    println!("New MaxCircuitDirtiness: {:?}", new_value);

    // Reset to default
    println!("Resetting MaxCircuitDirtiness to default...");
    client.reset_conf("MaxCircuitDirtiness").await?;

    let default_value = client.get_conf("MaxCircuitDirtiness").await?;
    println!("Default MaxCircuitDirtiness: {:?}", default_value);

    // ========================================
    // Setting Multiple Values
    // ========================================
    println!("\n=== Setting Multiple Values ===\n");

    // Set multiple configuration values at once
    client
        .set_conf_multi(&[
            ("MaxCircuitDirtiness", "600"),
            ("CircuitBuildTimeout", "90"),
        ])
        .await?;

    // Verify
    let configs = client
        .get_conf_multi(&["MaxCircuitDirtiness", "CircuitBuildTimeout"])
        .await?;
    println!("After setting multiple values:");
    for (key, values) in &configs {
        println!("  {}: {:?}", key, values);
    }

    // Reset both
    client.reset_conf("MaxCircuitDirtiness").await?;
    client.reset_conf("CircuitBuildTimeout").await?;
    println!("Reset both to defaults");

    // ========================================
    // Getting Runtime Information
    // ========================================
    println!("\n=== Runtime Information ===\n");

    // Get various runtime info
    let version = client.get_info("version").await?;
    println!("Tor version: {}", version);

    let uptime = client.get_info("uptime").await?;
    println!("Uptime: {} seconds", uptime);

    let traffic_read = client.get_info("traffic/read").await?;
    let traffic_written = client.get_info("traffic/written").await?;
    println!(
        "Traffic: {} bytes read, {} bytes written",
        traffic_read, traffic_written
    );

    let bootstrap = client.get_info("status/bootstrap-phase").await?;
    println!("Bootstrap status: {}", bootstrap);

    // Get dormant status
    if let Ok(dormant) = client.get_info("dormant").await {
        println!("Dormant mode: {}", dormant);
    }

    // Get process info
    if let Ok(pid) = client.get_info("process/pid").await {
        println!("Tor PID: {}", pid);
    }

    // ========================================
    // Configuration File Operations
    // ========================================
    println!("\n=== Configuration File Operations ===\n");

    // Get the config file path
    if let Ok(config_file) = client.get_info("config-file").await {
        println!("Config file: {}", config_file);
    }

    // Note: SAVECONF and LOADCONF operations should be used carefully
    // as they modify the torrc file on disk

    // To save current config (uncomment if you want to actually save):
    // println!("Saving configuration to disk...");
    // client.save_conf(false).await?;
    // println!("Configuration saved!");

    // To force save even if IncludeUsed is set:
    // client.save_conf(true).await?;

    // To load configuration from text:
    // client.load_conf("SocksPort 9050\nControlPort 9051").await?;

    println!("\n=== Done ===");
    client.quit().await?;

    Ok(())
}
