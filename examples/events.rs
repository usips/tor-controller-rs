//! Example: Monitor Tor events
//!
//! This example demonstrates how to subscribe to and receive Tor events.
//!
//! Run with: cargo run --example events

use tor_control::{Event, EventType, TorClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Connecting to Tor control port...");
    let mut client = TorClient::connect_default().await?;
    client.auto_authenticate().await?;
    println!("Connected and authenticated!");

    // Subscribe to various event types
    let events_to_monitor = [
        EventType::Circ,      // Circuit events
        EventType::Stream,    // Stream events
        EventType::Bw,        // Bandwidth events
        EventType::Notice,    // Notice-level log messages
        EventType::StatusGeneral, // General status events
    ];

    println!("\nSubscribing to events: {:?}", events_to_monitor);
    client.set_events(&events_to_monitor).await?;
    println!("Subscribed! Waiting for events (Ctrl+C to exit)...\n");

    // Read and display events
    loop {
        match client.read_event().await {
            Ok(event) => {
                match &event {
                    Event::CircuitStatus(circ) => {
                        let path: Vec<String> = circ.path.iter()
                            .map(|s| format!("{}", s))
                            .collect();
                        println!(
                            "[CIRCUIT] ID={} Status={:?} Path={}",
                            circ.circuit_id.0,
                            circ.status,
                            if path.is_empty() { "-".to_string() } else { path.join("->") }
                        );
                    }
                    Event::StreamStatus(stream) => {
                        println!(
                            "[STREAM] ID={} Status={:?} Target={}",
                            stream.stream_id.0,
                            stream.status,
                            stream.target
                        );
                    }
                    Event::Bandwidth(bw) => {
                        println!(
                            "[BANDWIDTH] Read: {} bytes/s, Written: {} bytes/s",
                            bw.bytes_read, bw.bytes_written
                        );
                    }
                    Event::Log(log) => {
                        println!("[LOG:{}] {}", log.severity.as_str(), log.message);
                    }
                    Event::Status(status) => {
                        let args: Vec<String> = status.arguments.iter()
                            .map(|(k, v)| format!("{}={}", k, v))
                            .collect();
                        println!(
                            "[STATUS:{}] {} - {}",
                            status.status_type.as_str(),
                            status.action,
                            args.join(" ")
                        );
                    }
                    _ => {
                        println!("[EVENT] {:?}", event);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading event: {}", e);
                break;
            }
        }
    }

    Ok(())
}
