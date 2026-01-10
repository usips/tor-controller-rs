//! # tor-controller
//!
//! A safe, async Rust client for the Tor Control Protocol.
//!
//! ## Overview
//!
//! This crate provides a complete implementation of the [Tor Control Protocol](https://spec.torproject.org/control-spec/)
//! for communicating with a running Tor daemon. It enables applications to:
//!
//! - Authenticate using any supported method (NULL, password, cookie, SAFECOOKIE)
//! - Query and modify Tor configuration at runtime
//! - Monitor Tor events (circuit changes, bandwidth, bootstrap status)
//! - Create and manage circuits and streams
//! - Create and manage onion services (hidden services)
//! - Send signals (NEWNYM, HUP, SHUTDOWN, etc.)
//!
//! ## Key Types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`TorClient`] | Main client for communicating with Tor control port |
//! | [`AuthCredential`] | Authentication method and credentials |
//! | [`Event`] | Asynchronous events from Tor |
//! | [`EventType`] | Event types to subscribe to |
//! | [`CircuitId`], [`StreamId`] | Identifiers for circuits and streams |
//! | [`OnionAddress`] | `.onion` address for hidden services |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use tor_controller::{TorClient, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Connect to default control port (127.0.0.1:9051)
//!     let mut client = TorClient::connect_default().await?;
//!     
//!     // Auto-authenticate using best available method
//!     client.auto_authenticate().await?;
//!     
//!     // Get Tor version
//!     let version = client.get_version().await?;
//!     println!("Connected to Tor {}", version);
//!     
//!     // Request new identity (new circuits)
//!     client.new_identity().await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Authentication Methods
//!
//! | Method | Use Case | Security |
//! |--------|----------|----------|
//! | `AuthCredential::None` | Testing, trusted environments | None |
//! | `AuthCredential::Password(...)` | Manual password configuration | Medium |
//! | `AuthCredential::CookieFile(...)` | Same-machine access | High |
//! | `AuthCredential::SafeCookie { ... }` | Recommended for production | Highest |
//!
//! ```rust,no_run
//! use tor_controller::{TorClient, AuthCredential};
//!
//! # async fn example() -> tor_controller::Result<()> {
//! let mut client = TorClient::connect_default().await?;
//!
//! // SAFECOOKIE (recommended) - HMAC-based mutual authentication
//! client.authenticate(&AuthCredential::SafeCookie {
//!     cookie_path: "/run/tor/control.authcookie".to_string(),
//! }).await?;
//!
//! // Or use auto-detection
//! client.auto_authenticate().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuration Management
//!
//! ```rust,no_run
//! # use tor_controller::TorClient;
//! # async fn example() -> tor_controller::Result<()> {
//! # let mut client = TorClient::connect_default().await?;
//! // Get configuration value
//! if let Some(port) = client.get_conf("SocksPort").await? {
//!     println!("SOCKS port: {}", port);
//! }
//!
//! // Set configuration
//! client.set_conf("MaxCircuitDirtiness", "300").await?;
//!
//! // Save to torrc
//! client.save_conf(false).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Event Monitoring
//!
//! Subscribe to asynchronous events from Tor:
//!
//! ```rust,no_run
//! use tor_controller::{TorClient, EventType, Event};
//!
//! # async fn example() -> tor_controller::Result<()> {
//! # let mut client = TorClient::connect_default().await?;
//! // Subscribe to circuit and bandwidth events
//! client.set_events(&[EventType::Circ, EventType::Bw]).await?;
//!
//! // Read events (blocking)
//! loop {
//!     match client.read_event().await? {
//!         Event::CircuitStatus(circ) => {
//!             println!("Circuit {}: {:?}", circ.circuit_id, circ.status);
//!         }
//!         Event::Bandwidth(bw) => {
//!             println!("Bandwidth: {} read, {} written", bw.bytes_read, bw.bytes_written);
//!         }
//!         _ => {}
//!     }
//! }
//! # }
//! ```
//!
//! ## Onion Services
//!
//! Create and manage hidden services:
//!
//! ```rust,no_run
//! # use tor_controller::TorClient;
//! # async fn example() -> tor_controller::Result<()> {
//! # let mut client = TorClient::connect_default().await?;
//! // Create ephemeral onion service
//! let service = client.add_onion(
//!     &[(80, Some("127.0.0.1:8080"))],  // Virtual port 80 -> local 8080
//!     None,                              // Generate new key
//!     &[],                               // No special flags
//! ).await?;
//!
//! println!("Service: http://{}.onion", service.address);
//!
//! // Optional: get private key for persistence
//! if let Some(key) = &service.private_key {
//!     println!("Private key: {}", key);
//! }
//!
//! // Delete when done
//! // client.del_onion(&service.address.service_id()).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Circuit Control
//!
//! Manage Tor circuits directly:
//!
//! ```rust,no_run
//! use tor_controller::{TorClient, Signal, CircuitId};
//!
//! # async fn example() -> tor_controller::Result<()> {
//! # let mut client = TorClient::connect_default().await?;
//! // Request new identity (closes existing circuits)
//! client.signal(Signal::NewNym).await?;
//!
//! // Get all circuits
//! let circuits = client.get_circuit_status().await?;
//! for circuit in &circuits {
//!     println!("Circuit {}: {:?} via {:?}",
//!         circuit.id, circuit.status, circuit.path);
//! }
//!
//! // Close a specific circuit
//! // client.close_circuit(CircuitId(12345), false).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `tokio-runtime` | ✓ | Async support using Tokio |
//! | `test-utils` | | Mock server and fixtures for testing |
//!
//! ## Test Utilities
//!
//! For testing without a real Tor daemon:
//!
//! ```toml
//! [dev-dependencies]
//! tor-controller = { version = "0.1", features = ["test-utils"] }
//! ```
//!
//! ```rust,ignore
//! use tor_controller::test_utils::{fixtures, is_tor_pseudo_address};
//!
//! // Check if address is Tor pseudo-IPv6
//! let addr = "fc00:dead:beef:4dad::1234".parse().unwrap();
//! assert!(is_tor_pseudo_address(&addr));
//!
//! // Extract circuit ID from pseudo-address
//! let circuit_id = extract_circuit_id(&addr);
//! ```
//!
//! ## Error Handling
//!
//! All operations return [`Result<T, TorControlError>`]:
//!
//! ```rust,no_run
//! use tor_controller::{TorClient, TorControlError};
//!
//! # async fn example() {
//! match TorClient::connect("127.0.0.1:9051").await {
//!     Ok(client) => println!("Connected"),
//!     Err(TorControlError::Io(e)) => eprintln!("Connection failed: {}", e),
//!     Err(TorControlError::AuthenticationFailed(msg)) => eprintln!("Auth failed: {}", msg),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! # }
//! ```
//!
//! ## Protocol Compatibility
//!
//! Implements Tor Control Protocol version 1 per the
//! [Tor Control Specification](https://spec.torproject.org/control-spec/).

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]

pub mod auth;
pub mod config;
pub mod error;
pub mod events;
pub mod protocol;
pub mod types;

#[cfg(feature = "tokio-runtime")]
pub mod connection;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Re-export main types for convenience
pub use error::{Result, TorControlError};

#[cfg(feature = "tokio-runtime")]
pub use connection::{CircuitInfo, OnionServiceInfo, StreamInfo, TorClient};

pub use auth::{AuthCredential, AuthMethod, ProtocolInfo};
pub use config::{ConnectionAddress, TorControlConfig};
pub use events::{Event, EventType};
pub use protocol::{Reply, ReplyLine};
pub use types::{
    BandwidthStats, BootstrapStatus, CircuitId, CircuitPurpose, CircuitStatus, ConnectionId,
    Fingerprint, OnionAddress, OrConnStatus, ServerSpec, Signal, StreamId, StreamStatus,
    TorVersion,
};

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Tor Control Protocol version supported.
pub const PROTOCOL_VERSION: u32 = 1;
