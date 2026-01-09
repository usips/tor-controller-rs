//! # tor-controller
//!
//! A safe, practical, robust, and configurable Rust crate for interfacing with
//! the Tor control protocol.
//!
//! This crate provides an async client for communicating with a Tor daemon
//! through its control port, allowing you to:
//!
//! - Authenticate using various methods (NULL, password, cookie, SAFECOOKIE)
//! - Query and modify Tor configuration
//! - Monitor Tor status and events
//! - Create and manage circuits and streams
//! - Create and manage onion services
//! - Send signals (NEWNYM, HUP, SHUTDOWN, etc.)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use tor_controller::{TorClient, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Connect to the default control port (127.0.0.1:9051)
//!     let mut client = TorClient::connect_default().await?;
//!     
//!     // Auto-authenticate using the best available method
//!     client.auto_authenticate().await?;
//!     
//!     // Get Tor version
//!     let version = client.get_version().await?;
//!     println!("Connected to Tor {}", version);
//!     
//!     // Request a new identity
//!     client.new_identity().await?;
//!     println!("New identity requested");
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Authentication
//!
//! The crate supports all Tor authentication methods:
//!
//! ```rust,no_run
//! use tor_controller::{TorClient, AuthCredential};
//!
//! # async fn example() -> tor_controller::Result<()> {
//! let mut client = TorClient::connect_default().await?;
//!
//! // NULL authentication (no password required)
//! client.authenticate(&AuthCredential::None).await?;
//!
//! // Password authentication
//! client.authenticate(&AuthCredential::Password("secret".to_string())).await?;
//!
//! // Cookie authentication
//! client.authenticate(&AuthCredential::CookieFile("/path/to/control_auth_cookie".to_string())).await?;
//!
//! // SAFECOOKIE authentication (recommended)
//! client.authenticate(&AuthCredential::SafeCookie {
//!     cookie_path: "/path/to/control_auth_cookie".to_string(),
//! }).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuration
//!
//! Query and modify Tor configuration:
//!
//! ```rust,no_run
//! # use tor_controller::TorClient;
//! # async fn example() -> tor_controller::Result<()> {
//! # let mut client = TorClient::connect_default().await?;
//! // Get a configuration value
//! if let Some(socks_port) = client.get_conf("SocksPort").await? {
//!     println!("SOCKS port: {}", socks_port);
//! }
//!
//! // Set a configuration value
//! client.set_conf("MaxCircuitDirtiness", "300").await?;
//!
//! // Save configuration to disk
//! client.save_conf(false).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Event Monitoring
//!
//! Subscribe to Tor events:
//!
//! ```rust,no_run
//! # use tor_controller::{TorClient, EventType};
//! # async fn example() -> tor_controller::Result<()> {
//! # let mut client = TorClient::connect_default().await?;
//! // Subscribe to circuit and bandwidth events
//! client.set_events(&[EventType::Circ, EventType::Bw]).await?;
//!
//! // Read events
//! loop {
//!     let event = client.read_event().await?;
//!     println!("Received event: {:?}", event);
//! }
//! # Ok(())
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
//! // Create a new onion service
//! let service = client.add_onion(
//!     &[(80, Some("127.0.0.1:8080"))],  // Map port 80 to local 8080
//!     None,                               // Generate new key
//!     &["DiscardPK"],                     // Don't return private key
//! ).await?;
//!
//! println!("Onion service: {}", service.address);
//!
//! // Delete the onion service when done
//! // client.del_onion(&service.address.service_id()).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! - `tokio-runtime` (default): Enable async support using Tokio runtime
//!
//! ## Protocol Compatibility
//!
//! This crate implements Tor Control Protocol version 1 as specified in
//! the [Tor Control Specification](https://spec.torproject.org/control-spec/).
//!
//! Version 0.1.1.0 corresponds to the Tor version where the control protocol
//! was last significantly changed.

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
