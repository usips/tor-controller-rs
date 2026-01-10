//! # Test Utilities for Tor Controller
//!
//! This module provides mock implementations, fixtures, and helper functions
//! for testing code that uses the Tor Controller library.
//!
//! ## Features
//!
//! Enable this module by adding `test-utils` feature:
//!
//! ```toml
//! [dev-dependencies]
//! tor-controller = { version = "0.1", features = ["test-utils"] }
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use tor_controller::test_utils::{MockTorResponse, fixtures};
//!
//! // Parse a mock response
//! let response = MockTorResponse::ok("250 OK");
//!
//! // Use pre-built fixtures
//! let circuit = fixtures::sample_circuit_info();
//! ```
//!
//! ## Mock Server
//!
//! For integration tests, you can use the mock Tor control server:
//!
//! ```rust,ignore
//! use tor_controller::test_utils::MockTorServer;
//!
//! #[tokio::test]
//! async fn test_with_mock_server() {
//!     let server = MockTorServer::start().await;
//!     
//!     // Server automatically responds to common commands
//!     let client = TorClient::connect(&server.address()).await.unwrap();
//!     client.authenticate(&AuthCredential::None).await.unwrap();
//! }
//! ```

use crate::types::{CircuitId, Fingerprint, StreamId};
use std::net::{IpAddr, Ipv6Addr};

/// Default Tor pseudo-IPv6 prefix used for circuit identification.
///
/// When a connection comes through a Tor hidden service, the PROXY protocol
/// encodes the circuit ID in a pseudo-IPv6 address with this prefix.
///
/// Format: `fc00:dead:beef:4dad::<circuit_id>`
pub const TOR_IPV6_PREFIX: &str = "fc00:dead:beef:4dad::";

/// Check if an IPv6 address is a Tor pseudo-address.
///
/// # Arguments
///
/// * `addr` - The IP address to check
///
/// # Returns
///
/// `true` if this is a Tor pseudo-address with the standard prefix
///
/// # Example
///
/// ```rust
/// use std::net::{IpAddr, Ipv6Addr};
/// use tor_controller::test_utils::is_tor_pseudo_address;
///
/// let tor_addr: IpAddr = "fc00:dead:beef:4dad::1234".parse().unwrap();
/// assert!(is_tor_pseudo_address(&tor_addr));
///
/// let regular_addr: IpAddr = "2001:db8::1".parse().unwrap();
/// assert!(!is_tor_pseudo_address(&regular_addr));
/// ```
pub fn is_tor_pseudo_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // Check prefix: fc00:dead:beef:4dad
            segments[0] == 0xfc00
                && segments[1] == 0xdead
                && segments[2] == 0xbeef
                && segments[3] == 0x4dad
        }
        IpAddr::V4(_) => false,
    }
}

/// Extract the circuit ID from a Tor pseudo-IPv6 address.
///
/// The circuit ID is encoded in the lower 64 bits of the address.
///
/// # Arguments
///
/// * `addr` - The Tor pseudo-IPv6 address
///
/// # Returns
///
/// The circuit ID if this is a valid Tor pseudo-address, `None` otherwise
///
/// # Example
///
/// ```rust
/// use std::net::IpAddr;
/// use tor_controller::test_utils::extract_circuit_id;
/// use tor_controller::CircuitId;
///
/// let addr: IpAddr = "fc00:dead:beef:4dad::1234".parse().unwrap();
/// let circuit_id = extract_circuit_id(&addr);
/// assert_eq!(circuit_id, Some(CircuitId(0x1234)));
/// ```
pub fn extract_circuit_id(addr: &IpAddr) -> Option<CircuitId> {
    if !is_tor_pseudo_address(addr) {
        return None;
    }

    match addr {
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // Lower 64 bits contain the circuit ID
            let circuit_id = ((segments[4] as u64) << 48)
                | ((segments[5] as u64) << 32)
                | ((segments[6] as u64) << 16)
                | (segments[7] as u64);
            Some(CircuitId(circuit_id))
        }
        IpAddr::V4(_) => None,
    }
}

/// Create a Tor pseudo-IPv6 address from a circuit ID.
///
/// # Arguments
///
/// * `circuit_id` - The circuit ID to encode
///
/// # Returns
///
/// An IPv6 address in the Tor pseudo-address format
///
/// # Example
///
/// ```rust
/// use tor_controller::test_utils::make_tor_pseudo_address;
/// use tor_controller::CircuitId;
///
/// let addr = make_tor_pseudo_address(CircuitId(0x1234));
/// assert_eq!(addr.to_string(), "fc00:dead:beef:4dad::1234");
/// ```
pub fn make_tor_pseudo_address(circuit_id: CircuitId) -> Ipv6Addr {
    let id = circuit_id.0;
    Ipv6Addr::new(
        0xfc00,
        0xdead,
        0xbeef,
        0x4dad,
        ((id >> 48) & 0xffff) as u16,
        ((id >> 32) & 0xffff) as u16,
        ((id >> 16) & 0xffff) as u16,
        (id & 0xffff) as u16,
    )
}

/// Pre-built fixtures for common Tor entities.
pub mod fixtures {
    use super::*;

    /// Sample circuit ID for testing.
    pub const SAMPLE_CIRCUIT_ID: CircuitId = CircuitId(12345);

    /// Sample stream ID for testing.
    pub const SAMPLE_STREAM_ID: StreamId = StreamId(67890);

    /// Sample relay fingerprint (from Tor directory).
    pub fn sample_fingerprint() -> Fingerprint {
        Fingerprint::new("9695DFC35FFEB861329B9F1AB04C46397020CE31")
    }

    /// Create a sample Tor pseudo-IPv6 address.
    pub fn sample_tor_address() -> IpAddr {
        IpAddr::V6(make_tor_pseudo_address(SAMPLE_CIRCUIT_ID))
    }

    /// Sample PROTOCOLINFO response.
    pub fn protocolinfo_response() -> &'static str {
        "250-PROTOCOLINFO 1\r\n\
         250-AUTH METHODS=NULL,HASHEDPASSWORD,COOKIE,SAFECOOKIE COOKIEFILE=\"/var/run/tor/control.authcookie\"\r\n\
         250-VERSION Tor=\"0.4.8.12\"\r\n\
         250 OK\r\n"
    }

    /// Sample AUTHENTICATE OK response.
    pub fn auth_ok_response() -> &'static str {
        "250 OK\r\n"
    }

    /// Sample GETINFO version response.
    pub fn version_response() -> &'static str {
        "250-version=0.4.8.12 (git-abc123)\r\n\
         250 OK\r\n"
    }

    /// Sample GETCONF SocksPort response.
    pub fn socksport_response() -> &'static str {
        "250 SocksPort=9050\r\n"
    }

    /// Sample CIRC event (circuit built).
    pub fn circuit_built_event() -> &'static str {
        "650 CIRC 12345 BUILT $9695DFC35FFEB861329B9F1AB04C46397020CE31~Relay1,$AAAA...\r\n"
    }

    /// Sample CIRC event (circuit closed).
    pub fn circuit_closed_event() -> &'static str {
        "650 CIRC 12345 CLOSED REASON=FINISHED\r\n"
    }

    /// Sample BW event (bandwidth stats).
    pub fn bandwidth_event() -> &'static str {
        "650 BW 1024 2048\r\n"
    }

    /// Sample error response.
    pub fn error_response() -> &'static str {
        "552 Unknown option\r\n"
    }
}

/// Mock Tor control protocol response builder.
///
/// Helps construct properly formatted Tor control protocol responses
/// for testing parsers and handlers.
#[derive(Debug, Clone)]
pub struct MockTorResponse {
    lines: Vec<String>,
}

impl MockTorResponse {
    /// Create a new empty response builder.
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }

    /// Create a simple OK response.
    pub fn ok() -> Self {
        Self {
            lines: vec!["250 OK".to_string()],
        }
    }

    /// Create an error response.
    pub fn error(code: u16, message: &str) -> Self {
        Self {
            lines: vec![format!("{} {}", code, message)],
        }
    }

    /// Add a data line (mid-reply line with '-').
    pub fn data_line(mut self, line: &str) -> Self {
        // Format: 250-key=value
        self.lines.push(format!("250-{}", line));
        self
    }

    /// Add the final OK line.
    pub fn finish(mut self) -> Self {
        self.lines.push("250 OK".to_string());
        self
    }

    /// Build the response as a string.
    pub fn build(&self) -> String {
        self.lines.iter().map(|l| format!("{}\r\n", l)).collect()
    }

    /// Build the response as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.build().into_bytes()
    }
}

impl Default for MockTorResponse {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tor_pseudo_address() {
        let tor: IpAddr = "fc00:dead:beef:4dad::1".parse().unwrap();
        assert!(is_tor_pseudo_address(&tor));

        let not_tor: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_tor_pseudo_address(&not_tor));

        let ipv4: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!is_tor_pseudo_address(&ipv4));
    }

    #[test]
    fn test_extract_circuit_id() {
        let addr: IpAddr = "fc00:dead:beef:4dad::1234".parse().unwrap();
        assert_eq!(extract_circuit_id(&addr), Some(CircuitId(0x1234)));

        let addr2: IpAddr = "fc00:dead:beef:4dad:0:0:0:ffff".parse().unwrap();
        assert_eq!(extract_circuit_id(&addr2), Some(CircuitId(0xffff)));

        let not_tor: IpAddr = "2001:db8::1234".parse().unwrap();
        assert_eq!(extract_circuit_id(&not_tor), None);
    }

    #[test]
    fn test_make_tor_pseudo_address() {
        let addr = make_tor_pseudo_address(CircuitId(0x1234));
        assert_eq!(addr.to_string(), "fc00:dead:beef:4dad::1234");

        let addr2 = make_tor_pseudo_address(CircuitId(0xdeadbeef));
        assert!(addr2.to_string().contains("dead:beef:4dad"));
    }

    #[test]
    fn test_roundtrip() {
        for id in [0, 1, 0x1234, 0xdeadbeef, u64::MAX] {
            let circuit_id = CircuitId(id);
            let addr = IpAddr::V6(make_tor_pseudo_address(circuit_id));
            let extracted = extract_circuit_id(&addr);
            assert_eq!(extracted, Some(circuit_id));
        }
    }

    #[test]
    fn test_mock_response_ok() {
        let response = MockTorResponse::ok();
        assert_eq!(response.build(), "250 OK\r\n");
    }

    #[test]
    fn test_mock_response_with_data() {
        let response = MockTorResponse::new()
            .data_line("version=0.4.8.12")
            .data_line("config-file=/etc/tor/torrc")
            .finish();

        let expected = "250-version=0.4.8.12\r\n250-config-file=/etc/tor/torrc\r\n250 OK\r\n";
        assert_eq!(response.build(), expected);
    }

    #[test]
    fn test_mock_response_error() {
        let response = MockTorResponse::error(552, "Unknown option");
        assert_eq!(response.build(), "552 Unknown option\r\n");
    }
}
