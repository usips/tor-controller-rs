//! Configuration for the Tor control connection.
//!
//! This module provides configuration options for connecting to and
//! interacting with the Tor control port.

use crate::auth::AuthCredential;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for connecting to Tor's control port.
#[derive(Debug, Clone)]
pub struct TorControlConfig {
    /// The address to connect to.
    pub address: ConnectionAddress,
    /// Authentication credentials.
    pub auth: AuthCredential,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Read timeout for commands.
    pub read_timeout: Duration,
    /// Write timeout for commands.
    pub write_timeout: Duration,
    /// Whether to automatically reconnect on connection loss.
    pub auto_reconnect: bool,
    /// Maximum number of reconnection attempts.
    pub max_reconnect_attempts: u32,
    /// Delay between reconnection attempts.
    pub reconnect_delay: Duration,
}

impl Default for TorControlConfig {
    fn default() -> Self {
        Self {
            address: ConnectionAddress::default(),
            auth: AuthCredential::None,
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            auto_reconnect: false,
            max_reconnect_attempts: 3,
            reconnect_delay: Duration::from_secs(1),
        }
    }
}

impl TorControlConfig {
    /// Create a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the connection address.
    pub fn address(mut self, address: ConnectionAddress) -> Self {
        self.address = address;
        self
    }

    /// Connect to a TCP address.
    pub fn tcp(mut self, addr: impl Into<SocketAddr>) -> Self {
        self.address = ConnectionAddress::Tcp(addr.into());
        self
    }

    /// Connect to a Unix socket.
    pub fn unix(mut self, path: impl Into<PathBuf>) -> Self {
        self.address = ConnectionAddress::Unix(path.into());
        self
    }

    /// Set authentication credentials.
    pub fn auth(mut self, auth: AuthCredential) -> Self {
        self.auth = auth;
        self
    }

    /// Set password authentication.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.auth = AuthCredential::Password(password.into());
        self
    }

    /// Set cookie file authentication.
    pub fn cookie_file(mut self, path: impl Into<String>) -> Self {
        self.auth = AuthCredential::CookieFile(path.into());
        self
    }

    /// Set safe cookie authentication.
    pub fn safe_cookie(mut self, cookie_path: impl Into<String>) -> Self {
        self.auth = AuthCredential::SafeCookie {
            cookie_path: cookie_path.into(),
        };
        self
    }

    /// Set the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the read timeout.
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Set the write timeout.
    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// Enable automatic reconnection.
    pub fn auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    /// Set the maximum number of reconnection attempts.
    pub fn max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }

    /// Set the delay between reconnection attempts.
    pub fn reconnect_delay(mut self, delay: Duration) -> Self {
        self.reconnect_delay = delay;
        self
    }
}

/// The address to connect to for the control port.
#[derive(Debug, Clone)]
pub enum ConnectionAddress {
    /// TCP socket address.
    Tcp(SocketAddr),
    /// Unix domain socket path.
    Unix(PathBuf),
}

impl Default for ConnectionAddress {
    fn default() -> Self {
        // Default Tor control port
        ConnectionAddress::Tcp("127.0.0.1:9051".parse().unwrap())
    }
}

impl ConnectionAddress {
    /// Create a TCP connection address.
    pub fn tcp(addr: impl Into<SocketAddr>) -> Self {
        ConnectionAddress::Tcp(addr.into())
    }

    /// Create a Unix socket connection address.
    pub fn unix(path: impl Into<PathBuf>) -> Self {
        ConnectionAddress::Unix(path.into())
    }

    /// Parse an address string.
    ///
    /// Supports:
    /// - `host:port` for TCP
    /// - `unix:/path/to/socket` for Unix sockets
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(path) = s.strip_prefix("unix:") {
            Ok(ConnectionAddress::Unix(PathBuf::from(path)))
        } else {
            s.parse::<SocketAddr>()
                .map(ConnectionAddress::Tcp)
                .map_err(|e| format!("Invalid address '{}': {}", s, e))
        }
    }
}

impl std::fmt::Display for ConnectionAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionAddress::Tcp(addr) => write!(f, "{}", addr),
            ConnectionAddress::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TorControlConfig::default();
        assert!(matches!(config.address, ConnectionAddress::Tcp(_)));
        assert!(matches!(config.auth, AuthCredential::None));
    }

    #[test]
    fn test_config_builder() {
        use std::net::SocketAddr;
        let config = TorControlConfig::new()
            .tcp("127.0.0.1:9051".parse::<SocketAddr>().unwrap())
            .password("mypassword")
            .connect_timeout(Duration::from_secs(10))
            .auto_reconnect(true);

        assert!(matches!(config.address, ConnectionAddress::Tcp(_)));
        assert!(matches!(config.auth, AuthCredential::Password(_)));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert!(config.auto_reconnect);
    }

    #[test]
    fn test_address_parsing() {
        let tcp = ConnectionAddress::parse("127.0.0.1:9051").unwrap();
        assert!(matches!(tcp, ConnectionAddress::Tcp(_)));

        let unix = ConnectionAddress::parse("unix:/var/run/tor/control").unwrap();
        assert!(matches!(unix, ConnectionAddress::Unix(_)));
    }
}
