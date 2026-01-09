//! Authentication mechanisms for the Tor control protocol.
//!
//! This module implements the various authentication methods supported
//! by the Tor control protocol: NULL, HASHEDPASSWORD, COOKIE, and SAFECOOKIE.

use crate::error::{Result, TorControlError};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

/// Authentication methods supported by Tor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication required.
    Null,
    /// Password authentication.
    HashedPassword,
    /// Cookie file authentication.
    Cookie,
    /// Safe cookie authentication (HMAC-based).
    SafeCookie,
}

impl AuthMethod {
    /// Parse an auth method from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "NULL" => Some(AuthMethod::Null),
            "HASHEDPASSWORD" => Some(AuthMethod::HashedPassword),
            "COOKIE" => Some(AuthMethod::Cookie),
            "SAFECOOKIE" => Some(AuthMethod::SafeCookie),
            _ => None,
        }
    }
}

/// Information retrieved from PROTOCOLINFO command.
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// Protocol version (currently always 1).
    pub protocol_version: u32,
    /// Tor version string.
    pub tor_version: String,
    /// Supported authentication methods.
    pub auth_methods: Vec<AuthMethod>,
    /// Path to the cookie file, if applicable.
    pub cookie_file: Option<String>,
}

impl ProtocolInfo {
    /// Parse PROTOCOLINFO response lines.
    pub fn parse(lines: &[String]) -> Result<Self> {
        let mut protocol_version = 1;
        let mut tor_version = String::new();
        let mut auth_methods = Vec::new();
        let mut cookie_file = None;

        for line in lines {
            let line = line.trim();

            if let Some(rest) = line.strip_prefix("PROTOCOLINFO ") {
                protocol_version = rest.trim().parse().unwrap_or(1);
            } else if let Some(rest) = line.strip_prefix("AUTH ") {
                // Parse AUTH line: AUTH METHODS=NULL,COOKIE,SAFECOOKIE COOKIEFILE="..."
                let parts = rest.split_whitespace();
                for part in parts {
                    if let Some(methods) = part.strip_prefix("METHODS=") {
                        for method in methods.split(',') {
                            if let Some(m) = AuthMethod::parse(method) {
                                auth_methods.push(m);
                            }
                        }
                    } else if let Some(file) = part.strip_prefix("COOKIEFILE=") {
                        // Remove quotes
                        let file = file.trim_matches('"');
                        cookie_file = Some(file.to_string());
                    }
                }
            } else if let Some(rest) = line.strip_prefix("VERSION ") {
                // Parse VERSION line: VERSION Tor="0.4.8.10"
                if let Some(ver) = rest.strip_prefix("Tor=") {
                    tor_version = ver.trim_matches('"').to_string();
                }
            }
        }

        Ok(ProtocolInfo {
            protocol_version,
            tor_version,
            auth_methods,
            cookie_file,
        })
    }

    /// Check if NULL authentication is supported.
    pub fn supports_null(&self) -> bool {
        self.auth_methods.contains(&AuthMethod::Null)
    }

    /// Check if password authentication is supported.
    pub fn supports_password(&self) -> bool {
        self.auth_methods.contains(&AuthMethod::HashedPassword)
    }

    /// Check if cookie authentication is supported.
    pub fn supports_cookie(&self) -> bool {
        self.auth_methods.contains(&AuthMethod::Cookie)
    }

    /// Check if safe cookie authentication is supported.
    pub fn supports_safe_cookie(&self) -> bool {
        self.auth_methods.contains(&AuthMethod::SafeCookie)
    }
}

/// Authentication credentials for connecting to Tor.
#[derive(Debug, Clone, Default)]
pub enum AuthCredential {
    /// No authentication (for NULL method).
    #[default]
    None,
    /// Password for HASHEDPASSWORD method.
    Password(String),
    /// Cookie file path - will be read automatically.
    CookieFile(String),
    /// Raw cookie data (32 bytes).
    CookieData(Vec<u8>),
    /// Use SAFECOOKIE authentication.
    SafeCookie {
        /// Path to the cookie file.
        cookie_path: String,
    },
}

impl AuthCredential {
    /// Create password credentials.
    pub fn password(password: impl Into<String>) -> Self {
        AuthCredential::Password(password.into())
    }

    /// Create cookie file credentials.
    pub fn cookie_file(path: impl Into<String>) -> Self {
        AuthCredential::CookieFile(path.into())
    }

    /// Create safe cookie credentials.
    pub fn safe_cookie(cookie_path: impl Into<String>) -> Self {
        AuthCredential::SafeCookie {
            cookie_path: cookie_path.into(),
        }
    }
}

/// Read the authentication cookie from a file.
pub fn read_cookie_file(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path).map_err(|e| {
        TorControlError::AuthenticationFailed(format!(
            "Failed to read cookie file '{}': {}",
            path.display(),
            e
        ))
    })?;

    if data.len() != 32 {
        return Err(TorControlError::AuthenticationFailed(format!(
            "Cookie file has invalid length {} (expected 32)",
            data.len()
        )));
    }

    Ok(data)
}

/// Generate a random client nonce for SAFECOOKIE authentication.
pub fn generate_client_nonce() -> [u8; 32] {
    use rand::Rng;
    let mut nonce = [0u8; 32];
    rand::rng().fill(&mut nonce);
    nonce
}

/// Compute the server hash for SAFECOOKIE authentication.
pub fn compute_server_hash(cookie: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(b"Tor safe cookie authentication server-to-controller hash")
            .expect("HMAC key length should be valid");

    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);

    let result = mac.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result.into_bytes());
    hash
}

/// Compute the client hash for SAFECOOKIE authentication.
pub fn compute_client_hash(cookie: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(b"Tor safe cookie authentication controller-to-server hash")
            .expect("HMAC key length should be valid");

    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);

    let result = mac.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result.into_bytes());
    hash
}

/// Format cookie data as hex for the AUTHENTICATE command.
pub fn format_cookie_hex(cookie: &[u8]) -> String {
    hex::encode_upper(cookie)
}

/// Parse the AUTHCHALLENGE response.
pub fn parse_authchallenge_response(text: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    // Format: AUTHCHALLENGE SERVERHASH=... SERVERNONCE=...
    let mut server_hash = None;
    let mut server_nonce = None;

    for part in text.split_whitespace() {
        if let Some(hash) = part.strip_prefix("SERVERHASH=") {
            server_hash = Some(hex::decode(hash).map_err(|e| {
                TorControlError::ProtocolError(format!("Invalid SERVERHASH hex: {}", e))
            })?);
        } else if let Some(nonce) = part.strip_prefix("SERVERNONCE=") {
            server_nonce = Some(hex::decode(nonce).map_err(|e| {
                TorControlError::ProtocolError(format!("Invalid SERVERNONCE hex: {}", e))
            })?);
        }
    }

    let server_hash = server_hash
        .ok_or_else(|| TorControlError::ProtocolError("Missing SERVERHASH".to_string()))?;
    let server_nonce = server_nonce
        .ok_or_else(|| TorControlError::ProtocolError("Missing SERVERNONCE".to_string()))?;

    if server_hash.len() != 32 {
        return Err(TorControlError::ProtocolError(format!(
            "Invalid SERVERHASH length: {}",
            server_hash.len()
        )));
    }

    if server_nonce.len() != 32 {
        return Err(TorControlError::ProtocolError(format!(
            "Invalid SERVERNONCE length: {}",
            server_nonce.len()
        )));
    }

    Ok((server_hash, server_nonce))
}

/// Verify the server's response in SAFECOOKIE authentication.
pub fn verify_server_hash(
    cookie: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    expected_hash: &[u8],
) -> bool {
    let computed = compute_server_hash(cookie, client_nonce, server_nonce);
    constant_time_compare(&computed, expected_hash)
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_parsing() {
        assert_eq!(AuthMethod::parse("NULL"), Some(AuthMethod::Null));
        assert_eq!(
            AuthMethod::parse("HASHEDPASSWORD"),
            Some(AuthMethod::HashedPassword)
        );
        assert_eq!(AuthMethod::parse("COOKIE"), Some(AuthMethod::Cookie));
        assert_eq!(
            AuthMethod::parse("SAFECOOKIE"),
            Some(AuthMethod::SafeCookie)
        );
        assert_eq!(AuthMethod::parse("UNKNOWN"), None);
    }

    #[test]
    fn test_protocol_info_parsing() {
        let lines = vec![
            "PROTOCOLINFO 1".to_string(),
            "AUTH METHODS=NULL,COOKIE,SAFECOOKIE COOKIEFILE=\"/var/lib/tor/control_auth_cookie\""
                .to_string(),
            "VERSION Tor=\"0.4.8.10\"".to_string(),
            "OK".to_string(),
        ];

        let info = ProtocolInfo::parse(&lines).unwrap();
        assert_eq!(info.protocol_version, 1);
        assert_eq!(info.tor_version, "0.4.8.10");
        assert!(info.supports_null());
        assert!(info.supports_cookie());
        assert!(info.supports_safe_cookie());
        assert!(!info.supports_password());
        assert_eq!(
            info.cookie_file,
            Some("/var/lib/tor/control_auth_cookie".to_string())
        );
    }

    #[test]
    fn test_client_nonce_generation() {
        let nonce1 = generate_client_nonce();
        let nonce2 = generate_client_nonce();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_hmac_computation() {
        let cookie = [0u8; 32];
        let client_nonce = [1u8; 32];
        let server_nonce = [2u8; 32];

        let server_hash = compute_server_hash(&cookie, &client_nonce, &server_nonce);
        let client_hash = compute_client_hash(&cookie, &client_nonce, &server_nonce);

        // They should be different
        assert_ne!(server_hash, client_hash);

        // Verify works correctly
        assert!(verify_server_hash(
            &cookie,
            &client_nonce,
            &server_nonce,
            &server_hash
        ));
        assert!(!verify_server_hash(
            &cookie,
            &client_nonce,
            &server_nonce,
            &client_hash
        ));
    }
}
