//! Tor Control connection and client.
//!
//! This module provides the main client for connecting to and
//! communicating with a Tor control port.

use crate::auth::{
    compute_client_hash, format_cookie_hex, generate_client_nonce,
    parse_authchallenge_response, read_cookie_file, verify_server_hash, AuthCredential,
    ProtocolInfo,
};
use crate::error::{Result, TorControlError};
use crate::events::{parse_event, Event, EventType};
use crate::protocol::{format_command, format_command_with_data, quote_string, Reply, ReplyLine};
use crate::types::*;

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tracing::{debug, trace};

/// A client for communicating with a Tor control port.
pub struct TorClient {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    protocol_info: Option<ProtocolInfo>,
}

impl TorClient {
    /// Connect to a Tor control port.
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(TorControlError::Io)?;

        let (read_half, write_half) = stream.into_split();

        Ok(Self {
            reader: BufReader::new(read_half),
            writer: BufWriter::new(write_half),
            protocol_info: None,
        })
    }

    /// Connect to the default Tor control port (127.0.0.1:9051).
    pub async fn connect_default() -> Result<Self> {
        Self::connect("127.0.0.1:9051").await
    }

    /// Send a raw command and receive the reply.
    pub async fn send_command(&mut self, command: &str) -> Result<Reply> {
        trace!("Sending command: {}", command.trim());

        // Write the command
        self.writer
            .write_all(command.as_bytes())
            .await
            .map_err(TorControlError::Io)?;
        self.writer.flush().await.map_err(TorControlError::Io)?;

        // Read the reply
        self.read_reply().await
    }

    /// Read a complete reply from Tor.
    async fn read_reply(&mut self) -> Result<Reply> {
        let mut lines = Vec::new();
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = self.reader
                .read_line(&mut line)
                .await
                .map_err(TorControlError::Io)?;

            if bytes_read == 0 {
                return Err(TorControlError::ConnectionClosed);
            }

            // Remove trailing CRLF
            let trimmed = line.trim_end_matches(['\r', '\n']);
            trace!("Received line: {}", trimmed);

            let reply_line = ReplyLine::parse(trimmed)?;
            let is_end = reply_line.is_end();

            // Handle data lines ('+')
            if reply_line.is_data() {
                // Read data until we see a line with just "."
                let mut data_lines = Vec::new();
                loop {
                    let mut data_line = String::new();
                    self.reader
                        .read_line(&mut data_line)
                        .await
                        .map_err(TorControlError::Io)?;
                    let data_line = data_line.trim_end_matches(['\r', '\n']);

                    if data_line == "." {
                        break;
                    }

                    // Remove leading dot escape
                    let data_line = if data_line.starts_with("..") {
                        &data_line[1..]
                    } else {
                        data_line
                    };

                    data_lines.push(data_line.to_string());
                }

                // Create a reply line with the data
                lines.push(ReplyLine {
                    code: reply_line.code,
                    separator: reply_line.separator,
                    text: format!("{}\n{}", reply_line.text, data_lines.join("\n")),
                });
            } else {
                lines.push(reply_line);
            }

            if is_end {
                break;
            }
        }

        Reply::new(lines)
    }

    /// Get protocol info from Tor.
    pub async fn protocol_info(&mut self) -> Result<ProtocolInfo> {
        let reply = self.send_command("PROTOCOLINFO 1\r\n").await?;

        let lines: Vec<String> = reply.lines.iter().map(|l| l.text.clone()).collect();
        let info = ProtocolInfo::parse(&lines)?;

        self.protocol_info = Some(info.clone());
        Ok(info)
    }

    /// Authenticate with Tor.
    pub async fn authenticate(&mut self, credential: &AuthCredential) -> Result<()> {
        match credential {
            AuthCredential::None => {
                debug!("Authenticating with NULL method");
                let reply = self.send_command("AUTHENTICATE\r\n").await?;
                reply.into_result()?;
            }
            AuthCredential::Password(password) => {
                debug!("Authenticating with password");
                let quoted = quote_string(password);
                let cmd = format!("AUTHENTICATE {}\r\n", quoted);
                let reply = self.send_command(&cmd).await?;
                reply.into_result().map_err(|_| {
                    TorControlError::AuthenticationFailed("Invalid password".to_string())
                })?;
            }
            AuthCredential::CookieFile(path) => {
                debug!("Authenticating with cookie file");
                let cookie = read_cookie_file(Path::new(path))?;
                let hex = format_cookie_hex(&cookie);
                let cmd = format!("AUTHENTICATE {}\r\n", hex);
                let reply = self.send_command(&cmd).await?;
                reply.into_result().map_err(|_| {
                    TorControlError::AuthenticationFailed("Invalid cookie".to_string())
                })?;
            }
            AuthCredential::CookieData(cookie) => {
                debug!("Authenticating with cookie data");
                let hex = format_cookie_hex(cookie);
                let cmd = format!("AUTHENTICATE {}\r\n", hex);
                let reply = self.send_command(&cmd).await?;
                reply.into_result().map_err(|_| {
                    TorControlError::AuthenticationFailed("Invalid cookie".to_string())
                })?;
            }
            AuthCredential::SafeCookie { cookie_path } => {
                debug!("Authenticating with SAFECOOKIE");

                // Read the cookie
                let cookie = read_cookie_file(Path::new(cookie_path))?;

                // Generate client nonce
                let client_nonce = generate_client_nonce();
                let client_nonce_hex = hex::encode_upper(client_nonce);

                // Send AUTHCHALLENGE
                let cmd = format!("AUTHCHALLENGE SAFECOOKIE {}\r\n", client_nonce_hex);
                let reply = self.send_command(&cmd).await?;
                let reply = reply.into_result()?;

                // Parse server response
                let (server_hash, server_nonce) =
                    parse_authchallenge_response(reply.first_line())?;

                // Verify server hash
                if !verify_server_hash(&cookie, &client_nonce, &server_nonce, &server_hash) {
                    return Err(TorControlError::AuthenticationFailed(
                        "Server hash verification failed".to_string(),
                    ));
                }

                // Compute client hash
                let client_hash = compute_client_hash(&cookie, &client_nonce, &server_nonce);
                let client_hash_hex = hex::encode_upper(client_hash);

                // Send AUTHENTICATE
                let cmd = format!("AUTHENTICATE {}\r\n", client_hash_hex);
                let reply = self.send_command(&cmd).await?;
                reply.into_result().map_err(|_| {
                    TorControlError::AuthenticationFailed("SAFECOOKIE authentication failed".to_string())
                })?;
            }
        }

        debug!("Authentication successful");
        Ok(())
    }

    /// Automatically authenticate using the best available method.
    pub async fn auto_authenticate(&mut self) -> Result<()> {
        let info = self.protocol_info().await?;

        if info.supports_null() {
            self.authenticate(&AuthCredential::None).await
        } else if info.supports_safe_cookie() {
            if let Some(ref cookie_file) = info.cookie_file {
                self.authenticate(&AuthCredential::SafeCookie {
                    cookie_path: cookie_file.clone(),
                })
                .await
            } else {
                Err(TorControlError::AuthenticationFailed(
                    "SAFECOOKIE supported but no cookie file specified".to_string(),
                ))
            }
        } else if info.supports_cookie() {
            if let Some(ref cookie_file) = info.cookie_file {
                self.authenticate(&AuthCredential::CookieFile(cookie_file.clone()))
                    .await
            } else {
                Err(TorControlError::AuthenticationFailed(
                    "Cookie auth supported but no cookie file specified".to_string(),
                ))
            }
        } else if info.supports_password() {
            Err(TorControlError::AuthenticationFailed(
                "Password required for authentication".to_string(),
            ))
        } else {
            Err(TorControlError::AuthenticationFailed(
                "No supported authentication method".to_string(),
            ))
        }
    }

    // ==================== Commands ====================

    /// Get the Tor version.
    pub async fn get_version(&mut self) -> Result<TorVersion> {
        let reply = self.send_command("GETINFO version\r\n").await?;
        let reply = reply.into_result()?;

        for line in &reply.lines {
            if let Some(version) = line.text.strip_prefix("version=") {
                return TorVersion::from_str(version);
            }
        }

        Err(TorControlError::ParseError(
            "Version not found in response".to_string(),
        ))
    }

    /// Get a configuration value.
    pub async fn get_conf(&mut self, key: &str) -> Result<Option<String>> {
        let cmd = format_command("GETCONF", &[key]);
        let reply = self.send_command(&cmd).await?;
        let reply = reply.into_result()?;

        for line in &reply.lines {
            if let Some(value) = line.text.strip_prefix(&format!("{}=", key)) {
                return Ok(Some(value.to_string()));
            } else if line.text == key {
                return Ok(None); // Key exists but has no value
            }
        }

        Ok(None)
    }

    /// Get multiple configuration values.
    pub async fn get_conf_multi(&mut self, keys: &[&str]) -> Result<HashMap<String, Vec<String>>> {
        let cmd = format_command("GETCONF", keys);
        let reply = self.send_command(&cmd).await?;
        let reply = reply.into_result()?;

        let mut result: HashMap<String, Vec<String>> = HashMap::new();

        for line in &reply.lines {
            if let Some(pos) = line.text.find('=') {
                let key = &line.text[..pos];
                let value = &line.text[pos + 1..];
                result.entry(key.to_string()).or_default().push(value.to_string());
            }
        }

        Ok(result)
    }

    /// Set a configuration value.
    pub async fn set_conf(&mut self, key: &str, value: &str) -> Result<()> {
        let arg = format!("{}={}", key, quote_string(value));
        let cmd = format_command("SETCONF", &[&arg]);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Set multiple configuration values.
    pub async fn set_conf_multi(&mut self, settings: &[(&str, &str)]) -> Result<()> {
        let args: Vec<String> = settings
            .iter()
            .map(|(k, v)| format!("{}={}", k, quote_string(v)))
            .collect();
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let cmd = format_command("SETCONF", &arg_refs);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Reset a configuration value to its default.
    pub async fn reset_conf(&mut self, key: &str) -> Result<()> {
        let cmd = format_command("RESETCONF", &[key]);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Get information from Tor.
    pub async fn get_info(&mut self, key: &str) -> Result<String> {
        let cmd = format_command("GETINFO", &[key]);
        let reply = self.send_command(&cmd).await?;
        let reply = reply.into_result()?;

        for line in &reply.lines {
            if let Some(value) = line.text.strip_prefix(&format!("{}=", key)) {
                return Ok(value.to_string());
            }
        }

        // Check for multi-line response
        if let Some(data) = reply.data {
            return Ok(data);
        }

        Err(TorControlError::ParseError(format!(
            "Key '{}' not found in response",
            key
        )))
    }

    /// Get multiple info values.
    pub async fn get_info_multi(&mut self, keys: &[&str]) -> Result<HashMap<String, String>> {
        let cmd = format_command("GETINFO", keys);
        let reply = self.send_command(&cmd).await?;
        let reply = reply.into_result()?;

        let mut result = HashMap::new();

        for line in &reply.lines {
            if let Some(pos) = line.text.find('=') {
                let key = &line.text[..pos];
                let value = &line.text[pos + 1..];
                result.insert(key.to_string(), value.to_string());
            }
        }

        Ok(result)
    }

    /// Send a signal to Tor.
    pub async fn signal(&mut self, signal: Signal) -> Result<()> {
        let cmd = format_command("SIGNAL", &[signal.as_str()]);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Request a new identity (new circuits).
    pub async fn new_identity(&mut self) -> Result<()> {
        self.signal(Signal::NewNym).await
    }

    /// Clear the DNS cache.
    pub async fn clear_dns_cache(&mut self) -> Result<()> {
        self.signal(Signal::ClearDnsCache).await
    }

    /// Set events to subscribe to.
    pub async fn set_events(&mut self, events: &[EventType]) -> Result<()> {
        let event_names: Vec<&str> = events.iter().map(|e| e.as_str()).collect();
        let cmd = format_command("SETEVENTS", &event_names);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Map an address.
    pub async fn map_address(&mut self, from: &str, to: &str) -> Result<String> {
        let arg = format!("{}={}", from, to);
        let cmd = format_command("MAPADDRESS", &[&arg]);
        let reply = self.send_command(&cmd).await?;
        let reply = reply.into_result()?;

        Ok(reply.first_line().to_string())
    }

    /// Extend a circuit.
    pub async fn extend_circuit(
        &mut self,
        circuit_id: Option<CircuitId>,
        path: &[&str],
    ) -> Result<CircuitId> {
        let circuit_id_str = circuit_id.map(|c| c.0.to_string()).unwrap_or_else(|| "0".to_string());
        let path_str = path.join(",");
        let cmd = format_command("EXTENDCIRCUIT", &[&circuit_id_str, &path_str]);
        let reply = self.send_command(&cmd).await?;
        let reply = reply.into_result()?;

        // Parse "EXTENDED <circuit_id>"
        let text = reply.first_line();
        if let Some(id_str) = text.strip_prefix("EXTENDED ") {
            let id: u64 = id_str.parse().map_err(|_| {
                TorControlError::ParseError(format!("Invalid circuit ID: {}", id_str))
            })?;
            Ok(CircuitId(id))
        } else {
            Err(TorControlError::ParseError(format!(
                "Unexpected response: {}",
                text
            )))
        }
    }

    /// Close a circuit.
    pub async fn close_circuit(&mut self, circuit_id: CircuitId, if_unused: bool) -> Result<()> {
        let id_str = circuit_id.0.to_string();
        let args = if if_unused {
            vec![id_str.as_str(), "IfUnused"]
        } else {
            vec![id_str.as_str()]
        };
        let cmd = format_command("CLOSECIRCUIT", &args);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Close a stream.
    pub async fn close_stream(&mut self, stream_id: StreamId, reason: u8) -> Result<()> {
        let id_str = stream_id.0.to_string();
        let reason_str = reason.to_string();
        let cmd = format_command("CLOSESTREAM", &[&id_str, &reason_str]);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Attach a stream to a circuit.
    pub async fn attach_stream(&mut self, stream_id: StreamId, circuit_id: CircuitId) -> Result<()> {
        let stream_str = stream_id.0.to_string();
        let circuit_str = circuit_id.0.to_string();
        let cmd = format_command("ATTACHSTREAM", &[&stream_str, &circuit_str]);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Get circuit status.
    pub async fn get_circuit_status(&mut self) -> Result<Vec<CircuitInfo>> {
        let info = self.get_info("circuit-status").await?;
        let mut circuits = Vec::new();

        for line in info.lines() {
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 2 {
                continue;
            }

            let circuit_id = CircuitId(parts[0].parse().unwrap_or(0));
            let status = CircuitStatus::from_str(parts[1]).unwrap_or(CircuitStatus::Unknown);

            let path = parts
                .get(2)
                .map(|s| {
                    s.split(',')
                        .filter_map(|p| ServerSpec::from_str(p).ok())
                        .collect()
                })
                .unwrap_or_default();

            circuits.push(CircuitInfo {
                id: circuit_id,
                status,
                path,
            });
        }

        Ok(circuits)
    }

    /// Get stream status.
    pub async fn get_stream_status(&mut self) -> Result<Vec<StreamInfo>> {
        let info = self.get_info("stream-status").await?;
        let mut streams = Vec::new();

        for line in info.lines() {
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 4 {
                continue;
            }

            let stream_id = StreamId(parts[0].parse().unwrap_or(0));
            let status = StreamStatus::from_str(parts[1]).unwrap_or(StreamStatus::Unknown);
            let circuit_id = CircuitId(parts[2].parse().unwrap_or(0));
            let target = parts[3].to_string();

            streams.push(StreamInfo {
                id: stream_id,
                status,
                circuit_id,
                target,
            });
        }

        Ok(streams)
    }

    /// Save configuration to disk.
    pub async fn save_conf(&mut self, force: bool) -> Result<()> {
        let cmd = if force {
            format_command("SAVECONF", &["FORCE"])
        } else {
            format_command("SAVECONF", &[])
        };
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Load configuration from text.
    pub async fn load_conf(&mut self, config_text: &str) -> Result<()> {
        let cmd = format_command_with_data("LOADCONF", &[], config_text);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Resolve a hostname.
    pub async fn resolve(&mut self, hostname: &str, reverse: bool) -> Result<()> {
        let args = if reverse {
            vec!["mode=reverse", hostname]
        } else {
            vec![hostname]
        };
        let cmd = format_command("RESOLVE", &args);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Take ownership of the Tor process.
    pub async fn take_ownership(&mut self) -> Result<()> {
        let reply = self.send_command("TAKEOWNERSHIP\r\n").await?;
        reply.into_result()?;
        Ok(())
    }

    /// Drop ownership of the Tor process.
    pub async fn drop_ownership(&mut self) -> Result<()> {
        let reply = self.send_command("DROPOWNERSHIP\r\n").await?;
        reply.into_result()?;
        Ok(())
    }

    /// Drop all guard nodes.
    pub async fn drop_guards(&mut self) -> Result<()> {
        let reply = self.send_command("DROPGUARDS\r\n").await?;
        reply.into_result()?;
        Ok(())
    }

    /// Create a new onion service.
    pub async fn add_onion(
        &mut self,
        ports: &[(u16, Option<&str>)],
        key: Option<&str>,
        flags: &[&str],
    ) -> Result<OnionServiceInfo> {
        let mut args = Vec::new();

        // Key type
        if let Some(key) = key {
            args.push(key.to_string());
        } else {
            args.push("NEW:BEST".to_string());
        }

        // Flags
        if !flags.is_empty() {
            args.push(format!("Flags={}", flags.join(",")));
        }

        // Ports
        for (virt_port, target) in ports {
            if let Some(target) = target {
                args.push(format!("Port={},{}", virt_port, target));
            } else {
                args.push(format!("Port={}", virt_port));
            }
        }

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let cmd = format_command("ADD_ONION", &arg_refs);
        let reply = self.send_command(&cmd).await?;
        let reply = reply.into_result()?;

        let mut service_id = String::new();
        let mut private_key = None;

        for line in &reply.lines {
            if let Some(id) = line.text.strip_prefix("ServiceID=") {
                service_id = id.to_string();
            } else if let Some(key) = line.text.strip_prefix("PrivateKey=") {
                private_key = Some(key.to_string());
            }
        }

        Ok(OnionServiceInfo {
            address: OnionAddress::new(service_id),
            private_key,
        })
    }

    /// Delete an onion service.
    pub async fn del_onion(&mut self, service_id: &str) -> Result<()> {
        let cmd = format_command("DEL_ONION", &[service_id]);
        let reply = self.send_command(&cmd).await?;
        reply.into_result()?;
        Ok(())
    }

    /// Close the connection.
    pub async fn quit(&mut self) -> Result<()> {
        let _ = self.send_command("QUIT\r\n").await;
        Ok(())
    }

    /// Read the next event (after SETEVENTS has been called).
    pub async fn read_event(&mut self) -> Result<Event> {
        let reply = self.read_reply().await?;

        if !reply.is_async_event() {
            return Err(TorControlError::ProtocolError(
                "Expected async event".to_string(),
            ));
        }

        let text = reply.first_line();
        let mut parts = text.splitn(2, ' ');
        let event_type = parts.next().unwrap_or("");
        let data = parts.next().unwrap_or("");

        Ok(parse_event(event_type, data))
    }
}

/// Information about a circuit.
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    /// Circuit ID.
    pub id: CircuitId,
    /// Circuit status.
    pub status: CircuitStatus,
    /// Path of relays.
    pub path: Vec<ServerSpec>,
}

/// Information about a stream.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream ID.
    pub id: StreamId,
    /// Stream status.
    pub status: StreamStatus,
    /// Circuit ID.
    pub circuit_id: CircuitId,
    /// Target address:port.
    pub target: String,
}

/// Information about a created onion service.
#[derive(Debug, Clone)]
pub struct OnionServiceInfo {
    /// The onion address.
    pub address: OnionAddress,
    /// The private key (if generated and not discarded).
    pub private_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Requires a running Tor instance"]
    async fn test_connect_and_auth() {
        let mut client = TorClient::connect_default().await.unwrap();
        client.auto_authenticate().await.unwrap();

        let version = client.get_version().await.unwrap();
        println!("Connected to Tor {}", version);
    }
}
