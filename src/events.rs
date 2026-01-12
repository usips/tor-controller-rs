//! Asynchronous events from Tor.
//!
//! This module defines the events that Tor can send asynchronously
//! after a SETEVENTS command has been issued.

use crate::protocol::parse_key_value_pairs;
use crate::types::*;
use std::collections::HashMap;
use std::str::FromStr;

/// Event types that can be subscribed to with SETEVENTS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    /// Circuit status changed.
    Circ,
    /// Stream status changed.
    Stream,
    /// OR connection status changed.
    OrConn,
    /// Bandwidth used in the last second.
    Bw,
    /// Debug log message.
    Debug,
    /// Info log message.
    Info,
    /// Notice log message.
    Notice,
    /// Warning log message.
    Warn,
    /// Error log message.
    Error,
    /// New descriptors available.
    NewDesc,
    /// New address mapping.
    AddrMap,
    /// Descriptors uploaded to us (directory authority).
    AuthDirNewDescs,
    /// Our descriptor changed.
    DescChanged,
    /// General status event.
    StatusGeneral,
    /// Client status event.
    StatusClient,
    /// Server status event.
    StatusServer,
    /// Guard node set changed.
    Guard,
    /// Network status changed.
    Ns,
    /// Stream bandwidth.
    StreamBw,
    /// Clients seen (bridge only).
    ClientsSeen,
    /// New consensus arrived.
    NewConsensus,
    /// Build timeout set.
    BuildTimeoutSet,
    /// Signal received.
    Signal,
    /// Configuration changed.
    ConfChanged,
    /// Minor circuit status change.
    CircMinor,
    /// Pluggable transport launched.
    TransportLaunched,
    /// Connection bandwidth.
    ConnBw,
    /// Circuit bandwidth.
    CircBw,
    /// Cell stats.
    CellStats,
    /// Token bucket empty.
    TbEmpty,
    /// Hidden service descriptor event.
    HsDesc,
    /// Hidden service descriptor content.
    HsDescContent,
    /// Network liveness changed.
    NetworkLiveness,
    /// Pluggable transport log.
    PtLog,
    /// Pluggable transport status.
    PtStatus,
}

impl EventType {
    /// Get the event name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Circ => "CIRC",
            EventType::Stream => "STREAM",
            EventType::OrConn => "ORCONN",
            EventType::Bw => "BW",
            EventType::Debug => "DEBUG",
            EventType::Info => "INFO",
            EventType::Notice => "NOTICE",
            EventType::Warn => "WARN",
            EventType::Error => "ERR",
            EventType::NewDesc => "NEWDESC",
            EventType::AddrMap => "ADDRMAP",
            EventType::AuthDirNewDescs => "AUTHDIR_NEWDESCS",
            EventType::DescChanged => "DESCCHANGED",
            EventType::StatusGeneral => "STATUS_GENERAL",
            EventType::StatusClient => "STATUS_CLIENT",
            EventType::StatusServer => "STATUS_SERVER",
            EventType::Guard => "GUARD",
            EventType::Ns => "NS",
            EventType::StreamBw => "STREAM_BW",
            EventType::ClientsSeen => "CLIENTS_SEEN",
            EventType::NewConsensus => "NEWCONSENSUS",
            EventType::BuildTimeoutSet => "BUILDTIMEOUT_SET",
            EventType::Signal => "SIGNAL",
            EventType::ConfChanged => "CONF_CHANGED",
            EventType::CircMinor => "CIRC_MINOR",
            EventType::TransportLaunched => "TRANSPORT_LAUNCHED",
            EventType::ConnBw => "CONN_BW",
            EventType::CircBw => "CIRC_BW",
            EventType::CellStats => "CELL_STATS",
            EventType::TbEmpty => "TB_EMPTY",
            EventType::HsDesc => "HS_DESC",
            EventType::HsDescContent => "HS_DESC_CONTENT",
            EventType::NetworkLiveness => "NETWORK_LIVENESS",
            EventType::PtLog => "PT_LOG",
            EventType::PtStatus => "PT_STATUS",
        }
    }
}

impl FromStr for EventType {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "CIRC" => Ok(EventType::Circ),
            "STREAM" => Ok(EventType::Stream),
            "ORCONN" => Ok(EventType::OrConn),
            "BW" => Ok(EventType::Bw),
            "DEBUG" => Ok(EventType::Debug),
            "INFO" => Ok(EventType::Info),
            "NOTICE" => Ok(EventType::Notice),
            "WARN" => Ok(EventType::Warn),
            "ERR" => Ok(EventType::Error),
            "NEWDESC" => Ok(EventType::NewDesc),
            "ADDRMAP" => Ok(EventType::AddrMap),
            "AUTHDIR_NEWDESCS" => Ok(EventType::AuthDirNewDescs),
            "DESCCHANGED" => Ok(EventType::DescChanged),
            "STATUS_GENERAL" => Ok(EventType::StatusGeneral),
            "STATUS_CLIENT" => Ok(EventType::StatusClient),
            "STATUS_SERVER" | "STATUS_SEVER" => Ok(EventType::StatusServer),
            "GUARD" => Ok(EventType::Guard),
            "NS" => Ok(EventType::Ns),
            "STREAM_BW" => Ok(EventType::StreamBw),
            "CLIENTS_SEEN" => Ok(EventType::ClientsSeen),
            "NEWCONSENSUS" => Ok(EventType::NewConsensus),
            "BUILDTIMEOUT_SET" => Ok(EventType::BuildTimeoutSet),
            "SIGNAL" => Ok(EventType::Signal),
            "CONF_CHANGED" => Ok(EventType::ConfChanged),
            "CIRC_MINOR" => Ok(EventType::CircMinor),
            "TRANSPORT_LAUNCHED" => Ok(EventType::TransportLaunched),
            "CONN_BW" => Ok(EventType::ConnBw),
            "CIRC_BW" => Ok(EventType::CircBw),
            "CELL_STATS" => Ok(EventType::CellStats),
            "TB_EMPTY" => Ok(EventType::TbEmpty),
            "HS_DESC" => Ok(EventType::HsDesc),
            "HS_DESC_CONTENT" => Ok(EventType::HsDescContent),
            "NETWORK_LIVENESS" => Ok(EventType::NetworkLiveness),
            "PT_LOG" => Ok(EventType::PtLog),
            "PT_STATUS" => Ok(EventType::PtStatus),
            other => Err(crate::error::TorControlError::ParseError(format!(
                "Unknown event type: {}",
                other
            ))),
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A parsed asynchronous event from Tor.
#[derive(Debug, Clone)]
pub enum Event {
    /// Circuit status changed.
    CircuitStatus(CircuitEvent),
    /// Stream status changed.
    StreamStatus(StreamEvent),
    /// OR connection status changed.
    OrConnStatus(OrConnEvent),
    /// Bandwidth used.
    Bandwidth(BandwidthEvent),
    /// Log message.
    Log(LogEvent),
    /// Address mapping changed.
    AddressMap(AddressMapEvent),
    /// New descriptors available.
    NewDescriptors(Vec<String>),
    /// Our descriptor changed.
    DescriptorChanged,
    /// Status event.
    Status(StatusEvent),
    /// Guard changed.
    Guard(GuardEvent),
    /// Network status changed.
    NetworkStatus(String),
    /// Stream bandwidth.
    StreamBandwidth(StreamBandwidthEvent),
    /// New consensus arrived.
    NewConsensus(String),
    /// Build timeout set.
    BuildTimeoutSet(BuildTimeoutEvent),
    /// Signal received.
    Signal(String),
    /// Configuration changed.
    ConfigChanged(Vec<(String, Option<String>)>),
    /// Network liveness changed.
    NetworkLiveness(bool),
    /// Hidden service descriptor event.
    HsDescriptor(HsDescEvent),
    /// Unknown or unparsed event.
    Unknown {
        /// The event type string.
        event_type: String,
        /// The raw event data.
        data: String,
    },
}

/// Circuit status event.
#[derive(Debug, Clone)]
pub struct CircuitEvent {
    /// Circuit ID.
    pub circuit_id: CircuitId,
    /// Circuit status.
    pub status: CircuitStatus,
    /// Path of relays.
    pub path: Vec<ServerSpec>,
    /// Build flags.
    pub build_flags: Vec<String>,
    /// Circuit purpose.
    pub purpose: Option<CircuitPurpose>,
    /// Hidden service state.
    pub hs_state: Option<String>,
    /// Rendezvous query address.
    pub rend_query: Option<String>,
    /// Time created.
    pub time_created: Option<String>,
    /// Reason for failure/closure.
    pub reason: Option<String>,
    /// Remote reason for failure/closure.
    pub remote_reason: Option<String>,
}

/// Stream status event.
#[derive(Debug, Clone)]
pub struct StreamEvent {
    /// Stream ID.
    pub stream_id: StreamId,
    /// Stream status.
    pub status: StreamStatus,
    /// Circuit ID (0 if unattached).
    pub circuit_id: CircuitId,
    /// Target address and port.
    pub target: String,
    /// Reason for failure/closure.
    pub reason: Option<String>,
    /// Source address.
    pub source_addr: Option<String>,
    /// Stream purpose.
    pub purpose: Option<String>,
}

/// OR connection status event.
#[derive(Debug, Clone)]
pub struct OrConnEvent {
    /// Target (LongName or address:port).
    pub target: String,
    /// Connection status.
    pub status: OrConnStatus,
    /// Reason for failure/closure.
    pub reason: Option<String>,
    /// Number of circuits.
    pub num_circuits: Option<u32>,
    /// Connection ID.
    pub conn_id: Option<u64>,
}

/// Bandwidth event.
#[derive(Debug, Clone, Copy)]
pub struct BandwidthEvent {
    /// Bytes read in the last second.
    pub bytes_read: u64,
    /// Bytes written in the last second.
    pub bytes_written: u64,
}

/// Log message event.
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// Log severity.
    pub severity: LogSeverity,
    /// Log message.
    pub message: String,
}

/// Log severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSeverity {
    /// Debug level.
    Debug,
    /// Info level.
    Info,
    /// Notice level.
    Notice,
    /// Warning level.
    Warn,
    /// Error level.
    Error,
}

impl LogSeverity {
    /// Get the severity level as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogSeverity::Debug => "DEBUG",
            LogSeverity::Info => "INFO",
            LogSeverity::Notice => "NOTICE",
            LogSeverity::Warn => "WARN",
            LogSeverity::Error => "ERR",
        }
    }
}

impl FromStr for LogSeverity {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "DEBUG" => Ok(LogSeverity::Debug),
            "INFO" => Ok(LogSeverity::Info),
            "NOTICE" => Ok(LogSeverity::Notice),
            "WARN" => Ok(LogSeverity::Warn),
            "ERR" => Ok(LogSeverity::Error),
            other => Err(crate::error::TorControlError::ParseError(format!(
                "Unknown log severity: {}",
                other
            ))),
        }
    }
}

/// Address mapping event.
#[derive(Debug, Clone)]
pub struct AddressMapEvent {
    /// Original address.
    pub original: String,
    /// New address.
    pub new: String,
    /// Expiry time.
    pub expiry: Option<String>,
    /// Error if any.
    pub error: Option<String>,
}

/// Status event.
#[derive(Debug, Clone)]
pub struct StatusEvent {
    /// Status type.
    pub status_type: StatusType,
    /// Severity.
    pub severity: StatusSeverity,
    /// Action.
    pub action: String,
    /// Additional arguments.
    pub arguments: HashMap<String, String>,
}

/// Status event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusType {
    /// General status.
    General,
    /// Client status.
    Client,
    /// Server status.
    Server,
}

impl StatusType {
    /// Get the status type as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            StatusType::General => "GENERAL",
            StatusType::Client => "CLIENT",
            StatusType::Server => "SERVER",
        }
    }
}

/// Status event severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusSeverity {
    /// Notice level.
    Notice,
    /// Warning level.
    Warn,
    /// Error level.
    Error,
}

impl StatusSeverity {
    /// Get the severity level as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            StatusSeverity::Notice => "NOTICE",
            StatusSeverity::Warn => "WARN",
            StatusSeverity::Error => "ERR",
        }
    }
}

impl FromStr for StatusSeverity {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "NOTICE" => Ok(StatusSeverity::Notice),
            "WARN" => Ok(StatusSeverity::Warn),
            "ERR" => Ok(StatusSeverity::Error),
            other => Err(crate::error::TorControlError::ParseError(format!(
                "Unknown status severity: {}",
                other
            ))),
        }
    }
}

/// Guard event.
#[derive(Debug, Clone)]
pub struct GuardEvent {
    /// Guard type.
    pub guard_type: String,
    /// Guard name.
    pub name: String,
    /// Guard status.
    pub status: String,
}

/// Stream bandwidth event.
#[derive(Debug, Clone)]
pub struct StreamBandwidthEvent {
    /// Stream ID.
    pub stream_id: StreamId,
    /// Bytes written.
    pub bytes_written: u64,
    /// Bytes read.
    pub bytes_read: u64,
}

/// Build timeout event.
#[derive(Debug, Clone)]
pub struct BuildTimeoutEvent {
    /// Event type.
    pub event_type: String,
    /// Total times.
    pub total_times: Option<u32>,
    /// Timeout in milliseconds.
    pub timeout_ms: Option<u32>,
}

/// Hidden service descriptor event.
#[derive(Debug, Clone)]
pub struct HsDescEvent {
    /// Action.
    pub action: String,
    /// Hidden service address.
    pub address: String,
    /// Authentication type.
    pub auth_type: String,
    /// HSDir.
    pub hs_dir: String,
    /// Descriptor ID.
    pub descriptor_id: Option<String>,
    /// Reason for failure.
    pub reason: Option<String>,
}

/// Parse an event from raw event text.
pub fn parse_event(event_type: &str, text: &str) -> Event {
    match event_type.to_uppercase().as_str() {
        "CIRC" => parse_circuit_event(text),
        "STREAM" => parse_stream_event(text),
        "ORCONN" => parse_orconn_event(text),
        "BW" => parse_bandwidth_event(text),
        "DEBUG" | "INFO" | "NOTICE" | "WARN" | "ERR" => parse_log_event(event_type, text),
        "ADDRMAP" => parse_addrmap_event(text),
        "NETWORK_LIVENESS" => parse_network_liveness(text),
        _ => Event::Unknown {
            event_type: event_type.to_string(),
            data: text.to_string(),
        },
    }
}

fn parse_circuit_event(text: &str) -> Event {
    let parts: Vec<&str> = text.splitn(4, ' ').collect();

    let circuit_id = parts
        .first()
        .and_then(|s| s.parse().ok())
        .map(CircuitId)
        .unwrap_or(CircuitId(0));

    let status = parts
        .get(1)
        .and_then(|s| CircuitStatus::from_str(s).ok())
        .unwrap_or(CircuitStatus::Unknown);

    let path = parts
        .get(2)
        .map(|s| {
            s.split(',')
                .filter_map(|p| ServerSpec::from_str(p).ok())
                .collect()
        })
        .unwrap_or_default();

    let rest = parts.get(3).unwrap_or(&"");
    let kv = parse_key_value_pairs(rest);

    Event::CircuitStatus(CircuitEvent {
        circuit_id,
        status,
        path,
        build_flags: kv
            .get("BUILD_FLAGS")
            .map(|s| s.split(',').map(String::from).collect())
            .unwrap_or_default(),
        purpose: kv
            .get("PURPOSE")
            .and_then(|s| CircuitPurpose::from_str(s).ok()),
        hs_state: kv.get("HS_STATE").cloned(),
        rend_query: kv.get("REND_QUERY").cloned(),
        time_created: kv.get("TIME_CREATED").cloned(),
        reason: kv.get("REASON").cloned(),
        remote_reason: kv.get("REMOTE_REASON").cloned(),
    })
}

fn parse_stream_event(text: &str) -> Event {
    let parts: Vec<&str> = text.splitn(5, ' ').collect();

    let stream_id = parts
        .first()
        .and_then(|s| s.parse().ok())
        .map(StreamId)
        .unwrap_or(StreamId(0));

    let status = parts
        .get(1)
        .and_then(|s| StreamStatus::from_str(s).ok())
        .unwrap_or(StreamStatus::Unknown);

    let circuit_id = parts
        .get(2)
        .and_then(|s| s.parse().ok())
        .map(CircuitId)
        .unwrap_or(CircuitId(0));

    let target = parts.get(3).unwrap_or(&"").to_string();

    let rest = parts.get(4).unwrap_or(&"");
    let kv = parse_key_value_pairs(rest);

    Event::StreamStatus(StreamEvent {
        stream_id,
        status,
        circuit_id,
        target,
        reason: kv.get("REASON").cloned(),
        source_addr: kv.get("SOURCE_ADDR").cloned(),
        purpose: kv.get("PURPOSE").cloned(),
    })
}

fn parse_orconn_event(text: &str) -> Event {
    let parts: Vec<&str> = text.splitn(3, ' ').collect();

    let target = parts.first().unwrap_or(&"").to_string();
    let status = parts
        .get(1)
        .and_then(|s| OrConnStatus::from_str(s).ok())
        .unwrap_or(OrConnStatus::Unknown);

    let rest = parts.get(2).unwrap_or(&"");
    let kv = parse_key_value_pairs(rest);

    Event::OrConnStatus(OrConnEvent {
        target,
        status,
        reason: kv.get("REASON").cloned(),
        num_circuits: kv.get("NCIRCS").and_then(|s| s.parse().ok()),
        conn_id: kv.get("ID").and_then(|s| s.parse().ok()),
    })
}

fn parse_bandwidth_event(text: &str) -> Event {
    let parts: Vec<&str> = text.split_whitespace().collect();

    let bytes_read = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let bytes_written = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    Event::Bandwidth(BandwidthEvent {
        bytes_read,
        bytes_written,
    })
}

fn parse_log_event(severity: &str, text: &str) -> Event {
    let severity = LogSeverity::from_str(severity).unwrap_or(LogSeverity::Notice);

    Event::Log(LogEvent {
        severity,
        message: text.to_string(),
    })
}

fn parse_addrmap_event(text: &str) -> Event {
    let parts: Vec<&str> = text.splitn(4, ' ').collect();

    let original = parts.first().unwrap_or(&"").to_string();
    let new = parts.get(1).unwrap_or(&"").to_string();
    let expiry = parts.get(2).map(|s| s.trim_matches('"').to_string());

    let rest = parts.get(3).unwrap_or(&"");
    let kv = parse_key_value_pairs(rest);

    Event::AddressMap(AddressMapEvent {
        original,
        new,
        expiry,
        error: kv.get("error").cloned(),
    })
}

fn parse_network_liveness(text: &str) -> Event {
    let is_up = text.trim().eq_ignore_ascii_case("UP");
    Event::NetworkLiveness(is_up)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_parsing() {
        assert_eq!(EventType::from_str("CIRC").unwrap(), EventType::Circ);
        assert_eq!(EventType::from_str("BW").unwrap(), EventType::Bw);
        assert!(EventType::from_str("UNKNOWN_EVENT").is_err());
    }

    #[test]
    fn test_bandwidth_event_parsing() {
        match parse_event("BW", "1234 5678") {
            Event::Bandwidth(bw) => {
                assert_eq!(bw.bytes_read, 1234);
                assert_eq!(bw.bytes_written, 5678);
            }
            _ => panic!("Expected Bandwidth event"),
        }
    }

    #[test]
    fn test_network_liveness_parsing() {
        match parse_event("NETWORK_LIVENESS", "UP") {
            Event::NetworkLiveness(is_up) => assert!(is_up),
            _ => panic!("Expected NetworkLiveness event"),
        }

        match parse_event("NETWORK_LIVENESS", "DOWN") {
            Event::NetworkLiveness(is_up) => assert!(!is_up),
            _ => panic!("Expected NetworkLiveness event"),
        }
    }

    #[test]
    fn test_circuit_event_parsing() {
        let event = parse_event(
            "CIRC",
            "123 BUILT $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~Guard,$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~Middle PURPOSE=GENERAL",
        );
        match event {
            Event::CircuitStatus(circ) => {
                assert_eq!(circ.circuit_id, CircuitId(123));
                assert_eq!(circ.status, CircuitStatus::Built);
                assert_eq!(circ.path.len(), 2);
                assert_eq!(circ.purpose, Some(CircuitPurpose::General));
            }
            _ => panic!("Expected CircuitStatus event"),
        }
    }

    #[test]
    fn test_circuit_event_minimal() {
        let event = parse_event("CIRC", "1 LAUNCHED");
        match event {
            Event::CircuitStatus(circ) => {
                assert_eq!(circ.circuit_id, CircuitId(1));
                assert_eq!(circ.status, CircuitStatus::Launched);
                assert!(circ.path.is_empty());
            }
            _ => panic!("Expected CircuitStatus event"),
        }
    }

    #[test]
    fn test_circuit_event_with_reason() {
        let event = parse_event("CIRC", "5 FAILED $FP~name REASON=TIMEOUT");
        match event {
            Event::CircuitStatus(circ) => {
                assert_eq!(circ.circuit_id, CircuitId(5));
                assert_eq!(circ.status, CircuitStatus::Failed);
                assert_eq!(circ.reason, Some("TIMEOUT".to_string()));
            }
            _ => panic!("Expected CircuitStatus event"),
        }
    }

    #[test]
    fn test_stream_event_parsing() {
        let event = parse_event(
            "STREAM",
            "42 SUCCEEDED 10 www.example.com:443 PURPOSE=DIR_FETCH",
        );
        match event {
            Event::StreamStatus(stream) => {
                assert_eq!(stream.stream_id, StreamId(42));
                assert_eq!(stream.status, StreamStatus::Succeeded);
                assert_eq!(stream.circuit_id, CircuitId(10));
                assert_eq!(stream.target, "www.example.com:443");
                assert_eq!(stream.purpose, Some("DIR_FETCH".to_string()));
            }
            _ => panic!("Expected StreamStatus event"),
        }
    }

    #[test]
    fn test_orconn_event_parsing() {
        let event = parse_event(
            "ORCONN",
            "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~Guard CONNECTED NCIRCS=3",
        );
        match event {
            Event::OrConnStatus(conn) => {
                assert_eq!(conn.status, OrConnStatus::Connected);
                assert_eq!(conn.num_circuits, Some(3));
            }
            _ => panic!("Expected OrConnStatus event"),
        }
    }

    #[test]
    fn test_log_event_parsing() {
        let event = parse_event("NOTICE", "Bootstrapped 100%: Done");
        match event {
            Event::Log(log) => {
                assert_eq!(log.severity, LogSeverity::Notice);
                assert_eq!(log.message, "Bootstrapped 100%: Done");
            }
            _ => panic!("Expected Log event"),
        }
    }

    #[test]
    fn test_log_event_severities() {
        for (sev_str, expected) in [
            ("DEBUG", LogSeverity::Debug),
            ("INFO", LogSeverity::Info),
            ("NOTICE", LogSeverity::Notice),
            ("WARN", LogSeverity::Warn),
            ("ERR", LogSeverity::Error),
        ] {
            let event = parse_event(sev_str, "test message");
            match event {
                Event::Log(log) => assert_eq!(log.severity, expected),
                _ => panic!("Expected Log event for {}", sev_str),
            }
        }
    }

    #[test]
    fn test_addrmap_event_parsing() {
        let event = parse_event("ADDRMAP", "www.example.com 1.2.3.4 \"2024-01-01 12:00:00\"");
        match event {
            Event::AddressMap(map) => {
                assert_eq!(map.original, "www.example.com");
                assert_eq!(map.new, "1.2.3.4");
                assert!(map.expiry.is_some());
            }
            _ => panic!("Expected AddressMap event"),
        }
    }

    #[test]
    fn test_unknown_event() {
        let event = parse_event("TOTALLY_UNKNOWN_EVENT", "some data");
        match event {
            Event::Unknown { event_type, data } => {
                assert_eq!(event_type, "TOTALLY_UNKNOWN_EVENT");
                assert_eq!(data, "some data");
            }
            _ => panic!("Expected Unknown event"),
        }
    }

    #[test]
    fn test_event_type_as_str() {
        assert_eq!(EventType::Circ.as_str(), "CIRC");
        assert_eq!(EventType::Bw.as_str(), "BW");
        assert_eq!(EventType::StatusClient.as_str(), "STATUS_CLIENT");
        assert_eq!(EventType::NetworkLiveness.as_str(), "NETWORK_LIVENESS");
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(format!("{}", EventType::Circ), "CIRC");
        assert_eq!(format!("{}", EventType::HsDesc), "HS_DESC");
    }

    #[test]
    fn test_log_severity_as_str() {
        assert_eq!(LogSeverity::Debug.as_str(), "DEBUG");
        assert_eq!(LogSeverity::Error.as_str(), "ERR");
    }

    #[test]
    fn test_status_severity_parsing() {
        assert_eq!(
            StatusSeverity::from_str("NOTICE").unwrap(),
            StatusSeverity::Notice
        );
        assert_eq!(
            StatusSeverity::from_str("WARN").unwrap(),
            StatusSeverity::Warn
        );
        assert_eq!(
            StatusSeverity::from_str("ERR").unwrap(),
            StatusSeverity::Error
        );
        assert!(StatusSeverity::from_str("UNKNOWN").is_err());
    }

    #[test]
    fn test_status_type_as_str() {
        assert_eq!(StatusType::General.as_str(), "GENERAL");
        assert_eq!(StatusType::Client.as_str(), "CLIENT");
        assert_eq!(StatusType::Server.as_str(), "SERVER");
    }
}
