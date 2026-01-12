//! Core types used throughout the Tor Control library.
//!
//! This module contains fundamental types for representing Tor entities
//! like circuits, streams, configuration options, and more.

use std::fmt;
use std::str::FromStr;

/// A circuit identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId(pub u64);

impl fmt::Display for CircuitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CircuitId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CircuitId(s.parse()?))
    }
}

/// A stream identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for StreamId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(StreamId(s.parse()?))
    }
}

/// A connection identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A relay fingerprint (40 hex characters, optionally prefixed with $).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Create a new Fingerprint from a hex string.
    pub fn new(fingerprint: impl Into<String>) -> Self {
        let mut fp = fingerprint.into();
        // Remove $ prefix if present
        if fp.starts_with('$') {
            fp = fp[1..].to_string();
        }
        // Normalize to uppercase
        Fingerprint(fp.to_uppercase())
    }

    /// Get the fingerprint as a string (without $ prefix).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the fingerprint with $ prefix.
    pub fn with_prefix(&self) -> String {
        format!("${}", self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Fingerprint {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches('$');
        if s.len() != 40 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(crate::error::TorControlError::ParseError(
                "Invalid fingerprint: must be 40 hex characters".to_string(),
            ));
        }
        Ok(Fingerprint::new(s))
    }
}

/// A relay specification - can be nickname, fingerprint, or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSpec {
    /// Just a nickname.
    Nickname(String),
    /// Just a fingerprint.
    Fingerprint(Fingerprint),
    /// Fingerprint with associated nickname.
    LongName {
        /// The relay fingerprint.
        fingerprint: Fingerprint,
        /// The relay nickname.
        nickname: String,
    },
}

impl fmt::Display for ServerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerSpec::Nickname(n) => write!(f, "{}", n),
            ServerSpec::Fingerprint(fp) => write!(f, "${}", fp),
            ServerSpec::LongName {
                fingerprint,
                nickname,
            } => write!(f, "${}~{}", fingerprint, nickname),
        }
    }
}

impl FromStr for ServerSpec {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix('$') {
            // Fingerprint or LongName
            if let Some(sep_pos) = rest.find(['~', '=']) {
                let fp = Fingerprint::from_str(&rest[..sep_pos])?;
                let nickname = rest[sep_pos + 1..].to_string();
                Ok(ServerSpec::LongName {
                    fingerprint: fp,
                    nickname,
                })
            } else {
                Ok(ServerSpec::Fingerprint(Fingerprint::from_str(rest)?))
            }
        } else {
            // Just a nickname
            Ok(ServerSpec::Nickname(s.to_string()))
        }
    }
}

/// Status of a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitStatus {
    /// Circuit ID assigned to new circuit.
    Launched,
    /// All hops finished, can now accept streams.
    Built,
    /// All hops finished, waiting to see if a circuit with a better guard will be usable.
    GuardWait,
    /// One more hop has been completed.
    Extended,
    /// Circuit closed (was not built).
    Failed,
    /// Circuit closed (was built).
    Closed,
    /// Unknown status.
    Unknown,
}

impl FromStr for CircuitStatus {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "LAUNCHED" => CircuitStatus::Launched,
            "BUILT" => CircuitStatus::Built,
            "GUARD_WAIT" => CircuitStatus::GuardWait,
            "EXTENDED" => CircuitStatus::Extended,
            "FAILED" => CircuitStatus::Failed,
            "CLOSED" => CircuitStatus::Closed,
            _ => CircuitStatus::Unknown,
        })
    }
}

impl fmt::Display for CircuitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CircuitStatus::Launched => "LAUNCHED",
            CircuitStatus::Built => "BUILT",
            CircuitStatus::GuardWait => "GUARD_WAIT",
            CircuitStatus::Extended => "EXTENDED",
            CircuitStatus::Failed => "FAILED",
            CircuitStatus::Closed => "CLOSED",
            CircuitStatus::Unknown => "UNKNOWN",
        };
        write!(f, "{}", s)
    }
}

/// Purpose of a circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitPurpose {
    /// General circuit for AP and/or directory request streams.
    General,
    /// Hidden service client-side introduction-point circuit.
    HsClientIntro,
    /// Hidden service client-side rendezvous circuit.
    HsClientRend,
    /// Hidden service service-side introduction-point circuit.
    HsServiceIntro,
    /// Hidden service service-side rendezvous circuit.
    HsServiceRend,
    /// Reachability-testing circuit.
    Testing,
    /// Circuit built by a controller.
    Controller,
    /// Circuit being kept around to see how long it takes.
    MeasureTimeout,
    /// Circuit created ahead of time for HS vanguards.
    HsVanguards,
    /// Circuit used to probe for path bias attacks.
    PathBiasTesting,
    /// Circuit held open to disguise its true close time.
    CircuitPadding,
    /// Unknown purpose.
    Unknown(String),
}

impl FromStr for CircuitPurpose {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "GENERAL" => CircuitPurpose::General,
            "HS_CLIENT_INTRO" => CircuitPurpose::HsClientIntro,
            "HS_CLIENT_REND" => CircuitPurpose::HsClientRend,
            "HS_SERVICE_INTRO" => CircuitPurpose::HsServiceIntro,
            "HS_SERVICE_REND" => CircuitPurpose::HsServiceRend,
            "TESTING" => CircuitPurpose::Testing,
            "CONTROLLER" => CircuitPurpose::Controller,
            "MEASURE_TIMEOUT" => CircuitPurpose::MeasureTimeout,
            "HS_VANGUARDS" => CircuitPurpose::HsVanguards,
            "PATH_BIAS_TESTING" => CircuitPurpose::PathBiasTesting,
            "CIRCUIT_PADDING" => CircuitPurpose::CircuitPadding,
            other => CircuitPurpose::Unknown(other.to_string()),
        })
    }
}

impl fmt::Display for CircuitPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CircuitPurpose::General => "GENERAL",
            CircuitPurpose::HsClientIntro => "HS_CLIENT_INTRO",
            CircuitPurpose::HsClientRend => "HS_CLIENT_REND",
            CircuitPurpose::HsServiceIntro => "HS_SERVICE_INTRO",
            CircuitPurpose::HsServiceRend => "HS_SERVICE_REND",
            CircuitPurpose::Testing => "TESTING",
            CircuitPurpose::Controller => "CONTROLLER",
            CircuitPurpose::MeasureTimeout => "MEASURE_TIMEOUT",
            CircuitPurpose::HsVanguards => "HS_VANGUARDS",
            CircuitPurpose::PathBiasTesting => "PATH_BIAS_TESTING",
            CircuitPurpose::CircuitPadding => "CIRCUIT_PADDING",
            CircuitPurpose::Unknown(s) => s.as_str(),
        };
        write!(f, "{}", s)
    }
}

/// Status of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStatus {
    /// New request to connect.
    New,
    /// New request to resolve an address.
    NewResolve,
    /// Address re-mapped to another.
    Remap,
    /// Sent a connect message along a circuit.
    SentConnect,
    /// Sent a resolve message along a circuit.
    SentResolve,
    /// Received a reply; stream established.
    Succeeded,
    /// Stream failed and not retriable.
    Failed,
    /// Stream closed.
    Closed,
    /// Detached from circuit; still retriable.
    Detached,
    /// Waiting for controller to use ATTACHSTREAM.
    ControllerWait,
    /// Unknown status.
    Unknown,
}

impl FromStr for StreamStatus {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "NEW" => StreamStatus::New,
            "NEWRESOLVE" => StreamStatus::NewResolve,
            "REMAP" => StreamStatus::Remap,
            "SENTCONNECT" => StreamStatus::SentConnect,
            "SENTRESOLVE" => StreamStatus::SentResolve,
            "SUCCEEDED" => StreamStatus::Succeeded,
            "FAILED" => StreamStatus::Failed,
            "CLOSED" => StreamStatus::Closed,
            "DETACHED" => StreamStatus::Detached,
            "CONTROLLER_WAIT" => StreamStatus::ControllerWait,
            _ => StreamStatus::Unknown,
        })
    }
}

/// Status of an OR connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrConnStatus {
    /// New incoming OR connection.
    New,
    /// New outgoing OR connection launched.
    Launched,
    /// OR connection is connected and handshake is done.
    Connected,
    /// Attempt to open the OR connection failed.
    Failed,
    /// OR connection closed.
    Closed,
    /// Unknown status.
    Unknown,
}

impl FromStr for OrConnStatus {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "NEW" => OrConnStatus::New,
            "LAUNCHED" => OrConnStatus::Launched,
            "CONNECTED" => OrConnStatus::Connected,
            "FAILED" => OrConnStatus::Failed,
            "CLOSED" => OrConnStatus::Closed,
            _ => OrConnStatus::Unknown,
        })
    }
}

/// A Tor signal that can be sent via the SIGNAL command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Reload: reload config items.
    Reload,
    /// Controlled shutdown.
    Shutdown,
    /// Dump stats.
    Dump,
    /// Switch all open logs to loglevel debug.
    Debug,
    /// Immediate shutdown.
    Halt,
    /// Switch to clean circuits.
    NewNym,
    /// Forget client-side cached IPs.
    ClearDnsCache,
    /// Make Tor dump an unscheduled Heartbeat message.
    Heartbeat,
    /// Tell Tor to become "dormant".
    Dormant,
    /// Tell Tor to stop being "dormant".
    Active,
}

impl Signal {
    /// Get the signal name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Signal::Reload => "RELOAD",
            Signal::Shutdown => "SHUTDOWN",
            Signal::Dump => "DUMP",
            Signal::Debug => "DEBUG",
            Signal::Halt => "HALT",
            Signal::NewNym => "NEWNYM",
            Signal::ClearDnsCache => "CLEARDNSCACHE",
            Signal::Heartbeat => "HEARTBEAT",
            Signal::Dormant => "DORMANT",
            Signal::Active => "ACTIVE",
        }
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Information about the Tor version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorVersion {
    /// The full version string.
    pub version_string: String,
    /// Major version number.
    pub major: u32,
    /// Minor version number.
    pub minor: u32,
    /// Micro version number.
    pub micro: u32,
    /// Patch version number.
    pub patch: u32,
}

impl FromStr for TorVersion {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let version_string = s.to_string();

        // Parse version like "0.4.8.10" or "Tor 0.4.8.10"
        let version_part = s
            .strip_prefix("Tor ")
            .unwrap_or(s)
            .split(|c: char| !c.is_ascii_digit() && c != '.')
            .next()
            .unwrap_or("");

        let parts: Vec<&str> = version_part.split('.').collect();

        let parse_num = |s: &str| -> u32 { s.parse().unwrap_or(0) };

        Ok(TorVersion {
            version_string,
            major: parts.first().map(|s| parse_num(s)).unwrap_or(0),
            minor: parts.get(1).map(|s| parse_num(s)).unwrap_or(0),
            micro: parts.get(2).map(|s| parse_num(s)).unwrap_or(0),
            patch: parts.get(3).map(|s| parse_num(s)).unwrap_or(0),
        })
    }
}

impl fmt::Display for TorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version_string)
    }
}

/// Bootstrap phase information.
#[derive(Debug, Clone)]
pub struct BootstrapStatus {
    /// Progress percentage (0-100).
    pub progress: u8,
    /// Short tag identifying the phase.
    pub tag: String,
    /// Human-readable summary of the phase.
    pub summary: String,
    /// Optional warning message if there's a problem.
    pub warning: Option<String>,
    /// Optional reason for the problem.
    pub reason: Option<String>,
    /// Recommendation on how to handle the status.
    pub recommendation: Option<String>,
}

/// Bandwidth information.
#[derive(Debug, Clone, Copy, Default)]
pub struct BandwidthStats {
    /// Bytes read.
    pub bytes_read: u64,
    /// Bytes written.
    pub bytes_written: u64,
}

/// Onion service address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OnionAddress {
    /// The address without the .onion suffix.
    address: String,
}

impl OnionAddress {
    /// Create a new onion address from a string.
    pub fn new(address: impl Into<String>) -> Self {
        let mut addr = address.into();
        // Remove .onion suffix if present
        if addr.ends_with(".onion") {
            addr = addr[..addr.len() - 6].to_string();
        }
        OnionAddress { address: addr }
    }

    /// Get the address without .onion suffix.
    pub fn as_str(&self) -> &str {
        &self.address
    }

    /// Get the service ID (same as address without .onion suffix).
    pub fn service_id(&self) -> &str {
        &self.address
    }

    /// Get the full address with .onion suffix.
    pub fn full_address(&self) -> String {
        format!("{}.onion", self.address)
    }

    /// Check if this is a v3 onion address (56 characters).
    pub fn is_v3(&self) -> bool {
        self.address.len() == 56
    }

    /// Check if this is a v2 onion address (16 characters, deprecated).
    pub fn is_v2(&self) -> bool {
        self.address.len() == 16
    }
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl FromStr for OnionAddress {
    type Err = crate::error::TorControlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(OnionAddress::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_parsing() {
        let fp = Fingerprint::from_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(fp.as_str(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        let fp2 = Fingerprint::from_str("$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
        assert_eq!(fp2.as_str(), "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        assert!(Fingerprint::from_str("tooshort").is_err());
    }

    #[test]
    fn test_server_spec_parsing() {
        let nick = ServerSpec::from_str("MyRelay").unwrap();
        assert!(matches!(nick, ServerSpec::Nickname(_)));

        let fp = ServerSpec::from_str("$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(matches!(fp, ServerSpec::Fingerprint(_)));

        let long =
            ServerSpec::from_str("$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~MyRelay").unwrap();
        assert!(matches!(long, ServerSpec::LongName { .. }));
    }

    #[test]
    fn test_onion_address() {
        let v3 =
            OnionAddress::new("exampleoniont2pqglbny66wpovyvao3ylc23eileodtevc4b75ikpad.onion");
        assert!(v3.is_v3());
        assert!(!v3.is_v2());

        let v2 = OnionAddress::new("exampleonion12");
        assert!(!v2.is_v3());
    }

    #[test]
    fn test_circuit_id_display() {
        let id = CircuitId(12345);
        assert_eq!(format!("{}", id), "12345");
    }

    #[test]
    fn test_circuit_id_from_str() {
        let id: CircuitId = "42".parse().unwrap();
        assert_eq!(id.0, 42);
    }

    #[test]
    fn test_stream_id_display() {
        let id = StreamId(999);
        assert_eq!(format!("{}", id), "999");
    }

    #[test]
    fn test_connection_id_display() {
        let id = ConnectionId(1);
        assert_eq!(format!("{}", id), "1");
    }

    #[test]
    fn test_fingerprint_with_prefix() {
        let fp = Fingerprint::new("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        assert_eq!(
            fp.with_prefix(),
            "$ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        );
    }

    #[test]
    fn test_fingerprint_lowercase_normalized() {
        let fp = Fingerprint::new("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        assert_eq!(fp.as_str(), "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD");
    }

    #[test]
    fn test_server_spec_display() {
        let nick = ServerSpec::Nickname("Guard".to_string());
        assert_eq!(format!("{}", nick), "Guard");

        let fp =
            ServerSpec::Fingerprint(Fingerprint::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert_eq!(
            format!("{}", fp),
            "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );

        let long = ServerSpec::LongName {
            fingerprint: Fingerprint::new("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            nickname: "Exit".to_string(),
        };
        assert_eq!(
            format!("{}", long),
            "$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~Exit"
        );
    }

    #[test]
    fn test_server_spec_with_equals() {
        let spec = ServerSpec::from_str("$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=Guard").unwrap();
        match spec {
            ServerSpec::LongName {
                fingerprint,
                nickname,
            } => {
                assert_eq!(
                    fingerprint.as_str(),
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                );
                assert_eq!(nickname, "Guard");
            }
            _ => panic!("Expected LongName"),
        }
    }

    #[test]
    fn test_circuit_status_display() {
        assert_eq!(format!("{}", CircuitStatus::Built), "BUILT");
        assert_eq!(format!("{}", CircuitStatus::Launched), "LAUNCHED");
        assert_eq!(format!("{}", CircuitStatus::Unknown), "UNKNOWN");
    }

    #[test]
    fn test_circuit_status_parsing_case_insensitive() {
        assert_eq!(
            CircuitStatus::from_str("built").unwrap(),
            CircuitStatus::Built
        );
        assert_eq!(
            CircuitStatus::from_str("BUILT").unwrap(),
            CircuitStatus::Built
        );
        assert_eq!(
            CircuitStatus::from_str("Built").unwrap(),
            CircuitStatus::Built
        );
    }

    #[test]
    fn test_circuit_purpose_display() {
        assert_eq!(format!("{}", CircuitPurpose::General), "GENERAL");
        assert_eq!(
            format!("{}", CircuitPurpose::HsClientRend),
            "HS_CLIENT_REND"
        );
        assert_eq!(
            format!("{}", CircuitPurpose::Unknown("CUSTOM".to_string())),
            "CUSTOM"
        );
    }

    #[test]
    fn test_circuit_purpose_all_variants() {
        let purposes = [
            ("GENERAL", CircuitPurpose::General),
            ("HS_CLIENT_INTRO", CircuitPurpose::HsClientIntro),
            ("HS_CLIENT_REND", CircuitPurpose::HsClientRend),
            ("HS_SERVICE_INTRO", CircuitPurpose::HsServiceIntro),
            ("HS_SERVICE_REND", CircuitPurpose::HsServiceRend),
            ("TESTING", CircuitPurpose::Testing),
            ("CONTROLLER", CircuitPurpose::Controller),
            ("MEASURE_TIMEOUT", CircuitPurpose::MeasureTimeout),
        ];
        for (s, expected) in purposes {
            assert_eq!(CircuitPurpose::from_str(s).unwrap(), expected);
        }
    }

    #[test]
    fn test_stream_status_all_variants() {
        let statuses = [
            ("NEW", StreamStatus::New),
            ("NEWRESOLVE", StreamStatus::NewResolve),
            ("REMAP", StreamStatus::Remap),
            ("SENTCONNECT", StreamStatus::SentConnect),
            ("SENTRESOLVE", StreamStatus::SentResolve),
            ("SUCCEEDED", StreamStatus::Succeeded),
            ("FAILED", StreamStatus::Failed),
            ("CLOSED", StreamStatus::Closed),
            ("DETACHED", StreamStatus::Detached),
            ("CONTROLLER_WAIT", StreamStatus::ControllerWait),
        ];
        for (s, expected) in statuses {
            assert_eq!(StreamStatus::from_str(s).unwrap(), expected);
        }
    }

    #[test]
    fn test_orconn_status_all_variants() {
        let statuses = [
            ("NEW", OrConnStatus::New),
            ("LAUNCHED", OrConnStatus::Launched),
            ("CONNECTED", OrConnStatus::Connected),
            ("FAILED", OrConnStatus::Failed),
            ("CLOSED", OrConnStatus::Closed),
        ];
        for (s, expected) in statuses {
            assert_eq!(OrConnStatus::from_str(s).unwrap(), expected);
        }
    }

    #[test]
    fn test_signal_as_str() {
        assert_eq!(Signal::Reload.as_str(), "RELOAD");
        assert_eq!(Signal::Shutdown.as_str(), "SHUTDOWN");
        assert_eq!(Signal::NewNym.as_str(), "NEWNYM");
        assert_eq!(Signal::ClearDnsCache.as_str(), "CLEARDNSCACHE");
    }

    #[test]
    fn test_signal_display() {
        assert_eq!(format!("{}", Signal::Heartbeat), "HEARTBEAT");
        assert_eq!(format!("{}", Signal::Dormant), "DORMANT");
    }

    #[test]
    fn test_tor_version_parsing() {
        let v = TorVersion::from_str("0.4.8.10").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 4);
        assert_eq!(v.micro, 8);
        assert_eq!(v.patch, 10);
    }

    #[test]
    fn test_tor_version_with_prefix() {
        let v = TorVersion::from_str("Tor 0.4.8.10").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 4);
    }

    #[test]
    fn test_tor_version_with_suffix() {
        let v = TorVersion::from_str("0.4.8.10-dev").unwrap();
        assert_eq!(v.patch, 10);
    }

    #[test]
    fn test_tor_version_display() {
        let v = TorVersion::from_str("0.4.8.10").unwrap();
        assert_eq!(format!("{}", v), "0.4.8.10");
    }

    #[test]
    fn test_onion_address_full() {
        let addr = OnionAddress::new("abc123");
        assert_eq!(addr.full_address(), "abc123.onion");
        assert_eq!(addr.service_id(), "abc123");
    }

    #[test]
    fn test_onion_address_from_str() {
        let addr: OnionAddress = "test.onion".parse().unwrap();
        assert_eq!(addr.as_str(), "test");
    }

    #[test]
    fn test_bandwidth_stats_default() {
        let stats = BandwidthStats::default();
        assert_eq!(stats.bytes_read, 0);
        assert_eq!(stats.bytes_written, 0);
    }
}
