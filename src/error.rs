//! Error types for the Tor Control Protocol library.
//!
//! This module provides comprehensive error handling for all operations
//! that can fail when communicating with a Tor control port.

use std::io;
use thiserror::Error;

/// The main error type for all Tor control operations.
#[derive(Error, Debug)]
pub enum TorControlError {
    /// I/O error occurred during communication.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Connection to Tor control port failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Authentication with Tor failed.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Command was rejected by Tor.
    #[error("Command rejected (code {code}): {message}")]
    CommandRejected {
        /// The status code returned by Tor.
        code: u16,
        /// The human-readable error message.
        message: String,
    },

    /// Protocol error - unexpected response format.
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Parsing error when interpreting Tor's response.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Timeout waiting for response.
    #[error("Operation timed out")]
    Timeout,

    /// The connection was closed unexpectedly.
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,

    /// Invalid argument provided to a command.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Feature not supported by this version of Tor.
    #[error("Feature not supported: {0}")]
    NotSupported(String),

    /// Event handling error.
    #[error("Event error: {0}")]
    EventError(String),
}

/// Result type alias for Tor control operations.
pub type Result<T> = std::result::Result<T, TorControlError>;

/// Tor reply status codes as defined in the control-spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    /// 250 - OK
    Ok = 250,
    /// 251 - Operation was unnecessary
    OperationUnnecessary = 251,
    /// 252 - Resource exhausted (with additional info)
    ResourceExhaustedInfo = 252,
    /// 451 - Resource exhausted
    ResourceExhausted = 451,
    /// 500 - Syntax error: protocol
    SyntaxErrorProtocol = 500,
    /// 510 - Unrecognized command
    UnrecognizedCommand = 510,
    /// 511 - Unimplemented command
    UnimplementedCommand = 511,
    /// 512 - Syntax error in command argument
    SyntaxErrorArgument = 512,
    /// 513 - Unrecognized command argument
    UnrecognizedArgument = 513,
    /// 514 - Authentication required
    AuthenticationRequired = 514,
    /// 515 - Bad authentication
    BadAuthentication = 515,
    /// 550 - Unspecified Tor error
    UnspecifiedError = 550,
    /// 551 - Internal error
    InternalError = 551,
    /// 552 - Unrecognized entity
    UnrecognizedEntity = 552,
    /// 553 - Invalid configuration value
    InvalidConfigValue = 553,
    /// 554 - Invalid descriptor
    InvalidDescriptor = 554,
    /// 555 - Unmanaged entity
    UnmanagedEntity = 555,
    /// 650 - Asynchronous event notification
    AsyncEvent = 650,
    /// Unknown status code
    Unknown = 0,
}

impl StatusCode {
    /// Parse a status code from a u16 value.
    pub fn from_u16(code: u16) -> Self {
        match code {
            250 => StatusCode::Ok,
            251 => StatusCode::OperationUnnecessary,
            252 => StatusCode::ResourceExhaustedInfo,
            451 => StatusCode::ResourceExhausted,
            500 => StatusCode::SyntaxErrorProtocol,
            510 => StatusCode::UnrecognizedCommand,
            511 => StatusCode::UnimplementedCommand,
            512 => StatusCode::SyntaxErrorArgument,
            513 => StatusCode::UnrecognizedArgument,
            514 => StatusCode::AuthenticationRequired,
            515 => StatusCode::BadAuthentication,
            550 => StatusCode::UnspecifiedError,
            551 => StatusCode::InternalError,
            552 => StatusCode::UnrecognizedEntity,
            553 => StatusCode::InvalidConfigValue,
            554 => StatusCode::InvalidDescriptor,
            555 => StatusCode::UnmanagedEntity,
            650 => StatusCode::AsyncEvent,
            _ => StatusCode::Unknown,
        }
    }

    /// Check if this status code indicates success.
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            StatusCode::Ok | StatusCode::OperationUnnecessary | StatusCode::ResourceExhaustedInfo
        )
    }

    /// Check if this status code indicates an error.
    pub fn is_error(&self) -> bool {
        !self.is_success() && *self != StatusCode::AsyncEvent
    }

    /// Get the numeric value of this status code.
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

impl From<u16> for StatusCode {
    fn from(code: u16) -> Self {
        StatusCode::from_u16(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_parsing() {
        assert_eq!(StatusCode::from_u16(250), StatusCode::Ok);
        assert_eq!(StatusCode::from_u16(515), StatusCode::BadAuthentication);
        assert_eq!(StatusCode::from_u16(9999), StatusCode::Unknown);
    }

    #[test]
    fn test_status_code_success() {
        assert!(StatusCode::Ok.is_success());
        assert!(StatusCode::OperationUnnecessary.is_success());
        assert!(!StatusCode::BadAuthentication.is_success());
    }
}
