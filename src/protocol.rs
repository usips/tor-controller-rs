//! Protocol message parsing and formatting.
//!
//! This module handles the low-level protocol details for communicating
//! with Tor's control port, including message framing and parsing.

use crate::error::{Result, StatusCode, TorControlError};
use std::collections::HashMap;

/// A raw reply line from Tor.
#[derive(Debug, Clone)]
pub struct ReplyLine {
    /// The 3-digit status code.
    pub code: u16,
    /// The separator character: '-' for mid-reply, '+' for data, ' ' for end.
    pub separator: char,
    /// The text content of the line.
    pub text: String,
}

impl ReplyLine {
    /// Parse a reply line from a string.
    pub fn parse(line: &str) -> Result<Self> {
        if line.len() < 4 {
            return Err(TorControlError::ProtocolError(format!(
                "Reply line too short: '{}'",
                line
            )));
        }

        let code: u16 = line[..3].parse().map_err(|_| {
            TorControlError::ProtocolError(format!("Invalid status code in: '{}'", line))
        })?;

        let separator = line.chars().nth(3).ok_or_else(|| {
            TorControlError::ProtocolError(format!("Missing separator in: '{}'", line))
        })?;

        if !matches!(separator, ' ' | '-' | '+') {
            return Err(TorControlError::ProtocolError(format!(
                "Invalid separator '{}' in: '{}'",
                separator, line
            )));
        }

        let text = if line.len() > 4 {
            line[4..].to_string()
        } else {
            String::new()
        };

        Ok(ReplyLine {
            code,
            separator,
            text,
        })
    }

    /// Check if this is the final line of a reply.
    pub fn is_end(&self) -> bool {
        self.separator == ' '
    }

    /// Check if this is a data line (multi-line response).
    pub fn is_data(&self) -> bool {
        self.separator == '+'
    }

    /// Check if this is a mid-reply line.
    pub fn is_mid(&self) -> bool {
        self.separator == '-'
    }

    /// Get the status code as an enum.
    pub fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.code)
    }
}

/// A complete reply from Tor, potentially spanning multiple lines.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The status code for this reply.
    pub code: u16,
    /// All reply lines.
    pub lines: Vec<ReplyLine>,
    /// Any data associated with this reply (from '+' lines).
    pub data: Option<String>,
}

impl Reply {
    /// Create a new Reply from a list of reply lines.
    pub fn new(lines: Vec<ReplyLine>) -> Result<Self> {
        if lines.is_empty() {
            return Err(TorControlError::ProtocolError("Empty reply".to_string()));
        }

        let code = lines[0].code;
        let mut data = None;

        // Extract data from '+' lines
        for line in &lines {
            if line.is_data() {
                data = Some(line.text.clone());
            }
        }

        Ok(Reply { code, lines, data })
    }

    /// Get the status code as an enum.
    pub fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.code)
    }

    /// Check if this reply indicates success.
    pub fn is_success(&self) -> bool {
        self.status_code().is_success()
    }

    /// Get all text lines concatenated.
    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get the first line's text.
    pub fn first_line(&self) -> &str {
        self.lines.first().map(|l| l.text.as_str()).unwrap_or("")
    }

    /// Convert this reply into a Result, returning an error if the reply indicates failure.
    pub fn into_result(self) -> Result<Self> {
        if self.is_success() {
            Ok(self)
        } else {
            Err(TorControlError::CommandRejected {
                code: self.code,
                message: self.text(),
            })
        }
    }

    /// Check if this is an asynchronous event.
    pub fn is_async_event(&self) -> bool {
        self.code == 650
    }
}

/// Parse keyword=value pairs from a reply line.
pub fn parse_key_value_pairs(text: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut remaining = text;

    while !remaining.is_empty() {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }

        // Find the key
        let key_end = remaining.find('=').unwrap_or(remaining.len());
        if key_end == remaining.len() {
            break;
        }

        let key = remaining[..key_end].to_string();
        remaining = &remaining[key_end + 1..];

        // Parse the value
        let (value, rest) = if remaining.starts_with('"') {
            // Quoted string
            parse_quoted_string(remaining)
        } else {
            // Unquoted value
            let end = remaining.find(' ').unwrap_or(remaining.len());
            (remaining[..end].to_string(), &remaining[end..])
        };

        result.insert(key, value);
        remaining = rest;
    }

    result
}

/// Parse a quoted string, handling escape sequences.
fn parse_quoted_string(s: &str) -> (String, &str) {
    if !s.starts_with('"') {
        return (String::new(), s);
    }

    let mut result = String::new();
    let mut chars = s[1..].chars().peekable();
    let mut consumed = 1;

    while let Some(c) = chars.next() {
        consumed += c.len_utf8();
        if c == '"' {
            break;
        } else if c == '\\' {
            if let Some(&next) = chars.peek() {
                consumed += next.len_utf8();
                chars.next();
                match next {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    _ => result.push(next),
                }
            }
        } else {
            result.push(c);
        }
    }

    (result, &s[consumed..])
}

/// Quote a string for use in a Tor control command.
pub fn quote_string(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }

    // Check if quoting is needed
    let needs_quoting = s
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\' || !(' '..='~').contains(&c));

    if !needs_quoting && !s.contains(' ') {
        return s.to_string();
    }

    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');

    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }

    result.push('"');
    result
}

/// Format a command with arguments.
pub fn format_command(keyword: &str, args: &[&str]) -> String {
    let mut cmd = keyword.to_string();
    for arg in args {
        cmd.push(' ');
        cmd.push_str(arg);
    }
    cmd.push_str("\r\n");
    cmd
}

/// Format a multi-line command with data.
pub fn format_command_with_data(keyword: &str, args: &[&str], data: &str) -> String {
    let mut cmd = String::from("+");
    cmd.push_str(keyword);
    for arg in args {
        cmd.push(' ');
        cmd.push_str(arg);
    }
    cmd.push_str("\r\n");

    // Add data, escaping leading dots
    for line in data.lines() {
        if line.starts_with('.') {
            cmd.push('.');
        }
        cmd.push_str(line);
        cmd.push_str("\r\n");
    }

    cmd.push_str(".\r\n");
    cmd
}

/// Parse a data block (content after a '+' line until '.').
pub fn parse_data_block(lines: &[String]) -> String {
    let mut result = String::new();

    for line in lines {
        if line == "." {
            break;
        }

        // Remove leading dot escape
        let line = if line.starts_with("..") {
            &line[1..]
        } else {
            line.as_str()
        };

        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(line);
    }

    result
}

/// Parse an event name and its data from an async reply.
pub fn parse_async_event(reply: &Reply) -> Option<(String, HashMap<String, String>)> {
    if !reply.is_async_event() {
        return None;
    }

    let first_line = reply.first_line();
    let mut parts = first_line.splitn(2, ' ');

    let event_name = parts.next()?.to_string();
    let rest = parts.next().unwrap_or("");

    let data = parse_key_value_pairs(rest);

    Some((event_name, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_line_parsing() {
        let line = ReplyLine::parse("250 OK").unwrap();
        assert_eq!(line.code, 250);
        assert_eq!(line.separator, ' ');
        assert_eq!(line.text, "OK");
        assert!(line.is_end());

        let mid = ReplyLine::parse("250-version=0.4.8.10").unwrap();
        assert!(mid.is_mid());

        let data = ReplyLine::parse("250+config-text=").unwrap();
        assert!(data.is_data());
    }

    #[test]
    fn test_key_value_parsing() {
        let pairs = parse_key_value_pairs("KEY1=value1 KEY2=\"quoted value\"");
        assert_eq!(pairs.get("KEY1"), Some(&"value1".to_string()));
        assert_eq!(pairs.get("KEY2"), Some(&"quoted value".to_string()));
    }

    #[test]
    fn test_quoting() {
        assert_eq!(quote_string("simple"), "simple");
        assert_eq!(quote_string("with space"), "\"with space\"");
        assert_eq!(quote_string("with\"quote"), "\"with\\\"quote\"");
    }

    #[test]
    fn test_command_formatting() {
        let cmd = format_command("SETCONF", &["SOCKSPort=9050"]);
        assert_eq!(cmd, "SETCONF SOCKSPort=9050\r\n");
    }
}
