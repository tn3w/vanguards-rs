//! Log monitoring for attacks, protocol issues, and debugging.
//!
//! This module provides log monitoring functionality that buffers recent Tor log
//! messages and dumps them when circuits are closed, helping with debugging and
//! attack detection.
//!
//! # Overview
//!
//! The logguard system:
//!
//! - **Buffers log messages**: Keeps recent log entries up to a configurable limit
//! - **Dumps on circuit close**: Outputs buffered logs before and after circuit closure
//! - **Monitors warnings**: Logs Tor WARN-level messages at NOTICE level
//! - **Enables ProtocolWarnings**: Optionally enables Tor's ProtocolWarnings setting
//!
//! # Configuration
//!
//! Key configuration options in [`crate::config::LogguardConfig`]:
//!
//! | Option | Default | Description |
//! |--------|---------|-------------|
//! | `protocol_warns` | true | Enable ProtocolWarnings in Tor |
//! | `dump_limit` | 25 | Maximum log entries to buffer |
//! | `dump_level` | NOTICE | Minimum log level to buffer |
//!
//! # What This Module Does NOT Do
//!
//! - **Log rotation**: Use external tools for log file management
//! - **Log persistence**: Buffered logs are lost on restart
//! - **Attack prevention**: This module aids debugging, not prevention
//!
//! # See Also
//!
//! - [`crate::config::LogguardConfig`] - Configuration options
//! - [`crate::logger`] - Main logging infrastructure
//! - [Python vanguards logguard](https://github.com/mikeperry-tor/vanguards)

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{LogLevel, LogguardConfig};
use crate::logger::plog;

/// A buffered log entry from Tor.
///
/// Contains the log level, message content, and arrival timestamp.
/// Entries are stored in a ring buffer and dumped when circuits are closed.
///
/// # Fields
///
/// * `runlevel` - The log level (DEBUG, INFO, NOTICE, WARN, ERR)
/// * `message` - The log message content
/// * `arrived_at` - Unix timestamp when the log entry arrived
///
/// # Example
///
/// ```rust
/// use vanguards_rs::logguard::LogEntry;
///
/// // Create entry with current timestamp
/// let entry = LogEntry::new("NOTICE", "Circuit 123 built");
/// assert_eq!(entry.runlevel, "NOTICE");
/// assert_eq!(entry.message, "Circuit 123 built");
///
/// // Create entry with specific timestamp
/// let entry = LogEntry::with_timestamp("WARN", "Connection lost", 1234567890.5);
/// println!("{}", entry.format());
/// ```
///
/// # See Also
///
/// - [`LogGuard`] - Container for log entries
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// The log level (DEBUG, INFO, NOTICE, WARN, ERR).
    pub runlevel: String,
    /// The log message content.
    pub message: String,
    /// Unix timestamp when the log entry arrived.
    pub arrived_at: f64,
}

impl LogEntry {
    /// Creates a new log entry with the current timestamp.
    pub fn new(runlevel: &str, message: &str) -> Self {
        let arrived_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            runlevel: runlevel.to_string(),
            message: message.to_string(),
            arrived_at,
        }
    }

    /// Creates a new log entry with a specific timestamp.
    pub fn with_timestamp(runlevel: &str, message: &str, arrived_at: f64) -> Self {
        Self {
            runlevel: runlevel.to_string(),
            message: message.to_string(),
            arrived_at,
        }
    }

    /// Formats the log entry for output.
    pub fn format(&self) -> String {
        let time_str = format_timestamp(self.arrived_at);
        format!("TOR_{}[{}]: {}", self.runlevel, time_str, self.message)
    }
}

/// Formats a Unix timestamp as a human-readable string.
fn format_timestamp(timestamp: f64) -> String {
    use chrono::DateTime;
    let secs = timestamp as i64;
    let nsecs = ((timestamp - secs as f64) * 1_000_000_000.0) as u32;
    if let Some(dt) = DateTime::from_timestamp(secs, nsecs) {
        dt.format("%a %b %e %H:%M:%S %Y").to_string()
    } else {
        format!("{:.3}", timestamp)
    }
}

/// Log monitoring state.
///
/// Buffers recent Tor log messages and provides functionality to dump them
/// when circuits are closed for debugging purposes.
///
/// # Buffer Behavior
///
/// The log buffer operates as a ring buffer with a configurable maximum size.
/// When the buffer is full, the oldest entries are discarded to make room
/// for new ones.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::logguard::LogGuard;
/// use vanguards_rs::config::LogguardConfig;
///
/// let config = LogguardConfig::default();
/// let mut guard = LogGuard::new(&config);
///
/// // Buffer log entries
/// guard.log_event("NOTICE", "Circuit 123 built");
/// guard.log_event("INFO", "Stream attached");
/// assert_eq!(guard.buffer_len(), 2);
///
/// // Dump logs before circuit close
/// guard.dump_log_queue("123", "Pre");
/// assert_eq!(guard.buffer_len(), 0);
/// ```
///
/// # Event Handling
///
/// The guard responds to circuit events:
///
/// - On `CLOSED` or `FAILED` with reason `REQUESTED`: Dumps buffered logs
/// - This captures context around intentional circuit closures
///
/// # See Also
///
/// - [`LogEntry`] - Individual log entries
/// - [`crate::config::LogguardConfig`] - Configuration options
/// - [`crate::logger`] - Main logging infrastructure
#[derive(Debug, Clone)]
pub struct LogGuard {
    /// Buffered log entries.
    pub log_buffer: VecDeque<LogEntry>,
    /// Minimum log level to buffer.
    pub log_level: LogLevel,
    /// Maximum number of entries to buffer.
    pub log_limit: usize,
}

impl LogGuard {
    /// Creates a new LogGuard with the specified configuration.
    pub fn new(config: &LogguardConfig) -> Self {
        Self {
            log_buffer: VecDeque::new(),
            log_level: config.dump_level,
            log_limit: config.dump_limit,
        }
    }

    /// Handles a log event from Tor.
    ///
    /// Buffers the log entry if it meets the minimum log level requirement.
    /// Automatically trims the buffer if it exceeds the configured limit.
    ///
    /// # Arguments
    ///
    /// * `runlevel` - The log level (DEBUG, INFO, NOTICE, WARN, ERR)
    /// * `message` - The log message content
    pub fn log_event(&mut self, runlevel: &str, message: &str) {
        let entry = LogEntry::new(runlevel, message);
        self.log_buffer.push_back(entry);

        while self.log_buffer.len() > self.log_limit {
            self.log_buffer.pop_front();
        }
    }

    /// Handles a log event with a specific timestamp.
    pub fn log_event_with_timestamp(&mut self, runlevel: &str, message: &str, arrived_at: f64) {
        let entry = LogEntry::with_timestamp(runlevel, message, arrived_at);
        self.log_buffer.push_back(entry);

        while self.log_buffer.len() > self.log_limit {
            self.log_buffer.pop_front();
        }
    }

    /// Handles a WARN-level log event.
    ///
    /// Logs the warning at NOTICE level for visibility.
    pub fn log_warn_event(&self, message: &str) {
        plog(LogLevel::Notice, &format!("Tor log warn: {}", message));
    }

    /// Dumps the log buffer for a circuit close event.
    ///
    /// This is called before and after circuit close. The "when" argument is
    /// "Pre" before we close a circuit and "Post" after.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - The circuit ID being closed
    /// * `when` - "Pre" for before close, "Post" for after close
    pub fn dump_log_queue(&mut self, circ_id: &str, when: &str) {
        while let Some(entry) = self.log_buffer.pop_front() {
            plog(
                LogLevel::Notice,
                &format!(
                    "{}-close CIRC ID={} Tor log: {}",
                    when,
                    circ_id,
                    entry.format()
                ),
            );
        }
    }

    /// Handles a circuit event for post-close log dumping.
    ///
    /// Dumps buffered logs after a circuit is closed with REQUESTED reason.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - The circuit ID
    /// * `status` - The circuit status (CLOSED, FAILED, etc.)
    /// * `reason` - The close reason
    pub fn circ_event(&mut self, circ_id: &str, status: &str, reason: Option<&str>) {
        if (status == "CLOSED" || status == "FAILED") && reason == Some("REQUESTED") {
            self.dump_log_queue(circ_id, "Post");
        }
    }

    /// Returns the number of buffered log entries.
    pub fn buffer_len(&self) -> usize {
        self.log_buffer.len()
    }

    /// Clears the log buffer.
    pub fn clear(&mut self) {
        self.log_buffer.clear();
    }

    /// Returns the log levels that should be subscribed to based on dump_level.
    ///
    /// Returns a list of Tor event types to subscribe to.
    pub fn get_log_event_types(dump_level: LogLevel) -> Vec<&'static str> {
        let mut events = Vec::new();

        if dump_level <= LogLevel::Debug {
            events.push("DEBUG");
        }
        if dump_level <= LogLevel::Info {
            events.push("INFO");
        }
        if dump_level <= LogLevel::Notice {
            events.push("NOTICE");
        }
        if dump_level <= LogLevel::Warn {
            events.push("WARN");
        }
        if dump_level <= LogLevel::Error {
            events.push("ERR");
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_new() {
        let entry = LogEntry::new("NOTICE", "Test message");
        assert_eq!(entry.runlevel, "NOTICE");
        assert_eq!(entry.message, "Test message");
        assert!(entry.arrived_at > 0.0);
    }

    #[test]
    fn test_log_entry_with_timestamp() {
        let entry = LogEntry::with_timestamp("WARN", "Warning", 1234567890.5);
        assert_eq!(entry.runlevel, "WARN");
        assert_eq!(entry.message, "Warning");
        assert!((entry.arrived_at - 1234567890.5).abs() < 0.001);
    }

    #[test]
    fn test_log_entry_format() {
        let entry = LogEntry::with_timestamp("NOTICE", "Test", 1234567890.0);
        let formatted = entry.format();
        assert!(formatted.contains("TOR_NOTICE"));
        assert!(formatted.contains("Test"));
    }

    #[test]
    fn test_logguard_new() {
        let config = LogguardConfig::default();
        let guard = LogGuard::new(&config);
        assert_eq!(guard.log_limit, 25);
        assert_eq!(guard.log_level, LogLevel::Notice);
        assert!(guard.log_buffer.is_empty());
    }

    #[test]
    fn test_logguard_log_event() {
        let config = LogguardConfig::default();
        let mut guard = LogGuard::new(&config);

        guard.log_event("NOTICE", "Test message 1");
        guard.log_event("WARN", "Test message 2");

        assert_eq!(guard.buffer_len(), 2);
    }

    #[test]
    fn test_logguard_buffer_limit() {
        let config = LogguardConfig {
            dump_limit: 3,
            ..Default::default()
        };
        let mut guard = LogGuard::new(&config);

        for i in 0..5 {
            guard.log_event("NOTICE", &format!("Message {}", i));
        }

        assert_eq!(guard.buffer_len(), 3);
        let first = guard.log_buffer.front().unwrap();
        assert_eq!(first.message, "Message 2");
    }

    #[test]
    fn test_logguard_clear() {
        let config = LogguardConfig::default();
        let mut guard = LogGuard::new(&config);

        guard.log_event("NOTICE", "Test");
        assert_eq!(guard.buffer_len(), 1);

        guard.clear();
        assert_eq!(guard.buffer_len(), 0);
    }

    #[test]
    fn test_get_log_event_types_debug() {
        let events = LogGuard::get_log_event_types(LogLevel::Debug);
        assert!(events.contains(&"DEBUG"));
        assert!(events.contains(&"INFO"));
        assert!(events.contains(&"NOTICE"));
        assert!(events.contains(&"WARN"));
        assert!(events.contains(&"ERR"));
    }

    #[test]
    fn test_get_log_event_types_notice() {
        let events = LogGuard::get_log_event_types(LogLevel::Notice);
        assert!(!events.contains(&"DEBUG"));
        assert!(!events.contains(&"INFO"));
        assert!(events.contains(&"NOTICE"));
        assert!(events.contains(&"WARN"));
        assert!(events.contains(&"ERR"));
    }

    #[test]
    fn test_get_log_event_types_error() {
        let events = LogGuard::get_log_event_types(LogLevel::Error);
        assert!(!events.contains(&"DEBUG"));
        assert!(!events.contains(&"INFO"));
        assert!(!events.contains(&"NOTICE"));
        assert!(!events.contains(&"WARN"));
        assert!(events.contains(&"ERR"));
    }

    #[test]
    fn test_logguard_init() {
        let config = LogguardConfig {
            dump_level: LogLevel::Debug,
            dump_limit: 25,
            protocol_warns: true,
        };
        let lg = LogGuard::new(&config);

        assert_eq!(lg.buffer_len(), 0);
    }

    #[test]
    fn test_log_event_buffering() {
        let config = LogguardConfig::default();
        let mut lg = LogGuard::new(&config);

        lg.log_event("WARN", "whatever");
        assert_eq!(lg.buffer_len(), 1);
    }

    #[test]
    fn test_circ_event_clears_buffer() {
        let config = LogguardConfig::default();
        let mut lg = LogGuard::new(&config);

        lg.log_event("WARN", "whatever");
        assert_eq!(lg.buffer_len(), 1);

        lg.circ_event("2", "FAILED", Some("REQUESTED"));
        assert_eq!(lg.buffer_len(), 0);
    }

    #[test]
    fn test_circ_event_non_requested_doesnt_clear() {
        let config = LogguardConfig::default();
        let mut lg = LogGuard::new(&config);

        lg.log_event("WARN", "whatever");
        assert_eq!(lg.buffer_len(), 1);

        lg.circ_event("2", "CLOSED", Some("FINISHED"));
        assert_eq!(lg.buffer_len(), 1);
    }

    #[test]
    fn test_buffer_limit_from_unit() {
        let config = LogguardConfig {
            dump_limit: 25,
            ..Default::default()
        };
        let mut lg = LogGuard::new(&config);

        for i in 0..(2 * config.dump_limit) {
            lg.log_event("WARN", &format!("message {}", i));
        }

        assert_eq!(lg.buffer_len(), config.dump_limit);
    }

    #[test]
    fn test_closing_circuit_with_empty_log() {
        let config = LogguardConfig::default();
        let mut lg = LogGuard::new(&config);

        lg.circ_event("3", "FAILED", Some("REQUESTED"));
        assert_eq!(lg.buffer_len(), 0);
    }

    #[test]
    fn test_buffer_fifo_order() {
        let config = LogguardConfig {
            dump_limit: 3,
            ..Default::default()
        };
        let mut lg = LogGuard::new(&config);

        for i in 0..5 {
            lg.log_event("NOTICE", &format!("Message {}", i));
        }

        assert_eq!(lg.buffer_len(), 3);
        let first = lg.log_buffer.front().unwrap();
        assert_eq!(first.message, "Message 2");
    }
}
