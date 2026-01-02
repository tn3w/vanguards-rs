//! Logging infrastructure for vanguards-rs.
//!
//! This module provides logging functionality using the tracing ecosystem.
//! It supports output to stdout, files, and syslog, with configurable log levels.
//!
//! # Overview
//!
//! The logging system provides:
//!
//! - **Multiple output destinations**: stdout, file, or syslog
//! - **Configurable log levels**: From DEBUG to ERROR
//! - **Python vanguards compatibility**: `plog` function matches Python API
//! - **Environment variable override**: `RUST_LOG` can override configured level
//!
//! # Log Levels
//!
//! From most to least verbose:
//!
//! | Level | Description | Use Case |
//! |-------|-------------|----------|
//! | [`Debug`](crate::LogLevel::Debug) | Low-level debugging | Development only |
//! | [`Info`](crate::LogLevel::Info) | Informational messages | Verbose operation |
//! | [`Notice`](crate::LogLevel::Notice) | Notable events | Default level |
//! | [`Warn`](crate::LogLevel::Warn) | Warning conditions | Potential issues |
//! | [`Error`](crate::LogLevel::Error) | Error conditions | Failures |
//!
//! # Example
//!
//! ```rust,no_run
//! use vanguards_rs::{LogLevel, logger};
//!
//! // Initialize logging to stdout at NOTICE level
//! logger::init(LogLevel::Notice, None).unwrap();
//!
//! // Log messages using the plog function
//! logger::plog(LogLevel::Notice, "Vanguards started");
//! logger::plog(LogLevel::Info, "Connected to Tor");
//! logger::plog(LogLevel::Warn, "High timeout rate detected");
//! ```
//!
//! # Output Destination Examples
//!
//! ```rust,no_run
//! use vanguards_rs::{LogLevel, logger};
//!
//! // Log to stdout (default)
//! logger::init(LogLevel::Notice, None).unwrap();
//!
//! // Log to a file
//! logger::init(LogLevel::Debug, Some("/var/log/vanguards.log")).unwrap();
//!
//! // Log to syslog
//! logger::init(LogLevel::Notice, Some(":syslog:")).unwrap();
//! ```
//!
//! # What This Module Does NOT Do
//!
//! - **Log rotation**: Use external tools like logrotate
//! - **Log aggregation**: Use external services for centralized logging
//! - **Structured logging**: Currently outputs plain text only
//!
//! # See Also
//!
//! - [`crate::config::LogLevel`] - Log level enumeration
//! - [`crate::logguard`] - Log buffering for circuit debugging
//! - [tracing crate](https://docs.rs/tracing) - Underlying logging framework

use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::OnceLock;
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use crate::config::LogLevel;
use crate::error::{Error, Result};

static LOGGER_INITIALIZED: OnceLock<()> = OnceLock::new();

/// Initialize the logging system.
///
/// This function sets up the tracing subscriber with the specified log level
/// and output destination. It should be called once at application startup.
/// Subsequent calls are no-ops.
///
/// # Arguments
///
/// * `level` - The minimum log level to output
/// * `logfile` - Output destination:
///   - `None` - Log to stdout with ANSI colors
///   - `Some(":syslog:")` - Log to system syslog
///   - `Some(path)` - Log to file at the specified path
///
/// # Returns
///
/// `Ok(())` on success, or an error if initialization fails.
///
/// # Errors
///
/// Returns [`Error::Io`] if:
/// - The log file cannot be created or opened
/// - The syslog socket cannot be found (Linux: `/dev/log`, macOS: `/var/run/syslog`)
///
/// Returns [`Error::Config`] if:
/// - The tracing subscriber cannot be set (usually means already initialized)
///
/// # Example
///
/// ```rust,no_run
/// use vanguards_rs::{LogLevel, logger};
///
/// // Log to stdout (with colors)
/// logger::init(LogLevel::Notice, None).unwrap();
///
/// // Log to file (no colors)
/// logger::init(LogLevel::Debug, Some("/var/log/vanguards.log")).unwrap();
///
/// // Log to syslog
/// logger::init(LogLevel::Notice, Some(":syslog:")).unwrap();
/// ```
///
/// # Notes
///
/// - The `RUST_LOG` environment variable can override the configured level
/// - File logging appends to existing files
/// - Syslog messages are prefixed with "vanguards:"
///
/// # See Also
///
/// - [`plog`] - Log messages after initialization
/// - [`crate::config::LogLevel`] - Available log levels
pub fn init(level: LogLevel, logfile: Option<&str>) -> Result<()> {
    if LOGGER_INITIALIZED.get().is_some() {
        return Ok(());
    }

    let filter = match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Notice => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    match logfile {
        None => {
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(false)
                .with_thread_ids(false)
                .with_span_events(FmtSpan::NONE)
                .with_ansi(true)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| Error::Config(format!("failed to set logger: {}", e)))?;
        }
        Some(":syslog:") => {
            init_syslog(env_filter)?;
        }
        Some(path) => {
            init_file_logger(path, env_filter)?;
        }
    }

    LOGGER_INITIALIZED.get_or_init(|| ());
    Ok(())
}

fn init_syslog(env_filter: EnvFilter) -> Result<()> {
    let syslog_path = if Path::new("/dev/log").exists() {
        "/dev/log"
    } else if Path::new("/var/run/syslog").exists() {
        "/var/run/syslog"
    } else {
        return Err(Error::Config("no syslog socket found".to_string()));
    };

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_ansi(false)
        .with_writer(move || {
            UnixDatagram::unbound()
                .and_then(|sock| {
                    sock.connect(syslog_path)?;
                    Ok(SyslogWriter { socket: sock })
                })
                .unwrap_or_else(|_| SyslogWriter {
                    socket: UnixDatagram::unbound().unwrap(),
                })
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| Error::Config(format!("failed to set logger: {}", e)))?;

    Ok(())
}

struct SyslogWriter {
    socket: UnixDatagram,
}

impl Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let msg = format!("vanguards: {}", String::from_utf8_lossy(buf));
        self.socket.send(msg.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_file_logger(path: &str, env_filter: EnvFilter) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(file))
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| Error::Config(format!("failed to set logger: {}", e)))?;

    Ok(())
}

/// Log a message at the specified level.
///
/// This function provides a Python vanguards-compatible logging interface.
/// It maps log levels to tracing macros.
///
/// # Arguments
///
/// * `level` - The log level for this message
/// * `message` - The message to log
///
/// # Level Mapping
///
/// | LogLevel | tracing macro |
/// |----------|---------------|
/// | Debug | `debug!` |
/// | Info | `info!` |
/// | Notice | `info!` |
/// | Warn | `warn!` |
/// | Error | `error!` |
///
/// # Example
///
/// ```rust
/// use vanguards_rs::{LogLevel, logger};
///
/// logger::plog(LogLevel::Notice, "Vanguards started");
/// logger::plog(LogLevel::Warn, "Connection lost, retrying...");
/// logger::plog(LogLevel::Error, "Failed to connect to Tor");
/// ```
///
/// # Notes
///
/// - Messages are only output if the level meets the configured minimum
/// - Notice maps to `info!` since tracing doesn't have a notice level
///
/// # See Also
///
/// - [`init`] - Initialize logging before calling plog
/// - [`plog_fmt`](crate::plog_fmt) - Formatted logging macro
pub fn plog(level: LogLevel, message: &str) {
    match level {
        LogLevel::Debug => debug!("{}", message),
        LogLevel::Info => info!("{}", message),
        LogLevel::Notice => info!("{}", message),
        LogLevel::Warn => warn!("{}", message),
        LogLevel::Error => error!("{}", message),
    }
}

/// Log a formatted message at the specified level.
///
/// This macro provides printf-style formatting for log messages.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::{LogLevel, plog_fmt};
///
/// plog_fmt!(LogLevel::Notice, "Connected to Tor version {}", "0.4.7.0");
/// plog_fmt!(LogLevel::Info, "Layer2 guards: {}", 4);
/// ```
#[macro_export]
macro_rules! plog_fmt {
    ($level:expr, $($arg:tt)*) => {
        $crate::logger::plog($level, &format!($($arg)*))
    };
}
