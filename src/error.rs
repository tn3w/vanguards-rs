//! Error types for vanguards-rs.
//!
//! This module defines the [`enum@Error`] enum representing all possible error conditions
//! in the vanguards-rs library. Each variant provides specific information about
//! the failure and guidance on recovery.
//!
//! # Overview
//!
//! The error system is designed to provide:
//!
//! - **Specific error types** for different failure categories
//! - **Recovery guidance** for each error type
//! - **Seamless integration** with stem-rs errors
//! - **Informative messages** without leaking sensitive data
//!
//! # Error Categories
//!
//! ```text
//!   Error
//!   ├── Io                     ◄── File/network I/O failures
//!   ├── Config                 ◄── Invalid configuration
//!   ├── Control                ◄── Tor control protocol errors (from stem-rs)
//!   ├── State                  ◄── State file corruption/format issues
//!   ├── Consensus              ◄── Consensus parsing failures
//!   ├── NoNodesRemain          ◄── All relays filtered out
//!   ├── Validation             ◄── Invalid input data
//!   └── DescriptorUnavailable  ◄── Missing descriptors
//! ```
//!
//! # Recovery Guide
//!
//! | Error | Recoverable | Retry | Recommended Action |
//! |-------|-------------|-------|-------------------|
//! | [`Io`](Error::Io) | Sometimes | Yes (backoff) | Check permissions, disk space |
//! | [`Config`](Error::Config) | No | No | Fix configuration file |
//! | [`Control`](Error::Control) | Sometimes | Yes | Reconnect to Tor |
//! | [`State`](Error::State) | Sometimes | No | Delete state file, restart |
//! | [`Consensus`](Error::Consensus) | Sometimes | Yes | Wait for new consensus |
//! | [`NoNodesRemain`](Error::NoNodesRemain) | No | No | Adjust ExcludeNodes |
//! | [`Validation`](Error::Validation) | No | No | Fix input data |
//! | [`DescriptorUnavailable`](Error::DescriptorUnavailable) | Yes | Yes | Wait for bootstrap |
//!
//! # Example
//!
//! ## Basic Error Handling
//!
//! ```rust
//! use vanguards_rs::{Config, Error, Result};
//!
//! fn load_config() -> Result<Config> {
//!     let config = Config::from_file(std::path::Path::new("vanguards.conf"))?;
//!     config.validate()?;
//!     Ok(config)
//! }
//!
//! fn main() {
//!     match load_config() {
//!         Ok(config) => println!("Config loaded successfully"),
//!         Err(Error::Io(e)) => eprintln!("File error: {}", e),
//!         Err(Error::Config(msg)) => eprintln!("Config error: {}", msg),
//!         Err(e) => eprintln!("Other error: {}", e),
//!     }
//! }
//! ```
//!
//! ## Retry Logic
//!
//! ```rust,no_run
//! use vanguards_rs::{Error, Result};
//! use std::time::Duration;
//!
//! async fn with_retry<F, T>(mut f: F, max_retries: u32) -> Result<T>
//! where
//!     F: FnMut() -> Result<T>,
//! {
//!     let mut attempts = 0;
//!     loop {
//!         match f() {
//!             Ok(result) => return Ok(result),
//!             Err(Error::Io(_)) | Err(Error::Control(_)) if attempts < max_retries => {
//!                 attempts += 1;
//!                 tokio::time::sleep(Duration::from_secs(1 << attempts)).await;
//!             }
//!             Err(e) => return Err(e),
//!         }
//!     }
//! }
//! ```
//!
//! # See Also
//!
//! - [`Result`] - Type alias for `std::result::Result<T, Error>`
//! - [`stem_rs::Error`] - Underlying Tor control errors
//! - [`Config::validate`](crate::Config::validate) - Configuration validation

use thiserror::Error;

/// Errors that can occur during vanguards-rs operations.
///
/// This enum represents all possible error conditions in the library.
/// Each variant provides specific information about the failure and
/// guidance on recovery.
///
/// # Error Handling Patterns
///
/// ## Match on Specific Errors
///
/// ```rust
/// use vanguards_rs::Error;
///
/// fn handle_error(err: Error) {
///     match err {
///         Error::Io(io_err) => {
///             eprintln!("I/O error: {}", io_err);
///             // Check file permissions, disk space, network
///         }
///         Error::Config(msg) => {
///             eprintln!("Configuration error: {}", msg);
///             // Fix configuration and restart
///         }
///         Error::Control(ctrl_err) => {
///             eprintln!("Tor control error: {}", ctrl_err);
///             // Reconnect to Tor
///         }
///         Error::State(msg) => {
///             eprintln!("State file error: {}", msg);
///             // Delete state file and restart
///         }
///         Error::Consensus(msg) => {
///             eprintln!("Consensus error: {}", msg);
///             // Wait for Tor to get new consensus
///         }
///         Error::NoNodesRemain => {
///             eprintln!("No nodes remain after filtering");
///             // Adjust ExcludeNodes configuration
///         }
///         Error::Validation(msg) => {
///             eprintln!("Validation error: {}", msg);
///             // Fix invalid input
///         }
///         Error::DescriptorUnavailable(msg) => {
///             eprintln!("Descriptor unavailable: {}", msg);
///             // Wait for Tor to finish bootstrapping
///         }
///     }
/// }
/// ```
///
/// ## Check if Retryable
///
/// ```rust
/// use vanguards_rs::Error;
///
/// fn is_retryable(err: &Error) -> bool {
///     matches!(err,
///         Error::Io(_) |
///         Error::Control(_) |
///         Error::Consensus(_) |
///         Error::DescriptorUnavailable(_)
///     )
/// }
/// ```
///
/// # See Also
///
/// - [`Result`] - Type alias using this error type
/// - [`stem_rs::Error`] - Underlying control protocol errors
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error during file or network operations.
    ///
    /// This error wraps standard I/O errors that occur during file operations
    /// (reading/writing state files, config files) or network operations.
    ///
    /// # Recovery
    ///
    /// - Check file permissions and paths
    /// - Retry with exponential backoff for transient issues
    /// - Verify disk space for write operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    ///
    /// This error indicates invalid configuration values or parsing failures.
    /// The message describes what was wrong with the configuration.
    ///
    /// # Recovery
    ///
    /// Fix the configuration file or command-line arguments. This error
    /// is not recoverable without user intervention.
    #[error("configuration error: {0}")]
    Config(String),

    /// Tor control protocol error.
    ///
    /// This error wraps errors from stem-rs when communicating with Tor's
    /// control port.
    ///
    /// # Recovery
    ///
    /// - Check if Tor is running
    /// - Verify control port configuration
    /// - Retry connection with backoff
    #[error("Tor control error: {0}")]
    Control(#[from] stem_rs::Error),

    /// State file error.
    ///
    /// This error indicates problems with the vanguard state file, such as
    /// corruption, invalid format, or incompatible version.
    ///
    /// # Recovery
    ///
    /// - Delete the corrupted state file and let vanguards create a fresh one
    /// - Check file permissions
    /// - Verify the file wasn't modified externally
    #[error("state file error: {0}")]
    State(String),

    /// Consensus parsing error.
    ///
    /// This error occurs when parsing the network consensus fails.
    ///
    /// # Recovery
    ///
    /// - Wait for a new consensus
    /// - Verify Tor has finished bootstrapping
    /// - Check DataDirectory configuration
    #[error("consensus parse error: {0}")]
    Consensus(String),

    /// No nodes remain after applying restrictions.
    ///
    /// This error occurs when all relays are filtered out by the configured
    /// restrictions (ExcludeNodes, flag requirements, etc.).
    ///
    /// # Recovery
    ///
    /// - Review ExcludeNodes configuration
    /// - Reduce restrictions
    /// - Wait for more relays to appear in consensus
    #[error("no nodes remain after restrictions")]
    NoNodesRemain,

    /// Input validation error.
    ///
    /// This error indicates that input data failed validation checks.
    ///
    /// # Recovery
    ///
    /// Fix the invalid input. This error is not recoverable without
    /// correcting the input data.
    #[error("validation error: {0}")]
    Validation(String),

    /// Descriptor unavailable.
    ///
    /// This error occurs when Tor doesn't have the required descriptors
    /// cached yet, typically during bootstrap.
    ///
    /// # Recovery
    ///
    /// - Wait for Tor to finish bootstrapping
    /// - Retry after a short delay
    #[error("descriptor unavailable: {0}")]
    DescriptorUnavailable(String),
}

/// Result type alias for vanguards-rs operations.
///
/// This is a convenience alias for `std::result::Result<T, Error>` used
/// throughout the vanguards-rs library.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::{Config, Result};
///
/// fn load_and_validate_config() -> Result<Config> {
///     let config = Config::from_file(std::path::Path::new("vanguards.conf"))?;
///     config.validate()?;
///     Ok(config)
/// }
/// ```
///
/// # See Also
///
/// - [`enum@Error`] - The error type used in this result
pub type Result<T> = std::result::Result<T, Error>;
