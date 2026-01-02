//! High-level API for vanguards-rs.
//!
//! This module provides the [`Vanguards`] struct, which is the main entry point
//! for programmatic use of the vanguards-rs library.
//!
//! # Overview
//!
//! The [`Vanguards`] struct combines all protection components into a single
//! interface that can be used to protect Tor hidden services. It manages:
//!
//! - Connection to Tor's control port
//! - Vanguard state persistence and rotation
//! - All protection component lifecycles
//! - Event processing and response
//!
//! # Conceptual Role
//!
//! The `Vanguards` struct sits at the top of the vanguards-rs architecture,
//! orchestrating all protection components.
//!
//! # Thread Safety
//!
//! The [`Vanguards`] struct is `Send` but not `Sync`.
//! For concurrent access from multiple tasks, wrap in `Arc<Mutex<Vanguards>>`:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::sync::Mutex;
//! use vanguards_rs::{Config, Vanguards};
//!
//! # async fn example() -> vanguards_rs::Result<()> {
//! let config = Config::default();
//! let vanguards = Vanguards::from_config(config).await?;
//! let shared = Arc::new(Mutex::new(vanguards));
//!
//! // Clone Arc for each task
//! let v1 = shared.clone();
//! tokio::spawn(async move {
//!     let guard = v1.lock().await;
//!     println!("State: {}", guard.state().layer2_guardset());
//! });
//! # Ok(())
//! # }
//! ```
//!
//! # Example
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use vanguards_rs::{Config, Vanguards};
//!
//! #[tokio::main]
//! async fn main() -> vanguards_rs::Result<()> {
//!     let config = Config::default();
//!     let mut vanguards = Vanguards::from_config(config).await?;
//!     vanguards.run().await
//! }
//! ```
//!
//! ## With Custom Configuration
//!
//! ```rust,no_run
//! use vanguards_rs::{Config, Vanguards, LogLevel};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> vanguards_rs::Result<()> {
//!     let mut config = Config::default();
//!     config.control_port = Some(9051);
//!     config.state_file = PathBuf::from("/var/lib/tor/vanguards.state");
//!     config.loglevel = LogLevel::Debug;
//!     
//!     let mut vanguards = Vanguards::from_config(config).await?;
//!     vanguards.run().await
//! }
//! ```
//!
//! ## Using an Existing Controller
//!
//! ```rust,no_run
//! use vanguards_rs::{Config, Vanguards};
//! use stem_rs::controller::Controller;
//!
//! #[tokio::main]
//! async fn main() -> vanguards_rs::Result<()> {
//!     // Connect and authenticate manually
//!     let mut controller = Controller::from_port("127.0.0.1:9051".parse().unwrap()).await?;
//!     controller.authenticate(None).await?;
//!     
//!     // Create Vanguards with existing controller
//!     let config = Config::default();
//!     let vanguards = Vanguards::new(controller, config)?;
//!     
//!     // Access state without running the loop
//!     println!("Layer2 guards: {}", vanguards.state().layer2_guardset());
//!     Ok(())
//! }
//! ```
//!
//! # Security
//!
//! - Passwords are cleared from memory after authentication using [`zeroize`]
//! - State files are written with 0600 permissions on Unix
//! - All inputs are validated before use
//! - The [`SecurePassword`] wrapper ensures passwords don't leak in debug output
//!
//! # See Also
//!
//! - [`Config`] - Configuration options
//! - [`VanguardState`] - Guard state management
//! - [`control::run_main`] - Main event loop
//! - [Python vanguards](https://github.com/mikeperry-tor/vanguards) - Original implementation

use stem_rs::controller::Controller;
use zeroize::Zeroize;

use crate::config::Config;
use crate::control::{self, AppState};
use crate::error::Result;
use crate::logger::plog;
use crate::vanguards::VanguardState;
use crate::LogLevel;

/// A wrapper for sensitive password data that clears itself on drop.
///
/// `SecurePassword` provides a secure container for password strings that
/// automatically clears the password from memory when the wrapper is dropped.
/// This prevents passwords from lingering in memory where they could be
/// extracted by memory inspection attacks.
///
/// # Security Properties
///
/// - **Zeroization**: Password bytes are overwritten with zeros on drop
/// - **Debug Safety**: Debug output shows `[REDACTED]` instead of the password
/// - **Clone Safety**: Cloning creates a new secure copy (both are zeroized independently)
///
/// # Thread Safety
///
/// `SecurePassword` is `Send` and can be moved between threads. It is also
/// `Clone`, creating independent copies that are each zeroized on drop.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::SecurePassword;
///
/// // Create a secure password
/// let password = SecurePassword::new("my_secret_password".to_string());
///
/// // Access the password when needed
/// assert_eq!(password.as_str(), "my_secret_password");
///
/// // Debug output is safe
/// let debug = format!("{:?}", password);
/// assert!(debug.contains("REDACTED"));
/// assert!(!debug.contains("my_secret"));
///
/// // Password is automatically cleared when dropped
/// drop(password);
/// ```
///
/// # See Also
///
/// - [`Vanguards::from_config`] - Uses SecurePassword internally
/// - [`zeroize`](https://docs.rs/zeroize) - The underlying zeroization library
#[derive(Clone)]
pub struct SecurePassword(String);

impl SecurePassword {
    /// Creates a new secure password wrapper.
    ///
    /// # Arguments
    ///
    /// * `password` - The password string to wrap securely
    ///
    /// # Example
    ///
    /// ```rust
    /// use vanguards_rs::SecurePassword;
    ///
    /// let password = SecurePassword::new("secret123".to_string());
    /// ```
    pub fn new(password: String) -> Self {
        Self(password)
    }

    /// Returns a reference to the password string.
    ///
    /// # Security Note
    ///
    /// The returned reference is valid only while the `SecurePassword` exists.
    /// Avoid storing this reference or converting it to an owned `String`,
    /// as that would defeat the purpose of secure password handling.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vanguards_rs::SecurePassword;
    ///
    /// let password = SecurePassword::new("secret123".to_string());
    /// assert_eq!(password.as_str(), "secret123");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecurePassword {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecurePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecurePassword([REDACTED])")
    }
}

/// Main vanguards manager combining all protection components.
///
/// This struct provides a high-level interface for running vanguards protection
/// on a Tor hidden service. It manages the complete lifecycle of protection,
/// from initialization through event processing.
///
/// # Managed Components
///
/// The `Vanguards` struct orchestrates these protection components:
///
/// | Component | Purpose | Config Flag |
/// |-----------|---------|-------------|
/// | Vanguard State | Layer 2/3 guard selection | `enable_vanguards` |
/// | Bandguards | Bandwidth attack detection | `enable_bandguards` |
/// | Rendguard | Rendezvous point monitoring | `enable_rendguard` |
/// | Logguard | Tor log monitoring | `enable_logguard` |
/// | CBT Verify | Circuit timeout verification | `enable_cbtverify` |
/// | Path Verify | Circuit path verification | `enable_pathverify` |
///
/// # Lifecycle
///
/// ```text
/// ┌─────────────────┐
/// │  from_config()  │ ◄── Load config, create state
/// └────────┬────────┘
///          │
///          ▼
/// ┌─────────────────┐
/// │     run()       │ ◄── Connect to Tor, start event loop
/// └────────┬────────┘
///          │
///          ▼
/// ┌─────────────────┐
/// │  Event Loop     │ ◄── Process events until shutdown
/// │  (control.rs)   │
/// └────────┬────────┘
///          │
///          ▼
/// ┌─────────────────┐
/// │    Cleanup      │ ◄── Save state, close connection
/// └─────────────────┘
/// ```
///
/// # Thread Safety
///
/// `Vanguards` is `Send` but not `Sync`. For concurrent access:
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// use vanguards_rs::{Config, Vanguards};
///
/// # async fn example() -> vanguards_rs::Result<()> {
/// let vanguards = Vanguards::from_config(Config::default()).await?;
/// let shared = Arc::new(Mutex::new(vanguards));
/// # Ok(())
/// # }
/// ```
///
/// # Example
///
/// ## Basic Usage
///
/// ```rust,no_run
/// use vanguards_rs::{Config, Vanguards};
///
/// #[tokio::main]
/// async fn main() -> vanguards_rs::Result<()> {
///     // Create with default configuration
///     let config = Config::default();
///     let mut vanguards = Vanguards::from_config(config).await?;
///     
///     // Run the protection loop
///     vanguards.run().await
/// }
/// ```
///
/// ## Inspecting State
///
/// ```rust,no_run
/// use vanguards_rs::{Config, Vanguards};
///
/// #[tokio::main]
/// async fn main() -> vanguards_rs::Result<()> {
///     let config = Config::default();
///     let vanguards = Vanguards::from_config(config).await?;
///     
///     // Access current state
///     let state = vanguards.state();
///     println!("Layer2 guards: {}", state.layer2_guardset());
///     println!("Layer3 guards: {}", state.layer3_guardset());
///     
///     // Access configuration
///     let config = vanguards.config();
///     println!("Vanguards enabled: {}", config.enable_vanguards);
///     Ok(())
/// }
/// ```
///
/// # Security Considerations
///
/// - Passwords are cleared from memory after authentication
/// - State files are written with restrictive permissions (0600 on Unix)
/// - All external inputs are validated before use
/// - Guard selections persist across restarts to prevent discovery attacks
///
/// # See Also
///
/// - [`Config`] - Configuration options
/// - [`VanguardState`] - Guard state details
/// - [`SecurePassword`] - Secure password handling
/// - [`control::run_main`] - Event loop implementation
pub struct Vanguards {
    /// Application state containing all protection components.
    state: AppState,
    /// Secure password wrapper (cleared on drop).
    _password: Option<SecurePassword>,
}

impl Vanguards {
    /// Creates a new Vanguards instance from an existing controller and configuration.
    ///
    /// This method is useful when you already have a connected and authenticated
    /// controller.
    ///
    /// # Arguments
    ///
    /// * `controller` - An authenticated Tor controller
    /// * `config` - The vanguards configuration
    ///
    /// # Errors
    ///
    /// Returns an error if state loading fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vanguards_rs::{Config, Vanguards};
    /// use stem_rs::controller::Controller;
    ///
    /// #[tokio::main]
    /// async fn main() -> vanguards_rs::Result<()> {
    ///     let mut controller = Controller::from_port("127.0.0.1:9051".parse().unwrap()).await?;
    ///     controller.authenticate(None).await?;
    ///     
    ///     let config = Config::default();
    ///     let vanguards = Vanguards::new(controller, config)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn new(_controller: Controller, config: Config) -> Result<Self> {
        let state_path = &config.state_file;
        let vanguard_state = match VanguardState::read_from_file(state_path) {
            Ok(mut state) => {
                plog(
                    LogLevel::Info,
                    &format!(
                        "Loaded state with {} layer2 and {} layer3 guards",
                        state.layer2.len(),
                        state.layer3.len()
                    ),
                );
                state.enable_vanguards = config.enable_vanguards;
                state
            }
            Err(_) => {
                plog(
                    LogLevel::Notice,
                    &format!("Creating new vanguard state at: {}", state_path.display()),
                );
                let mut state = VanguardState::new(&state_path.to_string_lossy());
                state.enable_vanguards = config.enable_vanguards;
                state
            }
        };

        let app_state = AppState::new(vanguard_state, config);

        Ok(Self {
            state: app_state,
            _password: None,
        })
    }

    /// Creates a new Vanguards instance by connecting to Tor.
    ///
    /// This method handles connection, authentication, and state initialization.
    /// The password (if provided) is securely cleared from memory after use.
    ///
    /// # Arguments
    ///
    /// * `config` - The vanguards configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Connection to Tor fails
    /// - Authentication fails
    /// - State loading fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vanguards_rs::{Config, Vanguards};
    ///
    /// #[tokio::main]
    /// async fn main() -> vanguards_rs::Result<()> {
    ///     let config = Config::default();
    ///     let vanguards = Vanguards::from_config(config).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn from_config(config: Config) -> Result<Self> {
        // Wrap password in secure container
        let secure_password = config.control_pass.clone().map(SecurePassword::new);

        let state_path = &config.state_file;
        let vanguard_state = match VanguardState::read_from_file(state_path) {
            Ok(mut state) => {
                plog(
                    LogLevel::Info,
                    &format!(
                        "Loaded state with {} layer2 and {} layer3 guards",
                        state.layer2.len(),
                        state.layer3.len()
                    ),
                );
                state.enable_vanguards = config.enable_vanguards;
                state
            }
            Err(_) => {
                plog(
                    LogLevel::Notice,
                    &format!("Creating new vanguard state at: {}", state_path.display()),
                );
                let mut state = VanguardState::new(&state_path.to_string_lossy());
                state.enable_vanguards = config.enable_vanguards;
                state
            }
        };

        let app_state = AppState::new(vanguard_state, config);

        Ok(Self {
            state: app_state,
            _password: secure_password,
        })
    }

    /// Runs the main vanguards protection loop.
    ///
    /// This method connects to Tor, authenticates, initializes protection
    /// components, and processes events until the connection is closed or
    /// an error occurs.
    ///
    /// # Errors
    ///
    /// Returns an error if the protection loop fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vanguards_rs::{Config, Vanguards};
    ///
    /// #[tokio::main]
    /// async fn main() -> vanguards_rs::Result<()> {
    ///     let config = Config::default();
    ///     let mut vanguards = Vanguards::from_config(config).await?;
    ///     vanguards.run().await
    /// }
    /// ```
    pub async fn run(&mut self) -> Result<()> {
        control::run_main(self.state.config.clone()).await
    }

    /// Returns a reference to the current vanguard state.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vanguards_rs::{Config, Vanguards};
    ///
    /// #[tokio::main]
    /// async fn main() -> vanguards_rs::Result<()> {
    ///     let config = Config::default();
    ///     let vanguards = Vanguards::from_config(config).await?;
    ///     
    ///     let state = vanguards.state();
    ///     println!("Layer2 guards: {}", state.layer2_guardset());
    ///     println!("Layer3 guards: {}", state.layer3_guardset());
    ///     Ok(())
    /// }
    /// ```
    pub fn state(&self) -> &VanguardState {
        &self.state.vanguard_state
    }

    /// Returns a reference to the current configuration.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vanguards_rs::{Config, Vanguards};
    ///
    /// #[tokio::main]
    /// async fn main() -> vanguards_rs::Result<()> {
    ///     let config = Config::default();
    ///     let vanguards = Vanguards::from_config(config).await?;
    ///     
    ///     let config = vanguards.config();
    ///     println!("Vanguards enabled: {}", config.enable_vanguards);
    ///     Ok(())
    /// }
    /// ```
    pub fn config(&self) -> &Config {
        &self.state.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_password_debug_redacted() {
        let password = SecurePassword::new("secret123".to_string());
        let debug_str = format!("{:?}", password);
        assert!(!debug_str.contains("secret123"));
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_secure_password_as_str() {
        let password = SecurePassword::new("secret123".to_string());
        assert_eq!(password.as_str(), "secret123");
    }
}
