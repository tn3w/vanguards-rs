//! Configuration management for vanguards-rs.
//!
//! This module provides configuration parsing from TOML files, command-line arguments,
//! and environment variables. Configuration is applied in order: defaults → config file →
//! command-line arguments, with later sources overriding earlier ones.
//!
//! # Overview
//!
//! The configuration system supports multiple sources with clear precedence rules,
//! allowing flexible deployment scenarios from simple defaults to complex multi-source
//! configurations.
//!
//! # Configuration Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        Configuration Loading Flow                           │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//!     ┌─────────────────┐
//!     │ Config::default │ ◄── Start with sensible defaults
//!     └────────┬────────┘
//!              │
//!              ▼
//!     ┌─────────────────┐     ┌─────────────────┐
//!     │ Config file     │ ◄───│ vanguards.conf  │  (TOML format)
//!     │ exists?         │     │ or --config     │
//!     └────────┬────────┘     └─────────────────┘
//!              │
//!         Yes  │  No
//!       ┌──────┴───────┐
//!       ▼              │
//! ┌─────────────┐      │
//! │ Merge file  │      │
//! │ settings    │      │
//! └──────┬──────┘      │
//!        │             │
//!        └──────┬──────┘
//!               │
//!               ▼
//!     ┌─────────────────┐     ┌─────────────────┐
//!     │ Apply CLI args  │ ◄───│ --control-port  │
//!     │ (override)      │     │ --state, etc.   │
//!     └────────┬────────┘     └─────────────────┘
//!              │
//!              ▼
//!     ┌─────────────────┐     ┌─────────────────┐
//!     │ Apply env vars  │ ◄───│ VANGUARDS_STATE │
//!     │ (if not set)    │     │ VANGUARDS_CONFIG│
//!     └────────┬────────┘     └─────────────────┘
//!              │
//!              ▼
//!     ┌─────────────────┐
//!     │ Validate &      │
//!     │ resolve hosts   │
//!     └────────┬────────┘
//!              │
//!              ▼
//!     ┌─────────────────┐
//!     │ Final Config    │ ◄── Ready to use
//!     └─────────────────┘
//! ```
//!
//! # Configuration Sources
//!
//! | Source | Priority | Description |
//! |--------|----------|-------------|
//! | Defaults | Lowest | Built-in sensible defaults |
//! | Config File | Medium | TOML file (`--config` or `VANGUARDS_CONFIG`) |
//! | Environment | High | `VANGUARDS_STATE`, `VANGUARDS_CONFIG` |
//! | CLI Arguments | Highest | Command-line flags override all |
//!
//! # Example Configuration File
//!
//! ```toml
//! # Connection settings
//! control_ip = "127.0.0.1"
//! control_port = 9051
//! # control_socket = "/run/tor/control"  # Alternative: Unix socket
//! # control_pass = "my_password"         # If using password auth
//!
//! # File paths
//! state_file = "vanguards.state"
//!
//! # Logging
//! loglevel = "notice"  # debug, info, notice, warn, error
//! # logfile = "/var/log/vanguards.log"  # Optional: log to file
//! # logfile = ":syslog:"                 # Optional: log to syslog
//!
//! # Component toggles
//! enable_vanguards = true
//! enable_bandguards = true
//! enable_rendguard = true
//! enable_logguard = true
//! enable_cbtverify = false
//! enable_pathverify = false
//!
//! # Operational settings
//! close_circuits = true
//! one_shot_vanguards = false
//! # retry_limit = 10  # Optional: limit reconnection attempts
//!
//! [vanguards]
//! num_layer1_guards = 2   # 0 = use Tor default
//! num_layer2_guards = 4
//! num_layer3_guards = 8
//! min_layer2_lifetime_hours = 24
//! max_layer2_lifetime_hours = 1080  # 45 days
//! min_layer3_lifetime_hours = 1
//! max_layer3_lifetime_hours = 48
//!
//! [bandguards]
//! circ_max_megabytes = 0           # 0 = disabled
//! circ_max_age_hours = 24
//! circ_max_hsdesc_kilobytes = 30
//! circ_max_serv_intro_kilobytes = 0
//! circ_max_disconnected_secs = 30
//! conn_max_disconnected_secs = 15
//!
//! [rendguard]
//! use_global_start_count = 1000
//! use_scale_at_count = 20000
//! use_relay_start_count = 100
//! use_max_use_to_bw_ratio = 5.0
//! use_max_consensus_weight_churn = 1.0
//! close_circuits_on_overuse = true
//!
//! [logguard]
//! protocol_warns = true
//! dump_limit = 25
//! dump_level = "notice"
//! ```
//!
//! # What This Module Does NOT Do
//!
//! - **Runtime reconfiguration**: Config is loaded once at startup
//! - **Config file watching**: Changes require restart
//! - **Encrypted config files**: Passwords are stored in plaintext
//!
//! # See Also
//!
//! - [`LogLevel`] for logging configuration
//! - [`VanguardsConfig`] for vanguard-specific settings
//! - [`BandguardsConfig`] for bandwidth monitoring settings
//! - [`RendguardConfig`] for rendezvous point monitoring settings
//! - [`LogguardConfig`] for log monitoring settings
//! - [`CliArgs`] for command-line argument parsing

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;

use crate::error::{Error, Result};

/// Log level for vanguards-rs output.
///
/// These levels control the verbosity of log output. From most to least verbose:
/// [`Debug`](LogLevel::Debug) > [`Info`](LogLevel::Info) > [`Notice`](LogLevel::Notice) >
/// [`Warn`](LogLevel::Warn) > [`Error`](LogLevel::Error)
///
/// # Example
///
/// ```rust
/// use vanguards_rs::LogLevel;
///
/// let level = LogLevel::Notice;
/// assert!(level < LogLevel::Warn);
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Low-level debugging information.
    Debug,
    /// Informational messages about normal operation.
    Info,
    /// Notable events that may be of interest.
    #[default]
    Notice,
    /// Warning conditions that don't prevent operation.
    Warn,
    /// Error conditions that may impair functionality.
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Notice => write!(f, "NOTICE"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "DEBUG" => Ok(LogLevel::Debug),
            "INFO" => Ok(LogLevel::Info),
            "NOTICE" => Ok(LogLevel::Notice),
            "WARN" | "WARNING" => Ok(LogLevel::Warn),
            "ERROR" | "ERR" => Ok(LogLevel::Error),
            _ => Err(Error::Config(format!("invalid log level: {}", s))),
        }
    }
}

/// Vanguard-specific configuration options.
///
/// Controls the number of guards at each layer and their rotation lifetimes.
/// These settings directly affect the security/performance tradeoff of vanguard
/// protection.
///
/// # Guard Layers
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                    Vanguard Guard Layers                        │
/// └─────────────────────────────────────────────────────────────────┘
///
///   Client ──▶ Layer1 ──▶ Layer2 ──▶ Layer3 ──▶ Rendezvous Point
///              (Entry)    (Middle)   (Middle)
///
///   Layer1: Entry guards (managed by Tor, configurable count)
///   Layer2: First vanguard layer (longer lifetime: 1-45 days)
///   Layer3: Second vanguard layer (shorter lifetime: 1-48 hours)
/// ```
///
/// # Fields
///
/// | Field | Default | Description |
/// |-------|---------|-------------|
/// | `num_layer1_guards` | 2 | Entry guards (0 = Tor default) |
/// | `num_layer2_guards` | 4 | Layer2 vanguard count |
/// | `num_layer3_guards` | 8 | Layer3 vanguard count |
/// | `layer1_lifetime_days` | 0 | Entry guard lifetime (0 = Tor default) |
/// | `min_layer2_lifetime_hours` | 24 | Minimum layer2 lifetime |
/// | `max_layer2_lifetime_hours` | 1080 | Maximum layer2 lifetime (45 days) |
/// | `min_layer3_lifetime_hours` | 1 | Minimum layer3 lifetime |
/// | `max_layer3_lifetime_hours` | 48 | Maximum layer3 lifetime |
///
/// # Security Considerations
///
/// - **More guards** = Better anonymity but more exposure to malicious relays
/// - **Longer lifetimes** = Better protection against guard discovery but slower recovery from compromise
/// - **Shorter lifetimes** = Faster recovery but more vulnerable to timing attacks
///
/// # Example
///
/// ```rust
/// use vanguards_rs::VanguardsConfig;
///
/// let mut config = VanguardsConfig::default();
///
/// // Increase guard counts for higher security
/// config.num_layer2_guards = 6;
/// config.num_layer3_guards = 12;
///
/// // Extend layer2 lifetime for better protection
/// config.max_layer2_lifetime_hours = 2160; // 90 days
/// ```
///
/// # See Also
///
/// - [`Config`] - Main configuration struct
/// - [`VanguardState`](crate::VanguardState) - Runtime guard state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VanguardsConfig {
    /// Number of layer1 (entry) guards. 0 means use Tor default.
    #[serde(default = "default_num_layer1_guards")]
    pub num_layer1_guards: u8,
    /// Number of layer2 guards.
    #[serde(default = "default_num_layer2_guards")]
    pub num_layer2_guards: u8,
    /// Number of layer3 guards.
    #[serde(default = "default_num_layer3_guards")]
    pub num_layer3_guards: u8,
    /// Layer1 guard lifetime in days. 0 means use Tor default.
    #[serde(default)]
    pub layer1_lifetime_days: u16,
    /// Minimum layer2 guard lifetime in hours.
    #[serde(default = "default_min_layer2_lifetime_hours")]
    pub min_layer2_lifetime_hours: u32,
    /// Maximum layer2 guard lifetime in hours.
    #[serde(default = "default_max_layer2_lifetime_hours")]
    pub max_layer2_lifetime_hours: u32,
    /// Minimum layer3 guard lifetime in hours.
    #[serde(default = "default_min_layer3_lifetime_hours")]
    pub min_layer3_lifetime_hours: u32,
    /// Maximum layer3 guard lifetime in hours.
    #[serde(default = "default_max_layer3_lifetime_hours")]
    pub max_layer3_lifetime_hours: u32,
}

fn default_num_layer1_guards() -> u8 {
    2
}
fn default_num_layer2_guards() -> u8 {
    4
}
fn default_num_layer3_guards() -> u8 {
    8
}
fn default_min_layer2_lifetime_hours() -> u32 {
    24
}
fn default_max_layer2_lifetime_hours() -> u32 {
    1080
}
fn default_min_layer3_lifetime_hours() -> u32 {
    1
}
fn default_max_layer3_lifetime_hours() -> u32 {
    48
}

impl Default for VanguardsConfig {
    fn default() -> Self {
        Self {
            num_layer1_guards: default_num_layer1_guards(),
            num_layer2_guards: default_num_layer2_guards(),
            num_layer3_guards: default_num_layer3_guards(),
            layer1_lifetime_days: 0,
            min_layer2_lifetime_hours: default_min_layer2_lifetime_hours(),
            max_layer2_lifetime_hours: default_max_layer2_lifetime_hours(),
            min_layer3_lifetime_hours: default_min_layer3_lifetime_hours(),
            max_layer3_lifetime_hours: default_max_layer3_lifetime_hours(),
        }
    }
}

/// Bandwidth monitoring configuration options.
///
/// Controls circuit bandwidth limits and disconnection warnings. These settings
/// help detect bandwidth-based side-channel attacks that attempt to identify
/// hidden services through traffic analysis.
///
/// # Attack Detection
///
/// Bandguards monitors for several attack patterns:
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                  Bandwidth Attack Detection                     │
/// └─────────────────────────────────────────────────────────────────┘
///
///   1. Circuit Size Attack
///      ├── Monitor total bytes per circuit
///      └── Alert/close if exceeds circ_max_megabytes
///
///   2. Circuit Age Attack
///      ├── Track circuit creation time
///      └── Alert/close if exceeds circ_max_age_hours
///
///   3. HSDIR Descriptor Attack
///      ├── Monitor HSDIR circuit bandwidth
///      └── Alert if exceeds circ_max_hsdesc_kilobytes
///
///   4. Connectivity Monitoring
///      ├── Track disconnection duration
///      └── Warn if exceeds threshold
/// ```
///
/// # Fields
///
/// | Field | Default | Description |
/// |-------|---------|-------------|
/// | `circ_max_megabytes` | 0 | Max circuit size in MB (0 = disabled) |
/// | `circ_max_age_hours` | 24 | Max circuit age in hours |
/// | `circ_max_hsdesc_kilobytes` | 30 | Max HSDIR circuit size in KB |
/// | `circ_max_serv_intro_kilobytes` | 0 | Max intro circuit size (0 = disabled) |
/// | `circ_max_disconnected_secs` | 30 | Warn after N seconds disconnected |
/// | `conn_max_disconnected_secs` | 15 | Warn after N seconds with no connections |
///
/// # Example
///
/// ```rust
/// use vanguards_rs::BandguardsConfig;
///
/// let mut config = BandguardsConfig::default();
///
/// // Enable circuit size limiting
/// config.circ_max_megabytes = 100;
///
/// // Reduce circuit age for higher security
/// config.circ_max_age_hours = 12;
/// ```
///
/// # See Also
///
/// - [`Config`] - Main configuration struct
/// - [`BandwidthStats`](crate::BandwidthStats) - Runtime bandwidth statistics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BandguardsConfig {
    /// Maximum circuit size in megabytes. 0 disables this check.
    #[serde(default)]
    pub circ_max_megabytes: u64,
    /// Maximum circuit age in hours.
    #[serde(default = "default_circ_max_age_hours")]
    pub circ_max_age_hours: u32,
    /// Maximum HSDIR circuit size in kilobytes.
    #[serde(default = "default_circ_max_hsdesc_kilobytes")]
    pub circ_max_hsdesc_kilobytes: u32,
    /// Maximum service intro circuit size in kilobytes. 0 disables.
    #[serde(default)]
    pub circ_max_serv_intro_kilobytes: u32,
    /// Warn after this many seconds disconnected from circuits.
    #[serde(default = "default_circ_max_disconnected_secs")]
    pub circ_max_disconnected_secs: u32,
    /// Warn after this many seconds with no connections.
    #[serde(default = "default_conn_max_disconnected_secs")]
    pub conn_max_disconnected_secs: u32,
}

fn default_circ_max_age_hours() -> u32 {
    24
}
fn default_circ_max_hsdesc_kilobytes() -> u32 {
    30
}
fn default_circ_max_disconnected_secs() -> u32 {
    30
}
fn default_conn_max_disconnected_secs() -> u32 {
    15
}

impl Default for BandguardsConfig {
    fn default() -> Self {
        Self {
            circ_max_megabytes: 0,
            circ_max_age_hours: default_circ_max_age_hours(),
            circ_max_hsdesc_kilobytes: default_circ_max_hsdesc_kilobytes(),
            circ_max_serv_intro_kilobytes: 0,
            circ_max_disconnected_secs: default_circ_max_disconnected_secs(),
            conn_max_disconnected_secs: default_conn_max_disconnected_secs(),
        }
    }
}

/// Rendezvous point monitoring configuration options.
///
/// Controls detection of rendezvous point overuse attacks. These attacks attempt
/// to identify hidden services by observing which relays are frequently used as
/// rendezvous points.
///
/// # Attack Detection
///
/// Rendguard tracks rendezvous point usage and compares it to expected bandwidth
/// distribution:
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                Rendezvous Point Overuse Detection               │
/// └─────────────────────────────────────────────────────────────────┘
///
///   Expected Usage = Relay Bandwidth Weight / Total Network Bandwidth
///
///   Actual Usage = Times Used as Rend Point / Total Rend Point Uses
///
///   Overuse Ratio = Actual Usage / Expected Usage
///
///   If Overuse Ratio > use_max_use_to_bw_ratio:
///      └── Alert and optionally close circuits
/// ```
///
/// # Fields
///
/// | Field | Default | Description |
/// |-------|---------|-------------|
/// | `use_global_start_count` | 1000 | Min total uses before checking |
/// | `use_scale_at_count` | 20000 | Scale counts by half at this total |
/// | `use_relay_start_count` | 100 | Min relay uses before checking |
/// | `use_max_use_to_bw_ratio` | 5.0 | Max ratio of use to bandwidth |
/// | `use_max_consensus_weight_churn` | 1.0 | Max consensus weight churn % |
/// | `close_circuits_on_overuse` | true | Close circuits on overuse detection |
///
/// # Example
///
/// ```rust
/// use vanguards_rs::RendguardConfig;
///
/// let mut config = RendguardConfig::default();
///
/// // More aggressive detection
/// config.use_max_use_to_bw_ratio = 3.0;
///
/// // Require more samples before alerting
/// config.use_global_start_count = 2000;
/// config.use_relay_start_count = 200;
/// ```
///
/// # See Also
///
/// - [`Config`] - Main configuration struct
/// - [`RendGuard`](crate::RendGuard) - Runtime rendezvous tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RendguardConfig {
    /// Minimum total uses before checking for overuse.
    #[serde(default = "default_use_global_start_count")]
    pub use_global_start_count: u32,
    /// Scale counts by half when reaching this total.
    #[serde(default = "default_use_scale_at_count")]
    pub use_scale_at_count: u32,
    /// Minimum relay uses before checking for overuse.
    #[serde(default = "default_use_relay_start_count")]
    pub use_relay_start_count: u32,
    /// Maximum ratio of use to bandwidth weight.
    #[serde(default = "default_use_max_use_to_bw_ratio")]
    pub use_max_use_to_bw_ratio: f64,
    /// Maximum consensus weight churn percentage.
    #[serde(default = "default_use_max_consensus_weight_churn")]
    pub use_max_consensus_weight_churn: f64,
    /// Close circuits on rendezvous point overuse.
    #[serde(default = "default_close_circuits_on_overuse")]
    pub close_circuits_on_overuse: bool,
}

fn default_use_global_start_count() -> u32 {
    1000
}
fn default_use_scale_at_count() -> u32 {
    20000
}
fn default_use_relay_start_count() -> u32 {
    100
}
fn default_use_max_use_to_bw_ratio() -> f64 {
    5.0
}
fn default_use_max_consensus_weight_churn() -> f64 {
    1.0
}
fn default_close_circuits_on_overuse() -> bool {
    true
}

impl Default for RendguardConfig {
    fn default() -> Self {
        Self {
            use_global_start_count: default_use_global_start_count(),
            use_scale_at_count: default_use_scale_at_count(),
            use_relay_start_count: default_use_relay_start_count(),
            use_max_use_to_bw_ratio: default_use_max_use_to_bw_ratio(),
            use_max_consensus_weight_churn: default_use_max_consensus_weight_churn(),
            close_circuits_on_overuse: default_close_circuits_on_overuse(),
        }
    }
}

/// Log monitoring configuration options.
///
/// Controls Tor log buffering and protocol warning handling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogguardConfig {
    /// Enable ProtocolWarnings in Tor.
    #[serde(default = "default_protocol_warns")]
    pub protocol_warns: bool,
    /// Maximum number of log entries to buffer.
    #[serde(default = "default_dump_limit")]
    pub dump_limit: usize,
    /// Minimum log level to buffer.
    #[serde(default)]
    pub dump_level: LogLevel,
}

fn default_protocol_warns() -> bool {
    true
}
fn default_dump_limit() -> usize {
    25
}

impl Default for LogguardConfig {
    fn default() -> Self {
        Self {
            protocol_warns: default_protocol_warns(),
            dump_limit: default_dump_limit(),
            dump_level: LogLevel::Notice,
        }
    }
}

/// Main configuration struct for vanguards-rs.
///
/// This struct contains all configuration options for the vanguards-rs library
/// and CLI application. Configuration can be loaded from TOML files, command-line
/// arguments, and environment variables.
///
/// # Fields Overview
///
/// ## Connection Settings
///
/// | Field | Type | Default | Description |
/// |-------|------|---------|-------------|
/// | `control_ip` | `String` | `"127.0.0.1"` | Tor control port IP address |
/// | `control_port` | `Option<u16>` | `None` | Tor control port number |
/// | `control_socket` | `Option<PathBuf>` | `None` | Unix socket path (alternative to TCP) |
/// | `control_pass` | `Option<String>` | `None` | Control port password |
///
/// ## File Settings
///
/// | Field | Type | Default | Description |
/// |-------|------|---------|-------------|
/// | `state_file` | `PathBuf` | `"vanguards.state"` | Vanguard state persistence file |
///
/// ## Logging Settings
///
/// | Field | Type | Default | Description |
/// |-------|------|---------|-------------|
/// | `loglevel` | `LogLevel` | `Notice` | Log verbosity level |
/// | `logfile` | `Option<String>` | `None` | Log destination (file, `:syslog:`, or stdout) |
///
/// ## Component Toggles
///
/// | Field | Type | Default | Description |
/// |-------|------|---------|-------------|
/// | `enable_vanguards` | `bool` | `true` | Enable vanguard selection |
/// | `enable_bandguards` | `bool` | `true` | Enable bandwidth monitoring |
/// | `enable_rendguard` | `bool` | `true` | Enable rendezvous point monitoring |
/// | `enable_logguard` | `bool` | `true` | Enable log monitoring |
/// | `enable_cbtverify` | `bool` | `false` | Enable circuit build timeout verification |
/// | `enable_pathverify` | `bool` | `false` | Enable path verification |
///
/// ## Operational Settings
///
/// | Field | Type | Default | Description |
/// |-------|------|---------|-------------|
/// | `close_circuits` | `bool` | `true` | Close circuits on detected attacks |
/// | `one_shot_vanguards` | `bool` | `false` | Set vanguards and exit immediately |
/// | `retry_limit` | `Option<u32>` | `None` | Max reconnection attempts (None = infinite) |
///
/// # Example
///
/// ## Creating Default Configuration
///
/// ```rust
/// use vanguards_rs::Config;
///
/// let config = Config::default();
/// assert_eq!(config.control_ip, "127.0.0.1");
/// assert!(config.enable_vanguards);
/// ```
///
/// ## Loading from File
///
/// ```rust,no_run
/// use vanguards_rs::Config;
/// use std::path::Path;
///
/// let config = Config::from_file(Path::new("vanguards.conf"))?;
/// # Ok::<(), vanguards_rs::Error>(())
/// ```
///
/// ## Programmatic Configuration
///
/// ```rust
/// use vanguards_rs::{Config, LogLevel};
/// use std::path::PathBuf;
///
/// let mut config = Config::default();
/// config.control_port = Some(9051);
/// config.loglevel = LogLevel::Debug;
/// config.state_file = PathBuf::from("/var/lib/tor/vanguards.state");
/// config.enable_cbtverify = true;
///
/// // Validate before use
/// config.validate().expect("Invalid configuration");
/// ```
///
/// # Validation
///
/// Call [`validate()`](Config::validate) to check configuration consistency:
///
/// - Layer lifetime ranges must be valid (min ≤ max)
/// - Ratio values must be positive
/// - Churn values must be non-negative
///
/// # See Also
///
/// - [`VanguardsConfig`] - Vanguard-specific settings
/// - [`BandguardsConfig`] - Bandwidth monitoring settings
/// - [`RendguardConfig`] - Rendezvous point monitoring settings
/// - [`LogguardConfig`] - Log monitoring settings
/// - [`CliArgs`] - Command-line argument parsing
/// - [`load_config`] - Configuration loading function
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// IP address of the Tor control port.
    #[serde(default = "default_control_ip")]
    pub control_ip: String,
    /// Port number of the Tor control port.
    #[serde(default)]
    pub control_port: Option<u16>,
    /// Path to the Tor control socket.
    #[serde(default)]
    pub control_socket: Option<PathBuf>,
    /// Password for Tor control authentication.
    #[serde(default)]
    pub control_pass: Option<String>,
    /// Path to the vanguard state file.
    #[serde(default = "default_state_file")]
    pub state_file: PathBuf,
    /// Log level for output.
    #[serde(default)]
    pub loglevel: LogLevel,
    /// Log file path. None for stdout, ":syslog:" for syslog.
    #[serde(default)]
    pub logfile: Option<String>,
    /// Maximum reconnection attempts. None for infinite.
    #[serde(default)]
    pub retry_limit: Option<u32>,
    /// Set vanguards and exit immediately.
    #[serde(default)]
    pub one_shot_vanguards: bool,
    /// Close circuits on detected attacks.
    #[serde(default = "default_close_circuits")]
    pub close_circuits: bool,
    /// Enable vanguard selection.
    #[serde(default = "default_enable_vanguards")]
    pub enable_vanguards: bool,
    /// Enable bandwidth monitoring.
    #[serde(default = "default_enable_bandguards")]
    pub enable_bandguards: bool,
    /// Enable rendezvous point monitoring.
    #[serde(default = "default_enable_rendguard")]
    pub enable_rendguard: bool,
    /// Enable log monitoring.
    #[serde(default = "default_enable_logguard")]
    pub enable_logguard: bool,
    /// Enable circuit build timeout verification.
    #[serde(default)]
    pub enable_cbtverify: bool,
    /// Enable path verification.
    #[serde(default)]
    pub enable_pathverify: bool,
    /// Vanguard-specific configuration.
    #[serde(default)]
    pub vanguards: VanguardsConfig,
    /// Bandwidth monitoring configuration.
    #[serde(default)]
    pub bandguards: BandguardsConfig,
    /// Rendezvous point monitoring configuration.
    #[serde(default)]
    pub rendguard: RendguardConfig,
    /// Log monitoring configuration.
    #[serde(default)]
    pub logguard: LogguardConfig,
}

fn default_control_ip() -> String {
    "127.0.0.1".to_string()
}
fn default_state_file() -> PathBuf {
    PathBuf::from("vanguards.state")
}
fn default_close_circuits() -> bool {
    true
}
fn default_enable_vanguards() -> bool {
    true
}
fn default_enable_bandguards() -> bool {
    true
}
fn default_enable_rendguard() -> bool {
    true
}
fn default_enable_logguard() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control_ip: default_control_ip(),
            control_port: None,
            control_socket: None,
            control_pass: None,
            state_file: default_state_file(),
            loglevel: LogLevel::default(),
            logfile: None,
            retry_limit: None,
            one_shot_vanguards: false,
            close_circuits: default_close_circuits(),
            enable_vanguards: default_enable_vanguards(),
            enable_bandguards: default_enable_bandguards(),
            enable_rendguard: default_enable_rendguard(),
            enable_logguard: default_enable_logguard(),
            enable_cbtverify: false,
            enable_pathverify: false,
            vanguards: VanguardsConfig::default(),
            bandguards: BandguardsConfig::default(),
            rendguard: RendguardConfig::default(),
            logguard: LogguardConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read.
    /// Returns [`Error::Config`] if the TOML is invalid.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| Error::Config(e.to_string()))
    }

    /// Serialize configuration to TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if serialization fails.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }

    /// Validate configuration values.
    ///
    /// Checks that all configuration values are within acceptable ranges
    /// and that required fields are present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if validation fails.
    pub fn validate(&self) -> Result<()> {
        if self.vanguards.min_layer2_lifetime_hours > self.vanguards.max_layer2_lifetime_hours {
            return Err(Error::Config(
                "min_layer2_lifetime_hours must be <= max_layer2_lifetime_hours".to_string(),
            ));
        }
        if self.vanguards.min_layer3_lifetime_hours > self.vanguards.max_layer3_lifetime_hours {
            return Err(Error::Config(
                "min_layer3_lifetime_hours must be <= max_layer3_lifetime_hours".to_string(),
            ));
        }
        if self.rendguard.use_max_use_to_bw_ratio <= 0.0 {
            return Err(Error::Config(
                "use_max_use_to_bw_ratio must be positive".to_string(),
            ));
        }
        if self.rendguard.use_max_consensus_weight_churn < 0.0 {
            return Err(Error::Config(
                "use_max_consensus_weight_churn must be non-negative".to_string(),
            ));
        }
        Ok(())
    }

    /// Resolve hostname to IP address if control_ip is a domain name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if hostname resolution fails.
    pub fn resolve_control_ip(&mut self) -> Result<()> {
        if self.control_ip.parse::<IpAddr>().is_err() {
            let addr = format!("{}:0", self.control_ip)
                .to_socket_addrs()
                .map_err(|e| {
                    Error::Config(format!(
                        "failed to resolve hostname {}: {}",
                        self.control_ip, e
                    ))
                })?
                .next()
                .ok_or_else(|| {
                    Error::Config(format!(
                        "no addresses found for hostname {}",
                        self.control_ip
                    ))
                })?;
            self.control_ip = addr.ip().to_string();
        }
        Ok(())
    }
}

/// Command-line arguments for vanguards-rs.
///
/// This struct is used by clap to parse command-line arguments. Arguments override
/// configuration file values, allowing runtime customization without modifying config files.
///
/// # Configuration Precedence
///
/// Configuration is applied in the following order (later sources override earlier):
/// 1. Built-in defaults
/// 2. Configuration file (TOML)
/// 3. Environment variables (`VANGUARDS_STATE`, `VANGUARDS_CONFIG`)
/// 4. Command-line arguments
///
/// # Usage
///
/// ```text
/// vanguards-rs [OPTIONS]
/// ```
///
/// # Options
///
/// ## Connection Options
///
/// | Option | Description |
/// |--------|-------------|
/// | `--control-ip <IP>` | IP address of the Tor control port (default: 127.0.0.1) |
/// | `--control-port <PORT>` | Tor control port number (typically 9051) |
/// | `--control-socket <PATH>` | Path to Tor control socket (e.g., /run/tor/control) |
/// | `--control-pass <PASS>` | Tor control port password for authentication |
///
/// ## File Options
///
/// | Option | Description |
/// |--------|-------------|
/// | `--state <FILE>` | Path to the vanguard state file [env: VANGUARDS_STATE] |
/// | `--config <FILE>` | Path to configuration file [env: VANGUARDS_CONFIG] [default: vanguards.conf] |
/// | `--generate_config <FILE>` | Write default config to file and exit |
///
/// ## Logging Options
///
/// | Option | Description |
/// |--------|-------------|
/// | `--loglevel <LEVEL>` | Log verbosity: DEBUG, INFO, NOTICE, WARN, ERROR |
/// | `--logfile <FILE>` | Log to file instead of stdout (use ":syslog:" for syslog) |
///
/// ## Component Control
///
/// | Option | Description |
/// |--------|-------------|
/// | `--disable-vanguards` | Disable vanguard selection |
/// | `--disable-bandguards` | Disable bandwidth monitoring |
/// | `--disable-rendguard` | Disable rendezvous point monitoring |
/// | `--disable-logguard` | Disable log monitoring |
/// | `--enable-cbtverify` | Enable circuit build timeout verification |
/// | `--enable-pathverify` | Enable path verification |
///
/// ## Operational Options
///
/// | Option | Description |
/// |--------|-------------|
/// | `--retry-limit <N>` | Reconnection attempt limit (default: infinite) |
/// | `--one-shot-vanguards` | Set vanguards and exit immediately |
///
/// ## Help Options
///
/// | Option | Description |
/// |--------|-------------|
/// | `-h, --help` | Print help (see a summary with '-h') |
/// | `-V, --version` | Print version |
///
/// # Examples
///
/// Connect to Tor via control port:
/// ```bash
/// vanguards-rs --control-ip 127.0.0.1 --control-port 9051
/// ```
///
/// Connect via Unix socket with password:
/// ```bash
/// vanguards-rs --control-socket /run/tor/control --control-pass mypassword
/// ```
///
/// Generate a default configuration file:
/// ```bash
/// vanguards-rs --generate_config vanguards.conf
/// ```
///
/// Run with custom state file and debug logging:
/// ```bash
/// vanguards-rs --state /var/lib/tor/vanguards.state --loglevel DEBUG
/// ```
///
/// Disable specific components:
/// ```bash
/// vanguards-rs --disable-bandguards --disable-logguard
/// ```
///
/// One-shot mode (set vanguards and exit):
/// ```bash
/// vanguards-rs --one-shot-vanguards
/// ```
///
/// # Environment Variables
///
/// - `VANGUARDS_STATE`: Path to the vanguard state file (equivalent to `--state`)
/// - `VANGUARDS_CONFIG`: Path to configuration file (equivalent to `--config`)
///
/// # See Also
///
/// - [`Config`] for the full configuration structure
/// - [`load_config`] for the configuration loading function
#[derive(Parser, Debug)]
#[command(name = "vanguards-rs")]
#[command(about = "Enhanced security for Tor hidden services")]
#[command(version)]
#[command(
    long_about = "vanguards-rs provides enhanced security for Tor hidden services through \
    persistent vanguard relay selection, bandwidth monitoring, rendezvous point protection, \
    circuit build timeout verification, path verification, and log monitoring."
)]
pub struct CliArgs {
    /// Path to the vanguard state file.
    ///
    /// The state file stores persistent vanguard selections and rendguard statistics.
    /// If not specified, defaults to "vanguards.state" in the current directory.
    #[arg(long = "state", env = "VANGUARDS_STATE")]
    pub state_file: Option<PathBuf>,

    /// Write default config to file and exit.
    ///
    /// Generates a TOML configuration file with all default values and documentation.
    /// Useful for creating a starting point for customization.
    #[arg(long = "generate_config")]
    pub generate_config: Option<PathBuf>,

    /// Log verbosity (DEBUG, INFO, NOTICE, WARN, ERROR).
    ///
    /// Controls the amount of output. DEBUG is most verbose, ERROR is least.
    /// Default is NOTICE.
    #[arg(long)]
    pub loglevel: Option<String>,

    /// Log to file instead of stdout (use ":syslog:" for syslog).
    ///
    /// By default, logs go to stdout. Specify a file path to redirect logs,
    /// or use the special value ":syslog:" to send logs to the system logger.
    #[arg(long)]
    pub logfile: Option<String>,

    /// Path to configuration file.
    ///
    /// TOML configuration file containing all settings. Command-line arguments
    /// override values from this file.
    #[arg(
        long = "config",
        env = "VANGUARDS_CONFIG",
        default_value = "vanguards.conf"
    )]
    pub config_file: PathBuf,

    /// IP address of the Tor control port.
    ///
    /// Can be an IPv4 address, IPv6 address, or hostname (will be resolved).
    /// Default is 127.0.0.1.
    #[arg(long)]
    pub control_ip: Option<String>,

    /// Tor control port number.
    ///
    /// The TCP port where Tor's control interface is listening.
    /// Typically 9051 for the Tor daemon.
    #[arg(long)]
    pub control_port: Option<u16>,

    /// Path to Tor control socket.
    ///
    /// Unix domain socket path for Tor control connection.
    /// Takes precedence over TCP connection if specified.
    /// Common paths: /run/tor/control, /var/run/tor/control
    #[arg(long)]
    pub control_socket: Option<PathBuf>,

    /// Tor control port password.
    ///
    /// Password for HashedControlPassword authentication.
    /// If not provided and required, will prompt interactively.
    #[arg(long)]
    pub control_pass: Option<String>,

    /// Reconnection attempt limit (default: infinite).
    ///
    /// Maximum number of times to attempt reconnection to Tor after
    /// connection loss. Set to 0 for infinite retries.
    #[arg(long)]
    pub retry_limit: Option<u32>,

    /// Set vanguards and exit.
    ///
    /// Configure Tor with vanguard settings, save the configuration,
    /// and exit immediately. Useful for one-time setup.
    #[arg(long)]
    pub one_shot_vanguards: bool,

    /// Disable vanguard selection.
    ///
    /// Prevents vanguards-rs from selecting and configuring vanguard relays.
    /// Other monitoring components will still run if enabled.
    #[arg(long)]
    pub disable_vanguards: bool,

    /// Disable bandwidth monitoring.
    ///
    /// Disables the bandguards component that monitors circuit bandwidth
    /// for potential side-channel attacks.
    #[arg(long)]
    pub disable_bandguards: bool,

    /// Disable rendezvous point monitoring.
    ///
    /// Disables the rendguard component that monitors rendezvous point
    /// usage for statistical anomalies.
    #[arg(long)]
    pub disable_rendguard: bool,

    /// Disable log monitoring.
    ///
    /// Disables the logguard component that monitors Tor logs for
    /// security-relevant events.
    #[arg(long)]
    pub disable_logguard: bool,

    /// Enable circuit build timeout verification.
    ///
    /// Enables the cbtverify component that monitors circuit construction
    /// timing for anomalies. Disabled by default.
    #[arg(long)]
    pub enable_cbtverify: bool,

    /// Enable path verification.
    ///
    /// Enables the pathverify component that verifies circuit paths
    /// conform to vanguard configuration. Disabled by default.
    #[arg(long)]
    pub enable_pathverify: bool,
}

impl CliArgs {
    /// Apply CLI arguments to a configuration, overriding values.
    pub fn apply_to(&self, config: &mut Config) {
        if let Some(ref state_file) = self.state_file {
            config.state_file = state_file.clone();
        }
        if let Some(ref loglevel) = self.loglevel {
            if let Ok(level) = loglevel.parse() {
                config.loglevel = level;
            }
        }
        if let Some(ref logfile) = self.logfile {
            config.logfile = Some(logfile.clone());
        }
        if let Some(ref control_ip) = self.control_ip {
            config.control_ip = control_ip.clone();
        }
        if let Some(control_port) = self.control_port {
            config.control_port = Some(control_port);
        }
        if let Some(ref control_socket) = self.control_socket {
            config.control_socket = Some(control_socket.clone());
        }
        if let Some(ref control_pass) = self.control_pass {
            config.control_pass = Some(control_pass.clone());
        }
        if let Some(retry_limit) = self.retry_limit {
            config.retry_limit = Some(retry_limit);
        }
        if self.one_shot_vanguards {
            config.one_shot_vanguards = true;
        }
        if self.disable_vanguards {
            config.enable_vanguards = false;
        }
        if self.disable_bandguards {
            config.enable_bandguards = false;
        }
        if self.disable_rendguard {
            config.enable_rendguard = false;
        }
        if self.disable_logguard {
            config.enable_logguard = false;
        }
        if self.enable_cbtverify {
            config.enable_cbtverify = true;
        }
        if self.enable_pathverify {
            config.enable_pathverify = true;
        }
    }
}

/// Load configuration from file and CLI arguments.
///
/// This function implements the configuration loading order:
/// 1. Start with defaults
/// 2. Apply config file if it exists
/// 3. Apply CLI arguments (override)
///
/// # Errors
///
/// Returns [`Error::Config`] if configuration is invalid.
pub fn load_config(args: &CliArgs) -> Result<Config> {
    let mut config = Config::default();

    if args.config_file.exists() {
        config = Config::from_file(&args.config_file)?;
    }

    args.apply_to(&mut config);
    config.resolve_control_ip()?;
    config.validate()?;

    Ok(config)
}
