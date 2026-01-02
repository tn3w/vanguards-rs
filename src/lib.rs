//! # vanguards-rs
//!
//! A Rust implementation of the Python vanguards library for enhanced Tor hidden service security.
//!
//! # Overview
//!
//! vanguards-rs provides protection against guard discovery attacks through persistent
//! vanguard relay selection, and additional protections through multiple security components:
//!
//! - **Vanguard Selection** ([`vanguards`]): Persistent layer2/layer3 guard selection
//! - **Bandwidth Monitoring** ([`bandguards`]): Detect bandwidth-based side-channel attacks
//! - **Rendezvous Point Analysis** ([`rendguard`]): Detect statistical attacks on rendezvous points
//! - **Log Monitoring** ([`logguard`]): Monitor Tor logs for security-relevant events
//! - **Circuit Build Timeout Verification** ([`cbtverify`]): Verify circuit construction timing
//! - **Path Verification** ([`pathverify`]): Verify circuit paths conform to vanguard configuration
//!
//! ## Module Overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`api`] | High-level [`Vanguards`] struct for programmatic use |
//! | [`config`] | Configuration management (TOML, CLI, environment) |
//! | [`error`] | Error types and [`Result`] alias |
//! | [`control`] | Main event loop and Tor connection management |
//! | [`vanguards`] | Vanguard state and guard selection |
//! | [`bandguards`] | Bandwidth monitoring and attack detection |
//! | [`rendguard`] | Rendezvous point usage tracking |
//! | [`logguard`] | Tor log monitoring and buffering |
//! | [`cbtverify`] | Circuit build timeout verification |
//! | [`pathverify`] | Circuit path verification |
//! | [`node_selection`] | Bandwidth-weighted relay selection |
//! | [`logger`] | Logging infrastructure using tracing |
//!
//! # What This Library Does NOT Do
//!
//! - **Direct relay communication**: Use [`stem_rs::client`] for ORPort connections
//! - **Descriptor parsing**: Use [`stem_rs::descriptor`] module
//! - **Exit policy evaluation**: Use [`stem_rs::exit_policy`]
//! - **Running a Tor relay**: This library protects hidden services, not relays
//! - **Onion service creation**: Use Tor's `ADD_ONION` command via stem-rs
//!
//! # Quick Start
//!
//! ## As a Library
//!
//! ```rust,no_run
//! use vanguards_rs::{Config, Vanguards};
//!
//! #[tokio::main]
//! async fn main() -> vanguards_rs::Result<()> {
//!     // Load configuration
//!     let config = Config::default();
//!     
//!     // Create and run vanguards protection
//!     let mut vanguards = Vanguards::from_config(config).await?;
//!     vanguards.run().await
//! }
//! ```
//!
//! ## As a CLI Application
//!
//! ```bash
//! # Run with default settings
//! vanguards-rs
//!
//! # Connect to specific control port
//! vanguards-rs --control-ip 127.0.0.1 --control-port 9051
//!
//! # Use Unix socket with custom state file
//! vanguards-rs --control-socket /run/tor/control --state /var/lib/tor/vanguards.state
//!
//! # Generate default configuration file
//! vanguards-rs --generate_config vanguards.conf
//! ```
//!
//! # Configuration
//!
//! Configuration can be loaded from multiple sources in order of precedence:
//!
//! ```text
//! ┌─────────────────┐
//! │   CLI Arguments │ ◄── Highest priority (overrides all)
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │   Environment   │ ◄── VANGUARDS_STATE, VANGUARDS_CONFIG
//! │    Variables    │
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │   Config File   │ ◄── TOML file (default: vanguards.conf)
//! │     (TOML)      │
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │    Defaults     │ ◄── Sensible defaults for all options
//! └─────────────────┘
//! ```
//!
//! See [`Config`] for all available options.
//!
//! # State File Compatibility
//!
//! State files are compatible with Python vanguards for seamless migration.
//! The library reads and writes Python pickle format state files, allowing
//! you to switch between Python vanguards and vanguards-rs without losing
//! your guard selections.
//!
//! # Security Considerations
//!
//! - **Memory Safety**: Passwords are cleared from memory after use (using zeroize)
//! - **File Permissions**: State files are written with restrictive permissions (0600)
//! - **Input Validation**: All external inputs are validated before use
//! - **Error Handling**: Error messages do not leak sensitive information
//! - **Guard Persistence**: Vanguard selections persist across restarts to prevent
//!   guard discovery through restart attacks
//!
//! # See Also
//!
//! - [Python vanguards](https://github.com/mikeperry-tor/vanguards) - Original Python implementation
//! - [stem-rs documentation](https://stem.tn3w.dev/docs/) - Tor control library used by vanguards-rs
//! - [Tor Control Protocol Specification](https://spec.torproject.org/control-spec) - Protocol reference
//! - [Vanguards Specification](https://github.com/torproject/torspec/blob/main/proposals/292-mesh-vanguards.txt) - Tor proposal 292
//! - [Guard Discovery Attacks](https://www.freehaven.net/anonbib/cache/wpes12-cogs.pdf) - Academic paper on the attacks vanguards mitigates

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

pub mod api;
pub mod bandguards;
pub mod cbtverify;
pub mod config;
pub mod control;
pub mod error;
pub mod logger;
pub mod logguard;
pub mod node_selection;
pub mod pathverify;
pub mod rendguard;
pub mod vanguards;

pub use api::{SecurePassword, Vanguards};
pub use bandguards::{
    BandwidthStats, BwCircuitStat, BwGuardStat, CircuitLimitResult, ConnectivityStatus,
    CELL_PAYLOAD_SIZE, MAX_CIRC_DESTROY_LAG_SECS, RELAY_HEADER_SIZE, RELAY_PAYLOAD_SIZE,
};
pub use cbtverify::{CircuitStat, TimeoutStats};
pub use config::{
    BandguardsConfig, CliArgs, Config, LogLevel, LogguardConfig, RendguardConfig, VanguardsConfig,
};
pub use error::{Error, Result};
pub use logguard::{LogEntry, LogGuard};
pub use node_selection::{
    is_valid_country_code, is_valid_fingerprint, is_valid_ip_or_network, BwWeightedGenerator,
    FlagsRestriction, NodeRestriction, NodeRestrictionList, Position,
};
pub use pathverify::{
    Layer1Guards, Layer1Stats, PathVerify, ROUTELEN_FOR_PURPOSE, ROUTELEN_FOR_PURPOSE_LITE,
};
pub use rendguard::{RendCheckResult, NOT_IN_CONSENSUS_ID};
pub use vanguards::{ExcludeNodes, GuardNode, RendGuard, RendUseCount, VanguardState};

pub use control::{
    authenticate_any, configure_tor, control_loop, get_close_circuits, get_consensus_weights,
    new_consensus_event, run_main, set_close_circuits, signal_event, try_close_circuit, AppState,
    VERSION,
};
