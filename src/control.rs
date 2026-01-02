//! Control module for Tor controller interaction and main application loop.
//!
//! This module provides the core functionality for connecting to Tor's control port,
//! authenticating, handling events, and managing the vanguard protection lifecycle.
//!
//! # Overview
//!
//! The control module handles:
//!
//! - **Connection Management**: Connect via TCP or Unix socket with auto-detection
//! - **Authentication**: Password, cookie, and interactive authentication
//! - **Consensus Processing**: Parse consensus weights and update vanguard state
//! - **Event Handling**: Register and dispatch events to protection components
//! - **Circuit Management**: Close circuits when attacks are detected
//! - **Signal Handling**: Handle SIGHUP for configuration reload
//!
//! # Architecture
//!
//! The control module orchestrates all protection components through a central event loop:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────────┐
//! │                         Main Event Loop                                  │
//! │                                                                          │
//! │  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────┐  │
//! │  │  Tor Control │───▶│   Event      │───▶│   Protection Components  │  │
//! │  │    Socket    │    │  Dispatcher  │      │                          │  │
//! │  └──────────────┘    └──────────────┘      │  ┌────────────────────┐  │  │
//! │         │                   │              │  │ VanguardState      │  │  │
//! │         │                   │              │  │ (guard management) │  │  │
//! │         ▼                   │              │  └────────────────────┘  │  │
//! │  ┌──────────────┐           │              │  ┌────────────────────┐  │  │
//! │  │ Authenticate │           │              │  │ BandwidthStats     │  │  │
//! │  │ (password/   │           │              │  │ (attack detection) │  │  │
//! │  │  cookie)     │           │              │  └────────────────────┘  │  │
//! │  └──────────────┘           │              │  ┌────────────────────┐  │  │
//! │                             │              │  │ RendGuard          │  │  │
//! │                             │              │  │ (RP monitoring)    │  │  │
//! │                             │              │  └────────────────────┘  │  │
//! │                             │              │  ┌────────────────────┐  │  │
//! │                             │              │  │ PathVerify         │  │  │
//! │                             │              │  │ (path validation)  │  │  │
//! │                             │              │  └────────────────────┘  │  │
//! │                             │              └──────────────────────────┘  │
//! │                             │                                            │
//! │                             ▼                                            │
//! │                    ┌──────────────────┐                                  │
//! │                    │ Circuit Actions  │                                  │
//! │                    │ (close on attack)│                                  │
//! │                    └──────────────────┘                                  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Main Loop Flow
//!
//! The main application loop follows this sequence:
//!
//! ```text
//!                    ┌─────────────────┐
//!                    │     Start       │
//!                    └────────┬────────┘
//!                             │
//!                             ▼
//!                    ┌─────────────────┐
//!                    │ Connect to Tor  │◀──────────────────┐
//!                    │ (socket/port)   │                   │
//!                    └────────┬────────┘                   │
//!                             │                            │
//!                             ▼                            │
//!                    ┌─────────────────┐                   │
//!                    │  Authenticate   │                   │
//!                    │ (auto-detect)   │                   │
//!                    └────────┬────────┘                   │
//!                             │                            │
//!                             ▼                            │
//!                    ┌─────────────────┐                   │
//!                    │ Load/Create     │                   │
//!                    │ Vanguard State  │                   │
//!                    └────────┬────────┘                   │
//!                             │                            │
//!                             ▼                            │
//!                    ┌─────────────────┐                   │
//!                    │ Subscribe to    │                   │
//!                    │ Tor Events      │                   │
//!                    └────────┬────────┘                   │
//!                             │                            │
//!                             ▼                            │
//!              ┌──────────────────────────────┐            │
//!              │      Event Processing Loop   │            │
//!              │  ┌────────────────────────┐  │            │
//!              │  │ Receive Event          │  │            │
//!              │  └───────────┬────────────┘  │            │
//!              │              │               │            │
//!              │              ▼               │            │
//!              │  ┌────────────────────────┐  │            │
//!              │  │ Dispatch to Handlers   │  │            │
//!              │  │ (CIRC, CIRC_BW, etc.)  │  │            │
//!              │  └───────────┬────────────┘  │            │
//!              │              │               │            │
//!              │              ▼               │            │
//!              │  ┌────────────────────────┐  │            │
//!              │  │ Check Circuit Limits   │  │            │
//!              │  │ (close if attack)      │  │            │
//!              │  └───────────┬────────────┘  │            │
//!              │              │               │            │
//!              │              ▼               │            │
//!              │         [Continue]           │            │
//!              └──────────────┬───────────────┘            │
//!                             │                            │
//!                    [Connection Lost]                     │
//!                             │                            │
//!                             ▼                            │
//!                    ┌─────────────────┐                   │
//!                    │ Reconnect?      │───────────────────┘
//!                    │ (retry limit)   │
//!                    └────────┬────────┘
//!                             │ [Limit Reached]
//!                             ▼
//!                    ┌─────────────────┐
//!                    │      Exit       │
//!                    └─────────────────┘
//! ```
//!
//! # Event Handling State Diagram
//!
//! Events are dispatched to different handlers based on type:
//!
//! ```text
//!                         ┌─────────────┐
//!                         │ Tor Event   │
//!                         └──────┬──────┘
//!                                │
//!          ┌─────────────────────┼─────────────────────┐
//!          │                     │                     │
//!          ▼                     ▼                     ▼
//!    ┌───────────┐        ┌───────────┐        ┌───────────┐
//!    │   CIRC    │        │  CIRC_BW  │        │ NEWCONSENS│
//!    └─────┬─────┘        └─────┬─────┘        └─────┬─────┘
//!          │                    │                    │
//!          ▼                    ▼                    ▼
//!    ┌───────────┐        ┌───────────┐        ┌───────────┐
//!    │RendGuard  │        │BandGuards │        │ Update    │
//!    │BandGuards │        │(bandwidth │        │ Vanguard  │
//!    │CBTVerify  │        │ tracking) │        │ State     │
//!    │PathVerify │        └───────────┘        └───────────┘
//!    │LogGuard   │
//!    └───────────┘
//!
//!          ┌─────────────────────┼─────────────────────┐
//!          │                     │                     │
//!          ▼                     ▼                     ▼
//!    ┌───────────┐        ┌───────────┐        ┌───────────┐
//!    │  ORCONN   │        │   GUARD   │        │  SIGNAL   │
//!    └─────┬─────┘        └─────┬─────┘        └─────┬─────┘
//!          │                    │                    │
//!          ▼                    ▼                    ▼
//!    ┌───────────┐        ┌───────────┐        ┌───────────┐
//!    │BandGuards │        │PathVerify │        │ Reapply   │
//!    │PathVerify │        │(guard     │        │ Vanguards │
//!    │(conn      │        │ tracking) │        │ (SIGHUP)  │
//!    │ tracking) │        └───────────┘        └───────────┘
//!    └───────────┘
//! ```
//!
//! # What This Module Does NOT Do
//!
//! - **Direct relay communication**: Use stem-rs client module for ORPort connections
//! - **Descriptor parsing**: Consensus parsing is limited to bandwidth weights
//! - **Guard selection**: Use [`crate::node_selection`] for bandwidth-weighted selection
//! - **State persistence**: Use [`crate::vanguards::VanguardState`] for state file I/O
//!
//! # Example
//!
//! Running the main application loop:
//!
//! ```rust,no_run
//! use vanguards_rs::config::Config;
//! use vanguards_rs::control::run_main;
//!
//! # async fn example() -> Result<(), vanguards_rs::error::Error> {
//! // Load configuration
//! let config = Config::default();
//!
//! // Run the main loop (blocks until shutdown)
//! run_main(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - Passwords are prompted interactively if not provided (never logged)
//! - Circuit closure decisions are logged for audit purposes
//! - State files contain guard fingerprints (protect accordingly)
//! - Reconnection attempts are rate-limited to prevent DoS
//!
//! # See Also
//!
//! - [`crate::config`] - Configuration management
//! - [`crate::vanguards`] - Vanguard state management
//! - [`crate::bandguards`] - Bandwidth-based attack detection
//! - [`crate::rendguard`] - Rendezvous point monitoring
//! - [`crate::pathverify`] - Circuit path verification
//! - [Python vanguards control](https://github.com/mikeperry-tor/vanguards) - Original implementation
//! - [Tor Control Protocol](https://spec.torproject.org/control-spec) - Protocol specification

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use stem_rs::controller::{CircuitId, Controller};
use stem_rs::descriptor::router_status::RouterStatusEntry;
use stem_rs::events::ParsedEvent;
use stem_rs::version::Version;
use stem_rs::EventType;

use crate::bandguards::BandwidthStats;
use crate::cbtverify::TimeoutStats;
use crate::config::{Config, LogLevel};
use crate::error::{Error, Result};
use crate::logger::plog;
use crate::logguard::LogGuard;
use crate::node_selection::{BwWeightedGenerator, FlagsRestriction, NodeRestrictionList, Position};
use crate::pathverify::PathVerify;
use crate::vanguards::{ExcludeNodes, VanguardState};

/// Library version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Minimum Tor version required for CIRC_BW and CIRC_MINOR events.
#[allow(dead_code)]
const MIN_TOR_VERSION_FOR_BW: &str = "0.3.4.10";

/// Minimum Tor version required for HSLayer2Nodes support.
#[allow(dead_code)]
const MIN_TOR_VERSION_FOR_VANGUARDS: &str = "0.3.3.0";

/// Global flag for close circuits configuration.
///
/// When true, detected attacks will result in circuit closure.
/// When false, attacks are logged but circuits remain open (monitoring mode).
static CLOSE_CIRCUITS: AtomicBool = AtomicBool::new(true);

/// Sets the global close circuits flag.
///
/// Controls whether circuits are actually closed when attacks are detected.
/// Set to `false` for monitoring-only mode where attacks are logged but
/// circuits are not closed.
///
/// # Arguments
///
/// * `value` - `true` to enable circuit closure, `false` for monitoring only
///
/// # Thread Safety
///
/// This function uses atomic operations and is safe to call from any thread.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::control::{set_close_circuits, get_close_circuits};
///
/// // Enable monitoring-only mode
/// set_close_circuits(false);
/// assert!(!get_close_circuits());
///
/// // Re-enable circuit closure
/// set_close_circuits(true);
/// assert!(get_close_circuits());
/// ```
pub fn set_close_circuits(value: bool) {
    CLOSE_CIRCUITS.store(value, Ordering::SeqCst);
}

/// Gets the global close circuits flag.
///
/// Returns whether circuits will be closed when attacks are detected.
///
/// # Returns
///
/// `true` if circuit closure is enabled, `false` if in monitoring-only mode.
///
/// # Thread Safety
///
/// This function uses atomic operations and is safe to call from any thread.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::control::get_close_circuits;
///
/// if get_close_circuits() {
///     println!("Circuit closure is enabled");
/// } else {
///     println!("Monitoring-only mode");
/// }
/// ```
pub fn get_close_circuits() -> bool {
    CLOSE_CIRCUITS.load(Ordering::SeqCst)
}

/// Authenticates with Tor using any available method.
///
/// Attempts authentication in this order:
/// 1. No authentication (if control port is open)
/// 2. Password authentication (if provided)
/// 3. Cookie authentication
///
/// If password authentication fails and no password was provided,
/// prompts the user interactively for a password.
///
/// # Arguments
///
/// * `controller` - The Tor controller to authenticate
/// * `password` - Optional password for authentication
///
/// # Errors
///
/// Returns [`Error::Control`] if authentication fails.
pub async fn authenticate_any(controller: &mut Controller, password: Option<&str>) -> Result<()> {
    let result = controller.authenticate(password).await;

    match result {
        Ok(()) => {
            let version = controller.get_version().await?;
            plog(
                LogLevel::Notice,
                &format!(
                    "Vanguards {} connected to Tor {} using stem-rs",
                    VERSION, version
                ),
            );
            Ok(())
        }
        Err(stem_rs::Error::Authentication(stem_rs::AuthError::MissingPassword)) => {
            // Prompt for password interactively
            let passwd = prompt_password()?;
            controller.authenticate(Some(&passwd)).await?;
            let version = controller.get_version().await?;
            plog(
                LogLevel::Notice,
                &format!(
                    "Vanguards {} connected to Tor {} using stem-rs",
                    VERSION, version
                ),
            );
            Ok(())
        }
        Err(e) => Err(Error::Control(e)),
    }
}

/// Prompts the user for a password interactively.
fn prompt_password() -> Result<String> {
    eprint!("Controller password: ");
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .map_err(Error::Io)?;
    Ok(password.trim().to_string())
}

/// Parses consensus bandwidth weights from a cached-microdesc-consensus file.
///
/// Bandwidth weights are used by Tor clients to select relays proportionally
/// to their contribution to the network. These weights are essential for
/// the bandwidth-weighted guard selection algorithm.
///
/// # Weight Keys
///
/// Common weight keys include:
///
/// | Key | Description |
/// |-----|-------------|
/// | `Wgg` | Weight for Guard-flagged nodes in guard position |
/// | `Wgm` | Weight for Guard-flagged nodes in middle position |
/// | `Wmm` | Weight for non-flagged nodes in middle position |
/// | `Wme` | Weight for Exit-flagged nodes in middle position |
/// | `Wee` | Weight for Exit-flagged nodes in exit position |
///
/// # Arguments
///
/// * `consensus_filename` - Path to the cached-microdesc-consensus file
///
/// # Returns
///
/// A HashMap mapping weight keys (e.g., "Wmm") to their integer values
/// (typically in range 0-10000, representing parts per 10000).
///
/// # Errors
///
/// Returns [`Error::Consensus`] if:
/// - The file cannot be opened or read
/// - No `bandwidth-weights` line is found in the file
///
/// # File Format
///
/// The function looks for a line starting with `bandwidth-weights ` followed
/// by space-separated key=value pairs:
///
/// ```text
/// bandwidth-weights Wbd=0 Wbe=0 Wbg=4194 Wbm=10000 ...
/// ```
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
/// use vanguards_rs::control::get_consensus_weights;
///
/// # fn example() -> Result<(), vanguards_rs::error::Error> {
/// let weights = get_consensus_weights(Path::new("/var/lib/tor/cached-microdesc-consensus"))?;
///
/// if let Some(wmm) = weights.get("Wmm") {
///     println!("Middle position weight: {}", wmm);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`BwWeightedGenerator`] - Uses these weights
/// - [dir-spec.txt](https://spec.torproject.org/dir-spec) - Consensus format specification
pub fn get_consensus_weights(consensus_filename: &Path) -> Result<HashMap<String, i64>> {
    let file = std::fs::File::open(consensus_filename).map_err(|e| {
        Error::Consensus(format!(
            "cannot read {}: {}",
            consensus_filename.display(),
            e
        ))
    })?;
    let reader = BufReader::new(file);

    let mut weights = HashMap::new();

    for line in reader.lines() {
        let line = line.map_err(|e| Error::Consensus(format!("read error: {}", e)))?;
        if line.starts_with("bandwidth-weights ") {
            // Parse bandwidth-weights line
            // Format: bandwidth-weights Wbd=0 Wbe=0 Wbg=4194 Wbm=10000 ...
            for part in line.split_whitespace().skip(1) {
                if let Some((key, value)) = part.split_once('=') {
                    if let Ok(v) = value.parse::<i64>() {
                        weights.insert(key.to_string(), v);
                    }
                }
            }
            break;
        }
    }

    if weights.is_empty() {
        return Err(Error::Consensus(
            "no bandwidth-weights found in consensus".to_string(),
        ));
    }

    Ok(weights)
}

/// Attempts to close a circuit, optionally dumping logs first.
///
/// This function is called when an attack is detected and a circuit needs
/// to be closed. If logguard is enabled, it dumps the log queue for the
/// circuit before closing to aid in post-incident analysis.
///
/// # Arguments
///
/// * `controller` - The Tor controller
/// * `circ_id` - The circuit ID to close
/// * `logguard` - Optional log guard for pre-close log dumping
///
/// # Behavior
///
/// 1. If logguard is provided, dumps buffered logs for the circuit
/// 2. If `close_circuits` global flag is true, sends CLOSECIRCUIT command
/// 3. Logs success or failure of the close operation
///
/// # Global Flag
///
/// The `close_circuits` flag (set via [`set_close_circuits`]) controls whether
/// circuits are actually closed. When false, the function logs but doesn't close.
/// This is useful for testing or monitoring-only mode.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::controller::Controller;
/// use vanguards_rs::control::try_close_circuit;
///
/// # async fn example() -> Result<(), vanguards_rs::error::Error> {
/// let mut controller = Controller::from_port("127.0.0.1:9051".parse().unwrap()).await?;
/// controller.authenticate(None).await?;
///
/// // Close circuit without log dumping
/// try_close_circuit(&mut controller, "42", None).await;
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`set_close_circuits`] - Control whether circuits are actually closed
/// - [`LogGuard::dump_log_queue`] - Log dumping implementation
pub async fn try_close_circuit(
    controller: &mut Controller,
    circ_id: &str,
    logguard: Option<&mut LogGuard>,
) {
    // Dump logs before closing
    if let Some(lg) = logguard {
        lg.dump_log_queue(circ_id, "Pre");
    }

    if get_close_circuits() {
        let circuit_id = CircuitId::new(circ_id);
        match controller.close_circuit(&circuit_id).await {
            Ok(()) => {
                plog(
                    LogLevel::Info,
                    &format!("We force-closed circuit {}", circ_id),
                );
            }
            Err(e) => {
                plog(
                    LogLevel::Info,
                    &format!("Failed to close circuit {}: {}", circ_id, e),
                );
            }
        }
    }
}

/// Configures Tor with the current vanguard settings.
///
/// Sets Tor configuration options to enforce the vanguard guard layers.
/// This function is called after vanguard state is updated to apply
/// the new guard sets to Tor.
///
/// # Configuration Options Set
///
/// | Option | Description | Condition |
/// |--------|-------------|-----------|
/// | `NumEntryGuards` | Number of layer 1 guards | If > 0 |
/// | `NumDirectoryGuards` | Number of directory guards | If > 0 |
/// | `GuardLifetime` | Layer 1 guard lifetime | If > 0 days |
/// | `HSLayer2Nodes` | Layer 2 guard fingerprints | Always |
/// | `HSLayer3Nodes` | Layer 3 guard fingerprints | If num_layer3 > 0 |
///
/// # Arguments
///
/// * `controller` - The Tor controller
/// * `state` - The current vanguard state containing guard sets
/// * `config` - The vanguards configuration
///
/// # Returns
///
/// Returns `Ok(())` on successful configuration.
///
/// # Errors
///
/// Returns [`Error::Control`] if Tor configuration fails. This typically
/// indicates an incompatible Tor version (requires 0.3.3.x or newer).
///
/// # Tor Version Requirements
///
/// - `HSLayer2Nodes`: Requires Tor 0.3.3.0+
/// - `HSLayer3Nodes`: Requires Tor 0.3.3.0+
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::controller::Controller;
/// use vanguards_rs::vanguards::VanguardState;
/// use vanguards_rs::config::Config;
/// use vanguards_rs::control::configure_tor;
///
/// # async fn example() -> Result<(), vanguards_rs::error::Error> {
/// let mut controller = Controller::from_port("127.0.0.1:9051".parse().unwrap()).await?;
/// controller.authenticate(None).await?;
///
/// let state = VanguardState::new("/tmp/vanguards.state");
/// let config = Config::default();
///
/// configure_tor(&mut controller, &state, &config).await?;
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`VanguardState::layer2_guardset`] - Get layer 2 fingerprint string
/// - [`VanguardState::layer3_guardset`] - Get layer 3 fingerprint string
pub async fn configure_tor(
    controller: &mut Controller,
    state: &VanguardState,
    config: &Config,
) -> Result<()> {
    let vg_config = &config.vanguards;

    // Set NumEntryGuards and NumDirectoryGuards if configured
    if vg_config.num_layer1_guards > 0 {
        controller
            .set_conf("NumEntryGuards", &vg_config.num_layer1_guards.to_string())
            .await?;
        controller
            .set_conf(
                "NumDirectoryGuards",
                &vg_config.num_layer1_guards.to_string(),
            )
            .await?;
    }

    // Set GuardLifetime if configured
    if vg_config.layer1_lifetime_days > 0 {
        controller
            .set_conf(
                "GuardLifetime",
                &format!("{} days", vg_config.layer1_lifetime_days),
            )
            .await?;
    }

    // Set HSLayer2Nodes
    let layer2_guardset = state.layer2_guardset();
    controller
        .set_conf("HSLayer2Nodes", &layer2_guardset)
        .await
        .inspect_err(|_e| {
            plog(
                LogLevel::Error,
                "Vanguards requires Tor 0.3.3.x (and ideally 0.3.4.x or newer).",
            );
        })?;

    // Set HSLayer3Nodes if configured
    if vg_config.num_layer3_guards > 0 {
        let layer3_guardset = state.layer3_guardset();
        controller
            .set_conf("HSLayer3Nodes", &layer3_guardset)
            .await?;
    }

    plog(
        LogLevel::Info,
        &format!("Layer2 guards: {}", layer2_guardset),
    );
    if vg_config.num_layer3_guards > 0 {
        plog(
            LogLevel::Info,
            &format!("Layer3 guards: {}", state.layer3_guardset()),
        );
    }

    Ok(())
}

/// Handles a new consensus event by updating vanguard state.
///
/// This function is called when a new consensus is received from Tor. It performs
/// a complete update cycle for all protection components.
///
/// # Processing Steps
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │                  new_consensus_event()                       │
/// │                                                              │
/// │  1. Get router list from Tor (GETINFO ns/all)               │
/// │  2. Get ExcludeNodes configuration                          │
/// │  3. Parse consensus weights from cached-microdesc-consensus │
/// │  4. Update vanguard state:                                  │
/// │     • Remove guards no longer in consensus                  │
/// │     • Remove expired guards                                 │
/// │     • Remove excluded guards                                │
/// │     • Replenish guard layers                                │
/// │  5. Update rendguard use counts                             │
/// │  6. Configure Tor with new HSLayer2/3Nodes                  │
/// │  7. Write state to file                                     │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// # Arguments
///
/// * `controller` - The Tor controller for querying and configuration
/// * `state` - The vanguard state to update
/// * `config` - The vanguards configuration
///
/// # Returns
///
/// Returns `Ok(())` on successful update.
///
/// # Errors
///
/// - [`Error::DescriptorUnavailable`] - Tor doesn't have descriptors yet (retry later)
/// - [`Error::Consensus`] - Failed to parse consensus file
/// - [`Error::Config`] - DataDirectory not configured in Tor
/// - [`Error::Control`] - Failed to configure Tor
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::controller::Controller;
/// use vanguards_rs::vanguards::VanguardState;
/// use vanguards_rs::config::Config;
/// use vanguards_rs::control::new_consensus_event;
///
/// # async fn example() -> Result<(), vanguards_rs::error::Error> {
/// let mut controller = Controller::from_port("127.0.0.1:9051".parse().unwrap()).await?;
/// controller.authenticate(None).await?;
///
/// let mut state = VanguardState::new("/tmp/vanguards.state");
/// let config = Config::default();
///
/// new_consensus_event(&mut controller, &mut state, &config).await?;
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`get_consensus_weights`] - Consensus weight parsing
/// - [`configure_tor`] - Tor configuration
/// - [`VanguardState::replenish_layers`] - Guard replenishment
pub async fn new_consensus_event(
    controller: &mut Controller,
    state: &mut VanguardState,
    config: &Config,
) -> Result<()> {
    // Get routers from Tor
    let routers = get_network_statuses(controller).await?;

    // Get ExcludeNodes configuration
    let exclude_nodes_conf = controller
        .get_conf("ExcludeNodes")
        .await
        .ok()
        .and_then(|v| v.first().cloned())
        .unwrap_or_default();
    let geoip_exclude = controller
        .get_conf("GeoIPExcludeUnknown")
        .await
        .ok()
        .and_then(|v| v.first().cloned());
    let exclude = ExcludeNodes::parse(&exclude_nodes_conf, geoip_exclude.as_deref());

    // Get DataDirectory for consensus file
    let data_dir = controller
        .get_conf("DataDirectory")
        .await?
        .first()
        .cloned()
        .ok_or_else(|| {
            Error::Config("You must set a DataDirectory location option in your torrc.".to_string())
        })?;

    let consensus_file = Path::new(&data_dir).join("cached-microdesc-consensus");
    let weights = get_consensus_weights(&consensus_file)?;

    // Update vanguard state
    consensus_update(state, &routers, &weights, &exclude, config)?;

    // Configure Tor if vanguards enabled
    if config.enable_vanguards {
        configure_tor(controller, state, config).await?;
    }

    // Write state to file
    let state_path = Path::new(&state.state_file);
    state.write_to_file(state_path).map_err(|e| {
        plog(
            LogLevel::Error,
            &format!("Cannot write state to {}: {}", state.state_file, e),
        );
        e
    })?;

    Ok(())
}

/// Updates vanguard state based on new consensus.
fn consensus_update(
    state: &mut VanguardState,
    routers: &[RouterStatusEntry],
    weights: &HashMap<String, i64>,
    exclude: &ExcludeNodes,
    config: &Config,
) -> Result<()> {
    // Sort routers by measured bandwidth
    let mut sorted_routers: Vec<RouterStatusEntry> = routers.to_vec();
    sorted_routers.sort_by(|a, b| {
        let bw_a = a.measured.or(a.bandwidth).unwrap_or(0);
        let bw_b = b.measured.or(b.bandwidth).unwrap_or(0);
        bw_b.cmp(&bw_a)
    });

    // Create router map for lookups
    let router_map: HashMap<String, &RouterStatusEntry> = sorted_routers
        .iter()
        .map(|r| (r.fingerprint.clone(), r))
        .collect();

    // Create consensus fingerprint set
    let consensus_fps: std::collections::HashSet<String> = sorted_routers
        .iter()
        .map(|r| r.fingerprint.clone())
        .collect();

    // Create generator for vanguard selection
    let restriction = FlagsRestriction::new(
        vec![
            "Fast".to_string(),
            "Stable".to_string(),
            "Valid".to_string(),
        ],
        vec!["Authority".to_string()],
    );
    let restrictions = NodeRestrictionList::new(vec![Box::new(restriction)]);
    let generator = BwWeightedGenerator::new(
        sorted_routers.clone(),
        restrictions,
        weights.clone(),
        Position::Middle,
    )?;

    if state.enable_vanguards {
        // Remove guards that are no longer in consensus
        VanguardState::remove_down_from_layer(&mut state.layer2, &consensus_fps);
        VanguardState::remove_down_from_layer(&mut state.layer3, &consensus_fps);

        // Remove expired guards
        VanguardState::remove_expired_from_layer(&mut state.layer2);
        VanguardState::remove_expired_from_layer(&mut state.layer3);

        // Remove excluded guards
        VanguardState::remove_excluded_from_layer(&mut state.layer2, &router_map, exclude);
        VanguardState::remove_excluded_from_layer(&mut state.layer3, &router_map, exclude);

        // Replenish guard layers
        state.replenish_layers(&generator, exclude, &config.vanguards)?;
    }

    // Create generator for rendguard (with Exit flag allowed)
    let rend_restriction = FlagsRestriction::new(
        vec!["Fast".to_string(), "Valid".to_string()],
        vec!["Authority".to_string()],
    );
    let rend_restrictions = NodeRestrictionList::new(vec![Box::new(rend_restriction)]);
    let mut rend_generator = BwWeightedGenerator::new(
        sorted_routers,
        rend_restrictions,
        weights.clone(),
        Position::Middle,
    )?;

    // Repair exit weights for RP selection
    rend_generator.repair_exits();

    // Update rendguard use counts
    state
        .rendguard
        .xfer_use_counts(&rend_generator, &config.rendguard);

    Ok(())
}

/// Gets network statuses from Tor.
async fn get_network_statuses(controller: &mut Controller) -> Result<Vec<RouterStatusEntry>> {
    let response = controller
        .get_info("ns/all")
        .await
        .map_err(|e| Error::DescriptorUnavailable(format!("Cannot get network statuses: {}", e)))?;

    parse_network_statuses(&response)
}

/// Parses network status entries from GETINFO ns/all response.
fn parse_network_statuses(response: &str) -> Result<Vec<RouterStatusEntry>> {
    use chrono::Utc;
    use stem_rs::descriptor::router_status::RouterStatusEntryType;

    let mut routers = Vec::new();
    let mut current_router: Option<RouterStatusEntry> = None;

    for line in response.lines() {
        if line.starts_with("r ") {
            // Save previous router if any
            if let Some(router) = current_router.take() {
                routers.push(router);
            }

            // Parse r line: r nickname identity digest published IP ORPort DirPort
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 8 {
                let nickname = parts[1].to_string();
                let fingerprint = decode_base64_fingerprint(parts[2]);
                let address = parts[5]
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
                let or_port = parts[6].parse().unwrap_or(9001);

                current_router = Some(RouterStatusEntry::new(
                    RouterStatusEntryType::V3,
                    nickname,
                    fingerprint,
                    Utc::now(),
                    address,
                    or_port,
                ));
            }
        } else if let Some(stripped) = line.strip_prefix("s ") {
            // Parse s line: s Flag1 Flag2 ...
            if let Some(ref mut router) = current_router {
                router.flags = stripped.split_whitespace().map(|s| s.to_string()).collect();
            }
        } else if let Some(stripped) = line.strip_prefix("w ") {
            // Parse w line: w Bandwidth=X Measured=Y
            if let Some(ref mut router) = current_router {
                for part in stripped.split_whitespace() {
                    if let Some((key, value)) = part.split_once('=') {
                        if let Ok(v) = value.parse::<u64>() {
                            match key {
                                "Bandwidth" => router.bandwidth = Some(v),
                                "Measured" => router.measured = Some(v),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    // Don't forget the last router
    if let Some(router) = current_router {
        routers.push(router);
    }

    Ok(routers)
}

/// Decodes a base64-encoded fingerprint to hex.
fn decode_base64_fingerprint(b64: &str) -> String {
    // Add padding if needed
    let padded = match b64.len() % 4 {
        0 => b64.to_string(),
        2 => format!("{}==", b64),
        3 => format!("{}=", b64),
        _ => b64.to_string(),
    };

    // Decode base64
    let decoded = base64_decode(&padded).unwrap_or_default();

    // Convert to hex
    decoded.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Simple base64 decoder.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim_end_matches('=');
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for c in input.bytes() {
        let value = ALPHABET.iter().position(|&x| x == c)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(output)
}

/// Handles a signal event from Tor.
///
/// Processes signals received by the Tor daemon and takes appropriate action.
/// Currently handles SIGHUP/RELOAD to reapply vanguard configuration.
///
/// # Supported Signals
///
/// | Signal | Action |
/// |--------|--------|
/// | `RELOAD` (SIGHUP) | Reapply vanguard configuration to Tor |
///
/// # Arguments
///
/// * `controller` - The Tor controller
/// * `state` - The vanguard state
/// * `config` - The vanguards configuration
/// * `signal` - The signal name (e.g., "RELOAD")
///
/// # Returns
///
/// Returns `Ok(())` on successful handling.
///
/// # Errors
///
/// Returns [`Error::Control`] if reconfiguring Tor fails.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::controller::Controller;
/// use vanguards_rs::vanguards::VanguardState;
/// use vanguards_rs::config::Config;
/// use vanguards_rs::control::signal_event;
///
/// # async fn example() -> Result<(), vanguards_rs::error::Error> {
/// let mut controller = Controller::from_port("127.0.0.1:9051".parse().unwrap()).await?;
/// controller.authenticate(None).await?;
///
/// let state = VanguardState::new("/tmp/vanguards.state");
/// let config = Config::default();
///
/// signal_event(&mut controller, &state, &config, "RELOAD").await?;
/// # Ok(())
/// # }
/// ```
pub async fn signal_event(
    controller: &mut Controller,
    state: &VanguardState,
    config: &Config,
    signal: &str,
) -> Result<()> {
    if signal == "RELOAD" {
        plog(LogLevel::Notice, "Tor got SIGHUP. Reapplying vanguards.");
        configure_tor(controller, state, config).await?;
    }
    Ok(())
}

/// Application state shared across event handlers.
///
/// `AppState` aggregates all the stateful components needed during the main
/// event loop. It is passed to event handlers to allow them to update their
/// respective state and access configuration.
///
/// # Components
///
/// ```text
/// ┌─────────────────────────────────────────────┐
/// │                  AppState                   │
/// │                                             │
/// │  ┌─────────────────┐  ┌─────────────────┐   │
/// │  │ VanguardState   │  │ BandwidthStats  │   │
/// │  │ • layer2 guards │  │ • circuit stats │   │
/// │  │ • layer3 guards │  │ • conn tracking │   │
/// │  │ • rendguard     │  │ • attack detect │   │
/// │  └─────────────────┘  └─────────────────┘   │
/// │                                             │
/// │  ┌─────────────────┐  ┌─────────────────┐   │
/// │  │ TimeoutStats    │  │ LogGuard        │   │
/// │  │ • CBT tracking  │  │ • log buffering │   │
/// │  │ • timeout rates │  │ • warn detection│   │
/// │  └─────────────────┘  └─────────────────┘   │
/// │                                             │
/// │  ┌─────────────────┐  ┌─────────────────┐   │
/// │  │ PathVerify      │  │ Config          │   │
/// │  │ • path checking │  │ • all settings  │   │
/// │  │ • guard verify  │  │ • thresholds    │   │
/// │  └─────────────────┘  └─────────────────┘   │
/// └────────────────────────────────────────────┘
/// ```
///
/// # Thread Safety
///
/// `AppState` is not thread-safe. It is designed to be used within a single
/// async task (the main event loop). For concurrent access, wrap in appropriate
/// synchronization primitives.
///
/// # Example
///
/// ```rust,no_run
/// use vanguards_rs::control::AppState;
/// use vanguards_rs::vanguards::VanguardState;
/// use vanguards_rs::config::Config;
///
/// // Create state for the event loop
/// let vanguard_state = VanguardState::new("/var/lib/tor/vanguards.state");
/// let config = Config::default();
/// let app_state = AppState::new(vanguard_state, config);
/// ```
///
/// # See Also
///
/// - [`VanguardState`] - Guard layer management
/// - [`BandwidthStats`] - Bandwidth attack detection
/// - [`TimeoutStats`] - Circuit build timeout verification
/// - [`LogGuard`] - Log buffering and analysis
/// - [`PathVerify`] - Circuit path verification
pub struct AppState {
    /// Vanguard state containing guard layers and rendguard.
    pub vanguard_state: VanguardState,
    /// Bandwidth statistics for attack detection.
    pub bandwidth_stats: BandwidthStats,
    /// Circuit build timeout statistics.
    pub timeout_stats: TimeoutStats,
    /// Optional log guard for log buffering and analysis.
    pub logguard: Option<LogGuard>,
    /// Optional path verifier for circuit path validation.
    pub pathverify: Option<PathVerify>,
    /// Application configuration.
    pub config: Config,
}

impl AppState {
    /// Creates a new application state with the given vanguard state and configuration.
    ///
    /// Initializes bandwidth and timeout statistics to empty state. LogGuard and
    /// PathVerify are initialized later in the control loop based on configuration.
    ///
    /// # Arguments
    ///
    /// * `vanguard_state` - The vanguard state (loaded from file or newly created)
    /// * `config` - The application configuration
    ///
    /// # Returns
    ///
    /// A new `AppState` with initialized statistics and the provided state/config.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vanguards_rs::control::AppState;
    /// use vanguards_rs::vanguards::VanguardState;
    /// use vanguards_rs::config::Config;
    ///
    /// let state = VanguardState::new("/tmp/vanguards.state");
    /// let config = Config::default();
    /// let app_state = AppState::new(state, config);
    /// ```
    pub fn new(vanguard_state: VanguardState, config: Config) -> Self {
        Self {
            vanguard_state,
            bandwidth_stats: BandwidthStats::new(),
            timeout_stats: TimeoutStats::new(),
            logguard: None,
            pathverify: None,
            config,
        }
    }
}

/// Connects to Tor's control port.
///
/// Attempts connection in this order:
/// 1. Unix socket if configured
/// 2. TCP port if configured
/// 3. Default Unix socket /run/tor/control
/// 4. Default TCP port 127.0.0.1:9051
async fn connect_to_tor(config: &Config) -> Result<Controller> {
    // Try configured socket first
    if let Some(ref socket_path) = config.control_socket {
        match Controller::from_socket_file(socket_path.as_path()).await {
            Ok(controller) => {
                plog(
                    LogLevel::Notice,
                    &format!("Connected to Tor via socket {}", socket_path.display()),
                );
                return Ok(controller);
            }
            Err(e) => {
                return Err(Error::Control(e));
            }
        }
    }

    // Try configured port
    if let Some(port) = config.control_port {
        let addr = format!("{}:{}", config.control_ip, port);
        match Controller::from_port(
            addr.parse()
                .map_err(|e| Error::Config(format!("Invalid control address: {}", e)))?,
        )
        .await
        {
            Ok(controller) => {
                plog(
                    LogLevel::Notice,
                    &format!("Connected to Tor via control port {}", addr),
                );
                return Ok(controller);
            }
            Err(e) => {
                return Err(Error::Control(e));
            }
        }
    }

    // Try default socket
    if let Ok(controller) = Controller::from_socket_file(Path::new("/run/tor/control")).await {
        plog(
            LogLevel::Notice,
            "Connected to Tor via /run/tor/control socket",
        );
        return Ok(controller);
    }

    // Try default port
    let addr = format!("{}:9051", config.control_ip);
    match Controller::from_port(
        addr.parse()
            .map_err(|e| Error::Config(format!("Invalid control address: {}", e)))?,
    )
    .await
    {
        Ok(controller) => {
            plog(
                LogLevel::Notice,
                &format!("Connected to Tor via {} control port", addr),
            );
            Ok(controller)
        }
        Err(e) => Err(Error::Control(e)),
    }
}

/// Gets the list of event types to subscribe to based on configuration.
fn get_event_types(config: &Config, tor_version: &Version) -> Vec<EventType> {
    let mut events = Vec::new();

    // Always subscribe to these if vanguards or rendguard enabled
    if config.enable_vanguards || config.enable_rendguard {
        events.push(EventType::NewConsensus);
        events.push(EventType::Signal);
    }

    // Rendguard needs CIRC events
    if config.enable_rendguard {
        events.push(EventType::Circ);
    }

    // Bandguards events
    if config.enable_bandguards {
        events.push(EventType::Circ);
        events.push(EventType::Bw);
        events.push(EventType::OrConn);
        events.push(EventType::NetworkLiveness);

        // CIRC_BW and CIRC_MINOR require Tor 0.3.4.10+
        let min_version = Version::new(0, 3, 4).with_patch(10);
        if *tor_version >= min_version {
            events.push(EventType::CircBw);
            events.push(EventType::CircMinor);
        } else {
            plog(
                LogLevel::Notice,
                "In order for bandwidth-based protections to be enabled, you must use Tor 0.3.4.10 or newer.",
            );
        }
    }

    // CBT verify events
    if config.enable_cbtverify {
        events.push(EventType::Circ);
        events.push(EventType::BuildTimeoutSet);
    }

    // Path verify events
    if config.enable_pathverify {
        events.push(EventType::Circ);
        events.push(EventType::CircMinor);
        events.push(EventType::OrConn);
        events.push(EventType::Guard);
        events.push(EventType::ConfChanged);
    }

    // Log guard events
    if config.enable_logguard {
        events.push(EventType::Circ);
        events.push(EventType::Warn);

        // Add log events based on dump level
        let log_events = LogGuard::get_log_event_types(config.logguard.dump_level);
        for event_name in log_events {
            match event_name {
                "DEBUG" => events.push(EventType::Debug),
                "INFO" => events.push(EventType::Info),
                "NOTICE" => events.push(EventType::Notice),
                "WARN" => events.push(EventType::Warn),
                "ERR" => events.push(EventType::Err),
                _ => {}
            }
        }
    }

    // Deduplicate
    events.sort_by_key(|e| format!("{:?}", e));
    events.dedup();

    events
}

/// Handles a circuit event, dispatching to all enabled handlers.
fn handle_circ_event(state: &mut AppState, event: &stem_rs::events::CircuitEvent, arrived_at: f64) {
    let circ_id = &event.id.0;
    let status = format!("{:?}", event.status);
    let purpose = event.purpose.as_ref().map(|p| format!("{:?}", p));
    let hs_state = event.hs_state.as_ref().map(|s| format!("{:?}", s));
    let reason = event.reason.as_ref().map(|r| format!("{:?}", r));
    let path: Vec<String> = event.path.iter().map(|(fp, _)| fp.clone()).collect();

    // Rendguard: check for HS_SERVICE_REND in HSSR_CONNECTING
    if state.config.enable_rendguard {
        if let (Some(ref p), Some(ref hs)) = (&purpose, &hs_state) {
            if p == "HS_SERVICE_REND" && hs == "HSSR_CONNECTING" {
                // Get the rendezvous point (last hop in path)
                if let Some(rp_fp) = path.last() {
                    let valid = state
                        .vanguard_state
                        .rendguard
                        .valid_rend_use(rp_fp, &state.config.rendguard);
                    if !valid {
                        let usage_rate = state.vanguard_state.rendguard.usage_rate(rp_fp);
                        let expected = state.vanguard_state.rendguard.expected_weight(rp_fp);
                        plog(
                            LogLevel::Warn,
                            &format!(
                                "Possible rendezvous point overuse attack: {} used {:.2}% vs expected {:.2}%",
                                rp_fp, usage_rate, expected
                            ),
                        );
                    }
                }
            }
        }
    }

    // Bandguards
    if state.config.enable_bandguards {
        state.bandwidth_stats.circ_event(
            circ_id,
            &status,
            purpose.as_deref().unwrap_or("GENERAL"),
            hs_state.as_deref(),
            &path,
            reason.as_deref(),
            arrived_at,
        );
    }

    // CBT verify
    if state.config.enable_cbtverify {
        state.timeout_stats.circ_event(
            circ_id,
            &status,
            purpose.as_deref().unwrap_or("GENERAL"),
            hs_state.as_deref(),
            reason.as_deref(),
        );
    }

    // Log guard
    if state.config.enable_logguard {
        if let Some(ref mut lg) = state.logguard {
            lg.circ_event(circ_id, &status, reason.as_deref());
        }
    }

    // Path verify
    if state.config.enable_pathverify {
        if let Some(ref mut pv) = state.pathverify {
            pv.circ_event(
                circ_id,
                &status,
                purpose.as_deref().unwrap_or("GENERAL"),
                hs_state.as_deref(),
                &event.path,
            );
        }
    }
}

/// Handles a circuit bandwidth event.
fn handle_circbw_event(
    state: &mut AppState,
    event: &stem_rs::events::CircuitBandwidthEvent,
    arrived_at: f64,
) {
    if state.config.enable_bandguards {
        state.bandwidth_stats.circbw_event(
            &event.id.0,
            event.read,
            event.written,
            event.delivered_read.unwrap_or(0),
            event.delivered_written.unwrap_or(0),
            event.overhead_read.unwrap_or(0),
            event.overhead_written.unwrap_or(0),
            arrived_at,
        );
    }
}

/// Handles a circuit minor event.
#[allow(dead_code)]
fn handle_circ_minor_event(state: &mut AppState, event: &stem_rs::events::CircuitEvent) {
    let circ_id = &event.id.0;
    let purpose = event.purpose.as_ref().map(|p| format!("{:?}", p));
    let hs_state = event.hs_state.as_ref().map(|s| format!("{:?}", s));
    let path: Vec<String> = event.path.iter().map(|(fp, _)| fp.clone()).collect();

    // Bandguards
    if state.config.enable_bandguards {
        // For CIRC_MINOR, we need old_purpose and old_hs_state which aren't in the event
        // We'll pass None for now as the event doesn't provide these
        state.bandwidth_stats.circ_minor_event(
            circ_id,
            "PURPOSE_CHANGED",
            purpose.as_deref().unwrap_or("GENERAL"),
            hs_state.as_deref(),
            None, // old_purpose
            None, // old_hs_state
            &path,
        );
    }

    // Path verify
    if state.config.enable_pathverify {
        if let Some(ref mut pv) = state.pathverify {
            pv.circ_minor_event(
                circ_id,
                purpose.as_deref().unwrap_or("GENERAL"),
                None, // old_purpose
                &event.path,
            );
        }
    }
}

/// Handles a raw CIRC_MINOR event from Unknown variant.
///
/// CIRC_MINOR events indicate minor changes to circuits like purpose changes.
/// Format: CircuitID EVENT [Path] [PURPOSE=...] [HS_STATE=...] [OLD_PURPOSE=...] [OLD_HS_STATE=...]
fn handle_circ_minor_raw(state: &mut AppState, content: &str) {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let circ_id = parts[0];
    let _event_type = parts[1]; // e.g., "PURPOSE_CHANGED"

    // Parse path and key-value pairs
    let mut path: Vec<(String, Option<String>)> = Vec::new();
    let mut purpose: Option<String> = None;
    let mut hs_state: Option<String> = None;
    let mut old_purpose: Option<String> = None;
    let mut old_hs_state: Option<String> = None;

    for part in parts.iter().skip(2) {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "PURPOSE" => purpose = Some(value.to_string()),
                "HS_STATE" => hs_state = Some(value.to_string()),
                "OLD_PURPOSE" => old_purpose = Some(value.to_string()),
                "OLD_HS_STATE" => old_hs_state = Some(value.to_string()),
                _ => {}
            }
        } else if part.starts_with('$') || part.contains('~') || part.contains(',') {
            // Parse path
            for hop in part.split(',') {
                let hop = hop.trim_start_matches('$');
                if let Some((fp, nick)) = hop.split_once('~') {
                    path.push((fp.to_string(), Some(nick.to_string())));
                } else if let Some((fp, nick)) = hop.split_once('=') {
                    path.push((fp.to_string(), Some(nick.to_string())));
                } else if !hop.is_empty() {
                    path.push((hop.to_string(), None));
                }
            }
        }
    }

    // Bandguards
    if state.config.enable_bandguards {
        let path_fps: Vec<String> = path.iter().map(|(fp, _)| fp.clone()).collect();
        state.bandwidth_stats.circ_minor_event(
            circ_id,
            _event_type,
            purpose.as_deref().unwrap_or("GENERAL"),
            hs_state.as_deref(),
            old_purpose.as_deref(),
            old_hs_state.as_deref(),
            &path_fps,
        );
    }

    // Path verify
    if state.config.enable_pathverify {
        if let Some(ref mut pv) = state.pathverify {
            pv.circ_minor_event(
                circ_id,
                purpose.as_deref().unwrap_or("GENERAL"),
                old_purpose.as_deref(),
                &path,
            );
        }
    }
}

/// Handles an OR connection event.
fn handle_orconn_event(
    state: &mut AppState,
    event: &stem_rs::events::OrConnEvent,
    arrived_at: f64,
) {
    let status = format!("{:?}", event.status);
    let reason = event.reason.as_ref().map(|r| format!("{:?}", r));
    let conn_id = event.id.as_deref().unwrap_or("");

    // Bandguards
    if state.config.enable_bandguards {
        state.bandwidth_stats.orconn_event(
            conn_id,
            &event.target,
            &status,
            reason.as_deref(),
            arrived_at,
        );
    }

    // Path verify
    if state.config.enable_pathverify {
        if let Some(ref mut pv) = state.pathverify {
            // Extract fingerprint from target (format: $fingerprint~nickname or $fingerprint=nickname)
            let guard_fp = if event.target.starts_with('$') {
                event.target[1..].split(['~', '=']).next().unwrap_or("")
            } else {
                &event.target
            };
            pv.orconn_event(guard_fp, &status);
        }
    }
}

/// Handles a bandwidth event (1x/sec heartbeat).
fn handle_bw_event(
    state: &mut AppState,
    _event: &stem_rs::events::BandwidthEvent,
    arrived_at: f64,
) {
    if state.config.enable_bandguards {
        state
            .bandwidth_stats
            .check_connectivity(arrived_at, &state.config.bandguards);
    }
}

/// Handles a network liveness event.
fn handle_network_liveness_event(
    state: &mut AppState,
    event: &stem_rs::events::NetworkLivenessEvent,
    arrived_at: f64,
) {
    if state.config.enable_bandguards {
        let status = format!("{:?}", event.status);
        state
            .bandwidth_stats
            .network_liveness_event(&status, arrived_at);
    }
}

/// Handles a build timeout set event.
fn handle_buildtimeout_set_event(
    state: &mut AppState,
    event: &stem_rs::events::BuildTimeoutSetEvent,
) {
    if state.config.enable_cbtverify {
        let set_type = format!("{:?}", event.set_type);
        state.timeout_stats.cbt_event(&set_type, event.timeout_rate);
    }
}

/// Handles a guard event.
fn handle_guard_event(state: &mut AppState, event: &stem_rs::events::GuardEvent) {
    if state.config.enable_pathverify {
        if let Some(ref mut pv) = state.pathverify {
            let status = format!("{:?}", event.status);
            // Use endpoint_fingerprint directly from the event
            pv.guard_event(&event.endpoint_fingerprint, &status);
        }
    }
}

/// Handles a configuration changed event.
fn handle_conf_changed_event(state: &mut AppState, event: &stem_rs::events::ConfChangedEvent) {
    if state.config.enable_pathverify {
        if let Some(ref mut pv) = state.pathverify {
            pv.conf_changed_event(&event.changed);
        }
    }
}

/// Handles a log event.
fn handle_log_event(state: &mut AppState, event: &stem_rs::events::LogEvent, arrived_at: f64) {
    if state.config.enable_logguard {
        if let Some(ref mut lg) = state.logguard {
            let runlevel = format!("{:?}", event.runlevel);
            lg.log_event_with_timestamp(&runlevel, &event.message, arrived_at);

            // Also handle warn events specially
            if matches!(event.runlevel, stem_rs::Runlevel::Warn) {
                lg.log_warn_event(&event.message);
            }
        }
    }
}

/// Handles a signal event.
async fn handle_signal_event(
    controller: &mut Controller,
    state: &mut AppState,
    event: &stem_rs::events::SignalEvent,
) -> Result<()> {
    let signal_name = format!("{:?}", event.signal);
    signal_event(
        controller,
        &state.vanguard_state,
        &state.config,
        &signal_name,
    )
    .await
}

/// Main control loop for event processing.
///
/// Connects to Tor, authenticates, initializes state, and processes events
/// in a continuous loop until the connection is lost or an error occurs.
///
/// # Flow
///
/// 1. Connect to Tor's control port (socket or TCP)
/// 2. Authenticate using available methods
/// 3. Get Tor version for feature detection
/// 4. Initialize vanguard state from consensus
/// 5. Initialize optional components (logguard, pathverify)
/// 6. Subscribe to configured event types
/// 7. Process events until connection closes
///
/// # Arguments
///
/// * `state` - The application state containing all protection components
///
/// # Returns
///
/// Returns a status string:
/// - `"closed"` - Connection was closed normally
/// - `"failed: <reason>"` - Connection or operation failed
///
/// # Event Processing
///
/// The loop dispatches events to appropriate handlers:
///
/// | Event Type | Handlers |
/// |------------|----------|
/// | CIRC | RendGuard, BandGuards, CBTVerify, PathVerify, LogGuard |
/// | CIRC_BW | BandGuards |
/// | CIRC_MINOR | BandGuards, PathVerify |
/// | ORCONN | BandGuards, PathVerify |
/// | BW | BandGuards (connectivity check) |
/// | NEWCONSENSUS | VanguardState update |
/// | SIGNAL | Configuration reload (SIGHUP) |
///
/// # Example
///
/// ```rust,no_run
/// use vanguards_rs::control::{AppState, control_loop};
/// use vanguards_rs::vanguards::VanguardState;
/// use vanguards_rs::config::Config;
///
/// # async fn example() {
/// let state = VanguardState::new("/tmp/vanguards.state");
/// let config = Config::default();
/// let mut app_state = AppState::new(state, config);
///
/// let result = control_loop(&mut app_state).await;
/// println!("Control loop exited: {}", result);
/// # }
/// ```
///
/// # See Also
///
/// - [`run_main`] - Higher-level entry point with reconnection support
/// - [`authenticate_any`] - Authentication implementation
/// - [`new_consensus_event`] - Consensus processing
pub async fn control_loop(state: &mut AppState) -> String {
    // Connect to Tor
    let mut controller = match connect_to_tor(&state.config).await {
        Ok(c) => c,
        Err(e) => return format!("failed: {}", e),
    };

    // Authenticate
    if let Err(e) = authenticate_any(&mut controller, state.config.control_pass.as_deref()).await {
        return format!("failed: {}", e);
    }

    // Get Tor version for feature detection
    let tor_version = match controller.get_version().await {
        Ok(v) => v,
        Err(e) => return format!("failed: {}", e),
    };

    // Initialize vanguard state from consensus
    if state.config.enable_vanguards || state.config.enable_rendguard {
        match new_consensus_event(&mut controller, &mut state.vanguard_state, &state.config).await {
            Ok(()) => {}
            Err(Error::DescriptorUnavailable(msg)) => {
                plog(
                    LogLevel::Notice,
                    &format!("Tor needs descriptors: {}. Trying again...", msg),
                );
                return format!("failed: {}", msg);
            }
            Err(e) => return format!("failed: {}", e),
        }
    }

    // Handle one-shot mode
    if state.config.one_shot_vanguards {
        // Note: SaveConf is not available in stem-rs Signal enum
        // We just exit after setting vanguards - user should save config manually if needed
        plog(
            LogLevel::Notice,
            "Updated vanguards. Exiting (one-shot mode).",
        );
        std::process::exit(0);
    }

    // Initialize logguard if enabled
    if state.config.enable_logguard {
        state.logguard = Some(LogGuard::new(&state.config.logguard));
    }

    // Initialize pathverify if enabled
    if state.config.enable_pathverify {
        state.pathverify = Some(PathVerify::new(
            state.config.enable_vanguards,
            state.config.vanguards.num_layer1_guards,
            state.config.vanguards.num_layer2_guards,
            state.config.vanguards.num_layer3_guards,
        ));

        // Send NEWNYM to get fresh circuits
        if let Err(e) = controller.signal(stem_rs::Signal::Newnym).await {
            plog(LogLevel::Warn, &format!("Failed to send NEWNYM: {}", e));
        }
    }

    // Subscribe to events
    let event_types = get_event_types(&state.config, &tor_version);
    if let Err(e) = controller.set_events(&event_types).await {
        return format!("failed: {}", e);
    }

    // Main event loop
    loop {
        match controller.recv_event().await {
            Ok(event) => {
                let arrived_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);

                match event {
                    ParsedEvent::Circuit(ref e) => {
                        handle_circ_event(state, e, arrived_at);
                    }
                    ParsedEvent::CircuitBandwidth(ref e) => {
                        handle_circbw_event(state, e, arrived_at);
                    }
                    ParsedEvent::OrConn(ref e) => {
                        handle_orconn_event(state, e, arrived_at);
                    }
                    ParsedEvent::Bandwidth(ref e) => {
                        handle_bw_event(state, e, arrived_at);
                    }
                    ParsedEvent::NetworkLiveness(ref e) => {
                        handle_network_liveness_event(state, e, arrived_at);
                    }
                    ParsedEvent::BuildTimeoutSet(ref e) => {
                        handle_buildtimeout_set_event(state, e);
                    }
                    ParsedEvent::Guard(ref e) => {
                        handle_guard_event(state, e);
                    }
                    ParsedEvent::ConfChanged(ref e) => {
                        handle_conf_changed_event(state, e);
                    }
                    ParsedEvent::Log(ref e) => {
                        handle_log_event(state, e, arrived_at);
                    }
                    ParsedEvent::Signal(ref e) => {
                        if let Err(err) = handle_signal_event(&mut controller, state, e).await {
                            plog(LogLevel::Warn, &format!("Signal event error: {}", err));
                        }
                    }
                    ParsedEvent::Unknown {
                        ref event_type,
                        ref content,
                    } => {
                        // Handle NEWCONSENSUS specially since it may not be in ParsedEvent
                        if event_type == "NEWCONSENSUS" {
                            if let Err(err) = new_consensus_event(
                                &mut controller,
                                &mut state.vanguard_state,
                                &state.config,
                            )
                            .await
                            {
                                plog(LogLevel::Warn, &format!("Consensus event error: {}", err));
                            }
                        } else if event_type == "CIRC_MINOR" {
                            // Parse CIRC_MINOR event manually
                            // Format: CircuitID EVENT [Path] [PURPOSE=...] [HS_STATE=...] [OLD_PURPOSE=...] [OLD_HS_STATE=...]
                            handle_circ_minor_raw(state, content);
                        }
                    }
                    _ => {
                        // Ignore other events
                    }
                }

                // Check circuit limits after bandwidth events
                if state.config.enable_bandguards {
                    let circs_to_check: Vec<String> =
                        state.bandwidth_stats.circs.keys().cloned().collect();
                    for circ_id in circs_to_check {
                        let limit_result = state
                            .bandwidth_stats
                            .check_circuit_limits(&circ_id, &state.config.bandguards);
                        match limit_result {
                            crate::bandguards::CircuitLimitResult::Ok => {}
                            crate::bandguards::CircuitLimitResult::TorBug {
                                bug_id,
                                dropped_cells,
                            } => {
                                plog(
                                    LogLevel::Info,
                                    &format!(
                                        "Tor bug {} (dropped {} cells): {}",
                                        bug_id, dropped_cells, circ_id
                                    ),
                                );
                            }
                            crate::bandguards::CircuitLimitResult::DroppedCells {
                                dropped_cells,
                            } => {
                                plog(
                                    LogLevel::Warn,
                                    &format!(
                                        "Dropped cells attack ({} cells): {}",
                                        dropped_cells, circ_id
                                    ),
                                );
                                try_close_circuit(
                                    &mut controller,
                                    &circ_id,
                                    state.logguard.as_mut(),
                                )
                                .await;
                            }
                            crate::bandguards::CircuitLimitResult::MaxBytesExceeded {
                                bytes,
                                limit,
                            } => {
                                plog(
                                    LogLevel::Warn,
                                    &format!(
                                        "Circuit {} exceeded max bytes ({} > {})",
                                        circ_id, bytes, limit
                                    ),
                                );
                                try_close_circuit(
                                    &mut controller,
                                    &circ_id,
                                    state.logguard.as_mut(),
                                )
                                .await;
                            }
                            crate::bandguards::CircuitLimitResult::HsdirBytesExceeded {
                                bytes,
                                limit,
                            } => {
                                plog(
                                    LogLevel::Warn,
                                    &format!(
                                        "HSDIR circuit {} exceeded max bytes ({} > {})",
                                        circ_id, bytes, limit
                                    ),
                                );
                                try_close_circuit(
                                    &mut controller,
                                    &circ_id,
                                    state.logguard.as_mut(),
                                )
                                .await;
                            }
                            crate::bandguards::CircuitLimitResult::ServIntroBytesExceeded {
                                bytes,
                                limit,
                            } => {
                                plog(
                                    LogLevel::Warn,
                                    &format!(
                                        "Service intro circuit {} exceeded max bytes ({} > {})",
                                        circ_id, bytes, limit
                                    ),
                                );
                                try_close_circuit(
                                    &mut controller,
                                    &circ_id,
                                    state.logguard.as_mut(),
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // Connection closed or error
                plog(LogLevel::Debug, &format!("Event receive error: {}", e));
                return "closed".to_string();
            }
        }
    }
}

/// Runs the main application loop with reconnection support.
///
/// This is the primary entry point for the vanguards application. It manages
/// the complete lifecycle including connection, reconnection, and graceful shutdown.
///
/// # Lifecycle
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │                      run_main()                             │
/// │                                                             │
/// │  1. Set up CTRL+C handler                                   │
/// │  2. Load/create vanguard state                              │
/// │  3. Enter reconnection loop:                                │
/// │     ┌─────────────────────────────────────────────────────┐ │
/// │     │  • Check shutdown flag                              │ │
/// │     │  • Check retry limit                                │ │
/// │     │  • Run control_loop()                               │ │
/// │     │  • Log disconnection                                │ │
/// │     │  • Wait 1 second                                    │ │
/// │     │  • Increment reconnect counter                      │ │
/// │     └─────────────────────────────────────────────────────┘ │
/// │  4. Exit when shutdown or retry limit reached               │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// # Arguments
///
/// * `config` - The application configuration
///
/// # Returns
///
/// Returns `Ok(())` on graceful shutdown, or an error if the application
/// fails to start or encounters an unrecoverable error.
///
/// # Errors
///
/// Returns [`Error::Config`] if:
/// - Failed to connect to Tor after all retry attempts
/// - Invalid configuration values
///
/// # Shutdown Behavior
///
/// The function handles graceful shutdown via:
/// - CTRL+C signal (sets shutdown flag)
/// - Retry limit reached (configurable via `config.retry_limit`)
///
/// # Example
///
/// ```rust,no_run
/// use vanguards_rs::config::Config;
/// use vanguards_rs::control::run_main;
///
/// #[tokio::main]
/// async fn main() -> Result<(), vanguards_rs::error::Error> {
///     // Load configuration from file or use defaults
///     let config = Config::default();
///     
///     // Run until shutdown signal or error
///     run_main(config).await
/// }
/// ```
///
/// # See Also
///
/// - [`control_loop`] - The inner event processing loop
/// - [`Config`] - Configuration options
/// - [`VanguardState`] - State persistence
pub async fn run_main(config: Config) -> Result<()> {
    // Set up CTRL+C handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            plog(LogLevel::Notice, "Got CTRL+C. Exiting.");
            shutdown_clone.store(true, Ordering::SeqCst);
        }
    });

    // Set close circuits flag from config
    set_close_circuits(config.close_circuits);

    // Load or create vanguard state
    let state_path = &config.state_file;
    let vanguard_state = match VanguardState::read_from_file(state_path) {
        Ok(mut state) => {
            plog(
                LogLevel::Info,
                &format!("Current layer2 guards: {}", state.layer2_guardset()),
            );
            plog(
                LogLevel::Info,
                &format!("Current layer3 guards: {}", state.layer3_guardset()),
            );
            state.enable_vanguards = config.enable_vanguards;
            state
        }
        Err(_) => {
            plog(
                LogLevel::Notice,
                &format!(
                    "Creating new vanguard state file at: {}",
                    state_path.display()
                ),
            );
            let mut state = VanguardState::new(&state_path.to_string_lossy());
            state.enable_vanguards = config.enable_vanguards;
            state
        }
    };

    let mut app_state = AppState::new(vanguard_state, config.clone());

    let mut reconnects = 0u32;
    let mut last_connected_at: Option<f64> = None;
    let mut connected = false;

    loop {
        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Check retry limit
        if let Some(limit) = config.retry_limit {
            if reconnects >= limit {
                break;
            }
        }

        let result = control_loop(&mut app_state).await;

        if last_connected_at.is_none() {
            last_connected_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0),
            );
        }

        if result == "closed" {
            connected = true;
        }

        // Log reconnection attempts (every 10 seconds or on first close)
        if result == "closed" || reconnects.is_multiple_of(10) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);

            let disconnected_secs = now - last_connected_at.unwrap_or(now);
            let max_disconnected = config.bandguards.conn_max_disconnected_secs as f64;

            if disconnected_secs > max_disconnected {
                plog(
                    LogLevel::Warn,
                    &format!("Tor daemon connection {}. Trying again...", result),
                );
            } else {
                plog(
                    LogLevel::Notice,
                    &format!("Tor daemon connection {}. Trying again...", result),
                );
            }
        }

        reconnects += 1;

        // Wait before reconnecting
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    if !connected {
        return Err(Error::Config("Failed to connect to Tor".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_get_consensus_weights() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "network-status-version 3 microdesc\n\
             bandwidth-weights Wbd=0 Wbe=0 Wbg=4194 Wbm=10000 Wdb=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5806 Wgm=5806 Wmb=10000 Wmd=0 Wme=0 Wmg=4194 Wmm=10000"
        )
        .unwrap();

        let weights = get_consensus_weights(file.path()).unwrap();

        assert_eq!(weights.get("Wmm"), Some(&10000));
        assert_eq!(weights.get("Wgg"), Some(&5806));
        assert_eq!(weights.get("Wbd"), Some(&0));
    }

    #[test]
    fn test_get_consensus_weights_missing() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "network-status-version 3 microdesc").unwrap();

        let result = get_consensus_weights(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_decode() {
        // Test standard base64 decoding
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");

        // Test without padding
        let decoded = base64_decode("SGVsbG8").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_decode_base64_fingerprint() {
        // A typical Tor fingerprint in base64 (27 chars without padding)
        // 20 bytes = 160 bits, which is 27 base64 chars (ceil(160/6) = 27)
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let hex = decode_base64_fingerprint(b64);
        // Should produce 40 hex characters (20 bytes)
        assert_eq!(hex.len(), 40);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_parse_network_statuses() {
        let response = "\
r relay1 AAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBBBBBBBBBB 2024-01-01 00:00:00 192.168.1.1 9001 0
s Fast Guard Running Stable Valid
w Bandwidth=1000 Measured=900
r relay2 CCCCCCCCCCCCCCCCCCCCCCCCCCCC DDDDDDDDDDDDDDDDDDDDDDDDDDDD 2024-01-01 00:00:00 192.168.1.2 9002 0
s Fast Running Stable Valid Exit
w Bandwidth=2000";

        let routers = parse_network_statuses(response).unwrap();
        assert_eq!(routers.len(), 2);

        assert_eq!(routers[0].nickname, "relay1");
        assert!(routers[0].flags.contains(&"Guard".to_string()));
        assert_eq!(routers[0].bandwidth, Some(1000));
        assert_eq!(routers[0].measured, Some(900));

        assert_eq!(routers[1].nickname, "relay2");
        assert!(routers[1].flags.contains(&"Exit".to_string()));
        assert_eq!(routers[1].bandwidth, Some(2000));
        assert_eq!(routers[1].measured, None);
    }

    #[test]
    fn test_close_circuits_flag() {
        set_close_circuits(true);
        assert!(get_close_circuits());

        set_close_circuits(false);
        assert!(!get_close_circuits());

        // Reset to default
        set_close_circuits(true);
    }
}
