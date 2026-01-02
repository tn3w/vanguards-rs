//! Vanguard state management and ExcludeNodes parsing.
//!
//! This module provides persistent vanguard guard selection and state management,
//! along with ExcludeNodes configuration parsing for relay exclusion.
//!
//! # Overview
//!
//! The vanguard system maintains persistent sets of guard relays at two layers:
//!
//! - **Layer 2 Guards**: Second-hop relays with longer lifetimes (1-45 days)
//! - **Layer 3 Guards**: Third-hop relays with shorter lifetimes (1-48 hours)
//!
//! Guards are selected using bandwidth-weighted random selection and rotated
//! based on configurable lifetime parameters.
//!
//! # Guard Layer Architecture
//!
//! Vanguards protect hidden services by restricting which relays can be used
//! at each position in the circuit:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────┐
//! │                    Hidden Service Circuit Path                             │
//! │                                                                            │
//! │  ┌──────────┐     ┌──────────┐       ┌──────────┐     ┌──────────┐         │
//! │  │  Client  │───▶│ Layer 1  │───▶ │ Layer 2  │───▶│ Layer 3  │───▶ HS  │
//! │  │          │    │ (Entry)  │      │ (Middle) │     │ (Middle) │           │
//! │  └──────────┘    └──────────┘      └──────────┘    └──────────┘            │
//! │                       │               │               │                    │
//! │                       ▼               ▼               ▼                    │
//! │                  ┌─────────┐    ┌─────────┐    ┌─────────┐                 │
//! │                  │ Tor's   │    │ 4-8     │    │ 4-8     │                 │
//! │                  │ Guard   │    │ Guards  │    │ Guards  │                 │
//! │                  │ System  │    │ 1-45    │    │ 1-48    │                 │
//! │                  │         │    │ days    │    │ hours   │                 │
//! │                  └─────────┘    └─────────┘    └─────────┘                 │
//! └────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Guard Lifecycle
//!
//! Guards progress through the following states:
//!
//! ```text
//!                    ┌─────────────────┐
//!                    │    Selection    │
//!                    │ (BW-weighted)   │
//!                    └────────┬────────┘
//!                             │
//!                             ▼
//!                    ┌─────────────────┐
//!                    │     Active      │
//!                    │ (in guardset)   │
//!                    └────────┬────────┘
//!                             │
//!          ┌──────────────────┼──────────────────┐
//!          │                  │                  │
//!          ▼                  ▼                  ▼
//!    ┌───────────┐     ┌───────────┐     ┌───────────┐
//!    │  Expired  │     │   Down    │     │ Excluded  │
//!    │(lifetime) │     │(consensus)│     │(ExcludeN) │
//!    └───────────┘     └───────────┘     └───────────┘
//!          │                  │                  │
//!          └──────────────────┼──────────────────┘
//!                             │
//!                             ▼
//!                    ┌─────────────────┐
//!                    │    Removed      │
//!                    │ (replenished)   │
//!                    └─────────────────┘
//! ```
//!
//! # State Persistence
//!
//! State is persisted in Python pickle format for compatibility with the
//! Python vanguards implementation. This allows seamless migration between
//! implementations.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        State File Format                                │
//! │                                                                         │
//! │  VanguardState {                                                        │
//! │      layer2: [                                                          │
//! │          GuardNode { idhex, chosen_at, expires_at },                    │
//! │          ...                                                            │
//! │      ],                                                                 │
//! │      layer3: [                                                          │
//! │          GuardNode { idhex, chosen_at, expires_at },                    │
//! │          ...                                                            │
//! │      ],                                                                 │
//! │      rendguard: RendGuard { use_counts, total_use_counts },             │
//! │      pickle_revision: 1,                                                │
//! │  }                                                                      │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # What This Module Does NOT Do
//!
//! - **Guard selection algorithm**: Use [`crate::node_selection`] for bandwidth-weighted selection
//! - **Tor configuration**: Use [`crate::control::configure_tor`] to apply guards to Tor
//! - **Attack detection**: Use [`crate::bandguards`] and [`crate::rendguard`] for monitoring
//!
//! # ExcludeNodes
//!
//! The [`ExcludeNodes`] struct parses Tor's ExcludeNodes configuration to
//! filter out unwanted relays based on:
//!
//! - Fingerprints (40 hex characters, optionally prefixed with $)
//! - Country codes ({cc} format)
//! - IP networks (CIDR notation)
//! - Nicknames
//!
//! # Example
//!
//! ```rust,no_run
//! use vanguards_rs::vanguards::{VanguardState, GuardNode, ExcludeNodes};
//! use std::path::Path;
//!
//! // Load or create vanguard state
//! let mut state = VanguardState::load_or_create(Path::new("vanguards.state"));
//!
//! // Check current guards
//! println!("Layer 2 guards: {}", state.layer2_guardset());
//! println!("Layer 3 guards: {}", state.layer3_guardset());
//!
//! // Parse exclusion configuration
//! let exclude = ExcludeNodes::parse("{us},{ru},BadRelay", None);
//! println!("Excluding {} countries", exclude.countries.len());
//! ```
//!
//! # Security Considerations
//!
//! - State files contain guard fingerprints - protect with appropriate permissions
//! - Guard lifetimes use max-of-two-uniform distribution for better security
//! - Atomic writes prevent state file corruption
//! - Validation prevents loading corrupted or malicious state files
//!
//! # See Also
//!
//! - [`crate::node_selection`] - Bandwidth-weighted node selection
//! - [`crate::config::VanguardsConfig`] - Vanguard configuration options
//! - [`crate::rendguard`] - Rendezvous point monitoring (uses RendGuard from this module)
//! - [Python vanguards](https://github.com/mikeperry-tor/vanguards) - Original implementation
//! - [Vanguards proposal](https://github.com/torproject/torspec/blob/main/proposals/292-mesh-vanguards.txt) - Design specification

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ipnetwork::IpNetwork;
use rand::Rng;
use serde::{Deserialize, Serialize};
use stem_rs::descriptor::router_status::RouterStatusEntry;

use crate::config::VanguardsConfig;
use crate::error::{Error, Result};
use crate::node_selection::{is_valid_country_code, is_valid_fingerprint, BwWeightedGenerator};

/// Seconds per hour constant.
const SEC_PER_HOUR: f64 = 3600.0;

/// A guard node selected as a vanguard with lifetime metadata.
///
/// Each guard node tracks when it was selected and when it should expire.
/// Timestamps are stored as Unix timestamps (f64) for Python pickle compatibility.
///
/// # Fields
///
/// - `idhex`: The relay's 40-character uppercase hex fingerprint
/// - `chosen_at`: Unix timestamp when this guard was selected
/// - `expires_at`: Unix timestamp when this guard should be rotated
///
/// # Lifetime Calculation
///
/// Guard lifetimes are calculated using the max of two uniform random samples
/// from the configured range. This distribution favors longer lifetimes,
/// providing better security by reducing guard rotation frequency.
///
/// ```text
/// Lifetime = max(uniform(min, max), uniform(min, max))
/// ```
///
/// # Example
///
/// ```rust
/// use vanguards_rs::vanguards::GuardNode;
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// let now = SystemTime::now()
///     .duration_since(UNIX_EPOCH)
///     .unwrap()
///     .as_secs_f64();
/// let expires = now + 86400.0; // 24 hours
///
/// let guard = GuardNode::new("A".repeat(40), now, expires);
/// assert!(!guard.is_expired());
/// ```
///
/// # See Also
///
/// - [`VanguardState::calculate_guard_lifetime`] - Lifetime calculation
/// - [`VanguardState::add_new_layer2`] - Layer 2 guard creation
/// - [`VanguardState::add_new_layer3`] - Layer 3 guard creation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardNode {
    /// The relay's 40-character hex fingerprint.
    pub idhex: String,
    /// Unix timestamp when this guard was selected.
    pub chosen_at: f64,
    /// Unix timestamp when this guard should be rotated.
    pub expires_at: f64,
}

impl GuardNode {
    /// Creates a new guard node with the specified fingerprint and timestamps.
    ///
    /// # Arguments
    ///
    /// * `idhex` - The relay's 40-character hex fingerprint
    /// * `chosen_at` - Unix timestamp when this guard was selected
    /// * `expires_at` - Unix timestamp when this guard should be rotated
    ///
    /// # Returns
    ///
    /// A new `GuardNode` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vanguards_rs::vanguards::GuardNode;
    ///
    /// let guard = GuardNode::new(
    ///     "AABBCCDD00112233445566778899AABBCCDDEEFF".to_string(),
    ///     1700000000.0,  // chosen_at
    ///     1700086400.0,  // expires_at (24 hours later)
    /// );
    /// ```
    pub fn new(idhex: String, chosen_at: f64, expires_at: f64) -> Self {
        Self {
            idhex,
            chosen_at,
            expires_at,
        }
    }

    /// Returns true if this guard has expired.
    ///
    /// Compares the current time against `expires_at` to determine if
    /// this guard should be rotated.
    ///
    /// # Returns
    ///
    /// `true` if the current time is past `expires_at`, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vanguards_rs::vanguards::GuardNode;
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// let now = SystemTime::now()
    ///     .duration_since(UNIX_EPOCH)
    ///     .unwrap()
    ///     .as_secs_f64();
    ///
    /// // Expired guard
    /// let expired = GuardNode::new("A".repeat(40), now - 1000.0, now - 100.0);
    /// assert!(expired.is_expired());
    ///
    /// // Active guard
    /// let active = GuardNode::new("B".repeat(40), now, now + 86400.0);
    /// assert!(!active.is_expired());
    /// ```
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        self.expires_at < now
    }
}

/// Rendezvous point usage count for a single relay.
///
/// Tracks how many times a relay has been used as a rendezvous point
/// and its expected weight based on consensus bandwidth.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RendUseCount {
    /// The relay's fingerprint.
    pub idhex: String,
    /// Number of times this relay has been used.
    pub used: f64,
    /// Expected usage weight based on bandwidth.
    pub weight: f64,
}

impl RendUseCount {
    /// Creates a new usage count entry.
    pub fn new(idhex: String, weight: f64) -> Self {
        Self {
            idhex,
            used: 0.0,
            weight,
        }
    }
}

/// Rendezvous point usage tracking for detecting statistical attacks.
///
/// Tracks usage counts for all relays used as rendezvous points and
/// detects when a relay is being used more than expected based on
/// its bandwidth weight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RendGuard {
    /// Usage counts per relay fingerprint.
    pub use_counts: HashMap<String, RendUseCount>,
    /// Total usage count across all relays.
    pub total_use_counts: f64,
    /// Version number for pickle compatibility.
    pub pickle_revision: f64,
}

impl Default for RendGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl RendGuard {
    /// Creates a new empty RendGuard.
    pub fn new() -> Self {
        Self {
            use_counts: HashMap::new(),
            total_use_counts: 0.0,
            pickle_revision: 1.0,
        }
    }

    /// Scales all usage counts by half.
    ///
    /// Called when total_use_counts reaches the scale threshold to prevent
    /// unbounded growth and to avoid over-counting high-uptime relays.
    pub fn scale_counts(&mut self) {
        for count in self.use_counts.values_mut() {
            count.used /= 2.0;
        }
        self.total_use_counts = self.use_counts.values().map(|c| c.used).sum();
    }

    /// Records a rendezvous point usage and checks for overuse.
    ///
    /// This method should be called each time a relay is used as a rendezvous
    /// point for a hidden service circuit.
    ///
    /// # Arguments
    ///
    /// * `fingerprint` - The relay's fingerprint (40 hex characters)
    /// * `config` - Rendguard configuration
    ///
    /// # Returns
    ///
    /// `true` if the usage is valid (not overused), `false` if overused.
    pub fn valid_rend_use(
        &mut self,
        fingerprint: &str,
        config: &crate::config::RendguardConfig,
    ) -> bool {
        const NOT_IN_CONSENSUS_ID: &str = "NOT_IN_CONSENSUS";

        let relay_id = if self.use_counts.contains_key(fingerprint) {
            fingerprint.to_string()
        } else {
            // Relay not in consensus - track under special ID
            if !self.use_counts.contains_key(NOT_IN_CONSENSUS_ID) {
                self.use_counts.insert(
                    NOT_IN_CONSENSUS_ID.to_string(),
                    RendUseCount::new(NOT_IN_CONSENSUS_ID.to_string(), 0.0),
                );
            }
            NOT_IN_CONSENSUS_ID.to_string()
        };

        // Increment usage counts
        if let Some(count) = self.use_counts.get_mut(&relay_id) {
            count.used += 1.0;
        }
        self.total_use_counts += 1.0;

        // Check for overuse
        if let Some(count) = self.use_counts.get(&relay_id) {
            if self.total_use_counts >= config.use_global_start_count as f64
                && count.used >= config.use_relay_start_count as f64
                && count.used / self.total_use_counts
                    > count.weight * config.use_max_use_to_bw_ratio
            {
                return false; // Overused
            }
        }

        true // Valid usage
    }

    /// Transfers and updates use counts on consensus change.
    ///
    /// This method should be called when a new consensus is received.
    pub fn xfer_use_counts(
        &mut self,
        generator: &BwWeightedGenerator,
        config: &crate::config::RendguardConfig,
    ) {
        const NOT_IN_CONSENSUS_ID: &str = "NOT_IN_CONSENSUS";

        let old_counts = std::mem::take(&mut self.use_counts);
        let should_scale = self.total_use_counts >= config.use_scale_at_count as f64;

        // Create entries for all routers in new consensus
        let routers = generator.routers();
        let node_weights = generator.node_weights();
        let weight_total = generator.weight_total();
        let exit_total = generator.exit_total();

        for (i, router) in routers.iter().enumerate() {
            let weight = if router.flags.contains(&"Exit".to_string()) && exit_total > 0.0 {
                node_weights[i] / exit_total
            } else if weight_total > 0.0 {
                node_weights[i] / weight_total
            } else {
                0.0
            };

            self.use_counts.insert(
                router.fingerprint.clone(),
                RendUseCount::new(router.fingerprint.clone(), weight),
            );
        }

        // Add NOT_IN_CONSENSUS entry
        self.use_counts.insert(
            NOT_IN_CONSENSUS_ID.to_string(),
            RendUseCount::new(
                NOT_IN_CONSENSUS_ID.to_string(),
                config.use_max_consensus_weight_churn / 100.0,
            ),
        );

        // Transfer old counts
        for (fp, old_count) in old_counts {
            if fp == NOT_IN_CONSENSUS_ID || self.use_counts.contains_key(&fp) {
                if let Some(new_count) = self.use_counts.get_mut(&fp) {
                    new_count.used = if should_scale {
                        old_count.used / 2.0
                    } else {
                        old_count.used
                    };
                }
            }
        }

        // Recalculate total
        self.total_use_counts = self.use_counts.values().map(|c| c.used).sum();
    }

    /// Returns the usage rate for a relay as a percentage.
    pub fn usage_rate(&self, fingerprint: &str) -> f64 {
        if self.total_use_counts <= 0.0 {
            return 0.0;
        }
        self.use_counts
            .get(fingerprint)
            .map(|c| 100.0 * c.used / self.total_use_counts)
            .unwrap_or(0.0)
    }

    /// Returns the expected weight for a relay as a percentage.
    pub fn expected_weight(&self, fingerprint: &str) -> f64 {
        self.use_counts
            .get(fingerprint)
            .map(|c| 100.0 * c.weight)
            .unwrap_or(0.0)
    }

    /// Checks if a relay is currently overused.
    pub fn is_overused(&self, fingerprint: &str, config: &crate::config::RendguardConfig) -> bool {
        if self.total_use_counts < config.use_global_start_count as f64 {
            return false;
        }

        if let Some(count) = self.use_counts.get(fingerprint) {
            if count.used < config.use_relay_start_count as f64 {
                return false;
            }
            count.used / self.total_use_counts > count.weight * config.use_max_use_to_bw_ratio
        } else {
            false
        }
    }
}

/// Persistent vanguard state containing guard layers and rendguard tracking.
///
/// Contains the layer 2 and layer 3 guard lists, along with rendguard state.
/// This state is persisted to disk in Python pickle format for compatibility.
///
/// # Guard Layers
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                         VanguardState                                   │
/// │                                                                         │
/// │  ┌─────────────────────────────────────────────────────────────────┐    │
/// │  │ Layer 2 Guards (HSLayer2Nodes)                                  │    │
/// │  │ • 4-8 guards (configurable)                                     │    │
/// │  │ • Lifetime: 1-45 days (configurable)                            │    │
/// │  │ • Used for second hop in HS circuits                            │    │
/// │  └─────────────────────────────────────────────────────────────────┘    │
/// │                                                                         │
/// │  ┌─────────────────────────────────────────────────────────────────┐    │
/// │  │ Layer 3 Guards (HSLayer3Nodes)                                  │    │
/// │  │ • 4-8 guards (configurable)                                     │    │
/// │  │ • Lifetime: 1-48 hours (configurable)                           │    │
/// │  │ • Used for third hop in HS circuits                             │    │
/// │  └─────────────────────────────────────────────────────────────────┘    │
/// │                                                                         │
/// │  ┌─────────────────────────────────────────────────────────────────┐    │
/// │  │ RendGuard                                                       │    │
/// │  │ • Tracks rendezvous point usage                                 │    │
/// │  │ • Detects statistical attacks                                   │    │
/// │  └─────────────────────────────────────────────────────────────────┘    │
/// └─────────────────────────────────────────────────────────────────────────┘
/// ```
///
/// # State File Format
///
/// The state file uses Python pickle format with the following structure:
///
/// ```text
/// VanguardState {
///     layer2: [GuardNode, ...],
///     layer3: [GuardNode, ...],
///     state_file: String,
///     rendguard: RendGuard,
///     pickle_revision: u32,
/// }
/// ```
///
/// # Thread Safety
///
/// `VanguardState` is not thread-safe. It should be accessed from a single
/// task or protected with appropriate synchronization.
///
/// # Example
///
/// ```rust,no_run
/// use vanguards_rs::vanguards::VanguardState;
/// use std::path::Path;
///
/// // Load existing state or create new
/// let mut state = VanguardState::load_or_create(Path::new("vanguards.state"));
///
/// // Check current guards
/// println!("Layer 2: {}", state.layer2_guardset());
/// println!("Layer 3: {}", state.layer3_guardset());
///
/// // Save state
/// state.write_to_file(Path::new("vanguards.state")).unwrap();
/// ```
///
/// # See Also
///
/// - [`GuardNode`] - Individual guard node
/// - [`RendGuard`] - Rendezvous point tracking
/// - [`crate::config::VanguardsConfig`] - Configuration options
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VanguardState {
    /// Layer 2 guard nodes (second hop).
    pub layer2: Vec<GuardNode>,
    /// Layer 3 guard nodes (third hop).
    pub layer3: Vec<GuardNode>,
    /// Path to the state file.
    pub state_file: String,
    /// Rendezvous point usage tracking.
    pub rendguard: RendGuard,
    /// Version number for pickle compatibility.
    pub pickle_revision: u32,
    /// Whether vanguards are enabled (runtime flag, not persisted).
    #[serde(skip)]
    pub enable_vanguards: bool,
}

impl Default for VanguardState {
    fn default() -> Self {
        Self::new("vanguards.state")
    }
}

impl VanguardState {
    /// Creates a new empty vanguard state.
    pub fn new(state_file: &str) -> Self {
        Self {
            layer2: Vec::new(),
            layer3: Vec::new(),
            state_file: state_file.to_string(),
            rendguard: RendGuard::new(),
            pickle_revision: 1,
            enable_vanguards: true,
        }
    }

    /// Loads state from a file or creates new state if the file doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the state file
    ///
    /// # Returns
    ///
    /// The loaded or newly created state.
    pub fn load_or_create(path: &Path) -> Self {
        match Self::read_from_file(path) {
            Ok(mut state) => {
                state.state_file = path.to_string_lossy().to_string();
                state
            }
            Err(_) => Self::new(&path.to_string_lossy()),
        }
    }

    /// Reads state from a pickle file with validation.
    ///
    /// Validates that:
    /// - All fingerprints are valid 40-character hex strings
    /// - No timestamps are in the future (with 1 hour tolerance)
    /// - The file format is valid
    ///
    /// # Errors
    ///
    /// Returns [`Error::State`] if the file cannot be read, parsed, or fails validation.
    pub fn read_from_file(path: &Path) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| Error::State(format!("cannot open state file: {}", e)))?;
        let reader = BufReader::new(file);
        let state: Self = serde_pickle::from_reader(reader, Default::default())
            .map_err(|e| Error::State(format!("cannot parse state file: {}", e)))?;

        // Validate the loaded state
        state.validate()?;

        Ok(state)
    }

    /// Validates the state for integrity.
    ///
    /// Checks:
    /// - All fingerprints are valid 40-character hex strings
    /// - No timestamps are in the future (with 1 hour tolerance for clock skew)
    ///
    /// # Errors
    ///
    /// Returns [`Error::State`] if validation fails.
    pub fn validate(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        // Allow 1 hour tolerance for clock skew
        let max_timestamp = now + 3600.0;

        // Validate layer2 guards
        for guard in &self.layer2 {
            if !is_valid_fingerprint(&guard.idhex) {
                return Err(Error::State(format!(
                    "invalid fingerprint in layer2: {}",
                    guard.idhex
                )));
            }
            if guard.chosen_at > max_timestamp {
                return Err(Error::State(format!(
                    "future timestamp in layer2 guard {}: chosen_at {} > now {}",
                    guard.idhex, guard.chosen_at, now
                )));
            }
            if guard.expires_at > max_timestamp + 86400.0 * 365.0 {
                // Allow up to 1 year in the future for expires_at
                return Err(Error::State(format!(
                    "unreasonable future expiration in layer2 guard {}: expires_at {}",
                    guard.idhex, guard.expires_at
                )));
            }
        }

        // Validate layer3 guards
        for guard in &self.layer3 {
            if !is_valid_fingerprint(&guard.idhex) {
                return Err(Error::State(format!(
                    "invalid fingerprint in layer3: {}",
                    guard.idhex
                )));
            }
            if guard.chosen_at > max_timestamp {
                return Err(Error::State(format!(
                    "future timestamp in layer3 guard {}: chosen_at {} > now {}",
                    guard.idhex, guard.chosen_at, now
                )));
            }
            if guard.expires_at > max_timestamp + 86400.0 * 365.0 {
                return Err(Error::State(format!(
                    "unreasonable future expiration in layer3 guard {}: expires_at {}",
                    guard.idhex, guard.expires_at
                )));
            }
        }

        // Validate rendguard fingerprints
        for fp in self.rendguard.use_counts.keys() {
            // Skip special NOT_IN_CONSENSUS_ID
            if fp == "NOT_IN_CONSENSUS" {
                continue;
            }
            if !is_valid_fingerprint(fp) {
                return Err(Error::State(format!(
                    "invalid fingerprint in rendguard: {}",
                    fp
                )));
            }
        }

        Ok(())
    }

    /// Writes state to a pickle file with atomic write and secure permissions.
    ///
    /// Uses atomic write (write to temp file, then rename) to prevent corruption.
    /// On Unix systems, sets file permissions to 0600 (owner read/write only).
    ///
    /// # Errors
    ///
    /// Returns [`Error::State`] if the file cannot be written.
    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        // Create a temporary file in the same directory for atomic write
        let temp_path = path.with_extension("tmp");

        // Create file with secure permissions on Unix
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)
                .map_err(|e| Error::State(format!("cannot create temp state file: {}", e)))?
        };

        #[cfg(not(unix))]
        let file = File::create(&temp_path)
            .map_err(|e| Error::State(format!("cannot create temp state file: {}", e)))?;

        let mut writer = BufWriter::new(file);
        serde_pickle::to_writer(&mut writer, self, Default::default())
            .map_err(|e| Error::State(format!("cannot write state file: {}", e)))?;

        // Ensure all data is flushed
        writer
            .flush()
            .map_err(|e| Error::State(format!("cannot flush state file: {}", e)))?;
        drop(writer);

        // Atomic rename
        std::fs::rename(&temp_path, path)
            .map_err(|e| Error::State(format!("cannot rename temp state file: {}", e)))?;

        Ok(())
    }

    /// Returns the layer 2 guard fingerprints as a comma-separated string.
    pub fn layer2_guardset(&self) -> String {
        self.layer2
            .iter()
            .map(|g| g.idhex.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Returns the layer 3 guard fingerprints as a comma-separated string.
    pub fn layer3_guardset(&self) -> String {
        self.layer3
            .iter()
            .map(|g| g.idhex.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Calculates a guard lifetime using max of two uniform random samples.
    ///
    /// This distribution favors longer lifetimes, providing better security
    /// by reducing guard rotation frequency.
    ///
    /// # Arguments
    ///
    /// * `min_hours` - Minimum lifetime in hours
    /// * `max_hours` - Maximum lifetime in hours
    ///
    /// # Returns
    ///
    /// Lifetime in seconds.
    pub fn calculate_guard_lifetime(min_hours: u32, max_hours: u32) -> f64 {
        let mut rng = rand::thread_rng();
        let min_secs = min_hours as f64 * SEC_PER_HOUR;
        let max_secs = max_hours as f64 * SEC_PER_HOUR;
        let sample1 = rng.gen_range(min_secs..=max_secs);
        let sample2 = rng.gen_range(min_secs..=max_secs);
        sample1.max(sample2)
    }

    /// Adds a new layer 2 guard.
    ///
    /// Selects a guard using the provided generator, avoiding duplicates
    /// and excluded nodes.
    pub fn add_new_layer2(
        &mut self,
        generator: &BwWeightedGenerator,
        excluded: &ExcludeNodes,
        config: &VanguardsConfig,
    ) -> Result<()> {
        let existing: HashSet<_> = self.layer2.iter().map(|g| g.idhex.as_str()).collect();

        for _ in 0..1000 {
            let guard = generator.generate()?;
            if existing.contains(guard.fingerprint.as_str()) {
                continue;
            }
            if excluded.router_is_excluded(guard) {
                continue;
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let lifetime = Self::calculate_guard_lifetime(
                config.min_layer2_lifetime_hours,
                config.max_layer2_lifetime_hours,
            );
            let expires = now + lifetime;

            self.layer2
                .push(GuardNode::new(guard.fingerprint.clone(), now, expires));
            return Ok(());
        }

        Err(Error::NoNodesRemain)
    }

    /// Adds a new layer 3 guard.
    ///
    /// Selects a guard using the provided generator, avoiding duplicates
    /// and excluded nodes.
    pub fn add_new_layer3(
        &mut self,
        generator: &BwWeightedGenerator,
        excluded: &ExcludeNodes,
        config: &VanguardsConfig,
    ) -> Result<()> {
        let existing: HashSet<_> = self.layer3.iter().map(|g| g.idhex.as_str()).collect();

        for _ in 0..1000 {
            let guard = generator.generate()?;
            if existing.contains(guard.fingerprint.as_str()) {
                continue;
            }
            if excluded.router_is_excluded(guard) {
                continue;
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let lifetime = Self::calculate_guard_lifetime(
                config.min_layer3_lifetime_hours,
                config.max_layer3_lifetime_hours,
            );
            let expires = now + lifetime;

            self.layer3
                .push(GuardNode::new(guard.fingerprint.clone(), now, expires));
            return Ok(());
        }

        Err(Error::NoNodesRemain)
    }

    /// Removes guards that are no longer in the consensus.
    pub fn remove_down_from_layer(layer: &mut Vec<GuardNode>, consensus_fps: &HashSet<String>) {
        layer.retain(|g| consensus_fps.contains(&g.idhex));
    }

    /// Removes guards whose rotation time has expired.
    pub fn remove_expired_from_layer(layer: &mut Vec<GuardNode>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        layer.retain(|g| g.expires_at >= now);
    }

    /// Removes guards that match the ExcludeNodes configuration.
    pub fn remove_excluded_from_layer(
        layer: &mut Vec<GuardNode>,
        router_map: &HashMap<String, &RouterStatusEntry>,
        excluded: &ExcludeNodes,
    ) {
        layer.retain(|g| {
            if let Some(router) = router_map.get(&g.idhex) {
                !excluded.router_is_excluded(router)
            } else {
                true
            }
        });
    }

    /// Replenishes guard layers to configured counts.
    ///
    /// First trims layers if they exceed configured counts, then adds
    /// new guards until the configured count is reached.
    pub fn replenish_layers(
        &mut self,
        generator: &BwWeightedGenerator,
        excluded: &ExcludeNodes,
        config: &VanguardsConfig,
    ) -> Result<()> {
        self.layer2.truncate(config.num_layer2_guards as usize);
        self.layer3.truncate(config.num_layer3_guards as usize);

        while self.layer2.len() < config.num_layer2_guards as usize {
            self.add_new_layer2(generator, excluded, config)?;
        }

        while self.layer3.len() < config.num_layer3_guards as usize {
            self.add_new_layer3(generator, excluded, config)?;
        }

        Ok(())
    }
}

/// Parsed ExcludeNodes configuration for relay filtering.
///
/// Parses Tor's ExcludeNodes configuration option to filter out unwanted
/// relays based on various criteria. This is used to ensure vanguard guards
/// respect the user's exclusion preferences.
///
/// # Supported Entry Types
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    ExcludeNodes Entry Types                             │
/// │                                                                         │
/// │  Type          │ Format                     │ Example                   │
/// │  ──────────────┼────────────────────────────┼───────────────────────────│
/// │  Fingerprint   │ $FINGERPRINT or FINGERPRINT│ $AABB...EEFF              │
/// │  Country       │ {cc}                       │ {us}, {ru}                │
/// │  Network       │ IP/CIDR                    │ 192.168.0.0/16            │
/// │  IP Address    │ IP                         │ 192.168.1.1               │
/// │  Nickname      │ name                       │ BadRelay                  │
/// └─────────────────────────────────────────────────────────────────────────┘
/// ```
///
/// # GeoIPExcludeUnknown
///
/// The `exclude_unknowns` field controls handling of relays with unknown
/// country codes:
///
/// | Setting | Behavior |
/// |---------|----------|
/// | `"1"` | Always exclude `??` and `a1` country codes |
/// | `"auto"` | Exclude `??` and `a1` only if other countries are excluded |
/// | `None` | Don't exclude unknown countries |
///
/// # Example
///
/// ```rust
/// use vanguards_rs::vanguards::ExcludeNodes;
///
/// // Parse mixed exclusion configuration
/// let exclude = ExcludeNodes::parse(
///     "$AABBCCDD00112233445566778899AABBCCDDEEFF,{us},192.168.0.0/16,BadRelay",
///     Some("auto")
/// );
///
/// assert!(exclude.idhexes.contains("AABBCCDD00112233445566778899AABBCCDDEEFF"));
/// assert!(exclude.countries.contains("us"));
/// assert!(exclude.countries.contains("??")); // auto-added due to {us}
/// assert_eq!(exclude.networks.len(), 1);
/// assert!(exclude.nicks.contains("BadRelay"));
/// ```
///
/// # See Also
///
/// - [`VanguardState::remove_excluded_from_layer`] - Uses this for filtering
/// - [Tor Manual - ExcludeNodes](https://2019.www.torproject.org/docs/tor-manual.html.en#ExcludeNodes)
#[derive(Debug, Clone, Default)]
pub struct ExcludeNodes {
    /// IP networks to exclude (CIDR notation).
    pub networks: Vec<IpNetwork>,
    /// Relay fingerprints to exclude (uppercase hex).
    pub idhexes: HashSet<String>,
    /// Relay nicknames to exclude.
    pub nicks: HashSet<String>,
    /// Country codes to exclude (lowercase).
    pub countries: HashSet<String>,
    /// GeoIPExcludeUnknown setting ("1", "auto", or None).
    pub exclude_unknowns: Option<String>,
}

impl ExcludeNodes {
    /// Creates a new empty ExcludeNodes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses an ExcludeNodes configuration line.
    ///
    /// # Arguments
    ///
    /// * `conf_line` - The ExcludeNodes configuration value (comma-separated)
    /// * `exclude_unknowns` - The GeoIPExcludeUnknown setting
    ///
    /// # Returns
    ///
    /// A parsed ExcludeNodes struct.
    ///
    /// # Entry Format
    ///
    /// Entries are comma-separated and can be:
    ///
    /// - `$FINGERPRINT` or `FINGERPRINT` - 40 hex character fingerprint
    /// - `$FINGERPRINT~nickname` or `$FINGERPRINT=nickname` - Fingerprint with suffix (suffix stripped)
    /// - `{cc}` - Country code (2 characters)
    /// - `192.168.0.0/24` or `2001:db8::/32` - IP network
    /// - `nickname` - Relay nickname
    pub fn parse(conf_line: &str, exclude_unknowns: Option<&str>) -> Self {
        let mut result = Self::new();
        result.exclude_unknowns = exclude_unknowns.map(|s| s.to_string());

        if let Some(ref setting) = result.exclude_unknowns {
            if setting == "1" {
                result.countries.insert("??".to_string());
                result.countries.insert("a1".to_string());
            }
        }

        if conf_line.is_empty() {
            return result;
        }

        result.parse_line(conf_line);
        result
    }

    /// Parses a single configuration line.
    fn parse_line(&mut self, conf_line: &str) {
        for part in conf_line.split(',') {
            let mut p = part.trim().to_string();
            if p.is_empty() {
                continue;
            }

            if p.starts_with('$') {
                p = p[1..].to_string();
            }

            if let Some(idx) = p.find('~') {
                p = p[..idx].to_string();
            }
            if let Some(idx) = p.find('=') {
                p = p[..idx].to_string();
            }

            if is_valid_fingerprint(&p) {
                self.idhexes.insert(p.to_uppercase());
            } else if p.starts_with('{') && p.ends_with('}') && p.len() >= 3 {
                let cc = &p[1..p.len() - 1];
                if is_valid_country_code(cc) {
                    self.countries.insert(cc.to_lowercase());
                }
            } else if p.contains(':') || p.contains('.') {
                if let Ok(network) = p.parse::<IpNetwork>() {
                    self.networks.push(network);
                } else if let Ok(ip) = p.parse::<IpAddr>() {
                    let network = match ip {
                        IpAddr::V4(_) => format!("{}/32", ip).parse().ok(),
                        IpAddr::V6(_) => format!("{}/128", ip).parse().ok(),
                    };
                    if let Some(net) = network {
                        self.networks.push(net);
                    }
                }
            } else {
                self.nicks.insert(p);
            }
        }

        if let Some(ref setting) = self.exclude_unknowns {
            if setting == "auto" && !self.countries.is_empty() {
                self.countries.insert("??".to_string());
                self.countries.insert("a1".to_string());
            }
        }
    }

    /// Checks if a router should be excluded.
    ///
    /// # Arguments
    ///
    /// * `router` - The router status entry to check
    ///
    /// # Returns
    ///
    /// `true` if the router matches any exclusion criteria.
    pub fn router_is_excluded(&self, router: &RouterStatusEntry) -> bool {
        if self.idhexes.contains(&router.fingerprint.to_uppercase()) {
            return true;
        }

        if self.nicks.contains(&router.nickname) {
            return true;
        }

        let addresses = self.get_router_addresses(router);
        for (addr, _port, _is_ipv6) in &addresses {
            for network in &self.networks {
                if network.contains(*addr) {
                    return true;
                }
            }
        }

        false
    }

    /// Gets all addresses for a router.
    fn get_router_addresses(&self, router: &RouterStatusEntry) -> Vec<(IpAddr, u16, bool)> {
        let mut addresses = vec![(router.address, router.or_port, router.address.is_ipv6())];
        addresses.extend(router.or_addresses.iter().cloned());
        addresses
    }

    /// Returns true if this ExcludeNodes has any exclusions configured.
    pub fn has_exclusions(&self) -> bool {
        !self.networks.is_empty()
            || !self.idhexes.is_empty()
            || !self.nicks.is_empty()
            || !self.countries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use stem_rs::descriptor::router_status::RouterStatusEntryType;

    fn create_test_router(fingerprint: &str, nickname: &str, address: &str) -> RouterStatusEntry {
        RouterStatusEntry::new(
            RouterStatusEntryType::V3,
            nickname.to_string(),
            fingerprint.to_string(),
            Utc::now(),
            address.parse().unwrap(),
            9001,
        )
    }

    #[test]
    fn test_guard_node_creation() {
        let now = 1000000.0;
        let expires = 2000000.0;
        let guard = GuardNode::new("A".repeat(40), now, expires);
        assert_eq!(guard.idhex, "A".repeat(40));
        assert_eq!(guard.chosen_at, now);
        assert_eq!(guard.expires_at, expires);
    }

    #[test]
    fn test_guard_node_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let expired = GuardNode::new("A".repeat(40), now - 1000.0, now - 100.0);
        assert!(expired.is_expired());

        let not_expired = GuardNode::new("B".repeat(40), now, now + 86400.0);
        assert!(!not_expired.is_expired());
    }

    #[test]
    fn test_vanguard_state_new() {
        let state = VanguardState::new("test.state");
        assert!(state.layer2.is_empty());
        assert!(state.layer3.is_empty());
        assert_eq!(state.state_file, "test.state");
        assert_eq!(state.pickle_revision, 1);
    }

    #[test]
    fn test_vanguard_state_guardset() {
        let mut state = VanguardState::new("test.state");
        state
            .layer2
            .push(GuardNode::new("A".repeat(40), 0.0, 1000.0));
        state
            .layer2
            .push(GuardNode::new("B".repeat(40), 0.0, 1000.0));

        let guardset = state.layer2_guardset();
        assert!(guardset.contains(&"A".repeat(40)));
        assert!(guardset.contains(&"B".repeat(40)));
        assert!(guardset.contains(','));
    }

    #[test]
    fn test_calculate_guard_lifetime() {
        for _ in 0..100 {
            let lifetime = VanguardState::calculate_guard_lifetime(24, 1080);
            let min_secs = 24.0 * SEC_PER_HOUR;
            let max_secs = 1080.0 * SEC_PER_HOUR;
            assert!(lifetime >= min_secs);
            assert!(lifetime <= max_secs);
        }
    }

    #[test]
    fn test_remove_expired_from_layer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut layer = vec![
            GuardNode::new("A".repeat(40), now - 1000.0, now - 100.0),
            GuardNode::new("B".repeat(40), now, now + 86400.0),
            GuardNode::new("C".repeat(40), now - 2000.0, now - 500.0),
        ];

        VanguardState::remove_expired_from_layer(&mut layer);
        assert_eq!(layer.len(), 1);
        assert_eq!(layer[0].idhex, "B".repeat(40));
    }

    #[test]
    fn test_remove_down_from_layer() {
        let mut layer = vec![
            GuardNode::new("A".repeat(40), 0.0, 1000.0),
            GuardNode::new("B".repeat(40), 0.0, 1000.0),
            GuardNode::new("C".repeat(40), 0.0, 1000.0),
        ];

        let mut consensus_fps = HashSet::new();
        consensus_fps.insert("A".repeat(40));
        consensus_fps.insert("C".repeat(40));

        VanguardState::remove_down_from_layer(&mut layer, &consensus_fps);
        assert_eq!(layer.len(), 2);
        assert!(layer.iter().any(|g| g.idhex == "A".repeat(40)));
        assert!(layer.iter().any(|g| g.idhex == "C".repeat(40)));
        assert!(!layer.iter().any(|g| g.idhex == "B".repeat(40)));
    }

    #[test]
    fn test_exclude_nodes_parse_fingerprint() {
        let exclude = ExcludeNodes::parse("$AABBCCDD00112233445566778899AABBCCDDEEFF", None);
        assert!(exclude
            .idhexes
            .contains("AABBCCDD00112233445566778899AABBCCDDEEFF"));
    }

    #[test]
    fn test_exclude_nodes_parse_fingerprint_without_dollar() {
        let exclude = ExcludeNodes::parse("AABBCCDD00112233445566778899AABBCCDDEEFF", None);
        assert!(exclude
            .idhexes
            .contains("AABBCCDD00112233445566778899AABBCCDDEEFF"));
    }

    #[test]
    fn test_exclude_nodes_parse_fingerprint_with_suffix() {
        let exclude =
            ExcludeNodes::parse("$AABBCCDD00112233445566778899AABBCCDDEEFF~nickname", None);
        assert!(exclude
            .idhexes
            .contains("AABBCCDD00112233445566778899AABBCCDDEEFF"));
        assert!(!exclude.nicks.contains("nickname"));

        let exclude2 =
            ExcludeNodes::parse("$AABBCCDD00112233445566778899AABBCCDDEEFF=nickname", None);
        assert!(exclude2
            .idhexes
            .contains("AABBCCDD00112233445566778899AABBCCDDEEFF"));
    }

    #[test]
    fn test_exclude_nodes_parse_country_code() {
        let exclude = ExcludeNodes::parse("{us}", None);
        assert!(exclude.countries.contains("us"));

        let exclude2 = ExcludeNodes::parse("{US}", None);
        assert!(exclude2.countries.contains("us"));
    }

    #[test]
    fn test_exclude_nodes_parse_network() {
        let exclude = ExcludeNodes::parse("192.168.0.0/24", None);
        assert_eq!(exclude.networks.len(), 1);

        let exclude2 = ExcludeNodes::parse("2001:db8::/32", None);
        assert_eq!(exclude2.networks.len(), 1);
    }

    #[test]
    fn test_exclude_nodes_parse_ip_address() {
        let exclude = ExcludeNodes::parse("192.168.1.1", None);
        assert_eq!(exclude.networks.len(), 1);
    }

    #[test]
    fn test_exclude_nodes_parse_nickname() {
        let exclude = ExcludeNodes::parse("BadRelay", None);
        assert!(exclude.nicks.contains("BadRelay"));
    }

    #[test]
    fn test_exclude_nodes_parse_mixed() {
        let exclude = ExcludeNodes::parse(
            "$AABBCCDD00112233445566778899AABBCCDDEEFF,{us},192.168.0.0/16,BadRelay",
            None,
        );
        assert!(exclude
            .idhexes
            .contains("AABBCCDD00112233445566778899AABBCCDDEEFF"));
        assert!(exclude.countries.contains("us"));
        assert_eq!(exclude.networks.len(), 1);
        assert!(exclude.nicks.contains("BadRelay"));
    }

    #[test]
    fn test_exclude_nodes_geoip_exclude_unknown_1() {
        let exclude = ExcludeNodes::parse("", Some("1"));
        assert!(exclude.countries.contains("??"));
        assert!(exclude.countries.contains("a1"));
    }

    #[test]
    fn test_exclude_nodes_geoip_exclude_unknown_auto() {
        let exclude = ExcludeNodes::parse("{us}", Some("auto"));
        assert!(exclude.countries.contains("us"));
        assert!(exclude.countries.contains("??"));
        assert!(exclude.countries.contains("a1"));
    }

    #[test]
    fn test_exclude_nodes_geoip_exclude_unknown_auto_no_countries() {
        let exclude = ExcludeNodes::parse("BadRelay", Some("auto"));
        assert!(!exclude.countries.contains("??"));
        assert!(!exclude.countries.contains("a1"));
    }

    #[test]
    fn test_router_is_excluded_by_fingerprint() {
        let exclude = ExcludeNodes::parse("$AABBCCDD00112233445566778899AABBCCDDEEFF", None);
        let router = create_test_router(
            "AABBCCDD00112233445566778899AABBCCDDEEFF",
            "test",
            "192.0.2.1",
        );
        assert!(exclude.router_is_excluded(&router));
    }

    #[test]
    fn test_router_is_excluded_by_nickname() {
        let exclude = ExcludeNodes::parse("BadRelay", None);
        let router = create_test_router(&"A".repeat(40), "BadRelay", "192.0.2.1");
        assert!(exclude.router_is_excluded(&router));
    }

    #[test]
    fn test_router_is_excluded_by_network() {
        let exclude = ExcludeNodes::parse("192.168.0.0/16", None);
        let router = create_test_router(&"A".repeat(40), "test", "192.168.1.1");
        assert!(exclude.router_is_excluded(&router));

        let router2 = create_test_router(&"B".repeat(40), "test2", "10.0.0.1");
        assert!(!exclude.router_is_excluded(&router2));
    }

    #[test]
    fn test_router_not_excluded() {
        let exclude = ExcludeNodes::parse("$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB,{de}", None);
        let router = create_test_router(&"A".repeat(40), "GoodRelay", "192.0.2.1");
        assert!(!exclude.router_is_excluded(&router));
    }

    #[test]
    fn test_rendguard_new() {
        let rg = RendGuard::new();
        assert!(rg.use_counts.is_empty());
        assert_eq!(rg.total_use_counts, 0.0);
        assert_eq!(rg.pickle_revision, 1.0);
    }

    #[test]
    fn test_rendguard_scale_counts() {
        let mut rg = RendGuard::new();
        rg.use_counts.insert(
            "A".repeat(40),
            RendUseCount {
                idhex: "A".repeat(40),
                used: 100.0,
                weight: 0.5,
            },
        );
        rg.use_counts.insert(
            "B".repeat(40),
            RendUseCount {
                idhex: "B".repeat(40),
                used: 200.0,
                weight: 0.5,
            },
        );
        rg.total_use_counts = 300.0;

        rg.scale_counts();

        assert_eq!(rg.use_counts.get(&"A".repeat(40)).unwrap().used, 50.0);
        assert_eq!(rg.use_counts.get(&"B".repeat(40)).unwrap().used, 100.0);
        assert_eq!(rg.total_use_counts, 150.0);
    }

    #[test]
    fn test_exclude_nodes_has_exclusions() {
        let empty = ExcludeNodes::new();
        assert!(!empty.has_exclusions());

        let with_fp = ExcludeNodes::parse("$AABBCCDD00112233445566778899AABBCCDDEEFF", None);
        assert!(with_fp.has_exclusions());

        let with_country = ExcludeNodes::parse("{us}", None);
        assert!(with_country.has_exclusions());

        let with_network = ExcludeNodes::parse("192.168.0.0/24", None);
        assert!(with_network.has_exclusions());

        let with_nick = ExcludeNodes::parse("BadRelay", None);
        assert!(with_nick.has_exclusions());
    }

    #[test]
    fn test_exclude_nodes_empty_string() {
        let exclude = ExcludeNodes::parse("", None);
        assert!(!exclude.has_exclusions());
    }

    #[test]
    fn test_exclude_nodes_whitespace_handling() {
        let exclude =
            ExcludeNodes::parse(" $AABBCCDD00112233445566778899AABBCCDDEEFF , {us} ", None);
        assert!(exclude
            .idhexes
            .contains("AABBCCDD00112233445566778899AABBCCDDEEFF"));
        assert!(exclude.countries.contains("us"));
    }

    #[test]
    fn test_vanguard_state_validation_valid() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut state = VanguardState::new("test.state");
        state
            .layer2
            .push(GuardNode::new("A".repeat(40), now - 1000.0, now + 86400.0));
        state
            .layer3
            .push(GuardNode::new("B".repeat(40), now - 500.0, now + 3600.0));

        assert!(state.validate().is_ok());
    }

    #[test]
    fn test_vanguard_state_validation_invalid_fingerprint() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut state = VanguardState::new("test.state");
        state
            .layer2
            .push(GuardNode::new("invalid".to_string(), now, now + 86400.0));

        assert!(state.validate().is_err());
    }

    #[test]
    fn test_vanguard_state_validation_future_timestamp() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut state = VanguardState::new("test.state");
        state
            .layer2
            .push(GuardNode::new("A".repeat(40), now + 10000.0, now + 86400.0));

        assert!(state.validate().is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::node_selection::is_valid_fingerprint;
    use proptest::prelude::*;

    fn arb_fingerprint() -> impl Strategy<Value = String> {
        "[0-9A-F]{40}".prop_map(|s| s.to_uppercase())
    }

    fn arb_country_code() -> impl Strategy<Value = String> {
        "[a-z]{2}"
    }

    fn arb_ipv4() -> impl Strategy<Value = String> {
        (1u8..=254, 0u8..=255, 0u8..=255, 1u8..=254)
            .prop_map(|(a, b, c, d)| format!("{}.{}.{}.{}", a, b, c, d))
    }

    fn arb_cidr() -> impl Strategy<Value = String> {
        (arb_ipv4(), 8u8..=30).prop_map(|(ip, prefix)| format!("{}/{}", ip, prefix))
    }

    fn arb_nickname() -> impl Strategy<Value = String> {
        "[A-Za-z][A-Za-z0-9]{0,18}"
    }

    fn arb_guard_node() -> impl Strategy<Value = GuardNode> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let chosen_min = now - 365.0 * 86400.0;
        let chosen_max = now;
        let expires_max = now + 365.0 * 86400.0;

        (
            arb_fingerprint(),
            chosen_min..chosen_max,
            chosen_max..expires_max,
        )
            .prop_map(|(idhex, chosen_at, expires_at)| GuardNode::new(idhex, chosen_at, expires_at))
    }

    fn arb_rend_use_count() -> impl Strategy<Value = RendUseCount> {
        (arb_fingerprint(), 0.0f64..10000.0, 0.0f64..1.0).prop_map(|(idhex, used, weight)| {
            RendUseCount {
                idhex,
                used,
                weight,
            }
        })
    }

    fn arb_rendguard() -> impl Strategy<Value = RendGuard> {
        (
            prop::collection::vec(arb_rend_use_count(), 0..10),
            0.0f64..100000.0,
        )
            .prop_map(|(counts, total)| {
                let mut rg = RendGuard::new();
                for count in counts {
                    rg.use_counts.insert(count.idhex.clone(), count);
                }
                rg.total_use_counts = total;
                rg
            })
    }

    fn arb_vanguard_state() -> impl Strategy<Value = VanguardState> {
        (
            prop::collection::vec(arb_guard_node(), 0..8),
            prop::collection::vec(arb_guard_node(), 0..16),
            arb_rendguard(),
        )
            .prop_map(|(layer2, layer3, rendguard)| {
                let mut state = VanguardState::new("test.state");
                state.layer2 = layer2;
                state.layer3 = layer3;
                state.rendguard = rendguard;
                state
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn exclude_nodes_parsing(
            fingerprints in prop::collection::vec(arb_fingerprint(), 0..5),
            countries in prop::collection::vec(arb_country_code(), 0..5),
            networks in prop::collection::vec(arb_cidr(), 0..3),
            nicknames in prop::collection::vec(arb_nickname(), 0..5),
        ) {
            let mut parts = Vec::new();

            for fp in &fingerprints {
                parts.push(format!("${}", fp));
            }
            for cc in &countries {
                parts.push(format!("{{{}}}", cc));
            }
            for net in &networks {
                parts.push(net.clone());
            }
            for nick in &nicknames {
                parts.push(nick.clone());
            }

            let conf_line = parts.join(",");
            let exclude = ExcludeNodes::parse(&conf_line, None);

            for fp in &fingerprints {
                prop_assert!(exclude.idhexes.contains(&fp.to_uppercase()),
                    "Fingerprint {} not found in parsed idhexes", fp);
            }

            for cc in &countries {
                prop_assert!(exclude.countries.contains(&cc.to_lowercase()),
                    "Country code {} not found in parsed countries", cc);
            }

            prop_assert_eq!(exclude.networks.len(), networks.len(),
                "Expected {} networks, got {}", networks.len(), exclude.networks.len());

            for nick in &nicknames {
                if !is_valid_fingerprint(nick) && !nick.contains('.') && !nick.contains(':') {
                    prop_assert!(exclude.nicks.contains(nick),
                        "Nickname {} not found in parsed nicks", nick);
                }
            }
        }

        #[test]
        fn state_serialization_round_trip(state in arb_vanguard_state()) {
            let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
            let state_path = temp_dir.path().join("test.state");

            state.write_to_file(&state_path).expect("Failed to write state");
            let loaded = VanguardState::read_from_file(&state_path).expect("Failed to read state");

            prop_assert_eq!(state.layer2.len(), loaded.layer2.len());
            prop_assert_eq!(state.layer3.len(), loaded.layer3.len());

            for (orig, load) in state.layer2.iter().zip(loaded.layer2.iter()) {
                prop_assert_eq!(&orig.idhex, &load.idhex);
                prop_assert!((orig.chosen_at - load.chosen_at).abs() < 0.001);
                prop_assert!((orig.expires_at - load.expires_at).abs() < 0.001);
            }

            for (orig, load) in state.layer3.iter().zip(loaded.layer3.iter()) {
                prop_assert_eq!(&orig.idhex, &load.idhex);
                prop_assert!((orig.chosen_at - load.chosen_at).abs() < 0.001);
                prop_assert!((orig.expires_at - load.expires_at).abs() < 0.001);
            }

            prop_assert_eq!(state.rendguard.use_counts.len(), loaded.rendguard.use_counts.len());
            prop_assert!((state.rendguard.total_use_counts - loaded.rendguard.total_use_counts).abs() < 0.001);
        }

        #[test]
        fn guard_lifetime_distribution(
            min_hours in 1u32..100,
            max_hours in 100u32..2000,
        ) {
            prop_assume!(min_hours < max_hours);

            let min_secs = min_hours as f64 * 3600.0;
            let max_secs = max_hours as f64 * 3600.0;

            let mut lifetimes = Vec::new();
            for _ in 0..100 {
                let lifetime = VanguardState::calculate_guard_lifetime(min_hours, max_hours);
                prop_assert!(lifetime >= min_secs, "Lifetime {} below min {}", lifetime, min_secs);
                prop_assert!(lifetime <= max_secs, "Lifetime {} above max {}", lifetime, max_secs);
                lifetimes.push(lifetime);
            }

            let avg = lifetimes.iter().sum::<f64>() / lifetimes.len() as f64;
            let midpoint = (min_secs + max_secs) / 2.0;
            prop_assert!(avg > midpoint,
                "Average lifetime {} should be above midpoint {} (max of two uniforms)", avg, midpoint);
        }

        #[test]
        fn expired_guard_removal(
            num_expired in 0usize..5,
            num_valid in 0usize..5,
        ) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();

            let mut layer = Vec::new();
            let mut expected_remaining = HashSet::new();

            for i in 0..num_expired {
                let fp = format!("{:0>40X}", i);
                layer.push(GuardNode::new(fp, now - 10000.0, now - 1000.0));
            }

            for i in 0..num_valid {
                let fp = format!("{:0>40X}", 100 + i);
                layer.push(GuardNode::new(fp.clone(), now - 1000.0, now + 86400.0));
                expected_remaining.insert(fp);
            }

            VanguardState::remove_expired_from_layer(&mut layer);

            prop_assert_eq!(layer.len(), num_valid,
                "Expected {} guards after removal, got {}", num_valid, layer.len());

            for guard in &layer {
                prop_assert!(expected_remaining.contains(&guard.idhex),
                    "Unexpected guard {} in layer", guard.idhex);
                prop_assert!(guard.expires_at >= now,
                    "Guard {} should not be expired", guard.idhex);
            }
        }

        #[test]
        fn down_guard_removal(
            num_in_consensus in 0usize..5,
            num_not_in_consensus in 0usize..5,
        ) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();

            let mut layer = Vec::new();
            let mut consensus_fps = HashSet::new();

            for i in 0..num_in_consensus {
                let fp = format!("{:0>40X}", i);
                layer.push(GuardNode::new(fp.clone(), now, now + 86400.0));
                consensus_fps.insert(fp);
            }

            for i in 0..num_not_in_consensus {
                let fp = format!("{:0>40X}", 100 + i);
                layer.push(GuardNode::new(fp, now, now + 86400.0));
            }

            VanguardState::remove_down_from_layer(&mut layer, &consensus_fps);

            prop_assert_eq!(layer.len(), num_in_consensus,
                "Expected {} guards after removal, got {}", num_in_consensus, layer.len());

            for guard in &layer {
                prop_assert!(consensus_fps.contains(&guard.idhex),
                    "Guard {} should be in consensus", guard.idhex);
            }
        }

        #[test]
        fn layer_trimming(
            initial_layer2 in 0usize..20,
            initial_layer3 in 0usize..30,
            target_layer2 in 1u8..10,
            target_layer3 in 1u8..15,
        ) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();

            let mut state = VanguardState::new("test.state");

            for i in 0..initial_layer2 {
                let fp = format!("{:0>40X}", i);
                state.layer2.push(GuardNode::new(fp, now, now + 86400.0));
            }

            for i in 0..initial_layer3 {
                let fp = format!("{:0>40X}", 100 + i);
                state.layer3.push(GuardNode::new(fp, now, now + 86400.0));
            }

            state.layer2.truncate(target_layer2 as usize);
            state.layer3.truncate(target_layer3 as usize);

            let expected_layer2 = initial_layer2.min(target_layer2 as usize);
            let expected_layer3 = initial_layer3.min(target_layer3 as usize);

            prop_assert_eq!(state.layer2.len(), expected_layer2,
                "Layer2 should have {} guards, got {}", expected_layer2, state.layer2.len());
            prop_assert_eq!(state.layer3.len(), expected_layer3,
                "Layer3 should have {} guards, got {}", expected_layer3, state.layer3.len());
        }
    }
}
