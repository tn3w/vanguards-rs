//! Bandwidth monitoring for detecting side-channel attacks.
//!
//! This module provides protection against bandwidth-based side-channel attacks
//! by monitoring circuit bandwidth usage and detecting anomalies.
//!
//! # Overview
//!
//! The bandguards system monitors:
//!
//! - **Circuit bandwidth**: Read/written bytes per circuit
//! - **Dropped cells**: Cells received but not delivered (potential attack indicator)
//! - **Circuit age**: Old circuits that may be vulnerable
//! - **Guard connections**: Connection state and closure correlation
//!
//! # Circuit State Diagram
//!
//! Circuits progress through the following states, with bandwidth monitoring at each stage:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                      Circuit State Transitions                          │
//! │                                                                         │
//! │                         ┌─────────────┐                                 │
//! │                         │  LAUNCHED   │                                 │
//! │                         │ (created)   │                                 │
//! │                         └──────┬──────┘                                 │
//! │                                │                                        │
//! │                                ▼                                        │
//! │                         ┌─────────────┐                                 │
//! │                         │  EXTENDED   │◀────────┐                      │
//! │                         │ (building)  │         │                       │
//! │                         └──────┬──────┘         │                       │
//! │                                │                │                       │
//! │                    ┌───────────┼───────────┐    │                       │
//! │                    │           │           │    │                       │
//! │                    ▼           ▼           ▼    │                       │
//! │             ┌───────────┐ ┌─────────┐ ┌────────┴───┐                    │
//! │             │   BUILT   │ │ FAILED  │ │ GUARD_WAIT │                    │
//! │             │ (active)  │ │         │ │            │                    │
//! │             └─────┬─────┘ └────┬────┘ └────────────┘                    │
//! │                   │            │                                        │
//! │    ┌──────────────┼────────────┘                                        │
//! │    │              │                                                     │
//! │    │              ▼                                                     │
//! │    │       ┌─────────────┐                                              │
//! │    │       │  Bandwidth  │                                              │
//! │    │       │  Monitoring │                                              │
//! │    │       │  (CIRC_BW)  │                                              │
//! │    │       └──────┬──────┘                                              │
//! │    │              │                                                     │
//! │    │    ┌─────────┼─────────┐                                           │
//! │    │    │         │         │                                           │
//! │    │    ▼         ▼         ▼                                           │
//! │    │ ┌──────┐ ┌──────┐ ┌──────────┐                                     │
//! │    │ │Normal│ │Attack│ │Tor Bug   │                                     │
//! │    │ │      │ │Detect│ │Workaround│                                     │
//! │    │ └──┬───┘ └──┬───┘ └────┬─────┘                                     │
//! │    │    │        │          │                                           │
//! │    │    │        ▼          │                                           │
//! │    │    │   ┌─────────┐     │                                           │
//! │    │    │   │ CLOSE   │     │                                           │
//! │    │    │   │ CIRCUIT │     │                                           │
//! │    │    │   └─────────┘     │                                           │
//! │    │    │                   │                                           │
//! │    └────┼───────────────────┘                                           │
//! │         │                                                               │
//! │         ▼                                                               │
//! │  ┌─────────────┐                                                        │
//! │  │   CLOSED    │                                                        │
//! │  │ (cleanup)   │                                                        │
//! │  └─────────────┘                                                        │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Attack Detection
//!
//! Several attack vectors are detected and mitigated:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Attack Detection Matrix                          │
//! │                                                                         │
//! │  Attack Type          │ Detection Method        │ Response              │
//! │  ─────────────────────┼─────────────────────────┼───────────────────────│
//! │  Dropped Cells        │ read - delivered ≠ 0    │ Close circuit         │
//! │  Excessive Bandwidth  │ bytes > max_megabytes   │ Close circuit         │
//! │  HSDIR Abuse          │ hsdir bytes > limit     │ Close circuit         │
//! │  Intro Abuse          │ intro bytes > limit     │ Close circuit         │
//! │  Old Circuits         │ age > max_age_hours     │ Close circuit         │
//! │  Guard Conn Kill      │ conn close + circ fail  │ Log warning           │
//! │  Network Disconnect   │ no conns for N secs     │ Log warning           │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Dropped Cell Detection
//!
//! Dropped cells indicate cells that were received but not delivered to the
//! application. This can indicate a tagging attack or protocol manipulation.
//!
//! ```text
//! Formula: dropped = read_bytes / CELL_PAYLOAD_SIZE
//!                  - (delivered_read + overhead_read) / RELAY_PAYLOAD_SIZE
//!
//! Where:
//!   CELL_PAYLOAD_SIZE = 509 bytes
//!   RELAY_PAYLOAD_SIZE = 498 bytes (509 - 11 byte header)
//! ```
//!
//! # Tor Bug Workarounds
//!
//! This module includes workarounds for known Tor bugs that can cause
//! false positive dropped cell detection:
//!
//! | Bug ID | Description | Affected Circuits |
//! |--------|-------------|-------------------|
//! | #29699 | Intro circuits get duped cells on retries | HS_SERVICE_INTRO |
//! | #29700 | Service rend circuits fail ntor handshake | HS_SERVICE_REND |
//! | #29786 | Path bias circuits have dropped cell cases | PATH_BIAS_TESTING |
//! | #29927 | Client-side dropped cells and protocol errors | HS_CLIENT_* |
//! | #40359 | Client intro circuits with dropped cells | CIRCUIT_PADDING |
//!
//! # What This Module Does NOT Do
//!
//! - **Circuit creation**: Use Tor's circuit building
//! - **Guard selection**: Use [`crate::vanguards`] for guard management
//! - **Rendezvous monitoring**: Use [`crate::rendguard`] for RP tracking
//!
//! # Example
//!
//! ```rust,no_run
//! use vanguards_rs::bandguards::{BandwidthStats, CircuitLimitResult};
//! use vanguards_rs::config::BandguardsConfig;
//!
//! let mut stats = BandwidthStats::new();
//! let config = BandguardsConfig::default();
//!
//! // Process circuit events
//! stats.circ_event("123", "LAUNCHED", "HS_SERVICE_REND",
//!                  Some("HSSR_CONNECTING"), &[], None, 1000.0);
//! stats.circ_event("123", "BUILT", "HS_SERVICE_REND",
//!                  Some("HSSR_CONNECTING"), &["A".repeat(40)], None, 1001.0);
//!
//! // Process bandwidth events
//! stats.circbw_event("123", 1000, 500, 800, 400, 100, 50, 1002.0);
//!
//! // Check for attacks
//! match stats.check_circuit_limits("123", &config) {
//!     CircuitLimitResult::Ok => println!("Circuit OK"),
//!     CircuitLimitResult::DroppedCells { dropped_cells } => {
//!         println!("Attack detected: {} dropped cells", dropped_cells);
//!     }
//!     _ => {}
//! }
//! ```
//!
//! # Security Considerations
//!
//! - Dropped cell detection may have false positives due to Tor bugs
//! - Configure appropriate thresholds for your threat model
//! - Monitor logs for attack patterns
//! - Consider enabling `close_circuits` only after testing
//!
//! # See Also
//!
//! - [`crate::config::BandguardsConfig`] - Configuration options
//! - [`crate::control`] - Event handling and circuit closure
//! - [Python vanguards bandguards](https://github.com/mikeperry-tor/vanguards) - Original implementation
//! - [Tor Bug Tracker](https://gitlab.torproject.org/tpo/core/tor/-/issues) - Bug references

use std::collections::HashMap;

use crate::config::BandguardsConfig;

/// Cell payload size in bytes.
pub const CELL_PAYLOAD_SIZE: u64 = 509;

/// Relay header size in bytes.
pub const RELAY_HEADER_SIZE: u64 = 11;

/// Relay payload size (cell payload minus relay header).
pub const RELAY_PAYLOAD_SIZE: u64 = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE;

/// Seconds per hour.
const SECS_PER_HOUR: u64 = 3600;

/// Bytes per kilobyte.
const BYTES_PER_KB: u64 = 1024;

/// Bytes per megabyte.
const BYTES_PER_MB: u64 = 1024 * BYTES_PER_KB;

/// Maximum lag between guard connection close and circuit destroy events.
pub const MAX_CIRC_DESTROY_LAG_SECS: u64 = 2;

/// Per-circuit bandwidth statistics for attack detection.
///
/// Tracks all bandwidth-related information for a single circuit,
/// including read/written bytes, delivered/overhead bytes, and
/// circuit state information.
///
/// # Circuit Tracking
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                        BwCircuitStat Fields                              │
/// │                                                                          │
/// │  Identity          │ State              │ Bandwidth                     │
/// │  ──────────────────┼────────────────────┼───────────────────────────────│
/// │  circ_id           │ purpose            │ read_bytes                    │
/// │  guard_fp          │ hs_state           │ sent_bytes                    │
/// │  created_at        │ old_purpose        │ delivered_read_bytes          │
/// │                    │ old_hs_state       │ delivered_sent_bytes          │
/// │                    │ built              │ overhead_read_bytes           │
/// │                    │ in_use             │ overhead_sent_bytes           │
/// │                                                                          │
/// │  Flags             │ Attack Detection                                   │
/// │  ──────────────────┼────────────────────────────────────────────────────│
/// │  is_hs             │ dropped_cells_allowed                              │
/// │  is_service        │ possibly_destroyed_at                              │
/// │  is_hsdir          │                                                    │
/// │  is_serv_intro     │                                                    │
/// └─────────────────────────────────────────────────────────────────────────┘
/// ```
///
/// # Dropped Cell Detection
///
/// Dropped cells are detected using the formula:
/// ```text
/// dropped = read_bytes / CELL_PAYLOAD_SIZE - (delivered_read + overhead_read) / RELAY_PAYLOAD_SIZE
/// ```
///
/// # Circuit Types
///
/// | Flag | Description |
/// |------|-------------|
/// | `is_hs` | Hidden service circuit (client or service) |
/// | `is_service` | Service-side circuit (vs client-side) |
/// | `is_hsdir` | HSDIR circuit for descriptor operations |
/// | `is_serv_intro` | Service introduction circuit |
///
/// # Example
///
/// ```rust
/// use vanguards_rs::bandguards::BwCircuitStat;
///
/// let mut circ = BwCircuitStat::new("123".to_string(), true);
/// circ.read_bytes = 5090;  // 10 cells
/// circ.delivered_read_bytes = 3984;  // 8 cells delivered
///
/// let dropped = circ.dropped_read_cells();
/// println!("Dropped cells: {}", dropped);
/// ```
///
/// # See Also
///
/// - [`BandwidthStats`] - Main tracking structure
/// - [`CircuitLimitResult`] - Limit check results
#[derive(Debug, Clone)]
pub struct BwCircuitStat {
    /// Circuit ID.
    pub circ_id: String,
    /// Whether this is a hidden service circuit.
    pub is_hs: bool,
    /// Whether this is a service-side circuit (vs client).
    pub is_service: bool,
    /// Whether this is an HSDIR circuit.
    pub is_hsdir: bool,
    /// Whether this is a service intro circuit.
    pub is_serv_intro: bool,
    /// Number of dropped cells allowed (for Tor bug workarounds).
    pub dropped_cells_allowed: u64,
    /// Current circuit purpose.
    pub purpose: Option<String>,
    /// Current hidden service state.
    pub hs_state: Option<String>,
    /// Previous circuit purpose (before PURPOSE_CHANGED).
    pub old_purpose: Option<String>,
    /// Previous hidden service state.
    pub old_hs_state: Option<String>,
    /// Whether the circuit is in use.
    pub in_use: bool,
    /// Whether the circuit has been built.
    pub built: bool,
    /// Unix timestamp when the circuit was created.
    pub created_at: f64,
    /// Total bytes read on this circuit.
    pub read_bytes: u64,
    /// Total bytes sent on this circuit.
    pub sent_bytes: u64,
    /// Delivered read bytes (application data).
    pub delivered_read_bytes: u64,
    /// Delivered sent bytes (application data).
    pub delivered_sent_bytes: u64,
    /// Overhead read bytes (protocol overhead).
    pub overhead_read_bytes: u64,
    /// Overhead sent bytes (protocol overhead).
    pub overhead_sent_bytes: u64,
    /// Guard fingerprint for this circuit.
    pub guard_fp: Option<String>,
    /// Timestamp when the circuit may have been destroyed due to guard closure.
    pub possibly_destroyed_at: Option<f64>,
}

impl BwCircuitStat {
    /// Creates a new circuit stat entry.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - The circuit ID
    /// * `is_hs` - Whether this is a hidden service circuit
    pub fn new(circ_id: String, is_hs: bool) -> Self {
        Self {
            circ_id,
            is_hs,
            is_service: true,
            is_hsdir: false,
            is_serv_intro: false,
            dropped_cells_allowed: 0,
            purpose: None,
            hs_state: None,
            old_purpose: None,
            old_hs_state: None,
            in_use: false,
            built: false,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            read_bytes: 0,
            sent_bytes: 0,
            delivered_read_bytes: 0,
            delivered_sent_bytes: 0,
            overhead_read_bytes: 0,
            overhead_sent_bytes: 0,
            guard_fp: None,
            possibly_destroyed_at: None,
        }
    }

    /// Returns the total bytes (read + sent) on this circuit.
    pub fn total_bytes(&self) -> u64 {
        self.read_bytes + self.sent_bytes
    }

    /// Calculates the number of dropped read cells.
    ///
    /// Dropped cells are cells that were received but not delivered to the
    /// application. This can indicate an attack or a Tor bug.
    ///
    /// # Formula
    ///
    /// ```text
    /// dropped = read_bytes / CELL_PAYLOAD_SIZE - (delivered_read + overhead_read) / RELAY_PAYLOAD_SIZE
    /// ```
    ///
    /// # Returns
    ///
    /// The number of dropped cells. Can be negative due to timing issues.
    pub fn dropped_read_cells(&self) -> i64 {
        let cells_received = self.read_bytes / CELL_PAYLOAD_SIZE;
        let cells_delivered =
            (self.delivered_read_bytes + self.overhead_read_bytes) / RELAY_PAYLOAD_SIZE;
        cells_received as i64 - cells_delivered as i64
    }

    /// Returns the circuit age in seconds.
    pub fn age_secs(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        now - self.created_at
    }

    /// Returns the circuit age in hours.
    pub fn age_hours(&self) -> f64 {
        self.age_secs() / SECS_PER_HOUR as f64
    }
}

/// Per-guard connection statistics.
///
/// Tracks connection state and closure information for a single guard relay.
#[derive(Debug, Clone)]
pub struct BwGuardStat {
    /// Guard fingerprint.
    pub to_guard: String,
    /// Number of connections killed with live circuits.
    pub killed_conns: u32,
    /// Timestamp of last killed connection.
    pub killed_conn_at: f64,
    /// Whether a killed connection is pending correlation.
    pub killed_conn_pending: bool,
    /// Total connections made to this guard.
    pub conns_made: u32,
    /// Close reasons and their counts.
    pub close_reasons: HashMap<String, u32>,
}

impl BwGuardStat {
    /// Creates a new guard stat entry.
    ///
    /// # Arguments
    ///
    /// * `guard_fp` - The guard's fingerprint
    pub fn new(guard_fp: String) -> Self {
        Self {
            to_guard: guard_fp,
            killed_conns: 0,
            killed_conn_at: 0.0,
            killed_conn_pending: false,
            conns_made: 0,
            close_reasons: HashMap::new(),
        }
    }

    /// Records a close reason.
    pub fn record_close_reason(&mut self, reason: &str) {
        *self.close_reasons.entry(reason.to_string()).or_insert(0) += 1;
    }
}

/// Main bandwidth monitoring state for attack detection.
///
/// Tracks all circuit and guard connection statistics for bandwidth monitoring.
/// This is the primary interface for the bandguards protection system.
///
/// # Architecture
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                         BandwidthStats                                   │
/// │                                                                          │
/// │  ┌─────────────────────────────────────────────────────────────────┐    │
/// │  │ Circuit Tracking (circs: HashMap<String, BwCircuitStat>)        │    │
/// │  │ • Per-circuit bandwidth statistics                              │    │
/// │  │ • Dropped cell detection                                        │    │
/// │  │ • Purpose and state tracking                                    │    │
/// │  └─────────────────────────────────────────────────────────────────┘    │
/// │                                                                          │
/// │  ┌─────────────────────────────────────────────────────────────────┐    │
/// │  │ Guard Tracking (guards: HashMap<String, BwGuardStat>)           │    │
/// │  │ • Connection state per guard                                    │    │
/// │  │ • Killed connection correlation                                 │    │
/// │  │ • Close reason tracking                                         │    │
/// │  └─────────────────────────────────────────────────────────────────┘    │
/// │                                                                          │
/// │  ┌─────────────────────────────────────────────────────────────────┐    │
/// │  │ Connectivity Tracking                                           │    │
/// │  │ • no_conns_since: When all guard connections were lost          │    │
/// │  │ • no_circs_since: When all circuits started failing             │    │
/// │  │ • network_down_since: When network liveness went down           │    │
/// │  └─────────────────────────────────────────────────────────────────┘    │
/// └─────────────────────────────────────────────────────────────────────────┘
/// ```
///
/// # Event Handling
///
/// This struct processes several Tor event types:
///
/// | Event | Method | Purpose |
/// |-------|--------|---------|
/// | ORCONN | `orconn_event` | Guard connection state changes |
/// | CIRC | `circ_event` | Circuit state changes |
/// | CIRC_MINOR | `circ_minor_event` | Purpose changes |
/// | CIRC_BW | `circbw_event` | Bandwidth updates |
/// | BW | `check_connectivity` | Periodic connectivity checks |
/// | NETWORK_LIVENESS | `network_liveness_event` | Network state changes |
///
/// # Example
///
/// ```rust
/// use vanguards_rs::bandguards::BandwidthStats;
/// use vanguards_rs::config::BandguardsConfig;
///
/// let mut stats = BandwidthStats::new();
/// let config = BandguardsConfig::default();
///
/// // Track a guard connection
/// stats.orconn_event("1", &"A".repeat(40), "CONNECTED", None, 1000.0);
///
/// // Track a circuit
/// stats.circ_event("123", "LAUNCHED", "GENERAL", None, &[], None, 1000.0);
/// stats.circ_event("123", "BUILT", "GENERAL", None, &["A".repeat(40)], None, 1001.0);
///
/// // Check connectivity
/// let status = stats.check_connectivity(1002.0, &config);
/// ```
///
/// # See Also
///
/// - [`BwCircuitStat`] - Per-circuit statistics
/// - [`BwGuardStat`] - Per-guard statistics
/// - [`CircuitLimitResult`] - Limit check results
/// - [`ConnectivityStatus`] - Connectivity check results
#[derive(Debug, Clone)]
pub struct BandwidthStats {
    /// Circuit statistics by circuit ID.
    pub circs: HashMap<String, BwCircuitStat>,
    /// Live guard connections by connection ID.
    pub live_guard_conns: HashMap<String, BwGuardStat>,
    /// All guard statistics by fingerprint.
    pub guards: HashMap<String, BwGuardStat>,
    /// Total circuits destroyed.
    pub circs_destroyed_total: u64,
    /// Timestamp when all connections were lost (None if connected).
    pub no_conns_since: Option<f64>,
    /// Timestamp when circuits started failing (None if working).
    pub no_circs_since: Option<f64>,
    /// Timestamp when network went down (None if up).
    pub network_down_since: Option<f64>,
    /// Maximum fake ID used for initial orconn-status entries.
    pub max_fake_id: i32,
    /// Whether we're currently disconnected (circuits failing).
    pub disconnected_circs: bool,
    /// Whether we're currently disconnected (no connections).
    pub disconnected_conns: bool,
}

impl Default for BandwidthStats {
    fn default() -> Self {
        Self::new()
    }
}

impl BandwidthStats {
    /// Creates a new bandwidth stats tracker.
    pub fn new() -> Self {
        Self {
            circs: HashMap::new(),
            live_guard_conns: HashMap::new(),
            guards: HashMap::new(),
            circs_destroyed_total: 0,
            no_conns_since: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
            ),
            no_circs_since: None,
            network_down_since: None,
            max_fake_id: -1,
            disconnected_circs: false,
            disconnected_conns: false,
        }
    }

    /// Handles an ORCONN event.
    ///
    /// Tracks guard connection state changes. When a connection closes,
    /// marks any circuits using that guard as possibly destroyed.
    ///
    /// # Arguments
    ///
    /// * `conn_id` - Connection ID
    /// * `guard_fp` - Guard fingerprint
    /// * `status` - Connection status (CONNECTED, CLOSED, FAILED)
    /// * `reason` - Close reason (for CLOSED status)
    /// * `arrived_at` - Event timestamp
    pub fn orconn_event(
        &mut self,
        conn_id: &str,
        guard_fp: &str,
        status: &str,
        reason: Option<&str>,
        arrived_at: f64,
    ) {
        // Ensure guard entry exists
        if !self.guards.contains_key(guard_fp) {
            self.guards
                .insert(guard_fp.to_string(), BwGuardStat::new(guard_fp.to_string()));
        }

        match status {
            "CONNECTED" => {
                if self.disconnected_conns {
                    self.disconnected_conns = false;
                }
                self.live_guard_conns
                    .insert(conn_id.to_string(), BwGuardStat::new(guard_fp.to_string()));
                if let Some(guard) = self.guards.get_mut(guard_fp) {
                    guard.conns_made += 1;
                }
                self.no_conns_since = None;
            }
            "CLOSED" | "FAILED" => {
                // Try to fix up fake IDs
                let actual_conn_id = self.fixup_orconn_id(conn_id, guard_fp);

                if self.live_guard_conns.contains_key(&actual_conn_id) {
                    // Mark circuits as possibly destroyed
                    for circ in self.circs.values_mut() {
                        if circ.in_use && circ.guard_fp.as_deref() == Some(guard_fp) {
                            circ.possibly_destroyed_at = Some(arrived_at);
                            if let Some(guard) = self.guards.get_mut(guard_fp) {
                                guard.killed_conn_at = arrived_at;
                            }
                        }
                    }

                    self.live_guard_conns.remove(&actual_conn_id);

                    if self.live_guard_conns.is_empty() && self.no_conns_since.is_none() {
                        self.no_conns_since = Some(arrived_at);
                    }
                }

                // Record close reason
                if status == "CLOSED" {
                    if let Some(r) = reason {
                        if let Some(guard) = self.guards.get_mut(guard_fp) {
                            guard.record_close_reason(r);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Fixes up connection IDs for fake IDs from initial orconn-status.
    fn fixup_orconn_id(&self, conn_id: &str, guard_fp: &str) -> String {
        // Check if this is a fake ID that needs fixing
        if let Ok(id) = conn_id.parse::<i32>() {
            if id <= self.max_fake_id {
                // Look for matching guard in live connections
                for (fake_id, stat) in &self.live_guard_conns {
                    if stat.to_guard == guard_fp {
                        if let Ok(fid) = fake_id.parse::<i32>() {
                            if fid <= self.max_fake_id {
                                return fake_id.clone();
                            }
                        }
                    }
                }
            }
        }
        conn_id.to_string()
    }

    /// Handles a CIRC event.
    ///
    /// Tracks circuit state changes including creation, building, and closure.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID
    /// * `status` - Circuit status (LAUNCHED, BUILT, EXTENDED, FAILED, CLOSED)
    /// * `purpose` - Circuit purpose
    /// * `hs_state` - Hidden service state
    /// * `path` - Circuit path (list of relay fingerprints)
    /// * `remote_reason` - Remote close reason
    /// * `arrived_at` - Event timestamp
    ///
    /// # Returns
    ///
    /// `Some(true)` if circuit was destroyed due to guard connection closure,
    /// `Some(false)` if circuit was closed normally, `None` otherwise.
    #[allow(clippy::too_many_arguments)]
    pub fn circ_event(
        &mut self,
        circ_id: &str,
        status: &str,
        purpose: &str,
        hs_state: Option<&str>,
        path: &[String],
        remote_reason: Option<&str>,
        arrived_at: f64,
    ) -> Option<bool> {
        // Handle circuit failures for connectivity tracking
        if status == "FAILED"
            && self.no_circs_since.is_none()
            && self.any_circuits_pending(Some(circ_id))
        {
            self.no_circs_since = Some(arrived_at);
        }

        // Handle circuit closure
        if status == "FAILED" || status == "CLOSED" {
            if let Some(circ) = self.circs.remove(circ_id) {
                if circ.in_use && circ.possibly_destroyed_at.is_some() {
                    if let Some(destroyed_at) = circ.possibly_destroyed_at {
                        if arrived_at - destroyed_at <= MAX_CIRC_DESTROY_LAG_SECS as f64
                            && remote_reason == Some("CHANNEL_CLOSED")
                        {
                            // Circuit was destroyed due to guard connection closure
                            if let Some(guard_fp) = &circ.guard_fp {
                                if let Some(guard) = self.guards.get_mut(guard_fp) {
                                    guard.killed_conn_at = 0.0;
                                    guard.killed_conns += 1;
                                }
                            }
                            self.circs_destroyed_total += 1;
                            return Some(true);
                        }
                    }
                }
                return Some(false);
            }
            return None;
        }

        // Create circuit entry if needed
        let is_hs = hs_state.is_some() || purpose.starts_with("HS");
        if !self.circs.contains_key(circ_id) {
            let mut circ = BwCircuitStat::new(circ_id.to_string(), is_hs);

            // Set service/client based on purpose
            if purpose.starts_with("HS_CLIENT") {
                circ.is_service = false;
            } else if purpose.starts_with("HS_SERVICE") {
                circ.is_service = true;
            }

            // Set HSDIR and intro flags
            if purpose == "HS_CLIENT_HSDIR" || purpose == "HS_SERVICE_HSDIR" {
                circ.is_hsdir = true;
            } else if purpose == "HS_SERVICE_INTRO" {
                circ.is_serv_intro = true;
            }

            self.circs.insert(circ_id.to_string(), circ);
        }

        // Update circuit state
        if let Some(circ) = self.circs.get_mut(circ_id) {
            circ.purpose = Some(purpose.to_string());
            circ.hs_state = hs_state.map(|s| s.to_string());

            // Handle BUILT and GUARD_WAIT
            if status == "BUILT" || status == "GUARD_WAIT" {
                circ.built = true;

                if self.disconnected_circs {
                    self.disconnected_circs = false;
                }
                self.no_circs_since = None;

                // Mark as in_use if HS purpose
                if purpose.starts_with("HS_CLIENT") || purpose.starts_with("HS_SERVICE") {
                    circ.in_use = true;
                    if !path.is_empty() {
                        circ.guard_fp = Some(path[0].clone());
                    }
                }
            } else if status == "EXTENDED" {
                if self.disconnected_circs {
                    self.disconnected_circs = false;
                }
                self.no_circs_since = None;
            }
        }

        None
    }

    /// Handles a CIRC_MINOR event (purpose changes).
    ///
    /// Tracks circuit purpose changes, particularly from HS_VANGUARDS to
    /// actual HS purposes.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID
    /// * `event_type` - Event type (PURPOSE_CHANGED, etc.)
    /// * `purpose` - New circuit purpose
    /// * `hs_state` - New hidden service state
    /// * `old_purpose` - Previous circuit purpose
    /// * `old_hs_state` - Previous hidden service state
    /// * `path` - Circuit path
    #[allow(clippy::too_many_arguments)]
    pub fn circ_minor_event(
        &mut self,
        circ_id: &str,
        event_type: &str,
        purpose: &str,
        hs_state: Option<&str>,
        old_purpose: Option<&str>,
        old_hs_state: Option<&str>,
        path: &[String],
    ) {
        if let Some(circ) = self.circs.get_mut(circ_id) {
            circ.purpose = Some(purpose.to_string());
            circ.hs_state = hs_state.map(|s| s.to_string());
            circ.old_purpose = old_purpose.map(|s| s.to_string());
            circ.old_hs_state = old_hs_state.map(|s| s.to_string());

            // Update service/client flag
            if purpose.starts_with("HS_CLIENT") {
                circ.is_service = false;
            } else if purpose.starts_with("HS_SERVICE") {
                circ.is_service = true;
            }

            // Update HSDIR and intro flags
            if purpose == "HS_CLIENT_HSDIR" || purpose == "HS_SERVICE_HSDIR" {
                circ.is_hsdir = true;
            } else if purpose == "HS_SERVICE_INTRO" {
                circ.is_serv_intro = true;
            }

            // PURPOSE_CHANGED from HS_VANGUARDS -> in_use
            if event_type == "PURPOSE_CHANGED" && old_purpose == Some("HS_VANGUARDS") {
                circ.in_use = true;
                if !path.is_empty() {
                    circ.guard_fp = Some(path[0].clone());
                }
            }
        }
    }

    /// Handles a CIRC_BW event (bandwidth update).
    ///
    /// Updates circuit bandwidth statistics and checks limits.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID
    /// * `read` - Bytes read
    /// * `written` - Bytes written
    /// * `delivered_read` - Delivered read bytes
    /// * `delivered_written` - Delivered written bytes
    /// * `overhead_read` - Overhead read bytes
    /// * `overhead_written` - Overhead written bytes
    /// * `arrived_at` - Event timestamp
    #[allow(clippy::too_many_arguments)]
    pub fn circbw_event(
        &mut self,
        circ_id: &str,
        read: u64,
        written: u64,
        delivered_read: u64,
        delivered_written: u64,
        overhead_read: u64,
        overhead_written: u64,
        _arrived_at: f64,
    ) {
        // Circuit bandwidth means circuits are working
        if self.disconnected_circs {
            self.disconnected_circs = false;
        }
        self.no_circs_since = None;

        if let Some(circ) = self.circs.get_mut(circ_id) {
            circ.read_bytes += read;
            circ.sent_bytes += written;
            circ.delivered_read_bytes += delivered_read;
            circ.delivered_sent_bytes += delivered_written;
            circ.overhead_read_bytes += overhead_read;
            circ.overhead_sent_bytes += overhead_written;
        }
    }

    /// Checks circuit limits and returns circuits that should be closed.
    ///
    /// Checks for:
    /// - Dropped cells (potential attack)
    /// - Maximum bytes exceeded
    /// - Maximum HSDIR bytes exceeded
    /// - Maximum service intro bytes exceeded
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID to check
    /// * `config` - Bandguards configuration
    ///
    /// # Returns
    ///
    /// A [`CircuitLimitResult`] indicating whether the circuit should be closed
    /// and why.
    pub fn check_circuit_limits(
        &self,
        circ_id: &str,
        config: &BandguardsConfig,
    ) -> CircuitLimitResult {
        let circ = match self.circs.get(circ_id) {
            Some(c) => c,
            None => return CircuitLimitResult::Ok,
        };

        // Check dropped cells
        let dropped = circ.dropped_read_cells();
        if dropped > circ.dropped_cells_allowed as i64 {
            // Check for Tor bug workarounds
            let tor_bug = self.check_tor_bug_workaround(circ, dropped);
            if let Some(bug_id) = tor_bug {
                return CircuitLimitResult::TorBug {
                    bug_id,
                    dropped_cells: dropped,
                };
            }

            if circ.built {
                return CircuitLimitResult::DroppedCells {
                    dropped_cells: dropped,
                };
            }
        }

        // Check max bytes
        if config.circ_max_megabytes > 0
            && circ.total_bytes() > config.circ_max_megabytes * BYTES_PER_MB
        {
            return CircuitLimitResult::MaxBytesExceeded {
                bytes: circ.total_bytes(),
                limit: config.circ_max_megabytes * BYTES_PER_MB,
            };
        }

        // Check HSDIR bytes
        if config.circ_max_hsdesc_kilobytes > 0
            && circ.is_hsdir
            && circ.total_bytes() > config.circ_max_hsdesc_kilobytes as u64 * BYTES_PER_KB
        {
            return CircuitLimitResult::HsdirBytesExceeded {
                bytes: circ.total_bytes(),
                limit: config.circ_max_hsdesc_kilobytes as u64 * BYTES_PER_KB,
            };
        }

        // Check service intro bytes
        if config.circ_max_serv_intro_kilobytes > 0
            && circ.is_serv_intro
            && circ.total_bytes() > config.circ_max_serv_intro_kilobytes as u64 * BYTES_PER_KB
        {
            return CircuitLimitResult::ServIntroBytesExceeded {
                bytes: circ.total_bytes(),
                limit: config.circ_max_serv_intro_kilobytes as u64 * BYTES_PER_KB,
            };
        }

        CircuitLimitResult::Ok
    }

    /// Checks for Tor bug workarounds for dropped cells.
    fn check_tor_bug_workaround(
        &self,
        circ: &BwCircuitStat,
        _dropped: i64,
    ) -> Option<&'static str> {
        let purpose = circ.purpose.as_deref().unwrap_or("");
        let hs_state = circ.hs_state.as_deref().unwrap_or("");
        let old_purpose = circ.old_purpose.as_deref().unwrap_or("");
        let old_hs_state = circ.old_hs_state.as_deref().unwrap_or("");

        // Bug #29699: Intro circuits can get duped cells on retries
        if purpose == "HS_SERVICE_INTRO" && hs_state == "HSSI_ESTABLISHED" {
            return Some("#29699");
        }

        // Bug #40359: Client intro circuits
        if purpose == "CIRCUIT_PADDING"
            && old_purpose == "HS_CLIENT_INTRO"
            && old_hs_state == "HSCI_INTRO_SENT"
        {
            return Some("#40359");
        }

        // Bug #29927: Client-side dropped cells
        if purpose == "HS_CLIENT_REND" || (purpose == "HS_CLIENT_INTRO" && hs_state == "HSCI_DONE")
        {
            return Some("#29927");
        }

        // Bug #29700: Service rend circuits
        if purpose == "HS_SERVICE_REND" && hs_state == "HSSR_CONNECTING" {
            return Some("#29700");
        }

        // Bug #29786: Path bias testing
        if purpose == "PATH_BIAS_TESTING" {
            return Some("#29786");
        }

        None
    }

    /// Returns circuits that have exceeded the maximum age.
    ///
    /// # Arguments
    ///
    /// * `config` - Bandguards configuration
    ///
    /// # Returns
    ///
    /// A list of circuit IDs that should be closed due to age.
    pub fn get_aged_circuits(&self, config: &BandguardsConfig) -> Vec<String> {
        if config.circ_max_age_hours == 0 {
            return Vec::new();
        }

        let max_age_secs = config.circ_max_age_hours as f64 * SECS_PER_HOUR as f64;
        self.circs
            .iter()
            .filter(|(_, circ)| circ.age_secs() > max_age_secs)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Checks connectivity status and returns warnings if disconnected.
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp
    /// * `config` - Bandguards configuration
    ///
    /// # Returns
    ///
    /// A [`ConnectivityStatus`] indicating the current connectivity state.
    pub fn check_connectivity(
        &mut self,
        now: f64,
        config: &BandguardsConfig,
    ) -> ConnectivityStatus {
        // Check connection disconnection
        if let Some(no_conns_since) = self.no_conns_since {
            let disconnected_secs = (now - no_conns_since) as u32;

            if config.conn_max_disconnected_secs > 0
                && disconnected_secs >= config.conn_max_disconnected_secs
                && (!self.disconnected_conns
                    || disconnected_secs.is_multiple_of(config.conn_max_disconnected_secs))
            {
                self.disconnected_conns = true;
                return ConnectivityStatus::NoConnections {
                    secs: disconnected_secs,
                };
            }
        } else if let Some(no_circs_since) = self.no_circs_since {
            let disconnected_secs = (now - no_circs_since) as u32;

            if config.circ_max_disconnected_secs > 0
                && disconnected_secs >= config.circ_max_disconnected_secs
                && self.any_circuits_pending(None)
                && (!self.disconnected_circs
                    || disconnected_secs.is_multiple_of(config.circ_max_disconnected_secs))
            {
                self.disconnected_circs = true;
                return ConnectivityStatus::CircuitsFailing {
                    secs: disconnected_secs,
                    network_down_secs: self.network_down_since.map(|t| (now - t) as u32),
                };
            }
        }

        ConnectivityStatus::Connected
    }

    /// Handles a NETWORK_LIVENESS event.
    ///
    /// # Arguments
    ///
    /// * `status` - Network status ("UP" or "DOWN")
    /// * `arrived_at` - Event timestamp
    pub fn network_liveness_event(&mut self, status: &str, arrived_at: f64) {
        match status {
            "UP" => {
                self.network_down_since = None;
            }
            "DOWN" => {
                self.network_down_since = Some(arrived_at);
            }
            _ => {}
        }
    }

    /// Returns true if any circuits are pending (not yet built).
    fn any_circuits_pending(&self, except_id: Option<&str>) -> bool {
        self.circs
            .iter()
            .any(|(id, circ)| !circ.built && except_id.is_none_or(|e| id != e))
    }

    /// Returns the number of tracked circuits.
    pub fn circuit_count(&self) -> usize {
        self.circs.len()
    }

    /// Returns the number of live guard connections.
    pub fn live_connection_count(&self) -> usize {
        self.live_guard_conns.len()
    }
}

/// Result of checking circuit limits.
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitLimitResult {
    /// Circuit is within limits.
    Ok,
    /// Circuit has dropped cells (potential attack).
    DroppedCells {
        /// Number of dropped cells.
        dropped_cells: i64,
    },
    /// Dropped cells due to known Tor bug.
    TorBug {
        /// Tor bug ID.
        bug_id: &'static str,
        /// Number of dropped cells.
        dropped_cells: i64,
    },
    /// Circuit exceeded maximum bytes.
    MaxBytesExceeded {
        /// Current bytes.
        bytes: u64,
        /// Configured limit.
        limit: u64,
    },
    /// HSDIR circuit exceeded maximum bytes.
    HsdirBytesExceeded {
        /// Current bytes.
        bytes: u64,
        /// Configured limit.
        limit: u64,
    },
    /// Service intro circuit exceeded maximum bytes.
    ServIntroBytesExceeded {
        /// Current bytes.
        bytes: u64,
        /// Configured limit.
        limit: u64,
    },
}

/// Connectivity status result.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectivityStatus {
    /// Connected and working.
    Connected,
    /// No guard connections.
    NoConnections {
        /// Seconds disconnected.
        secs: u32,
    },
    /// Circuits are failing.
    CircuitsFailing {
        /// Seconds circuits have been failing.
        secs: u32,
        /// Seconds network has been down (if known).
        network_down_secs: Option<u32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bw_circuit_stat_new() {
        let circ = BwCircuitStat::new("123".to_string(), true);
        assert_eq!(circ.circ_id, "123");
        assert!(circ.is_hs);
        assert!(circ.is_service);
        assert!(!circ.is_hsdir);
        assert!(!circ.is_serv_intro);
        assert_eq!(circ.read_bytes, 0);
        assert_eq!(circ.sent_bytes, 0);
    }

    #[test]
    fn test_total_bytes() {
        let mut circ = BwCircuitStat::new("123".to_string(), true);
        circ.read_bytes = 1000;
        circ.sent_bytes = 500;
        assert_eq!(circ.total_bytes(), 1500);
    }

    #[test]
    fn test_dropped_read_cells() {
        let mut circ = BwCircuitStat::new("123".to_string(), true);

        // 10 cells received (10 * 509 = 5090 bytes)
        circ.read_bytes = 5090;
        // 8 cells delivered (8 * 498 = 3984 bytes)
        circ.delivered_read_bytes = 3984;
        circ.overhead_read_bytes = 0;

        // Should have 2 dropped cells
        assert_eq!(circ.dropped_read_cells(), 2);
    }

    #[test]
    fn test_dropped_read_cells_with_overhead() {
        let mut circ = BwCircuitStat::new("123".to_string(), true);

        // 10 cells received
        circ.read_bytes = 5090;
        // 7 delivered + 1 overhead = 8 cells accounted for
        circ.delivered_read_bytes = 3486; // 7 * 498
        circ.overhead_read_bytes = 498; // 1 * 498

        // Should have 2 dropped cells
        assert_eq!(circ.dropped_read_cells(), 2);
    }

    #[test]
    fn test_bw_guard_stat_new() {
        let guard = BwGuardStat::new("A".repeat(40));
        assert_eq!(guard.to_guard, "A".repeat(40));
        assert_eq!(guard.killed_conns, 0);
        assert_eq!(guard.conns_made, 0);
        assert!(guard.close_reasons.is_empty());
    }

    #[test]
    fn test_record_close_reason() {
        let mut guard = BwGuardStat::new("A".repeat(40));
        guard.record_close_reason("DONE");
        guard.record_close_reason("DONE");
        guard.record_close_reason("ERROR");

        assert_eq!(guard.close_reasons.get("DONE"), Some(&2));
        assert_eq!(guard.close_reasons.get("ERROR"), Some(&1));
    }

    #[test]
    fn test_bandwidth_stats_new() {
        let stats = BandwidthStats::new();
        assert!(stats.circs.is_empty());
        assert!(stats.live_guard_conns.is_empty());
        assert!(stats.guards.is_empty());
        assert_eq!(stats.circs_destroyed_total, 0);
        assert!(stats.no_conns_since.is_some());
    }

    #[test]
    fn test_orconn_event_connected() {
        let mut stats = BandwidthStats::new();
        let fp = "A".repeat(40);

        stats.orconn_event("1", &fp, "CONNECTED", None, 1000.0);

        assert!(stats.live_guard_conns.contains_key("1"));
        assert!(stats.guards.contains_key(&fp));
        assert_eq!(stats.guards.get(&fp).unwrap().conns_made, 1);
        assert!(stats.no_conns_since.is_none());
    }

    #[test]
    fn test_orconn_event_closed() {
        let mut stats = BandwidthStats::new();
        let fp = "A".repeat(40);

        stats.orconn_event("1", &fp, "CONNECTED", None, 1000.0);
        stats.orconn_event("1", &fp, "CLOSED", Some("DONE"), 1001.0);

        assert!(!stats.live_guard_conns.contains_key("1"));
        assert!(stats.no_conns_since.is_some());
        assert_eq!(
            stats.guards.get(&fp).unwrap().close_reasons.get("DONE"),
            Some(&1)
        );
    }

    #[test]
    fn test_circ_event_creates_circuit() {
        let mut stats = BandwidthStats::new();

        stats.circ_event(
            "123",
            "LAUNCHED",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            &[],
            None,
            1000.0,
        );

        assert!(stats.circs.contains_key("123"));
        let circ = stats.circs.get("123").unwrap();
        assert!(circ.is_hs);
        assert!(circ.is_service);
    }

    #[test]
    fn test_circ_event_built() {
        let mut stats = BandwidthStats::new();
        let path = vec!["A".repeat(40)];

        stats.circ_event(
            "123",
            "LAUNCHED",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "123",
            "BUILT",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            &path,
            None,
            1001.0,
        );

        let circ = stats.circs.get("123").unwrap();
        assert!(circ.built);
        assert!(circ.in_use);
        assert_eq!(circ.guard_fp, Some("A".repeat(40)));
    }

    #[test]
    fn test_circbw_event() {
        let mut stats = BandwidthStats::new();

        stats.circ_event("123", "LAUNCHED", "GENERAL", None, &[], None, 1000.0);
        stats.circbw_event("123", 1000, 500, 800, 400, 100, 50, 1001.0);

        let circ = stats.circs.get("123").unwrap();
        assert_eq!(circ.read_bytes, 1000);
        assert_eq!(circ.sent_bytes, 500);
        assert_eq!(circ.delivered_read_bytes, 800);
        assert_eq!(circ.delivered_sent_bytes, 400);
        assert_eq!(circ.overhead_read_bytes, 100);
        assert_eq!(circ.overhead_sent_bytes, 50);
    }

    #[test]
    fn test_check_circuit_limits_ok() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event("123", "LAUNCHED", "GENERAL", None, &[], None, 1000.0);

        let result = stats.check_circuit_limits("123", &config);
        assert_eq!(result, CircuitLimitResult::Ok);
    }

    #[test]
    fn test_check_circuit_limits_max_bytes() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig {
            circ_max_megabytes: 1, // 1 MB limit
            ..Default::default()
        };

        stats.circ_event("123", "BUILT", "GENERAL", None, &[], None, 1000.0);
        // Set read_bytes with matching delivered bytes to avoid dropped cell detection
        let bytes = 2 * BYTES_PER_MB;
        let delivered = (bytes / CELL_PAYLOAD_SIZE) * RELAY_PAYLOAD_SIZE;
        stats.circbw_event("123", bytes, 0, delivered, 0, 0, 0, 1001.0);

        let result = stats.check_circuit_limits("123", &config);
        match result {
            CircuitLimitResult::MaxBytesExceeded { bytes: b, limit } => {
                assert_eq!(b, bytes);
                assert_eq!(limit, BYTES_PER_MB);
            }
            _ => panic!("Expected MaxBytesExceeded, got {:?}", result),
        }
    }

    #[test]
    fn test_network_liveness_event() {
        let mut stats = BandwidthStats::new();

        stats.network_liveness_event("DOWN", 1000.0);
        assert_eq!(stats.network_down_since, Some(1000.0));

        stats.network_liveness_event("UP", 1001.0);
        assert_eq!(stats.network_down_since, None);
    }

    #[test]
    fn test_connectivity_status_connected() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        // Simulate connected state
        stats.no_conns_since = None;
        stats.no_circs_since = None;

        let status = stats.check_connectivity(1000.0, &config);
        assert_eq!(status, ConnectivityStatus::Connected);
    }

    const BYTES_PER_KB_TEST: u64 = 1024;
    const CELL_DATA_RATE: f64 = RELAY_PAYLOAD_SIZE as f64 / CELL_PAYLOAD_SIZE as f64;

    fn check_hsdir(stats: &mut BandwidthStats, config: &BandguardsConfig, circ_id: &str) -> bool {
        let limit = config.circ_max_hsdesc_kilobytes as u64 * BYTES_PER_KB_TEST;
        let mut read: u64 = CELL_PAYLOAD_SIZE;

        while read < limit {
            let delivered = (CELL_DATA_RATE * CELL_PAYLOAD_SIZE as f64) as u64;
            stats.circbw_event(circ_id, CELL_PAYLOAD_SIZE, 0, delivered, 0, 0, 0, 1000.0);
            read += CELL_PAYLOAD_SIZE;

            if let CircuitLimitResult::HsdirBytesExceeded { .. } =
                stats.check_circuit_limits(circ_id, config)
            {
                return true;
            }
        }

        let delivered = (CELL_DATA_RATE * CELL_PAYLOAD_SIZE as f64) as u64;
        stats.circbw_event(circ_id, CELL_PAYLOAD_SIZE, 0, delivered, 0, 0, 0, 1000.0);
        matches!(
            stats.check_circuit_limits(circ_id, config),
            CircuitLimitResult::HsdirBytesExceeded { .. }
        )
    }

    fn check_serv_intro(
        stats: &mut BandwidthStats,
        config: &BandguardsConfig,
        circ_id: &str,
    ) -> bool {
        let limit = config.circ_max_serv_intro_kilobytes as u64 * BYTES_PER_KB_TEST;
        let mut read: u64 = CELL_PAYLOAD_SIZE;

        while read < limit {
            let delivered = (CELL_DATA_RATE * CELL_PAYLOAD_SIZE as f64) as u64;
            stats.circbw_event(circ_id, CELL_PAYLOAD_SIZE, 0, delivered, 0, 0, 0, 1000.0);
            read += CELL_PAYLOAD_SIZE;

            if let CircuitLimitResult::ServIntroBytesExceeded { .. } =
                stats.check_circuit_limits(circ_id, config)
            {
                return true;
            }
        }

        let delivered = (CELL_DATA_RATE * CELL_PAYLOAD_SIZE as f64) as u64;
        stats.circbw_event(circ_id, CELL_PAYLOAD_SIZE, 0, delivered, 0, 0, 0, 1000.0);
        matches!(
            stats.check_circuit_limits(circ_id, config),
            CircuitLimitResult::ServIntroBytesExceeded { .. }
        )
    }

    fn check_maxbytes(
        stats: &mut BandwidthStats,
        config: &BandguardsConfig,
        circ_id: &str,
    ) -> bool {
        let limit = config.circ_max_megabytes * BYTES_PER_MB;
        let chunk = 1000 * CELL_PAYLOAD_SIZE;
        let mut read: u64 = 0;

        while read + 2 * chunk < limit {
            let delivered = (CELL_DATA_RATE * chunk as f64) as u64;
            stats.circbw_event(circ_id, chunk, chunk, delivered, 0, 0, 0, 1000.0);
            read += 2 * chunk;

            if let CircuitLimitResult::MaxBytesExceeded { .. } =
                stats.check_circuit_limits(circ_id, config)
            {
                return true;
            }
        }

        let delivered = (CELL_DATA_RATE * (2 * chunk) as f64) as u64;
        stats.circbw_event(circ_id, 2 * chunk, 0, delivered, 0, 0, 0, 1000.0);
        matches!(
            stats.check_circuit_limits(circ_id, config),
            CircuitLimitResult::MaxBytesExceeded { .. }
        )
    }

    fn check_dropped_bytes(
        stats: &mut BandwidthStats,
        config: &BandguardsConfig,
        circ_id: &str,
        delivered_cells: u64,
        dropped_cells: u64,
    ) -> Option<CircuitLimitResult> {
        let valid_bytes = (CELL_DATA_RATE * CELL_PAYLOAD_SIZE as f64 / 2.0) as u64;
        for _ in 0..delivered_cells {
            stats.circbw_event(
                circ_id,
                CELL_PAYLOAD_SIZE,
                CELL_PAYLOAD_SIZE,
                valid_bytes,
                0,
                valid_bytes,
                0,
                1000.0,
            );
            let result = stats.check_circuit_limits(circ_id, config);
            if !matches!(result, CircuitLimitResult::Ok) {
                return Some(result);
            }
        }

        for _ in 0..dropped_cells {
            stats.circbw_event(
                circ_id,
                CELL_PAYLOAD_SIZE,
                CELL_PAYLOAD_SIZE,
                0,
                0,
                0,
                0,
                1000.0,
            );
            let result = stats.check_circuit_limits(circ_id, config);
            if !matches!(result, CircuitLimitResult::Ok) {
                return Some(result);
            }
        }

        None
    }

    #[test]
    fn test_circuit_built_failed_closed_removed_from_map() {
        let mut stats = BandwidthStats::new();

        stats.circ_event("1", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("1", "BUILT", "HS_VANGUARDS", None, &[], None, 1001.0);
        assert!(stats.circs.contains_key("1"));

        stats.circ_event("1", "FAILED", "HS_VANGUARDS", None, &[], None, 1002.0);
        assert!(!stats.circs.contains_key("1"));

        stats.circ_event("1", "CLOSED", "HS_VANGUARDS", None, &[], None, 1003.0);
        assert!(!stats.circs.contains_key("1"));
    }

    #[test]
    fn test_circuit_built_closed_removed_from_map() {
        let mut stats = BandwidthStats::new();

        stats.circ_event("2", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("2", "BUILT", "HS_VANGUARDS", None, &[], None, 1001.0);
        assert!(stats.circs.contains_key("2"));

        stats.circ_event("2", "CLOSED", "HS_VANGUARDS", None, &[], None, 1002.0);
        assert!(!stats.circs.contains_key("2"));
    }

    #[test]
    fn test_hsdir_size_cap_exceeded_direct_service_circ() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig {
            circ_max_hsdesc_kilobytes: 30,
            ..Default::default()
        };

        stats.circ_event(
            "3",
            "LAUNCHED",
            "HS_SERVICE_HSDIR",
            Some("HSSI_CONNECTING"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "3",
            "BUILT",
            "HS_SERVICE_HSDIR",
            Some("HSSI_CONNECTING"),
            &[],
            None,
            1001.0,
        );

        let circ = stats.circs.get("3").unwrap();
        assert!(circ.is_hsdir);
        assert!(circ.is_service);

        assert!(check_hsdir(&mut stats, &config, "3"));
    }

    #[test]
    fn test_hsdir_size_cap_disabled() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig {
            circ_max_hsdesc_kilobytes: 0,
            ..Default::default()
        };

        stats.circ_event(
            "5",
            "LAUNCHED",
            "HS_SERVICE_HSDIR",
            Some("HSSI_CONNECTING"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "5",
            "BUILT",
            "HS_SERVICE_HSDIR",
            Some("HSSI_CONNECTING"),
            &[],
            None,
            1001.0,
        );

        assert!(!check_hsdir(&mut stats, &config, "5"));
    }

    #[test]
    fn test_intro_size_cap_disabled_by_default() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        assert_eq!(config.circ_max_serv_intro_kilobytes, 0);

        stats.circ_event(
            "6",
            "LAUNCHED",
            "HS_SERVICE_INTRO",
            Some("HSSI_CONNECTING"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "6",
            "BUILT",
            "HS_SERVICE_INTRO",
            Some("HSSI_CONNECTING"),
            &[],
            None,
            1001.0,
        );

        let circ = stats.circs.get("6").unwrap();
        assert!(circ.is_serv_intro);
        assert!(circ.is_service);

        assert!(!check_serv_intro(&mut stats, &config, "6"));
    }

    #[test]
    fn test_intro_size_cap_exceeded() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig {
            circ_max_serv_intro_kilobytes: 1024,
            ..Default::default()
        };

        stats.circ_event(
            "7",
            "LAUNCHED",
            "HS_SERVICE_INTRO",
            Some("HSSI_CONNECTING"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "7",
            "BUILT",
            "HS_SERVICE_INTRO",
            Some("HSSI_CONNECTING"),
            &[],
            None,
            1001.0,
        );

        assert!(check_serv_intro(&mut stats, &config, "7"));
    }

    #[test]
    fn test_max_bytes_exceeded() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig {
            circ_max_megabytes: 100,
            ..Default::default()
        };

        stats.circ_event("10", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("10", "BUILT", "HS_VANGUARDS", None, &[], None, 1001.0);

        assert!(check_maxbytes(&mut stats, &config, "10"));
    }

    #[test]
    fn test_max_bytes_disabled() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig {
            circ_max_megabytes: 0,
            ..Default::default()
        };

        stats.circ_event(
            "11",
            "LAUNCHED",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "11",
            "BUILT",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            &[],
            None,
            1001.0,
        );

        assert!(!check_maxbytes(&mut stats, &config, "11"));
    }

    #[test]
    fn test_regular_reading_ok() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event("20", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("20", "BUILT", "HS_VANGUARDS", None, &[], None, 1001.0);

        let result = check_dropped_bytes(&mut stats, &config, "20", 100, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_dropped_cells_before_app_data() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event("21", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("21", "BUILT", "HS_VANGUARDS", None, &[], None, 1001.0);

        let result = check_dropped_bytes(&mut stats, &config, "21", 0, 1);
        assert!(matches!(
            result,
            Some(CircuitLimitResult::DroppedCells { .. })
        ));
    }

    #[test]
    fn test_dropped_cells_after_app_data() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event("22", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("22", "BUILT", "HS_VANGUARDS", None, &[], None, 1001.0);

        let result = check_dropped_bytes(&mut stats, &config, "22", 1000, 1);
        assert!(matches!(
            result,
            Some(CircuitLimitResult::DroppedCells { .. })
        ));
    }

    #[test]
    fn test_dropped_cells_allowed_on_not_built_circ() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event("23", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("23", "EXTENDED", "HS_VANGUARDS", None, &[], None, 1001.0);

        let result = check_dropped_bytes(&mut stats, &config, "23", 0, 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_general_circ_dropped_cells() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event("24", "LAUNCHED", "GENERAL", None, &[], None, 1000.0);
        stats.circ_event("24", "BUILT", "GENERAL", None, &[], None, 1001.0);

        let result = check_dropped_bytes(&mut stats, &config, "24", 1000, 1);
        assert!(matches!(
            result,
            Some(CircuitLimitResult::DroppedCells { .. })
        ));
    }

    #[test]
    fn test_orconn_connected() {
        let mut stats = BandwidthStats::new();
        let guard_fp = "5416F3E8F80101A133B1970495B04FDBD1C7446B";

        stats.orconn_event("11", guard_fp, "CONNECTED", None, 1000.0);

        assert!(stats.live_guard_conns.contains_key("11"));
        assert!(stats.guards.contains_key(guard_fp));
        assert_eq!(stats.guards.get(guard_fp).unwrap().conns_made, 1);
    }

    #[test]
    fn test_orconn_closed() {
        let mut stats = BandwidthStats::new();
        let guard_fp = "5416F3E8F80101A133B1970495B04FDBD1C7446B";

        stats.orconn_event("11", guard_fp, "CONNECTED", None, 1000.0);
        assert!(stats.live_guard_conns.contains_key("11"));

        stats.orconn_event("11", guard_fp, "CLOSED", Some("DONE"), 1001.0);
        assert!(!stats.live_guard_conns.contains_key("11"));
    }

    #[test]
    fn test_no_conns_since_tracking() {
        let mut stats = BandwidthStats::new();
        let guard_fp = "5416F3E8F80101A133B1970495B04FDBD1C7446B";

        assert!(stats.no_conns_since.is_some());

        stats.orconn_event("1", guard_fp, "CONNECTED", None, 1000.0);
        assert!(stats.no_conns_since.is_none());

        stats.orconn_event("1", guard_fp, "CLOSED", None, 1001.0);
        assert!(stats.no_conns_since.is_some());
    }

    #[test]
    fn test_connectivity_check_no_connections() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig {
            conn_max_disconnected_secs: 15,
            ..Default::default()
        };

        stats.no_conns_since = Some(1000.0);

        let status = stats.check_connectivity(1020.0, &config);
        assert!(matches!(
            status,
            ConnectivityStatus::NoConnections { secs: 20 }
        ));
    }

    #[test]
    fn test_connectivity_disabled() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig {
            conn_max_disconnected_secs: 0,
            ..Default::default()
        };

        stats.no_conns_since = Some(1000.0);

        let status = stats.check_connectivity(2000.0, &config);
        assert_eq!(status, ConnectivityStatus::Connected);
    }

    #[test]
    fn test_circ_minor_purpose_changed() {
        let mut stats = BandwidthStats::new();
        let path = vec!["5416F3E8F80101A133B1970495B04FDBD1C7446B".to_string()];

        stats.circ_event("30", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("30", "BUILT", "HS_VANGUARDS", None, &path, None, 1001.0);

        stats.circ_minor_event(
            "30",
            "PURPOSE_CHANGED",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            Some("HS_VANGUARDS"),
            None,
            &path,
        );

        let circ = stats.circs.get("30").unwrap();
        assert_eq!(circ.purpose, Some("HS_SERVICE_REND".to_string()));
        assert!(circ.in_use);
        assert_eq!(circ.guard_fp, Some(path[0].clone()));
    }

    #[test]
    fn test_circ_minor_cannibalized_to_hsdir() {
        let mut stats = BandwidthStats::new();

        stats.circ_event("31", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("31", "BUILT", "HS_VANGUARDS", None, &[], None, 1001.0);

        let circ = stats.circs.get("31").unwrap();
        assert!(!circ.is_hsdir);

        stats.circ_minor_event(
            "31",
            "CANNIBALIZED",
            "HS_CLIENT_HSDIR",
            Some("HSCI_CONNECTING"),
            Some("HS_VANGUARDS"),
            None,
            &[],
        );

        let circ = stats.circs.get("31").unwrap();
        assert!(circ.is_hsdir);
        assert!(!circ.is_service);
    }

    #[test]
    fn test_circ_minor_cannibalized_to_serv_intro() {
        let mut stats = BandwidthStats::new();

        stats.circ_event("32", "LAUNCHED", "HS_VANGUARDS", None, &[], None, 1000.0);
        stats.circ_event("32", "BUILT", "HS_VANGUARDS", None, &[], None, 1001.0);

        let circ = stats.circs.get("32").unwrap();
        assert!(!circ.is_serv_intro);

        stats.circ_minor_event(
            "32",
            "CANNIBALIZED",
            "HS_SERVICE_INTRO",
            Some("HSSI_CONNECTING"),
            Some("HS_VANGUARDS"),
            None,
            &[],
        );

        let circ = stats.circs.get("32").unwrap();
        assert!(circ.is_serv_intro);
        assert!(circ.is_service);
    }

    #[test]
    fn test_tor_bug_29699_workaround() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event(
            "40",
            "LAUNCHED",
            "HS_SERVICE_INTRO",
            Some("HSSI_ESTABLISHED"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "40",
            "BUILT",
            "HS_SERVICE_INTRO",
            Some("HSSI_ESTABLISHED"),
            &[],
            None,
            1001.0,
        );

        stats.circbw_event("40", CELL_PAYLOAD_SIZE, 0, 0, 0, 0, 0, 1002.0);

        let result = stats.check_circuit_limits("40", &config);
        assert!(matches!(
            result,
            CircuitLimitResult::TorBug {
                bug_id: "#29699",
                ..
            }
        ));
    }

    #[test]
    fn test_tor_bug_29700_workaround() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event(
            "41",
            "LAUNCHED",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "41",
            "BUILT",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            &[],
            None,
            1001.0,
        );

        stats.circbw_event("41", CELL_PAYLOAD_SIZE, 0, 0, 0, 0, 0, 1002.0);

        let result = stats.check_circuit_limits("41", &config);
        assert!(matches!(
            result,
            CircuitLimitResult::TorBug {
                bug_id: "#29700",
                ..
            }
        ));
    }

    #[test]
    fn test_tor_bug_29786_workaround() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event(
            "42",
            "LAUNCHED",
            "PATH_BIAS_TESTING",
            None,
            &[],
            None,
            1000.0,
        );
        stats.circ_event("42", "BUILT", "PATH_BIAS_TESTING", None, &[], None, 1001.0);

        stats.circbw_event("42", CELL_PAYLOAD_SIZE, 0, 0, 0, 0, 0, 1002.0);

        let result = stats.check_circuit_limits("42", &config);
        assert!(matches!(
            result,
            CircuitLimitResult::TorBug {
                bug_id: "#29786",
                ..
            }
        ));
    }

    #[test]
    fn test_tor_bug_29927_workaround() {
        let mut stats = BandwidthStats::new();
        let config = BandguardsConfig::default();

        stats.circ_event(
            "43",
            "LAUNCHED",
            "HS_CLIENT_INTRO",
            Some("HSCI_DONE"),
            &[],
            None,
            1000.0,
        );
        stats.circ_event(
            "43",
            "BUILT",
            "HS_CLIENT_INTRO",
            Some("HSCI_DONE"),
            &[],
            None,
            1001.0,
        );

        stats.circbw_event("43", CELL_PAYLOAD_SIZE, 0, 0, 0, 0, 0, 1002.0);

        let result = stats.check_circuit_limits("43", &config);
        assert!(matches!(
            result,
            CircuitLimitResult::TorBug {
                bug_id: "#29927",
                ..
            }
        ));
    }

    #[test]
    fn test_stray_circ_minor_event() {
        let mut stats = BandwidthStats::new();

        stats.circ_minor_event(
            "999",
            "CANNIBALIZED",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            Some("HS_VANGUARDS"),
            None,
            &[],
        );

        assert!(!stats.circs.contains_key("999"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn bandwidth_tracking_accuracy(
            events in prop::collection::vec(
                (100u64..10000, 100u64..10000, 50u64..5000, 50u64..5000, 10u64..500, 10u64..500),
                1..20
            ),
        ) {
            let mut stats = BandwidthStats::new();

            stats.circ_event("123", "LAUNCHED", "GENERAL", None, &[], None, 1000.0);

            let mut expected_read = 0u64;
            let mut expected_sent = 0u64;
            let mut expected_delivered_read = 0u64;
            let mut expected_delivered_sent = 0u64;
            let mut expected_overhead_read = 0u64;
            let mut expected_overhead_sent = 0u64;

            for (i, (read, written, del_read, del_written, oh_read, oh_written)) in events.iter().enumerate() {
                stats.circbw_event(
                    "123",
                    *read,
                    *written,
                    *del_read,
                    *del_written,
                    *oh_read,
                    *oh_written,
                    1001.0 + i as f64,
                );

                expected_read += read;
                expected_sent += written;
                expected_delivered_read += del_read;
                expected_delivered_sent += del_written;
                expected_overhead_read += oh_read;
                expected_overhead_sent += oh_written;
            }

            let circ = stats.circs.get("123").unwrap();
            prop_assert_eq!(circ.read_bytes, expected_read);
            prop_assert_eq!(circ.sent_bytes, expected_sent);
            prop_assert_eq!(circ.delivered_read_bytes, expected_delivered_read);
            prop_assert_eq!(circ.delivered_sent_bytes, expected_delivered_sent);
            prop_assert_eq!(circ.overhead_read_bytes, expected_overhead_read);
            prop_assert_eq!(circ.overhead_sent_bytes, expected_overhead_sent);
        }

        #[test]
        fn circuit_limit_enforcement(
            limit_mb in 1u64..100,
            bytes_mb in 0u64..200,
        ) {
            let mut stats = BandwidthStats::new();
            let config = BandguardsConfig {
                circ_max_megabytes: limit_mb,
                ..Default::default()
            };

            stats.circ_event("123", "BUILT", "GENERAL", None, &[], None, 1000.0);

            let bytes = bytes_mb * 1024 * 1024;
            let delivered = (bytes / CELL_PAYLOAD_SIZE) * RELAY_PAYLOAD_SIZE;
            stats.circbw_event("123", bytes, 0, delivered, 0, 0, 0, 1001.0);

            let result = stats.check_circuit_limits("123", &config);

            if bytes > limit_mb * 1024 * 1024 {
                match result {
                    CircuitLimitResult::MaxBytesExceeded { .. } => {}
                    _ => prop_assert!(false, "Expected MaxBytesExceeded for {} bytes > {} MB limit", bytes, limit_mb),
                }
            } else {
                prop_assert_eq!(result, CircuitLimitResult::Ok,
                    "Expected Ok for {} bytes <= {} MB limit", bytes, limit_mb);
            }
        }

        #[test]
        fn dropped_cell_detection(
            cells_received in 10u64..1000,
            cells_delivered in 0u64..1000,
            cells_overhead in 0u64..100,
        ) {
            let mut circ = BwCircuitStat::new("123".to_string(), false);

            circ.read_bytes = cells_received * CELL_PAYLOAD_SIZE;
            circ.delivered_read_bytes = cells_delivered * RELAY_PAYLOAD_SIZE;
            circ.overhead_read_bytes = cells_overhead * RELAY_PAYLOAD_SIZE;

            let dropped = circ.dropped_read_cells();
            let expected_dropped = cells_received as i64 - (cells_delivered + cells_overhead) as i64;

            prop_assert_eq!(dropped, expected_dropped,
                "Expected {} dropped cells, got {}", expected_dropped, dropped);
        }
    }
}
