//! Path verification for ensuring circuits use configured vanguards.
//!
//! This module verifies that Tor circuits are using the configured vanguard
//! relays and have the expected path lengths for each circuit purpose.
//!
//! # Overview
//!
//! The path verifier monitors:
//!
//! - **Layer 1 guards**: Entry guard connections and usage
//! - **Layer 2 guards**: Second-hop relay verification
//! - **Layer 3 guards**: Third-hop relay verification
//! - **Path lengths**: Expected hop counts for each circuit purpose
//!
//! # Path Length Mappings
//!
//! Circuit path lengths vary based on the vanguards mode and circuit purpose:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Path Length by Purpose                           │
//! ├─────────────────────┬──────────────────┬───────────────────────────┤
//! │ Circuit Purpose     │ Full Vanguards   │ Vanguards-Lite            │
//! ├─────────────────────┼──────────────────┼───────────────────────────┤
//! │ HS_VANGUARDS        │ 4 hops           │ 3 hops                    │
//! │ HS_CLIENT_HSDIR     │ 5 hops           │ 4 hops                    │
//! │ HS_CLIENT_INTRO     │ 5 hops           │ 4 hops                    │
//! │ HS_CLIENT_REND      │ 4 hops           │ 3 hops                    │
//! │ HS_SERVICE_HSDIR    │ 4 hops           │ 4 hops                    │
//! │ HS_SERVICE_INTRO    │ 4 hops           │ 4 hops                    │
//! │ HS_SERVICE_REND     │ 5 hops           │ 4 hops                    │
//! └─────────────────────┴──────────────────┴───────────────────────────┘
//! ```
//!
//! # Guard Layer Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Vanguard Layer Structure                         │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  Client ──▶ Layer 1 ──▶ Layer 2 ──▶ Layer 3 ──▶ Destination     │
//! │             (Guard)     (Middle)    (Middle)                        │
//! │                                                                     │
//! │  Full Vanguards:                                                    │
//! │    • Layer 1: 2 guards (long-term)                                  │
//! │    • Layer 2: 4 guards (medium-term rotation)                       │
//! │    • Layer 3: 8 guards (short-term rotation)                        │
//! │                                                                     │
//! │  Vanguards-Lite:                                                    │
//! │    • Layer 1: 1 guard                                               │
//! │    • Layer 2: 4 guards (managed by Tor)                             │
//! │    • Layer 3: None                                                  │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # What This Module Does NOT Do
//!
//! - **Guard selection**: Use [`crate::node_selection`] for selecting guards
//! - **Guard rotation**: Use [`crate::vanguards`] for managing guard state
//! - **Circuit building**: This module only verifies existing circuits
//!
//! # See Also
//!
//! - [`crate::vanguards`] - Vanguard state management
//! - [`crate::control`] - Event handling that calls path verification
//! - [Python vanguards pathverify](https://github.com/mikeperry-tor/vanguards)

use std::collections::{HashMap, HashSet};

use crate::config::LogLevel;
use crate::logger::plog;

/// Expected path lengths for full vanguards mode.
pub const ROUTELEN_FOR_PURPOSE: &[(&str, usize)] = &[
    ("HS_VANGUARDS", 4),
    ("HS_CLIENT_HSDIR", 5),
    ("HS_CLIENT_INTRO", 5),
    ("HS_CLIENT_REND", 4),
    ("HS_SERVICE_HSDIR", 4),
    ("HS_SERVICE_INTRO", 4),
    ("HS_SERVICE_REND", 5),
];

/// Expected path lengths for vanguards-lite mode.
pub const ROUTELEN_FOR_PURPOSE_LITE: &[(&str, usize)] = &[
    ("HS_VANGUARDS", 3),
    ("HS_CLIENT_HSDIR", 4),
    ("HS_CLIENT_INTRO", 4),
    ("HS_CLIENT_REND", 3),
    ("HS_SERVICE_HSDIR", 4),
    ("HS_SERVICE_INTRO", 4),
    ("HS_SERVICE_REND", 4),
];

/// Per-guard usage statistics.
///
/// Tracks how many times a guard has been used and how many connections
/// have been made to it. This helps detect anomalies in guard usage patterns.
///
/// # Fields
///
/// * `use_count` - Number of times this guard has been used in circuits
/// * `conn_count` - Number of active connections to this guard
///
/// # Example
///
/// ```rust
/// use vanguards_rs::pathverify::Layer1Stats;
///
/// let stats = Layer1Stats::new();
/// assert_eq!(stats.use_count, 0);
/// assert_eq!(stats.conn_count, 1);
/// ```
///
/// # See Also
///
/// - [`Layer1Guards`] - Container for guard statistics
#[derive(Debug, Clone, Default)]
pub struct Layer1Stats {
    /// Number of times this guard has been used in circuits.
    pub use_count: u32,
    /// Number of connections to this guard.
    pub conn_count: u32,
}

impl Layer1Stats {
    /// Creates a new Layer1Stats with one connection.
    pub fn new() -> Self {
        Self {
            use_count: 0,
            conn_count: 1,
        }
    }
}

/// Layer 1 guard tracking.
///
/// Tracks connections and usage for entry guards. Monitors for anomalies
/// such as too many or too few guard connections, or unexpected guard usage.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::pathverify::Layer1Guards;
///
/// let mut guards = Layer1Guards::new(2);
///
/// // Track a guard connection
/// guards.add_conn("AABBCCDD00112233445566778899AABBCCDDEEFF");
/// assert!(guards.contains("AABBCCDD00112233445566778899AABBCCDDEEFF"));
///
/// // Track guard usage
/// guards.add_use_count("AABBCCDD00112233445566778899AABBCCDDEEFF");
/// ```
///
/// # See Also
///
/// - [`Layer1Stats`] - Statistics for individual guards
/// - [`PathVerify`] - Uses this for layer 1 tracking
#[derive(Debug, Clone)]
pub struct Layer1Guards {
    /// Guard statistics by fingerprint.
    pub guards: HashMap<String, Layer1Stats>,
    /// Expected number of layer 1 guards.
    pub num_layer1: u8,
}

impl Layer1Guards {
    /// Creates a new Layer1Guards tracker.
    pub fn new(num_layer1: u8) -> Self {
        Self {
            guards: HashMap::new(),
            num_layer1,
        }
    }

    /// Adds a connection to a guard.
    pub fn add_conn(&mut self, guard_fp: &str) {
        if let Some(stats) = self.guards.get_mut(guard_fp) {
            stats.conn_count += 1;
        } else {
            self.guards.insert(guard_fp.to_string(), Layer1Stats::new());
        }
    }

    /// Removes a connection from a guard.
    pub fn del_conn(&mut self, guard_fp: &str) {
        if let Some(stats) = self.guards.get_mut(guard_fp) {
            if stats.conn_count > 1 {
                stats.conn_count -= 1;
            } else {
                self.guards.remove(guard_fp);
            }
        }
    }

    /// Checks connection counts and logs warnings.
    ///
    /// Returns -1 when fewer than expected, 0 when correct, +1 when too many.
    pub fn check_conn_counts(&self) -> i32 {
        let mut ret = 0;

        if self.guards.len() < self.num_layer1 as usize {
            plog(
                LogLevel::Notice,
                &format!(
                    "Fewer guard connections than configured. Connected to: {:?}",
                    self.guards.keys().collect::<Vec<_>>()
                ),
            );
            ret = -1;
        } else if self.guards.len() > self.num_layer1 as usize {
            plog(
                LogLevel::Notice,
                &format!(
                    "More guard connections than configured. Connected to: {:?}",
                    self.guards.keys().collect::<Vec<_>>()
                ),
            );
            ret = 1;
        }

        for (guard_fp, stats) in &self.guards {
            if stats.conn_count > 1 {
                plog(
                    LogLevel::Notice,
                    &format!(
                        "Extra connections to guard {}: {}",
                        guard_fp, stats.conn_count
                    ),
                );
                ret = 1;
            }
        }

        ret
    }

    /// Adds a use count for a guard.
    pub fn add_use_count(&mut self, guard_fp: &str) {
        if !self.guards.contains_key(guard_fp) {
            plog(
                LogLevel::Warn,
                &format!(
                    "Guard {} not in {:?}",
                    guard_fp,
                    self.guards.keys().collect::<Vec<_>>()
                ),
            );
        } else if let Some(stats) = self.guards.get_mut(guard_fp) {
            stats.use_count += 1;
        }
    }

    /// Checks use counts and logs warnings.
    ///
    /// Returns -1 when fewer than expected, 0 when correct, +1 when too many.
    pub fn check_use_counts(&self) -> i32 {
        let mut ret = 0;

        let layer1_in_use: Vec<_> = self
            .guards
            .iter()
            .filter(|(_, stats)| stats.use_count > 0)
            .map(|(fp, _)| fp.clone())
            .collect();

        let layer1_counts: Vec<_> = layer1_in_use
            .iter()
            .map(|fp| {
                format!(
                    "{}: {}",
                    fp,
                    self.guards.get(fp).map(|s| s.use_count).unwrap_or(0)
                )
            })
            .collect();

        if layer1_in_use.len() > self.num_layer1 as usize {
            plog(
                LogLevel::Warn,
                &format!(
                    "Circuits are being used on more guards than configured. \
                     Current guard use: {:?}",
                    layer1_counts
                ),
            );
            ret = 1;
        } else if layer1_in_use.len() < self.num_layer1 as usize {
            plog(
                LogLevel::Notice,
                &format!(
                    "Circuits are being used on fewer guards than configured. \
                     Current guard use: {:?}",
                    layer1_counts
                ),
            );
            ret = -1;
        }

        ret
    }

    /// Returns true if the guard is tracked.
    pub fn contains(&self, guard_fp: &str) -> bool {
        self.guards.contains_key(guard_fp)
    }
}

/// Path verification state.
///
/// Verifies that circuits use the configured vanguard relays and have
/// the expected path lengths. Monitors guard connections and usage patterns
/// to detect potential attacks or misconfigurations.
///
/// # State Tracking
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────┐
/// │                    PathVerify State                                 │
/// ├─────────────────────────────────────────────────────────────────────┤
/// │                                                                     │
/// │  layer1: Layer1Guards                                               │
/// │    └── guards: HashMap<fingerprint, Layer1Stats>                    │
/// │                                                                     │
/// │  layer2: HashSet<fingerprint>                                       │
/// │    └── Expected layer 2 guard fingerprints                          │
/// │                                                                     │
/// │  layer3: HashSet<fingerprint>                                       │
/// │    └── Expected layer 3 guard fingerprints                          │
/// │                                                                     │
/// └─────────────────────────────────────────────────────────────────────┘
/// ```
///
/// # Example
///
/// ```rust
/// use vanguards_rs::pathverify::PathVerify;
///
/// // Create verifier for full vanguards mode
/// let mut verifier = PathVerify::new(true, 2, 4, 8);
/// assert!(verifier.full_vanguards);
/// assert_eq!(verifier.routelen_for_purpose("HS_VANGUARDS"), Some(4));
///
/// // Create verifier for vanguards-lite mode
/// let mut verifier_lite = PathVerify::new(false, 1, 4, 0);
/// assert!(!verifier_lite.full_vanguards);
/// assert_eq!(verifier_lite.routelen_for_purpose("HS_VANGUARDS"), Some(3));
/// ```
///
/// # Event Handling
///
/// The verifier responds to several Tor events:
///
/// - `ORCONN`: Track guard connection state changes
/// - `GUARD`: Track layer 2 guard changes (vanguards-lite)
/// - `CIRC`: Verify circuit paths when built
/// - `CIRC_MINOR`: Detect suspicious purpose changes
/// - `CONF_CHANGED`: Update layer configuration
///
/// # See Also
///
/// - [`Layer1Guards`] - Layer 1 guard tracking
/// - [`crate::control`] - Event dispatch to path verification
#[derive(Debug, Clone)]
pub struct PathVerify {
    /// Layer 1 guard tracking.
    pub layer1: Layer1Guards,
    /// Layer 2 guard fingerprints.
    pub layer2: HashSet<String>,
    /// Layer 3 guard fingerprints.
    pub layer3: HashSet<String>,
    /// Whether full vanguards mode is enabled.
    pub full_vanguards: bool,
    /// Expected number of layer 1 guards.
    pub num_layer1: u8,
    /// Expected number of layer 2 guards.
    pub num_layer2: u8,
    /// Expected number of layer 3 guards.
    pub num_layer3: u8,
}

impl PathVerify {
    /// Creates a new PathVerify with the specified configuration.
    pub fn new(full_vanguards: bool, num_layer1: u8, num_layer2: u8, num_layer3: u8) -> Self {
        Self {
            layer1: Layer1Guards::new(num_layer1),
            layer2: HashSet::new(),
            layer3: HashSet::new(),
            full_vanguards,
            num_layer1,
            num_layer2,
            num_layer3,
        }
    }

    /// Initializes layer 2 and layer 3 from configuration values.
    ///
    /// # Arguments
    ///
    /// * `layer2_nodes` - Comma-separated layer 2 fingerprints (or None)
    /// * `layer3_nodes` - Comma-separated layer 3 fingerprints (or None)
    pub fn init_layers(&mut self, layer2_nodes: Option<&str>, layer3_nodes: Option<&str>) {
        if let Some(nodes) = layer2_nodes {
            if !nodes.is_empty() {
                self.layer2 = nodes.split(',').map(|s| s.trim().to_string()).collect();
                self.full_vanguards = true;
            }
        }

        if let Some(nodes) = layer3_nodes {
            if !nodes.is_empty() {
                self.layer3 = nodes.split(',').map(|s| s.trim().to_string()).collect();
                self.full_vanguards = true;
            }
        }

        // If layers are empty and vanguards disabled, we're monitoring vg-lite
        if self.layer2.is_empty() && self.layer3.is_empty() && !self.full_vanguards {
            plog(
                LogLevel::Notice,
                "Monitoring vanguards-lite with pathverify.",
            );
            self.num_layer1 = 1;
            self.num_layer2 = 4;
            self.num_layer3 = 0;
        } else {
            plog(LogLevel::Notice, "Monitoring vanguards with pathverify.");
        }

        self.check_layer_counts();
    }

    /// Checks layer counts and logs warnings.
    ///
    /// Returns true when counts are correct, false otherwise.
    pub fn check_layer_counts(&self) -> bool {
        let mut ret = true;

        // Layer2 can become empty briefly on sighup and startup
        if self.layer2.len() > 1 && self.layer2.len() != self.num_layer2 as usize {
            plog(
                LogLevel::Notice,
                &format!(
                    "Wrong number of layer2 guards. {} vs: {:?}",
                    self.num_layer2, self.layer2
                ),
            );
            ret = false;
        }

        if self.layer3.len() > 1 && self.layer3.len() != self.num_layer3 as usize {
            plog(
                LogLevel::Notice,
                &format!(
                    "Wrong number of layer3 guards. {} vs: {:?}",
                    self.num_layer3, self.layer3
                ),
            );
            ret = false;
        }

        ret
    }

    /// Handles a CONF_CHANGED event.
    ///
    /// Updates layer configuration when HSLayer2Nodes or HSLayer3Nodes change.
    pub fn conf_changed_event(&mut self, changed: &HashMap<String, Vec<String>>) {
        if let Some(values) = changed.get("HSLayer2Nodes") {
            if let Some(first) = values.first() {
                self.layer2 = first.split(',').map(|s| s.trim().to_string()).collect();
                self.full_vanguards = true;
            }
        }

        if let Some(values) = changed.get("HSLayer3Nodes") {
            if let Some(first) = values.first() {
                self.layer3 = first.split(',').map(|s| s.trim().to_string()).collect();
                self.full_vanguards = true;
            }
        }

        self.check_layer_counts();
    }

    /// Handles an ORCONN event.
    ///
    /// Tracks guard connection state changes.
    pub fn orconn_event(&mut self, guard_fp: &str, status: &str) {
        match status {
            "CONNECTED" => {
                self.layer1.add_conn(guard_fp);
            }
            "CLOSED" | "FAILED" => {
                self.layer1.del_conn(guard_fp);
            }
            _ => {}
        }

        self.layer1.check_conn_counts();
    }

    /// Handles a GUARD event.
    ///
    /// Tracks layer 2 guard changes for vanguards-lite.
    pub fn guard_event(&mut self, guard_fp: &str, status: &str) {
        match status {
            "GOOD_L2" => {
                self.layer2.insert(guard_fp.to_string());
            }
            "BAD_L2" => {
                self.layer2.remove(guard_fp);
            }
            _ => {}
        }
    }

    /// Returns the expected path length for a circuit purpose.
    pub fn routelen_for_purpose(&self, purpose: &str) -> Option<usize> {
        let table = if self.full_vanguards {
            ROUTELEN_FOR_PURPOSE
        } else {
            ROUTELEN_FOR_PURPOSE_LITE
        };

        table
            .iter()
            .find(|(p, _)| *p == purpose)
            .map(|(_, len)| *len)
    }

    /// Handles a CIRC event.
    ///
    /// Verifies circuit paths when circuits are built.
    pub fn circ_event(
        &mut self,
        _circ_id: &str,
        status: &str,
        purpose: &str,
        hs_state: Option<&str>,
        path: &[(String, Option<String>)],
    ) {
        if !purpose.starts_with("HS_") {
            return;
        }

        if status != "BUILT" && status != "GUARD_WAIT" {
            return;
        }

        // Check path length
        if let Some(expected_len) = self.routelen_for_purpose(purpose) {
            if path.len() != expected_len {
                // Some cases are expected (cannibalized circuits, retries)
                let is_expected = (purpose == "HS_SERVICE_HSDIR"
                    && hs_state == Some("HSSI_CONNECTING"))
                    || (purpose == "HS_CLIENT_INTRO" && hs_state == Some("HSCI_CONNECTING"));

                let level = if is_expected {
                    LogLevel::Info
                } else {
                    LogLevel::Notice
                };

                plog(
                    level,
                    &format!(
                        "Tor made a {}-hop path, but I wanted a {}-hop path for purpose {}:{:?}",
                        path.len(),
                        expected_len,
                        purpose,
                        hs_state
                    ),
                );
            }
        }

        // Check layer 1 guard
        if !path.is_empty() {
            let guard_fp = &path[0].0;
            self.layer1.add_use_count(guard_fp);
            self.layer1.check_use_counts();
        }

        // Check layer 2 guard
        if path.len() > 1 && !self.layer2.contains(&path[1].0) {
            plog(
                LogLevel::Warn,
                &format!("Layer2 {} not in {:?}", path[1].0, self.layer2),
            );
        }

        // Check layer 3 guard
        if self.num_layer3 > 0 && path.len() > 2 && !self.layer3.contains(&path[2].0) {
            plog(
                LogLevel::Warn,
                &format!("Layer3 {} not in {:?}", path[2].0, self.layer3),
            );
        }

        // Check layer counts
        if self.layer2.len() != self.num_layer2 as usize {
            plog(
                LogLevel::Warn,
                &format!(
                    "Circuit built with different number of layer2 nodes than configured. \
                     Currently using: {:?}",
                    self.layer2
                ),
            );
        }

        if self.layer3.len() != self.num_layer3 as usize {
            plog(
                LogLevel::Warn,
                &format!(
                    "Circuit built with different number of layer3 nodes than configured. \
                     Currently using: {:?}",
                    self.layer3
                ),
            );
        }
    }

    /// Handles a CIRC_MINOR event (purpose changes).
    ///
    /// Warns on suspicious purpose changes.
    pub fn circ_minor_event(
        &mut self,
        _circ_id: &str,
        purpose: &str,
        old_purpose: Option<&str>,
        path: &[(String, Option<String>)],
    ) {
        let is_hs = purpose.starts_with("HS_");
        let was_hs = old_purpose.map(|p| p.starts_with("HS_")).unwrap_or(false);

        // Warn on purpose changes between HS and non-HS
        if is_hs && !was_hs {
            plog(
                LogLevel::Warn,
                &format!(
                    "Purpose switched from non-hs to hs: {:?} -> {}",
                    old_purpose, purpose
                ),
            );
        } else if !is_hs && was_hs {
            // Some purpose changes are expected
            if purpose != "CIRCUIT_PADDING"
                && purpose != "MEASURE_TIMEOUT"
                && purpose != "PATH_BIAS_TESTING"
            {
                plog(
                    LogLevel::Warn,
                    &format!(
                        "Purpose switched from hs to non-hs: {:?} -> {}",
                        old_purpose, purpose
                    ),
                );
            }
        }

        // Verify guards for HS circuits
        if is_hs || was_hs {
            if !path.is_empty() && !self.layer1.contains(&path[0].0) {
                plog(
                    LogLevel::Warn,
                    &format!(
                        "Guard {} not in {:?}",
                        path[0].0,
                        self.layer1.guards.keys().collect::<Vec<_>>()
                    ),
                );
            }

            if path.len() > 1 && !self.layer2.contains(&path[1].0) {
                plog(
                    LogLevel::Warn,
                    &format!("Layer2 {} not in {:?}", path[1].0, self.layer2),
                );
            }

            if self.num_layer3 > 0 && path.len() > 2 && !self.layer3.contains(&path[2].0) {
                plog(
                    LogLevel::Warn,
                    &format!("Layer3 {} not in {:?}", path[2].0, self.layer3),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer1_stats_new() {
        let stats = Layer1Stats::new();
        assert_eq!(stats.use_count, 0);
        assert_eq!(stats.conn_count, 1);
    }

    #[test]
    fn test_layer1_guards_new() {
        let guards = Layer1Guards::new(2);
        assert!(guards.guards.is_empty());
        assert_eq!(guards.num_layer1, 2);
    }

    #[test]
    fn test_layer1_guards_add_conn() {
        let mut guards = Layer1Guards::new(2);
        let fp = "A".repeat(40);

        guards.add_conn(&fp);
        assert!(guards.guards.contains_key(&fp));
        assert_eq!(guards.guards.get(&fp).unwrap().conn_count, 1);

        guards.add_conn(&fp);
        assert_eq!(guards.guards.get(&fp).unwrap().conn_count, 2);
    }

    #[test]
    fn test_layer1_guards_del_conn() {
        let mut guards = Layer1Guards::new(2);
        let fp = "A".repeat(40);

        guards.add_conn(&fp);
        guards.add_conn(&fp);
        assert_eq!(guards.guards.get(&fp).unwrap().conn_count, 2);

        guards.del_conn(&fp);
        assert_eq!(guards.guards.get(&fp).unwrap().conn_count, 1);

        guards.del_conn(&fp);
        assert!(!guards.guards.contains_key(&fp));
    }

    #[test]
    fn test_layer1_guards_add_use_count() {
        let mut guards = Layer1Guards::new(2);
        let fp = "A".repeat(40);

        guards.add_conn(&fp);
        guards.add_use_count(&fp);
        guards.add_use_count(&fp);

        assert_eq!(guards.guards.get(&fp).unwrap().use_count, 2);
    }

    #[test]
    fn test_path_verify_new() {
        let verifier = PathVerify::new(true, 2, 4, 8);
        assert!(verifier.full_vanguards);
        assert_eq!(verifier.num_layer1, 2);
        assert_eq!(verifier.num_layer2, 4);
        assert_eq!(verifier.num_layer3, 8);
        assert!(verifier.layer2.is_empty());
        assert!(verifier.layer3.is_empty());
    }

    #[test]
    fn test_path_verify_init_layers() {
        let mut verifier = PathVerify::new(false, 2, 4, 8);

        verifier.init_layers(
            Some("AAAA,BBBB,CCCC,DDDD"),
            Some("1111,2222,3333,4444,5555,6666,7777,8888"),
        );

        assert!(verifier.full_vanguards);
        assert_eq!(verifier.layer2.len(), 4);
        assert_eq!(verifier.layer3.len(), 8);
        assert!(verifier.layer2.contains("AAAA"));
        assert!(verifier.layer3.contains("1111"));
    }

    #[test]
    fn test_routelen_for_purpose_full() {
        let verifier = PathVerify::new(true, 2, 4, 8);

        assert_eq!(verifier.routelen_for_purpose("HS_VANGUARDS"), Some(4));
        assert_eq!(verifier.routelen_for_purpose("HS_CLIENT_HSDIR"), Some(5));
        assert_eq!(verifier.routelen_for_purpose("HS_CLIENT_INTRO"), Some(5));
        assert_eq!(verifier.routelen_for_purpose("HS_CLIENT_REND"), Some(4));
        assert_eq!(verifier.routelen_for_purpose("HS_SERVICE_HSDIR"), Some(4));
        assert_eq!(verifier.routelen_for_purpose("HS_SERVICE_INTRO"), Some(4));
        assert_eq!(verifier.routelen_for_purpose("HS_SERVICE_REND"), Some(5));
        assert_eq!(verifier.routelen_for_purpose("GENERAL"), None);
    }

    #[test]
    fn test_routelen_for_purpose_lite() {
        let verifier = PathVerify::new(false, 1, 4, 0);

        assert_eq!(verifier.routelen_for_purpose("HS_VANGUARDS"), Some(3));
        assert_eq!(verifier.routelen_for_purpose("HS_CLIENT_HSDIR"), Some(4));
        assert_eq!(verifier.routelen_for_purpose("HS_CLIENT_INTRO"), Some(4));
        assert_eq!(verifier.routelen_for_purpose("HS_CLIENT_REND"), Some(3));
        assert_eq!(verifier.routelen_for_purpose("HS_SERVICE_HSDIR"), Some(4));
        assert_eq!(verifier.routelen_for_purpose("HS_SERVICE_INTRO"), Some(4));
        assert_eq!(verifier.routelen_for_purpose("HS_SERVICE_REND"), Some(4));
    }

    #[test]
    fn test_orconn_event() {
        let mut verifier = PathVerify::new(true, 2, 4, 8);
        let fp = "A".repeat(40);

        verifier.orconn_event(&fp, "CONNECTED");
        assert!(verifier.layer1.guards.contains_key(&fp));

        verifier.orconn_event(&fp, "CLOSED");
        assert!(!verifier.layer1.guards.contains_key(&fp));
    }

    #[test]
    fn test_guard_event() {
        let mut verifier = PathVerify::new(true, 2, 4, 8);
        let fp = "A".repeat(40);

        verifier.guard_event(&fp, "GOOD_L2");
        assert!(verifier.layer2.contains(&fp));

        verifier.guard_event(&fp, "BAD_L2");
        assert!(!verifier.layer2.contains(&fp));
    }

    #[test]
    fn test_conf_changed_event() {
        let mut verifier = PathVerify::new(false, 2, 4, 8);

        let mut changed = HashMap::new();
        changed.insert(
            "HSLayer2Nodes".to_string(),
            vec!["AAAA,BBBB,CCCC,DDDD".to_string()],
        );

        verifier.conf_changed_event(&changed);

        assert!(verifier.full_vanguards);
        assert_eq!(verifier.layer2.len(), 4);
    }

    #[test]
    fn test_check_conn_counts_correct() {
        let mut guards = Layer1Guards::new(2);
        guards.add_conn(&"A".repeat(40));
        guards.add_conn(&"B".repeat(40));

        assert_eq!(guards.check_conn_counts(), 0);
    }

    #[test]
    fn test_check_conn_counts_fewer() {
        let mut guards = Layer1Guards::new(2);
        guards.add_conn(&"A".repeat(40));

        assert_eq!(guards.check_conn_counts(), -1);
    }

    #[test]
    fn test_check_conn_counts_more() {
        let mut guards = Layer1Guards::new(2);
        guards.add_conn(&"A".repeat(40));
        guards.add_conn(&"B".repeat(40));
        guards.add_conn(&"C".repeat(40));

        assert_eq!(guards.check_conn_counts(), 1);
    }

    #[test]
    fn test_pathverify_init_correct_counts() {
        let mut pv = PathVerify::new(true, 2, 3, 8);

        pv.layer2
            .insert("5416F3E8F80101A133B1970495B04FDBD1C7446B".to_string());
        pv.layer2
            .insert("855BC2DABE24C861CD887DB9B2E950424B49FC34".to_string());
        pv.layer2
            .insert("1F9544C0A80F1C5D8A5117FBFFB50694469CC7F4".to_string());

        for i in 0..8 {
            pv.layer3.insert(format!("{:0>40X}", i));
        }

        pv.layer1
            .add_conn("66CA5474346F35E375C4D4514C51A540545347EE");
        pv.layer1
            .add_conn("5416F3E8F80101A133B1970495B04FDBD1C7446B");

        assert_eq!(pv.layer1.check_conn_counts(), 0);
        assert!(pv.check_layer_counts());
    }

    #[test]
    fn test_pathverify_too_many_guards() {
        let mut pv = PathVerify::new(true, 2, 3, 8);

        pv.layer1
            .add_conn("66CA5474346F35E375C4D4514C51A540545347EE");
        pv.layer1
            .add_conn("5416F3E8F80101A133B1970495B04FDBD1C7446B");
        pv.layer1
            .add_conn("3E53D3979DB07EFD736661C934A1DED14127B684");

        assert_eq!(pv.layer1.check_conn_counts(), 1);
    }

    #[test]
    fn test_pathverify_too_few_guards() {
        let mut pv = PathVerify::new(true, 2, 3, 8);

        pv.layer1
            .add_conn("66CA5474346F35E375C4D4514C51A540545347EE");

        assert_eq!(pv.layer1.check_conn_counts(), -1);
    }

    #[test]
    fn test_layer1_use_counts() {
        let mut pv = PathVerify::new(true, 2, 4, 8);

        pv.layer1
            .add_conn("5416F3E8F80101A133B1970495B04FDBD1C7446B");
        pv.layer1
            .add_conn("66CA5474346F35E375C4D4514C51A540545347EE");

        pv.layer1
            .add_use_count("5416F3E8F80101A133B1970495B04FDBD1C7446B");

        assert_eq!(pv.layer1.check_use_counts(), -1);

        pv.layer1
            .add_use_count("66CA5474346F35E375C4D4514C51A540545347EE");

        assert_eq!(pv.layer1.check_use_counts(), 0);
    }

    #[test]
    fn test_layer1_too_many_in_use() {
        let mut pv = PathVerify::new(true, 2, 4, 8);

        pv.layer1
            .add_conn("5416F3E8F80101A133B1970495B04FDBD1C7446B");
        pv.layer1
            .add_conn("66CA5474346F35E375C4D4514C51A540545347EE");
        pv.layer1
            .add_conn("5416F3E8F80101A133B1970495B04FDBD1C7446D");

        pv.layer1
            .add_use_count("5416F3E8F80101A133B1970495B04FDBD1C7446B");
        pv.layer1
            .add_use_count("66CA5474346F35E375C4D4514C51A540545347EE");
        pv.layer1
            .add_use_count("5416F3E8F80101A133B1970495B04FDBD1C7446D");

        assert_eq!(pv.layer1.check_use_counts(), 1);
    }

    #[test]
    fn test_conf_changed_event_both_layers() {
        let mut pv = PathVerify::new(false, 2, 4, 8);

        let mut changed = HashMap::new();
        changed.insert(
            "HSLayer2Nodes".to_string(),
            vec!["5416F3E8F80101A133B1970495B04FDBD1C7446D".to_string()],
        );
        changed.insert(
            "HSLayer3Nodes".to_string(),
            vec!["5416F3E8F80101A133B1970495B04FDBD1C7446D".to_string()],
        );

        pv.conf_changed_event(&changed);

        assert!(pv.full_vanguards);
        assert_eq!(pv.layer2.len(), 1);
        assert_eq!(pv.layer3.len(), 1);
    }

    #[test]
    fn test_init_layers_vanguards_lite() {
        let mut pv = PathVerify::new(false, 2, 4, 8);

        pv.init_layers(None, None);

        assert!(!pv.full_vanguards);
        assert_eq!(pv.num_layer1, 1);
        assert_eq!(pv.num_layer2, 4);
        assert_eq!(pv.num_layer3, 0);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn path_length_verification(
            full_vanguards in any::<bool>(),
            purpose_idx in 0usize..7,
        ) {
            let purposes = [
                "HS_VANGUARDS",
                "HS_CLIENT_HSDIR",
                "HS_CLIENT_INTRO",
                "HS_CLIENT_REND",
                "HS_SERVICE_HSDIR",
                "HS_SERVICE_INTRO",
                "HS_SERVICE_REND",
            ];

            let purpose = purposes[purpose_idx];
            let verifier = PathVerify::new(full_vanguards, 2, 4, 8);

            let expected_len = if full_vanguards {
                ROUTELEN_FOR_PURPOSE.iter()
                    .find(|(p, _)| *p == purpose)
                    .map(|(_, len)| *len)
            } else {
                ROUTELEN_FOR_PURPOSE_LITE.iter()
                    .find(|(p, _)| *p == purpose)
                    .map(|(_, len)| *len)
            };

            let actual_len = verifier.routelen_for_purpose(purpose);

            prop_assert_eq!(actual_len, expected_len,
                "Path length for {} (full_vanguards={}): expected {:?}, got {:?}",
                purpose, full_vanguards, expected_len, actual_len);

            if full_vanguards {
                match purpose {
                    "HS_VANGUARDS" => prop_assert_eq!(actual_len, Some(4)),
                    "HS_CLIENT_HSDIR" => prop_assert_eq!(actual_len, Some(5)),
                    "HS_CLIENT_INTRO" => prop_assert_eq!(actual_len, Some(5)),
                    "HS_CLIENT_REND" => prop_assert_eq!(actual_len, Some(4)),
                    "HS_SERVICE_HSDIR" => prop_assert_eq!(actual_len, Some(4)),
                    "HS_SERVICE_INTRO" => prop_assert_eq!(actual_len, Some(4)),
                    "HS_SERVICE_REND" => prop_assert_eq!(actual_len, Some(5)),
                    _ => {}
                }
            } else {
                match purpose {
                    "HS_VANGUARDS" => prop_assert_eq!(actual_len, Some(3)),
                    "HS_CLIENT_HSDIR" => prop_assert_eq!(actual_len, Some(4)),
                    "HS_CLIENT_INTRO" => prop_assert_eq!(actual_len, Some(4)),
                    "HS_CLIENT_REND" => prop_assert_eq!(actual_len, Some(3)),
                    "HS_SERVICE_HSDIR" => prop_assert_eq!(actual_len, Some(4)),
                    "HS_SERVICE_INTRO" => prop_assert_eq!(actual_len, Some(4)),
                    "HS_SERVICE_REND" => prop_assert_eq!(actual_len, Some(4)),
                    _ => {}
                }
            }
        }
    }
}
