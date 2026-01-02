//! Circuit Build Timeout verification for monitoring circuit construction timing.
//!
//! This module monitors circuit build timeouts to detect anomalies in circuit
//! construction timing that could indicate attacks or network issues.
//!
//! # Overview
//!
//! The CBT verifier tracks:
//!
//! - **Launched circuits**: Circuits that have started building
//! - **Built circuits**: Circuits that completed successfully
//! - **Timed out circuits**: Circuits that exceeded the build timeout
//! - **Hidden service circuits**: Separate tracking for HS circuits
//!
//! # Timeout Rate Monitoring
//!
//! The module calculates timeout rates to detect anomalies:
//!
//! - **Overall timeout rate**: `all_timeout / all_launched`
//! - **HS timeout rate**: `hs_timeout / hs_launched`
//!
//! Elevated HS timeout rates compared to overall rates may indicate
//! targeted attacks against hidden services.
//!
//! # What This Module Does NOT Do
//!
//! - **Circuit building**: This module only monitors, not builds circuits
//! - **Timeout adjustment**: Tor manages its own CBT algorithm
//! - **Attack mitigation**: This module detects but doesn't prevent attacks
//!
//! # See Also
//!
//! - [`crate::control`] - Event handling that calls CBT verification
//! - [`crate::bandguards`] - Related bandwidth monitoring
//! - [Python vanguards cbtverify](https://github.com/mikeperry-tor/vanguards)

use std::collections::HashMap;

use crate::config::LogLevel;
use crate::logger::plog;

/// Per-circuit tracking for timeout statistics.
///
/// Tracks whether a circuit is a hidden service circuit for separate
/// timeout rate calculations. This allows comparing HS circuit timeout
/// rates against overall rates to detect targeted attacks.
///
/// # Fields
///
/// * `circ_id` - The circuit ID being tracked
/// * `is_hs` - Whether this is a hidden service circuit
///
/// # Example
///
/// ```rust
/// use vanguards_rs::cbtverify::CircuitStat;
///
/// let stat = CircuitStat::new("123", true);
/// assert_eq!(stat.circ_id, "123");
/// assert!(stat.is_hs);
/// ```
///
/// # See Also
///
/// - [`TimeoutStats`] - Container for circuit statistics
#[derive(Debug, Clone)]
pub struct CircuitStat {
    /// The circuit ID.
    pub circ_id: String,
    /// Whether this is a hidden service circuit.
    pub is_hs: bool,
}

impl CircuitStat {
    /// Creates a new circuit stat entry.
    pub fn new(circ_id: &str, is_hs: bool) -> Self {
        Self {
            circ_id: circ_id.to_string(),
            is_hs,
        }
    }
}

/// Circuit build timeout statistics.
///
/// Tracks circuit build statistics for all circuits and hidden service
/// circuits separately, allowing comparison of timeout rates.
///
/// # Statistics Tracked
///
/// | Statistic | Description |
/// |-----------|-------------|
/// | `all_launched` | Total circuits that started building |
/// | `all_built` | Circuits that completed successfully |
/// | `all_timeout` | Circuits that timed out |
/// | `hs_launched` | Hidden service circuits started |
/// | `hs_built` | HS circuits completed |
/// | `hs_timeout` | HS circuits that timed out |
///
/// # Example
///
/// ```rust
/// use vanguards_rs::cbtverify::TimeoutStats;
///
/// let mut stats = TimeoutStats::new();
///
/// // Track a circuit launch
/// stats.add_circuit("123", true);
/// assert_eq!(stats.all_launched, 1);
/// assert_eq!(stats.hs_launched, 1);
///
/// // Track circuit completion
/// stats.built_circuit("123");
/// assert_eq!(stats.all_built, 1);
/// assert_eq!(stats.hs_built, 1);
///
/// // Check timeout rates
/// assert_eq!(stats.timeout_rate_all(), 0.0);
/// assert_eq!(stats.timeout_rate_hs(), 0.0);
/// ```
///
/// # CBT Event Handling
///
/// The statistics respond to Tor's CBT algorithm events:
///
/// - `COMPUTED`: CBT algorithm has computed a new timeout value
/// - `RESET`: CBT algorithm has been reset (e.g., after network change)
///
/// After a `RESET`, statistics are zeroed and recording is paused until
/// the next `COMPUTED` event.
///
/// # See Also
///
/// - [`CircuitStat`] - Individual circuit tracking
/// - [`crate::control`] - Event dispatch to CBT verification
#[derive(Debug, Clone)]
pub struct TimeoutStats {
    /// Circuits currently being tracked (not yet built or timed out).
    pub circuits: HashMap<String, CircuitStat>,
    /// Total circuits launched.
    pub all_launched: u64,
    /// Total circuits successfully built.
    pub all_built: u64,
    /// Total circuits that timed out.
    pub all_timeout: u64,
    /// Hidden service circuits launched.
    pub hs_launched: u64,
    /// Hidden service circuits successfully built.
    pub hs_built: u64,
    /// Hidden service circuits that timed out.
    pub hs_timeout: u64,
    /// Whether to record timeouts (false after RESET, true after COMPUTED).
    pub record_timeouts: bool,
}

impl Default for TimeoutStats {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeoutStats {
    /// Creates a new timeout statistics tracker.
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            all_launched: 0,
            all_built: 0,
            all_timeout: 0,
            hs_launched: 0,
            hs_built: 0,
            hs_timeout: 0,
            record_timeouts: true,
        }
    }

    /// Resets all counters to zero.
    pub fn zero_fields(&mut self) {
        self.all_launched = 0;
        self.all_built = 0;
        self.all_timeout = 0;
        self.hs_launched = 0;
        self.hs_built = 0;
        self.hs_timeout = 0;
    }

    /// Handles a circuit event.
    ///
    /// Tracks circuit state transitions and updates statistics accordingly.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - The circuit ID
    /// * `status` - The circuit status (LAUNCHED, BUILT, FAILED, CLOSED)
    /// * `purpose` - The circuit purpose
    /// * `hs_state` - The hidden service state (if any)
    /// * `reason` - The close/fail reason (if any)
    pub fn circ_event(
        &mut self,
        circ_id: &str,
        status: &str,
        purpose: &str,
        hs_state: Option<&str>,
        reason: Option<&str>,
    ) {
        let is_hs = hs_state.is_some() || purpose.starts_with("HS");

        // Check for HS state change (non-HS to HS)
        if is_hs {
            if let Some(existing) = self.circuits.get(circ_id) {
                if !existing.is_hs {
                    plog(
                        LogLevel::Error,
                        &format!(
                            "Circuit {} just changed from non-HS to HS: purpose={}, hs_state={:?}",
                            circ_id, purpose, hs_state
                        ),
                    );
                }
            }
        }

        // Do not record circuits built while we have no timeout
        // (ie: after reset but before computed)
        if !self.record_timeouts {
            return;
        }

        match status {
            "LAUNCHED" => {
                self.add_circuit(circ_id, is_hs);
            }
            "BUILT" => {
                self.built_circuit(circ_id);
            }
            "FAILED" | "CLOSED" => {
                if reason == Some("TIMEOUT") {
                    self.timeout_circuit(circ_id);
                } else if purpose != "MEASURE_TIMEOUT" {
                    self.closed_circuit(circ_id);
                }
            }
            _ => {}
        }
    }

    /// Handles a CBT (Circuit Build Timeout) event.
    ///
    /// Processes COMPUTED and RESET events from Tor's circuit build timeout
    /// algorithm.
    ///
    /// # Arguments
    ///
    /// * `set_type` - The CBT event type (COMPUTED, RESET)
    /// * `timeout_rate` - Tor's reported timeout rate (if available)
    pub fn cbt_event(&mut self, set_type: &str, timeout_rate: Option<f64>) {
        if let Some(rate) = timeout_rate {
            plog(
                LogLevel::Info,
                &format!(
                    "CBT Timeout rate: {}; Our measured timeout rate: {:.4}; \
                     Hidden service timeout rate: {:.4}",
                    rate,
                    self.timeout_rate_all(),
                    self.timeout_rate_hs()
                ),
            );
        }

        match set_type {
            "COMPUTED" => {
                plog(LogLevel::Info, "CBT Timeout computed");
                self.record_timeouts = true;
            }
            "RESET" => {
                plog(LogLevel::Info, "CBT Timeout reset");
                self.record_timeouts = false;
                self.zero_fields();
            }
            _ => {}
        }
    }

    /// Adds a new circuit to tracking.
    pub fn add_circuit(&mut self, circ_id: &str, is_hs: bool) {
        if self.circuits.contains_key(circ_id) {
            plog(
                LogLevel::Error,
                &format!("Circuit {} already exists in map!", circ_id),
            );
        }
        self.circuits
            .insert(circ_id.to_string(), CircuitStat::new(circ_id, is_hs));
        self.all_launched += 1;
        if is_hs {
            self.hs_launched += 1;
        }
    }

    /// Records a circuit as successfully built.
    pub fn built_circuit(&mut self, circ_id: &str) {
        if let Some(circ) = self.circuits.remove(circ_id) {
            self.all_built += 1;
            if circ.is_hs {
                self.hs_built += 1;
            }
        }
    }

    /// Records a circuit as closed before completion.
    ///
    /// If we are closed but still in circuits, then we closed before being
    /// built or timing out. Don't count as a launched circuit.
    pub fn closed_circuit(&mut self, circ_id: &str) {
        if let Some(circ) = self.circuits.remove(circ_id) {
            // Decrement launched count since this circuit didn't complete
            self.all_launched = self.all_launched.saturating_sub(1);
            if circ.is_hs {
                self.hs_launched = self.hs_launched.saturating_sub(1);
            }
        }
    }

    /// Records a circuit as timed out.
    pub fn timeout_circuit(&mut self, circ_id: &str) {
        if let Some(circ) = self.circuits.remove(circ_id) {
            self.all_timeout += 1;
            if circ.is_hs {
                self.hs_timeout += 1;
            }
        }
    }

    /// Calculates the timeout rate for all circuits.
    ///
    /// Returns the ratio of timed out circuits to launched circuits.
    pub fn timeout_rate_all(&self) -> f64 {
        if self.all_launched > 0 {
            self.all_timeout as f64 / self.all_launched as f64
        } else {
            0.0
        }
    }

    /// Calculates the timeout rate for hidden service circuits.
    ///
    /// Returns the ratio of timed out HS circuits to launched HS circuits.
    pub fn timeout_rate_hs(&self) -> f64 {
        if self.hs_launched > 0 {
            self.hs_timeout as f64 / self.hs_launched as f64
        } else {
            0.0
        }
    }

    /// Returns the number of circuits currently being tracked.
    pub fn pending_count(&self) -> usize {
        self.circuits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_stat_new() {
        let stat = CircuitStat::new("123", true);
        assert_eq!(stat.circ_id, "123");
        assert!(stat.is_hs);
    }

    #[test]
    fn test_timeout_stats_new() {
        let stats = TimeoutStats::new();
        assert!(stats.circuits.is_empty());
        assert_eq!(stats.all_launched, 0);
        assert_eq!(stats.all_built, 0);
        assert_eq!(stats.all_timeout, 0);
        assert_eq!(stats.hs_launched, 0);
        assert_eq!(stats.hs_built, 0);
        assert_eq!(stats.hs_timeout, 0);
        assert!(stats.record_timeouts);
    }

    #[test]
    fn test_add_circuit() {
        let mut stats = TimeoutStats::new();

        stats.add_circuit("123", false);
        assert_eq!(stats.all_launched, 1);
        assert_eq!(stats.hs_launched, 0);
        assert!(stats.circuits.contains_key("123"));

        stats.add_circuit("456", true);
        assert_eq!(stats.all_launched, 2);
        assert_eq!(stats.hs_launched, 1);
    }

    #[test]
    fn test_built_circuit() {
        let mut stats = TimeoutStats::new();

        stats.add_circuit("123", true);
        stats.built_circuit("123");

        assert_eq!(stats.all_built, 1);
        assert_eq!(stats.hs_built, 1);
        assert!(!stats.circuits.contains_key("123"));
    }

    #[test]
    fn test_timeout_circuit() {
        let mut stats = TimeoutStats::new();

        stats.add_circuit("123", true);
        stats.timeout_circuit("123");

        assert_eq!(stats.all_timeout, 1);
        assert_eq!(stats.hs_timeout, 1);
        assert!(!stats.circuits.contains_key("123"));
    }

    #[test]
    fn test_closed_circuit() {
        let mut stats = TimeoutStats::new();

        stats.add_circuit("123", true);
        assert_eq!(stats.all_launched, 1);
        assert_eq!(stats.hs_launched, 1);

        stats.closed_circuit("123");

        // Closed before built/timeout - should decrement launched
        assert_eq!(stats.all_launched, 0);
        assert_eq!(stats.hs_launched, 0);
        assert!(!stats.circuits.contains_key("123"));
    }

    #[test]
    fn test_timeout_rate_all() {
        let mut stats = TimeoutStats::new();

        assert_eq!(stats.timeout_rate_all(), 0.0);

        stats.add_circuit("1", false);
        stats.add_circuit("2", false);
        stats.add_circuit("3", false);
        stats.add_circuit("4", false);

        stats.built_circuit("1");
        stats.built_circuit("2");
        stats.built_circuit("3");
        stats.timeout_circuit("4");

        // 1 timeout out of 4 launched = 0.25
        assert!((stats.timeout_rate_all() - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_timeout_rate_hs() {
        let mut stats = TimeoutStats::new();

        assert_eq!(stats.timeout_rate_hs(), 0.0);

        stats.add_circuit("1", true);
        stats.add_circuit("2", true);
        stats.add_circuit("3", false);

        stats.built_circuit("1");
        stats.timeout_circuit("2");
        stats.built_circuit("3");

        // 1 HS timeout out of 2 HS launched = 0.5
        assert!((stats.timeout_rate_hs() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_zero_fields() {
        let mut stats = TimeoutStats::new();

        stats.all_launched = 10;
        stats.all_built = 8;
        stats.all_timeout = 2;
        stats.hs_launched = 5;
        stats.hs_built = 4;
        stats.hs_timeout = 1;

        stats.zero_fields();

        assert_eq!(stats.all_launched, 0);
        assert_eq!(stats.all_built, 0);
        assert_eq!(stats.all_timeout, 0);
        assert_eq!(stats.hs_launched, 0);
        assert_eq!(stats.hs_built, 0);
        assert_eq!(stats.hs_timeout, 0);
    }

    #[test]
    fn test_cbt_event_reset() {
        let mut stats = TimeoutStats::new();
        stats.all_launched = 10;
        stats.record_timeouts = true;

        stats.cbt_event("RESET", None);

        assert!(!stats.record_timeouts);
        assert_eq!(stats.all_launched, 0);
    }

    #[test]
    fn test_cbt_event_computed() {
        let mut stats = TimeoutStats::new();
        stats.record_timeouts = false;

        stats.cbt_event("COMPUTED", Some(0.1));

        assert!(stats.record_timeouts);
    }

    #[test]
    fn test_circ_event_launched() {
        let mut stats = TimeoutStats::new();

        stats.circ_event(
            "123",
            "LAUNCHED",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            None,
        );

        assert_eq!(stats.all_launched, 1);
        assert_eq!(stats.hs_launched, 1);
        assert!(stats.circuits.contains_key("123"));
    }

    #[test]
    fn test_circ_event_built() {
        let mut stats = TimeoutStats::new();

        stats.circ_event(
            "123",
            "LAUNCHED",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            None,
        );
        stats.circ_event(
            "123",
            "BUILT",
            "HS_SERVICE_REND",
            Some("HSSR_CONNECTING"),
            None,
        );

        assert_eq!(stats.all_built, 1);
        assert_eq!(stats.hs_built, 1);
    }

    #[test]
    fn test_circ_event_timeout() {
        let mut stats = TimeoutStats::new();

        stats.circ_event("123", "LAUNCHED", "GENERAL", None, None);
        stats.circ_event("123", "FAILED", "GENERAL", None, Some("TIMEOUT"));

        assert_eq!(stats.all_timeout, 1);
    }

    #[test]
    fn test_circ_event_closed_before_built() {
        let mut stats = TimeoutStats::new();

        stats.circ_event("123", "LAUNCHED", "GENERAL", None, None);
        assert_eq!(stats.all_launched, 1);

        stats.circ_event("123", "CLOSED", "GENERAL", None, Some("DESTROYED"));

        // Should decrement launched since it closed before built/timeout
        assert_eq!(stats.all_launched, 0);
    }

    #[test]
    fn test_record_timeouts_disabled() {
        let mut stats = TimeoutStats::new();
        stats.record_timeouts = false;

        stats.circ_event("123", "LAUNCHED", "GENERAL", None, None);

        // Should not record when disabled
        assert_eq!(stats.all_launched, 0);
        assert!(!stats.circuits.contains_key("123"));
    }

    #[test]
    fn test_hs_detection_by_purpose() {
        let mut stats = TimeoutStats::new();

        stats.circ_event("123", "LAUNCHED", "HS_CLIENT_REND", None, None);

        assert_eq!(stats.hs_launched, 1);
        assert!(stats.circuits.get("123").unwrap().is_hs);
    }

    #[test]
    fn test_hs_detection_by_state() {
        let mut stats = TimeoutStats::new();

        stats.circ_event("123", "LAUNCHED", "GENERAL", Some("HSCI_CONNECTING"), None);

        assert_eq!(stats.hs_launched, 1);
        assert!(stats.circuits.get("123").unwrap().is_hs);
    }

    #[test]
    fn test_initial_timeout_rates() {
        let ts = TimeoutStats::new();
        assert_eq!(ts.timeout_rate_hs(), 0.0);
        assert_eq!(ts.timeout_rate_all(), 0.0);
    }

    #[test]
    fn test_hs_timeout_rate_20_percent() {
        let mut ts = TimeoutStats::new();

        for i in 1..=8 {
            let circ_id = format!("{}", i);
            ts.circ_event(
                &circ_id,
                "LAUNCHED",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
            ts.circ_event(
                &circ_id,
                "BUILT",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
        }

        ts.circ_event(
            "9",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "9",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );
        ts.circ_event(
            "9",
            "FAILED",
            "MEASURE_TIMEOUT",
            None,
            Some("MEASUREMENT_EXPIRED"),
        );

        ts.circ_event(
            "10",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "10",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        assert!((ts.timeout_rate_hs() - 0.2).abs() < 0.001);
        assert!((ts.timeout_rate_all() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_general_circuits_dont_affect_hs_rate() {
        let mut ts = TimeoutStats::new();

        for i in 1..=8 {
            let circ_id = format!("{}", i);
            ts.circ_event(
                &circ_id,
                "LAUNCHED",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
            ts.circ_event(
                &circ_id,
                "BUILT",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
        }

        ts.circ_event(
            "9",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "9",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        ts.circ_event(
            "10",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "10",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        for i in 11..=19 {
            let circ_id = format!("{}", i);
            ts.circ_event(&circ_id, "LAUNCHED", "GENERAL", None, None);
            ts.circ_event(&circ_id, "BUILT", "GENERAL", None, None);
        }

        ts.circ_event("20", "LAUNCHED", "GENERAL", None, None);
        ts.circ_event("20", "FAILED", "GENERAL", None, Some("TIMEOUT"));

        assert!((ts.timeout_rate_hs() - 0.2).abs() < 0.001);
        assert!((ts.timeout_rate_all() - 0.15).abs() < 0.001);
    }

    #[test]
    fn test_failed_circuits_dont_impact_rates() {
        let mut ts = TimeoutStats::new();

        for i in 1..=8 {
            let circ_id = format!("{}", i);
            ts.circ_event(
                &circ_id,
                "LAUNCHED",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
            ts.circ_event(
                &circ_id,
                "BUILT",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
        }

        ts.circ_event(
            "9",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "9",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        ts.circ_event(
            "10",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "10",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        let rate_before = ts.timeout_rate_hs();

        ts.circ_event("21", "LAUNCHED", "GENERAL", None, None);
        ts.circ_event("21", "FAILED", "GENERAL", None, Some("FINISHED"));

        ts.circ_event(
            "22",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "22",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("FINISHED"),
        );

        assert!((ts.timeout_rate_hs() - rate_before).abs() < 0.001);
    }

    #[test]
    fn test_closed_circuits_dont_impact_rates() {
        let mut ts = TimeoutStats::new();

        for i in 1..=8 {
            let circ_id = format!("{}", i);
            ts.circ_event(
                &circ_id,
                "LAUNCHED",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
            ts.circ_event(
                &circ_id,
                "BUILT",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
        }

        ts.circ_event(
            "9",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "9",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        ts.circ_event(
            "10",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "10",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        let rate_before = ts.timeout_rate_hs();

        ts.circ_event("23", "LAUNCHED", "GENERAL", None, None);
        ts.circ_event("23", "CLOSED", "GENERAL", None, Some("FINISHED"));

        ts.circ_event(
            "24",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "24",
            "CLOSED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("FINISHED"),
        );

        assert!((ts.timeout_rate_hs() - rate_before).abs() < 0.001);
    }

    #[test]
    fn test_circuits_not_counted_after_reset() {
        let mut ts = TimeoutStats::new();

        ts.cbt_event("RESET", None);
        assert!(!ts.record_timeouts);

        for i in 1..=8 {
            let circ_id = format!("{}", i);
            ts.circ_event(
                &circ_id,
                "LAUNCHED",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
            ts.circ_event(
                &circ_id,
                "BUILT",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
        }

        ts.circ_event(
            "9",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "9",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        ts.circ_event(
            "10",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "10",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        assert_eq!(ts.timeout_rate_hs(), 0.0);
        assert_eq!(ts.timeout_rate_all(), 0.0);
    }

    #[test]
    fn test_circuits_counted_after_computed() {
        let mut ts = TimeoutStats::new();

        ts.cbt_event("RESET", None);
        ts.cbt_event("COMPUTED", Some(0.1));

        assert!(ts.record_timeouts);

        for i in 1..=8 {
            let circ_id = format!("{}", i);
            ts.circ_event(
                &circ_id,
                "LAUNCHED",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
            ts.circ_event(
                &circ_id,
                "BUILT",
                "HS_VANGUARDS",
                Some("HSVI_CONNECTING"),
                None,
            );
        }

        ts.circ_event(
            "9",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "9",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        ts.circ_event(
            "10",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "10",
            "FAILED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            Some("TIMEOUT"),
        );

        assert!((ts.timeout_rate_hs() - 0.2).abs() < 0.001);
        assert!((ts.timeout_rate_all() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_double_launch_coverage() {
        let mut ts = TimeoutStats::new();

        ts.circ_event(
            "25",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );
        ts.circ_event(
            "25",
            "LAUNCHED",
            "HS_VANGUARDS",
            Some("HSVI_CONNECTING"),
            None,
        );

        ts.circ_event("25", "BUILT", "HS_VANGUARDS", Some("HSVI_CONNECTING"), None);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn cbt_statistics_accuracy(
            num_circuits in 1usize..50,
            outcomes in prop::collection::vec(prop_oneof![Just("BUILT"), Just("TIMEOUT"), Just("CLOSED")], 1..50),
            is_hs_flags in prop::collection::vec(any::<bool>(), 1..50),
        ) {
            let mut stats = TimeoutStats::new();

            let mut expected_launched = 0u64;
            let mut expected_built = 0u64;
            let mut expected_timeout = 0u64;
            let mut expected_hs_launched = 0u64;
            let mut expected_hs_built = 0u64;
            let mut expected_hs_timeout = 0u64;

            for i in 0..num_circuits.min(outcomes.len()).min(is_hs_flags.len()) {
                let circ_id = format!("{}", i);
                let is_hs = is_hs_flags[i];
                let outcome = outcomes[i];

                stats.circ_event(&circ_id, "LAUNCHED", if is_hs { "HS_SERVICE_REND" } else { "GENERAL" },
                                if is_hs { Some("HSSR_CONNECTING") } else { None }, None);
                expected_launched += 1;
                if is_hs {
                    expected_hs_launched += 1;
                }

                match outcome {
                    "BUILT" => {
                        stats.circ_event(&circ_id, "BUILT", if is_hs { "HS_SERVICE_REND" } else { "GENERAL" },
                                        if is_hs { Some("HSSR_CONNECTING") } else { None }, None);
                        expected_built += 1;
                        if is_hs {
                            expected_hs_built += 1;
                        }
                    }
                    "TIMEOUT" => {
                        stats.circ_event(&circ_id, "FAILED", if is_hs { "HS_SERVICE_REND" } else { "GENERAL" },
                                        if is_hs { Some("HSSR_CONNECTING") } else { None }, Some("TIMEOUT"));
                        expected_timeout += 1;
                        if is_hs {
                            expected_hs_timeout += 1;
                        }
                    }
                    "CLOSED" => {
                        stats.circ_event(&circ_id, "CLOSED", if is_hs { "HS_SERVICE_REND" } else { "GENERAL" },
                                        if is_hs { Some("HSSR_CONNECTING") } else { None }, Some("DESTROYED"));
                        expected_launched -= 1;
                        if is_hs {
                            expected_hs_launched -= 1;
                        }
                    }
                    _ => {}
                }
            }

            prop_assert_eq!(stats.all_launched, expected_launched,
                "all_launched: expected {}, got {}", expected_launched, stats.all_launched);
            prop_assert_eq!(stats.all_built, expected_built,
                "all_built: expected {}, got {}", expected_built, stats.all_built);
            prop_assert_eq!(stats.all_timeout, expected_timeout,
                "all_timeout: expected {}, got {}", expected_timeout, stats.all_timeout);
            prop_assert_eq!(stats.hs_launched, expected_hs_launched,
                "hs_launched: expected {}, got {}", expected_hs_launched, stats.hs_launched);
            prop_assert_eq!(stats.hs_built, expected_hs_built,
                "hs_built: expected {}, got {}", expected_hs_built, stats.hs_built);
            prop_assert_eq!(stats.hs_timeout, expected_hs_timeout,
                "hs_timeout: expected {}, got {}", expected_hs_timeout, stats.hs_timeout);

            if expected_launched > 0 {
                let expected_rate = expected_timeout as f64 / expected_launched as f64;
                prop_assert!((stats.timeout_rate_all() - expected_rate).abs() < 0.001,
                    "timeout_rate_all: expected {}, got {}", expected_rate, stats.timeout_rate_all());
            }

            if expected_hs_launched > 0 {
                let expected_hs_rate = expected_hs_timeout as f64 / expected_hs_launched as f64;
                prop_assert!((stats.timeout_rate_hs() - expected_hs_rate).abs() < 0.001,
                    "timeout_rate_hs: expected {}, got {}", expected_hs_rate, stats.timeout_rate_hs());
            }
        }
    }
}
