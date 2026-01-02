//! Rendezvous point monitoring for detecting statistical attacks.
//!
//! This module provides protection against statistical attacks on hidden services
//! by monitoring rendezvous point usage patterns. It detects when a relay is being
//! used as a rendezvous point more frequently than expected based on its bandwidth.
//!
//! # Overview
//!
//! The rendguard system tracks:
//!
//! - **Usage counts**: How many times each relay has been used as a rendezvous point
//! - **Expected weights**: The expected usage based on bandwidth proportion
//! - **Overuse detection**: When a relay is used more than expected
//!
//! # Overuse Detection Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    Rendezvous Point Usage Check                         │
//! │                                                                         │
//! │                    ┌─────────────────────┐                              │
//! │                    │ HS_SERVICE_REND     │                              │
//! │                    │ Circuit Created     │                              │
//! │                    └──────────┬──────────┘                              │
//! │                               │                                         │
//! │                               ▼                                         │
//! │                    ┌─────────────────────┐                              │
//! │                    │ Extract RP          │                              │
//! │                    │ Fingerprint         │                              │
//! │                    └──────────┬──────────┘                              │
//! │                               │                                         │
//! │                               ▼                                         │
//! │                    ┌─────────────────────┐                              │
//! │                    │ Increment Usage     │                              │
//! │                    │ Count               │                              │
//! │                    └──────────┬──────────┘                              │
//! │                               │                                         │
//! │              ┌────────────────┼────────────────┐                        │
//! │              │                │                │                        │
//! │              ▼                ▼                ▼                        │
//! │    ┌─────────────────┐ ┌───────────┐ ┌─────────────────┐                │
//! │    │ total_uses <    │ │ relay_uses│ │ Check Ratio:    │                │
//! │    │ global_start?   │ │ < relay_  │ │ used/total >    │                │
//! │    │                 │ │ start?    │ │ weight * max?   │                │
//! │    └────────┬────────┘ └─────┬─────┘ └────────┬────────┘                │
//! │             │                │                │                         │
//! │             ▼                ▼                ▼                         │
//! │         [VALID]          [VALID]    ┌────────┴────────┐                 │
//! │                                     │                 │                 │
//! │                                     ▼                 ▼                 │
//! │                               [OVERUSED]          [VALID]               │
//! │                                     │                                   │
//! │                                     ▼                                   │
//! │                          ┌─────────────────────┐                        │
//! │                          │ Log Warning         │                        │
//! │                          │ (potential attack)  │                        │
//! │                          └─────────────────────┘                        │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Attack Detection
//!
//! An attacker controlling a relay could try to become the rendezvous point for
//! a target hidden service more often than expected. This module detects such
//! statistical anomalies by comparing actual usage to expected bandwidth-weighted
//! usage.
//!
//! ```text
//! Detection Formula:
//!
//!   overused = (relay_uses / total_uses) > (relay_weight * max_ratio)
//!
//! Where:
//!   relay_uses   = Number of times this relay was used as RP
//!   total_uses   = Total RP uses across all relays
//!   relay_weight = Relay's bandwidth / total network bandwidth
//!   max_ratio    = Configured maximum use-to-bandwidth ratio (default: 5.0)
//! ```
//!
//! # Usage Tracking
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         RendGuard State                                 │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐    │
//! │  │ use_counts: HashMap<String, RendUseCount>                       │    │
//! │  │                                                                 │    │
//! │  │   Fingerprint          │ Used  │ Weight                         │    │
//! │  │   ─────────────────────┼───────┼────────                        │    │
//! │  │   AABBCCDD...          │ 15    │ 0.0023                         │    │
//! │  │   EEFF0011...          │ 8     │ 0.0015                         │    │
//! │  │   NOT_IN_CONSENSUS     │ 2     │ 0.01 (churn allowance)         │    │
//! │  │   ...                  │ ...   │ ...                            │    │
//! │  └─────────────────────────────────────────────────────────────────┘    │
//! │                                                                         │
//! │  total_use_counts: 1250                                                 │
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐    │
//! │  │ Scaling: When total_use_counts >= use_scale_at_count            │    │
//! │  │          All counts are halved to prevent unbounded growth      │    │
//! │  └─────────────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # What This Module Does NOT Do
//!
//! - **Guard selection**: Use [`crate::vanguards`] for guard management
//! - **Circuit closure**: Use [`crate::control`] for circuit management
//! - **Bandwidth monitoring**: Use [`crate::bandguards`] for bandwidth attacks
//!
//! # Configuration
//!
//! Key configuration options in [`RendguardConfig`](crate::config::RendguardConfig):
//!
//! | Option | Default | Description |
//! |--------|---------|-------------|
//! | `use_global_start_count` | 1000 | Minimum total uses before checking |
//! | `use_relay_start_count` | 100 | Minimum relay uses before checking |
//! | `use_max_use_to_bw_ratio` | 5.0 | Maximum ratio of use to bandwidth |
//! | `use_scale_at_count` | 20000 | Scale counts when reaching this total |
//! | `use_max_consensus_weight_churn` | 1.0 | Weight for NOT_IN_CONSENSUS relays |
//!
//! # Example
//!
//! ```rust
//! use vanguards_rs::rendguard::{RendGuard, RendUseCount, RendCheckResult};
//! use vanguards_rs::config::RendguardConfig;
//!
//! let mut rendguard = RendGuard::new();
//! let config = RendguardConfig::default();
//!
//! // Simulate relay usage
//! let fingerprint = "AABBCCDD00112233445566778899AABBCCDDEEFF";
//!
//! // Check if usage is valid
//! let valid = rendguard.valid_rend_use(fingerprint, &config);
//! if !valid {
//!     let usage_rate = rendguard.usage_rate(fingerprint);
//!     let expected = rendguard.expected_weight(fingerprint);
//!     println!("Overuse detected: {:.2}% vs expected {:.2}%", usage_rate, expected);
//! }
//! ```
//!
//! # Security Considerations
//!
//! - Start counts prevent false positives during initial operation
//! - Scaling prevents long-running relays from accumulating unfair counts
//! - NOT_IN_CONSENSUS tracking catches relays that leave the network
//! - Weight churn allowance handles consensus changes gracefully
//!
//! # See Also
//!
//! - [`crate::config::RendguardConfig`] - Configuration options
//! - [`crate::vanguards::RendGuard`] - Main implementation (re-exported here)
//! - [`crate::vanguards::RendUseCount`] - Per-relay usage tracking
//! - [Python vanguards rendguard](https://github.com/mikeperry-tor/vanguards) - Original implementation

// Re-export types from vanguards module
pub use crate::vanguards::{RendGuard, RendUseCount};

/// Identifier used for relays not in the current consensus.
///
/// When a relay is used as a rendezvous point but is not found in the
/// current consensus, its usage is tracked under this special identifier.
/// This handles cases where relays leave the network or consensus churn.
pub const NOT_IN_CONSENSUS_ID: &str = "NOT_IN_CONSENSUS";

/// Result of checking a rendezvous point usage.
///
/// Returned by usage validation to indicate whether a rendezvous point
/// selection is valid or represents a potential statistical attack.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::rendguard::RendCheckResult;
///
/// fn handle_rend_check(result: RendCheckResult) {
///     match result {
///         RendCheckResult::Valid => {
///             println!("RP usage is within expected bounds");
///         }
///         RendCheckResult::Overused { fingerprint, usage_rate, expected_weight } => {
///             println!(
///                 "Potential attack: {} used {:.2}% vs expected {:.2}%",
///                 fingerprint, usage_rate, expected_weight
///             );
///         }
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`RendGuard::valid_rend_use`] - Validation method
/// - [`RendGuard::is_overused`] - Direct overuse check
#[derive(Debug, Clone, PartialEq)]
pub enum RendCheckResult {
    /// Usage is valid, circuit can proceed.
    ///
    /// The relay's usage rate is within acceptable bounds relative to
    /// its bandwidth weight.
    Valid,
    /// Relay is overused, circuit should be closed.
    ///
    /// The relay is being used as a rendezvous point more frequently
    /// than expected based on its bandwidth. This may indicate a
    /// statistical attack attempting to correlate hidden service activity.
    Overused {
        /// The relay's fingerprint (40 hex characters).
        fingerprint: String,
        /// Actual usage rate as a percentage of total RP uses.
        usage_rate: f64,
        /// Expected weight as a percentage based on bandwidth.
        expected_weight: f64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RendguardConfig;

    #[test]
    fn test_rendguard_new() {
        let rg = RendGuard::new();

        assert!(rg.use_counts.is_empty());
        assert_eq!(rg.total_use_counts, 0.0);
        assert_eq!(rg.pickle_revision, 1.0);
    }

    #[test]
    fn test_not_in_consensus_tracking() {
        let mut rg = RendGuard::new();
        let config = RendguardConfig::default();

        let fp = "7791CA6B67303ACE46C2B6F5211206B765948147";

        for i in 1..config.use_global_start_count {
            let valid = rg.valid_rend_use(fp, &config);
            assert!(valid, "Use {} should be valid", i);

            assert!(rg.use_counts.contains_key(NOT_IN_CONSENSUS_ID));
            assert_eq!(
                rg.use_counts.get(NOT_IN_CONSENSUS_ID).unwrap().used,
                i as f64
            );
        }
    }

    #[test]
    fn test_overuse_detection() {
        let mut rg = RendGuard::new();
        let config = RendguardConfig {
            use_global_start_count: 10,
            use_relay_start_count: 5,
            use_max_use_to_bw_ratio: 5.0,
            ..Default::default()
        };

        let fp = "BC630CBBB518BE7E9F4E09712AB0269E9DC7D626";
        rg.use_counts.insert(
            fp.to_string(),
            RendUseCount {
                idhex: fp.to_string(),
                used: 0.0,
                weight: 0.01,
            },
        );

        for _ in 0..20 {
            rg.valid_rend_use(fp, &config);
        }

        let is_overused = rg.is_overused(fp, &config);
        assert!(is_overused, "Relay should be overused");
    }

    #[test]
    fn test_scale_counts() {
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
    fn test_usage_rate() {
        let mut rg = RendGuard::new();
        let fp = "A".repeat(40);

        rg.use_counts.insert(
            fp.clone(),
            RendUseCount {
                idhex: fp.clone(),
                used: 25.0,
                weight: 0.1,
            },
        );
        rg.total_use_counts = 100.0;

        let rate = rg.usage_rate(&fp);
        assert!((rate - 25.0).abs() < 0.001);
    }

    #[test]
    fn test_expected_weight() {
        let mut rg = RendGuard::new();
        let fp = "A".repeat(40);

        rg.use_counts.insert(
            fp.clone(),
            RendUseCount {
                idhex: fp.clone(),
                used: 0.0,
                weight: 0.05,
            },
        );

        let weight = rg.expected_weight(&fp);
        assert!((weight - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_below_global_start_count_not_overused() {
        let mut rg = RendGuard::new();
        let config = RendguardConfig {
            use_global_start_count: 1000,
            use_relay_start_count: 100,
            ..Default::default()
        };

        let fp = "A".repeat(40);
        rg.use_counts.insert(
            fp.clone(),
            RendUseCount {
                idhex: fp.clone(),
                used: 500.0,
                weight: 0.001,
            },
        );
        rg.total_use_counts = 500.0;

        assert!(!rg.is_overused(&fp, &config));
    }

    #[test]
    fn test_below_relay_start_count_not_overused() {
        let mut rg = RendGuard::new();
        let config = RendguardConfig {
            use_global_start_count: 100,
            use_relay_start_count: 100,
            ..Default::default()
        };

        let fp = "A".repeat(40);
        rg.use_counts.insert(
            fp.clone(),
            RendUseCount {
                idhex: fp.clone(),
                used: 50.0,
                weight: 0.001,
            },
        );
        rg.total_use_counts = 1000.0;

        assert!(!rg.is_overused(&fp, &config));
    }

    #[test]
    fn test_valid_rend_use_increments_counts() {
        let mut rg = RendGuard::new();
        let config = RendguardConfig::default();

        let fp = "A".repeat(40);
        rg.use_counts.insert(
            fp.clone(),
            RendUseCount {
                idhex: fp.clone(),
                used: 0.0,
                weight: 0.1,
            },
        );

        rg.valid_rend_use(&fp, &config);

        assert_eq!(rg.use_counts.get(&fp).unwrap().used, 1.0);
        assert_eq!(rg.total_use_counts, 1.0);
    }

    #[test]
    fn test_rend_use_count_creation() {
        let count = RendUseCount::new("A".repeat(40), 0.05);

        assert_eq!(count.idhex, "A".repeat(40));
        assert_eq!(count.used, 0.0);
        assert!((count.weight - 0.05).abs() < 0.001);
    }

    #[test]
    fn test_rend_check_result_variants() {
        let valid = RendCheckResult::Valid;
        assert_eq!(valid, RendCheckResult::Valid);

        let overused = RendCheckResult::Overused {
            fingerprint: "A".repeat(40),
            usage_rate: 10.0,
            expected_weight: 1.0,
        };

        match overused {
            RendCheckResult::Overused {
                fingerprint,
                usage_rate,
                expected_weight,
            } => {
                assert_eq!(fingerprint, "A".repeat(40));
                assert!((usage_rate - 10.0).abs() < 0.001);
                assert!((expected_weight - 1.0).abs() < 0.001);
            }
            _ => panic!("Expected Overused variant"),
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::config::RendguardConfig;
    use proptest::prelude::*;
    use std::collections::HashMap;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn rendguard_use_count_tracking(
            num_relays in 1usize..10,
            uses_per_relay in prop::collection::vec(1u32..50, 1..10),
        ) {
            let mut rg = RendGuard::new();
            let config = RendguardConfig::default();

            let relays: Vec<String> = (0..num_relays)
                .map(|i| format!("{:0>40X}", i))
                .collect();

            for relay in &relays {
                rg.use_counts.insert(
                    relay.clone(),
                    RendUseCount::new(relay.clone(), 1.0 / num_relays as f64),
                );
            }

            let mut expected_uses: HashMap<String, u32> = HashMap::new();
            let mut total_uses = 0u32;

            for (i, &uses) in uses_per_relay.iter().enumerate() {
                let relay = &relays[i % num_relays];
                for _ in 0..uses {
                    rg.valid_rend_use(relay, &config);
                    *expected_uses.entry(relay.clone()).or_insert(0) += 1;
                    total_uses += 1;
                }
            }

            for (relay, expected) in &expected_uses {
                let actual = rg.use_counts.get(relay).map(|c| c.used as u32).unwrap_or(0);
                prop_assert_eq!(actual, *expected,
                    "Relay {} expected {} uses, got {}", relay, expected, actual);
            }

            prop_assert!((rg.total_use_counts - total_uses as f64).abs() < 0.001,
                "Total expected {}, got {}", total_uses, rg.total_use_counts);
        }

        #[test]
        fn rendguard_scaling(
            counts in prop::collection::vec(10.0f64..1000.0, 2..10),
        ) {
            let mut rg = RendGuard::new();

            let fingerprints: Vec<String> = (0..counts.len())
                .map(|i| format!("{:0>40X}", i))
                .collect();

            for (i, &count) in counts.iter().enumerate() {
                rg.use_counts.insert(
                    fingerprints[i].clone(),
                    RendUseCount {
                        idhex: fingerprints[i].clone(),
                        used: count,
                        weight: 0.1,
                    },
                );
            }
            rg.total_use_counts = counts.iter().sum();

            let original_total = rg.total_use_counts;
            let original_counts: HashMap<String, f64> = rg.use_counts.iter()
                .map(|(k, v)| (k.clone(), v.used))
                .collect();

            rg.scale_counts();

            for (fp, original) in &original_counts {
                let scaled = rg.use_counts.get(fp).map(|c| c.used).unwrap_or(0.0);
                prop_assert!((scaled - original / 2.0).abs() < 0.001,
                    "Count {} expected {}, got {}", fp, original / 2.0, scaled);
            }

            prop_assert!((rg.total_use_counts - original_total / 2.0).abs() < 0.001,
                "Total expected {}, got {}", original_total / 2.0, rg.total_use_counts);
        }

        #[test]
        fn rendguard_overuse_detection(
            weight in 0.01f64..0.1,
            ratio in 2.0f64..10.0,
        ) {
            let config = RendguardConfig {
                use_global_start_count: 1000,
                use_relay_start_count: 100,
                use_max_use_to_bw_ratio: ratio,
                ..Default::default()
            };

            let mut rg = RendGuard::new();
            let fp = "A".repeat(40);

            rg.use_counts.insert(
                fp.clone(),
                RendUseCount {
                    idhex: fp.clone(),
                    used: 0.0,
                    weight,
                },
            );

            let total = 2000.0;
            let overuse_used = total * weight * ratio * 2.0;

            rg.use_counts.get_mut(&fp).unwrap().used = overuse_used;
            rg.total_use_counts = total + overuse_used;

            let actual_ratio = overuse_used / rg.total_use_counts;
            let threshold = weight * ratio;

            if overuse_used >= config.use_relay_start_count as f64
                && rg.total_use_counts >= config.use_global_start_count as f64
                && actual_ratio > threshold {
                prop_assert!(rg.is_overused(&fp, &config),
                    "Relay should be overused: used={}, total={}, actual_ratio={}, threshold={}",
                    overuse_used, rg.total_use_counts, actual_ratio, threshold);
            }

            let safe_used = total * weight * ratio * 0.3;
            rg.use_counts.get_mut(&fp).unwrap().used = safe_used.max(config.use_relay_start_count as f64);
            rg.total_use_counts = total;

            let actual_ratio_safe = rg.use_counts.get(&fp).unwrap().used / rg.total_use_counts;

            if actual_ratio_safe <= threshold {
                prop_assert!(!rg.is_overused(&fp, &config),
                    "Relay should not be overused: used={}, total={}, actual_ratio={}, threshold={}",
                    rg.use_counts.get(&fp).unwrap().used, rg.total_use_counts, actual_ratio_safe, threshold);
            }
        }
    }
}
