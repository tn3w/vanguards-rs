//! Node selection and input validation for vanguards-rs.
//!
//! This module provides bandwidth-weighted node selection for vanguard relay selection,
//! along with input validation functions for fingerprints, IP addresses, and country codes.
//!
//! # Overview
//!
//! The node selection system implements:
//!
//! - **Input Validation**: Functions to validate relay fingerprints, IP addresses, and country codes
//! - **Node Restrictions**: Trait-based system for filtering relays by flags and other criteria
//! - **Bandwidth-Weighted Selection**: Random selection proportional to relay bandwidth
//!
//! # Bandwidth-Weighted Selection Algorithm
//!
//! The selection algorithm ensures relays are chosen proportionally to their bandwidth,
//! which helps distribute load across the network while respecting Tor's consensus weights.
//!
//! # Validation Functions
//!
//! - [`is_valid_fingerprint`]: Validates 40-character hexadecimal relay fingerprints
//! - [`is_valid_ip_or_network`]: Validates IPv4/IPv6 addresses and CIDR networks
//! - [`is_valid_country_code`]: Validates 2-character country codes
//!
//! # Node Selection
//!
//! The [`BwWeightedGenerator`] implements bandwidth-weighted random selection:
//!
//! ```rust,ignore
//! use vanguards_rs::node_selection::{BwWeightedGenerator, FlagsRestriction, NodeRestrictionList, Position};
//!
//! // Create restrictions requiring Fast, Stable, Valid flags
//! let restriction = FlagsRestriction::new(
//!     vec!["Fast".to_string(), "Stable".to_string(), "Valid".to_string()],
//!     vec!["Authority".to_string()],
//! );
//! let restrictions = NodeRestrictionList::new(vec![Box::new(restriction)]);
//!
//! // Create generator with consensus weights
//! let generator = BwWeightedGenerator::new(routers, restrictions, weights, Position::Middle)?;
//!
//! // Generate nodes
//! let node = generator.generate()?;
//! ```
//!
//! # What This Module Does NOT Do
//!
//! - **Consensus fetching**: Use [`stem_rs::descriptor::remote`] to fetch consensus data
//! - **Guard persistence**: Use [`crate::vanguards::VanguardState`] for state management
//! - **Circuit building**: This module only selects nodes; circuit construction is handled elsewhere
//!
//! # Security Considerations
//!
//! - Bandwidth weighting prevents attackers from easily positioning malicious relays
//! - Flag restrictions ensure only qualified relays are selected for sensitive positions
//! - The random selection uses a cryptographically secure random number generator
//!
//! # See Also
//!
//! - [`crate::error::Error::NoNodesRemain`] - Error when all nodes are filtered
//! - [`crate::vanguards`] - Vanguard state management using selected nodes
//! - [`crate::config`] - Configuration for node selection parameters
//! - [Python vanguards NodeSelection](https://github.com/mikeperry-tor/vanguards)

use std::collections::HashMap;
use std::net::IpAddr;

use ipnetwork::IpNetwork;
use rand::Rng;
use stem_rs::descriptor::router_status::RouterStatusEntry;

use crate::error::{Error, Result};

/// Validates that a string is a valid relay fingerprint.
///
/// A valid fingerprint is exactly 40 hexadecimal characters (case-insensitive).
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid fingerprint, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::node_selection::is_valid_fingerprint;
///
/// assert!(is_valid_fingerprint("AABBCCDD00112233445566778899AABBCCDDEEFF"));
/// assert!(is_valid_fingerprint("aabbccdd00112233445566778899aabbccddeeff"));
/// assert!(!is_valid_fingerprint("AABBCCDD")); // Too short
/// assert!(!is_valid_fingerprint("GGHHIIJJ00112233445566778899AABBCCDDEEFF")); // Invalid hex
/// ```
pub fn is_valid_fingerprint(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validates that a string is a valid IP address or CIDR network.
///
/// Accepts IPv4 addresses, IPv6 addresses, and CIDR notation for both.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid IP address or network, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::node_selection::is_valid_ip_or_network;
///
/// // IPv4
/// assert!(is_valid_ip_or_network("192.168.1.1"));
/// assert!(is_valid_ip_or_network("192.168.1.0/24"));
///
/// // IPv6
/// assert!(is_valid_ip_or_network("::1"));
/// assert!(is_valid_ip_or_network("2001:db8::/32"));
///
/// // Invalid
/// assert!(!is_valid_ip_or_network("not-an-ip"));
/// assert!(!is_valid_ip_or_network("192.168.1.1/33")); // Invalid prefix
/// ```
pub fn is_valid_ip_or_network(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok() || s.parse::<IpNetwork>().is_ok()
}

/// Validates that a string is a valid 2-character country code.
///
/// Country codes must be exactly 2 alphabetic characters (case-insensitive).
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid country code, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use vanguards_rs::node_selection::is_valid_country_code;
///
/// assert!(is_valid_country_code("US"));
/// assert!(is_valid_country_code("de"));
/// assert!(!is_valid_country_code("USA")); // Too long
/// assert!(!is_valid_country_code("U1")); // Contains digit
/// ```
pub fn is_valid_country_code(s: &str) -> bool {
    s.len() == 2 && s.chars().all(|c| c.is_ascii_alphabetic())
}

/// Interface for node restriction policies.
///
/// Implementations of this trait define criteria for filtering relay nodes.
/// Multiple restrictions can be combined using [`NodeRestrictionList`].
///
/// # Implementing Custom Restrictions
///
/// Create custom restrictions by implementing this trait:
///
/// ```rust
/// use vanguards_rs::node_selection::NodeRestriction;
/// use stem_rs::descriptor::router_status::RouterStatusEntry;
///
/// struct BandwidthRestriction {
///     min_bandwidth: u64,
/// }
///
/// impl NodeRestriction for BandwidthRestriction {
///     fn r_is_ok(&self, router: &RouterStatusEntry) -> bool {
///         router.bandwidth.unwrap_or(0) >= self.min_bandwidth
///     }
/// }
/// ```
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow use across threads.
///
/// # See Also
///
/// - [`FlagsRestriction`] - Built-in restriction for router flags
/// - [`NodeRestrictionList`] - Combine multiple restrictions
pub trait NodeRestriction: Send + Sync {
    /// Returns true if the router passes this restriction.
    fn r_is_ok(&self, router: &RouterStatusEntry) -> bool;
}

/// Restriction for mandatory and forbidden router flags.
///
/// This restriction filters routers based on their assigned flags.
/// Routers must have all mandatory flags and none of the forbidden flags.
///
/// # Common Flag Combinations
///
/// | Use Case | Mandatory | Forbidden |
/// |----------|-----------|-----------|
/// | Vanguard Layer 2 | Fast, Stable, Valid | Authority, BadExit |
/// | Vanguard Layer 3 | Fast, Stable, Valid | Authority, BadExit |
/// | Exit Selection | Fast, Stable, Valid, Exit | BadExit |
///
/// # Example
///
/// ```rust
/// use vanguards_rs::node_selection::FlagsRestriction;
///
/// // Require Fast, Stable, Valid; forbid Authority
/// let restriction = FlagsRestriction::new(
///     vec!["Fast".to_string(), "Stable".to_string(), "Valid".to_string()],
///     vec!["Authority".to_string()],
/// );
/// ```
///
/// # See Also
///
/// - [`NodeRestriction`] - The trait this implements
/// - [`NodeRestrictionList`] - Combine with other restrictions
#[derive(Debug, Clone)]
pub struct FlagsRestriction {
    /// Flags that must be present on the router.
    pub mandatory: Vec<String>,
    /// Flags that must not be present on the router.
    pub forbidden: Vec<String>,
}

impl FlagsRestriction {
    /// Creates a new flags restriction.
    ///
    /// # Arguments
    ///
    /// * `mandatory` - List of flags that must be present
    /// * `forbidden` - List of flags that must not be present
    pub fn new(mandatory: Vec<String>, forbidden: Vec<String>) -> Self {
        Self {
            mandatory,
            forbidden,
        }
    }
}

impl NodeRestriction for FlagsRestriction {
    fn r_is_ok(&self, router: &RouterStatusEntry) -> bool {
        for m in &self.mandatory {
            if !router.flags.contains(m) {
                return false;
            }
        }
        for f in &self.forbidden {
            if router.flags.contains(f) {
                return false;
            }
        }
        true
    }
}

/// A list of node restrictions to apply.
///
/// All restrictions must pass for a router to be accepted. This allows
/// combining multiple filtering criteria (e.g., flags + bandwidth + country).
///
/// # Example
///
/// ```rust
/// use vanguards_rs::node_selection::{FlagsRestriction, NodeRestrictionList};
///
/// let flags = FlagsRestriction::new(
///     vec!["Fast".to_string()],
///     vec!["BadExit".to_string()],
/// );
/// let restrictions = NodeRestrictionList::new(vec![Box::new(flags)]);
/// ```
///
/// # See Also
///
/// - [`NodeRestriction`] - Trait for individual restrictions
/// - [`FlagsRestriction`] - Built-in flag-based restriction
pub struct NodeRestrictionList {
    restrictions: Vec<Box<dyn NodeRestriction>>,
}

impl NodeRestrictionList {
    /// Creates a new restriction list.
    pub fn new(restrictions: Vec<Box<dyn NodeRestriction>>) -> Self {
        Self { restrictions }
    }

    /// Returns true if the router passes all restrictions.
    pub fn r_is_ok(&self, router: &RouterStatusEntry) -> bool {
        self.restrictions.iter().all(|r| r.r_is_ok(router))
    }
}

/// Position in circuit for weight calculation.
///
/// Different positions in a Tor circuit use different bandwidth weight
/// multipliers from the consensus. This affects how relays are selected
/// for each hop in the circuit.
///
/// # Weight Keys by Position
///
/// | Position | Weight Keys Used |
/// |----------|------------------|
/// | Guard | Wgg, Wgd |
/// | Middle | Wmm, Wmg, Wme, Wmd |
/// | Exit | Wee, Wed |
///
/// # See Also
///
/// - [`BwWeightedGenerator`] - Uses position for weight calculation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// Guard (entry) position - uses Wgg/Wgd weights.
    Guard,
    /// Middle position - uses Wmm/Wmg/Wme/Wmd weights.
    Middle,
    /// Exit position - uses Wee/Wed weights.
    Exit,
}

impl Position {
    fn weight_key_suffix(&self) -> char {
        match self {
            Position::Guard => 'g',
            Position::Middle => 'm',
            Position::Exit => 'e',
        }
    }
}

/// Bandwidth-weighted node generator.
///
/// Implements bandwidth-weighted random selection of relay nodes.
/// Selection probability is proportional to each relay's bandwidth weight.
///
/// # Weight Calculation
///
/// The weight for each relay is calculated as:
///
/// ```text
/// weight = measured_bandwidth × flag_weight_multiplier
/// ```
///
/// Where `flag_weight_multiplier` depends on the relay's flags and position:
///
/// | Flags | Middle Position | Guard Position | Exit Position |
/// |-------|-----------------|----------------|---------------|
/// | Neither Guard nor Exit | Wmm | Wgm | Wem |
/// | Guard only | Wmg | Wgg | Weg |
/// | Exit only | Wme | Wge | Wee |
/// | Guard + Exit | Wmd | Wgd | Wed |
///
/// # Selection Algorithm
///
/// 1. Filter routers through all restrictions
/// 2. Calculate weighted bandwidth for each remaining router
/// 3. Build cumulative weight distribution
/// 4. Generate random value in [0, total_weight)
/// 5. Select router where cumulative weight exceeds random value
///
/// # Example
///
/// ```rust,ignore
/// use vanguards_rs::node_selection::{BwWeightedGenerator, FlagsRestriction, NodeRestrictionList, Position};
///
/// let restriction = FlagsRestriction::new(
///     vec!["Fast".to_string(), "Stable".to_string(), "Valid".to_string()],
///     vec!["Authority".to_string()],
/// );
/// let restrictions = NodeRestrictionList::new(vec![Box::new(restriction)]);
///
/// let generator = BwWeightedGenerator::new(routers, restrictions, weights, Position::Middle)?;
/// let selected = generator.generate()?;
/// println!("Selected relay: {}", selected.fingerprint);
/// ```
///
/// # See Also
///
/// - [`Position`] - Circuit position affecting weight calculation
/// - [`NodeRestrictionList`] - Filtering criteria
/// - [`crate::error::Error::NoNodesRemain`] - Error when no nodes pass filters
pub struct BwWeightedGenerator {
    rstr_routers: Vec<RouterStatusEntry>,
    node_weights: Vec<f64>,
    weight_total: f64,
    exit_total: f64,
    position: Position,
    bw_weights: HashMap<String, i64>,
}

impl BwWeightedGenerator {
    /// Weight scale factor from consensus (typically 10000).
    const WEIGHT_SCALE: f64 = 10000.0;

    /// Creates a new bandwidth-weighted generator.
    ///
    /// # Arguments
    ///
    /// * `sorted_routers` - Routers sorted by measured bandwidth (descending)
    /// * `restrictions` - Restrictions to filter routers
    /// * `bw_weights` - Consensus bandwidth weights (Wmm, Wmg, Wme, Wmd, etc.)
    /// * `position` - Circuit position for weight calculation
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoNodesRemain`] if all routers are filtered out.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let generator = BwWeightedGenerator::new(routers, restrictions, weights, Position::Middle)?;
    /// ```
    pub fn new(
        sorted_routers: Vec<RouterStatusEntry>,
        restrictions: NodeRestrictionList,
        bw_weights: HashMap<String, i64>,
        position: Position,
    ) -> Result<Self> {
        let rstr_routers: Vec<RouterStatusEntry> = sorted_routers
            .into_iter()
            .filter(|r| restrictions.r_is_ok(r))
            .collect();

        if rstr_routers.is_empty() {
            return Err(Error::NoNodesRemain);
        }

        let mut generator = Self {
            rstr_routers,
            node_weights: Vec::new(),
            weight_total: 0.0,
            exit_total: 0.0,
            position,
            bw_weights,
        };

        generator.rebuild_weights();
        Ok(generator)
    }

    /// Rebuilds the weight arrays after router list changes.
    fn rebuild_weights(&mut self) {
        self.node_weights.clear();
        self.weight_total = 0.0;

        for router in &self.rstr_routers {
            let bw = router.measured.or(router.bandwidth).unwrap_or(0) as f64;
            let weight = bw * self.flag_to_weight(router);
            self.node_weights.push(weight);
            self.weight_total += weight;
        }
    }

    /// Calculates the weight multiplier based on router flags and position.
    ///
    /// Uses consensus bandwidth weights:
    /// - Wmm: Middle-only relay (no Guard, no Exit)
    /// - Wmg: Guard relay (no Exit)
    /// - Wme: Exit relay (no Guard)
    /// - Wmd: Guard+Exit relay
    fn flag_to_weight(&self, router: &RouterStatusEntry) -> f64 {
        let has_guard = router.flags.contains(&"Guard".to_string());
        let has_exit = router.flags.contains(&"Exit".to_string());
        let pos = self.position.weight_key_suffix();

        let key = if has_guard && has_exit {
            format!("W{}d", pos)
        } else if has_exit {
            format!("W{}e", pos)
        } else if has_guard {
            format!("W{}g", pos)
        } else {
            "Wmm".to_string()
        };

        self.bw_weights.get(&key).copied().unwrap_or(10000) as f64 / Self::WEIGHT_SCALE
    }

    /// Repairs exit node weights for rendezvous point selection.
    ///
    /// Exit nodes got their weights set based on middle position, but they can
    /// still be used as rendezvous points in cannibalized circuits. This method
    /// recalculates their weights using exit position weights and tracks a
    /// separate `exit_total`.
    ///
    /// Note: We deliberately don't re-normalize `weight_total` since we don't
    /// want to lower the upper bound of other nodes. But we do want a separate
    /// `exit_total` for use with Exit nodes.
    pub fn repair_exits(&mut self) {
        let old_position = self.position;
        self.position = Position::Exit;
        self.exit_total = 0.0;

        for (i, router) in self.rstr_routers.iter().enumerate() {
            if router.flags.contains(&"Exit".to_string()) {
                let bw = router.measured.or(router.bandwidth).unwrap_or(0) as f64;
                let weight = bw * self.flag_to_weight(router);
                self.node_weights[i] = weight;
                self.exit_total += weight;
            }
        }

        self.position = old_position;
    }

    /// Generates a randomly selected router using bandwidth-weighted selection.
    ///
    /// Selection probability is proportional to each router's bandwidth weight.
    ///
    /// # Returns
    ///
    /// A reference to the selected router.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoNodesRemain`] if the router list is empty or total weight is zero.
    pub fn generate(&self) -> Result<&RouterStatusEntry> {
        if self.rstr_routers.is_empty() || self.weight_total <= 0.0 {
            return Err(Error::NoNodesRemain);
        }

        let mut rng = rand::thread_rng();
        let choice_val = rng.gen_range(0.0..self.weight_total);
        let mut cumulative = 0.0;

        for (i, weight) in self.node_weights.iter().enumerate() {
            cumulative += weight;
            if cumulative > choice_val {
                return Ok(&self.rstr_routers[i]);
            }
        }

        Ok(self.rstr_routers.last().unwrap())
    }

    /// Returns the total weight of all routers.
    pub fn weight_total(&self) -> f64 {
        self.weight_total
    }

    /// Returns the total weight of exit-flagged routers.
    pub fn exit_total(&self) -> f64 {
        self.exit_total
    }

    /// Returns the number of routers after restrictions.
    pub fn router_count(&self) -> usize {
        self.rstr_routers.len()
    }

    /// Returns a reference to the filtered routers.
    pub fn routers(&self) -> &[RouterStatusEntry] {
        &self.rstr_routers
    }

    /// Returns a reference to the node weights.
    pub fn node_weights(&self) -> &[f64] {
        &self.node_weights
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_fingerprints() {
        assert!(is_valid_fingerprint(
            "AABBCCDD00112233445566778899AABBCCDDEEFF"
        ));
        assert!(is_valid_fingerprint(
            "aabbccdd00112233445566778899aabbccddeeff"
        ));
        assert!(is_valid_fingerprint(
            "0123456789abcdefABCDEF0123456789abcdefAB"
        ));
    }

    #[test]
    fn test_invalid_fingerprints() {
        assert!(!is_valid_fingerprint(""));
        assert!(!is_valid_fingerprint("AABBCCDD"));
        assert!(!is_valid_fingerprint(
            "AABBCCDD00112233445566778899AABBCCDDEEFFGG"
        ));
        assert!(!is_valid_fingerprint(
            "GGHHIIJJ00112233445566778899AABBCCDDEEFF"
        ));
        assert!(!is_valid_fingerprint(
            "AABBCCDD00112233445566778899AABBCCDDEEF"
        ));
        assert!(!is_valid_fingerprint(
            "AABBCCDD00112233445566778899AABBCCDDEEFFF"
        ));
    }

    #[test]
    fn test_valid_ip_addresses() {
        assert!(is_valid_ip_or_network("192.168.1.1"));
        assert!(is_valid_ip_or_network("10.0.0.0"));
        assert!(is_valid_ip_or_network("255.255.255.255"));
        assert!(is_valid_ip_or_network("0.0.0.0"));
        assert!(is_valid_ip_or_network("::1"));
        assert!(is_valid_ip_or_network("2001:db8::1"));
        assert!(is_valid_ip_or_network("fe80::1"));
    }

    #[test]
    fn test_valid_networks() {
        assert!(is_valid_ip_or_network("192.168.1.0/24"));
        assert!(is_valid_ip_or_network("10.0.0.0/8"));
        assert!(is_valid_ip_or_network("0.0.0.0/0"));
        assert!(is_valid_ip_or_network("2001:db8::/32"));
        assert!(is_valid_ip_or_network("::/0"));
    }

    #[test]
    fn test_invalid_ip_or_network() {
        assert!(!is_valid_ip_or_network(""));
        assert!(!is_valid_ip_or_network("not-an-ip"));
        assert!(!is_valid_ip_or_network("192.168.1.256"));
        assert!(!is_valid_ip_or_network("192.168.1.1/33"));
        assert!(!is_valid_ip_or_network("192.168.1"));
        assert!(!is_valid_ip_or_network("example.com"));
    }

    #[test]
    fn test_valid_country_codes() {
        assert!(is_valid_country_code("US"));
        assert!(is_valid_country_code("us"));
        assert!(is_valid_country_code("DE"));
        assert!(is_valid_country_code("de"));
        assert!(is_valid_country_code("GB"));
        assert!(is_valid_country_code("JP"));
    }

    #[test]
    fn test_invalid_country_codes() {
        assert!(!is_valid_country_code(""));
        assert!(!is_valid_country_code("U"));
        assert!(!is_valid_country_code("USA"));
        assert!(!is_valid_country_code("U1"));
        assert!(!is_valid_country_code("12"));
        assert!(!is_valid_country_code("U-"));
    }

    #[test]
    fn test_flags_restriction() {
        use chrono::Utc;
        use stem_rs::descriptor::router_status::RouterStatusEntryType;

        let mut router = RouterStatusEntry::new(
            RouterStatusEntryType::V3,
            "test".to_string(),
            "A".repeat(40),
            Utc::now(),
            "192.0.2.1".parse().unwrap(),
            9001,
        );
        router.flags = vec![
            "Fast".to_string(),
            "Stable".to_string(),
            "Valid".to_string(),
        ];

        let restriction = FlagsRestriction::new(
            vec!["Fast".to_string(), "Stable".to_string()],
            vec!["Authority".to_string()],
        );

        assert!(restriction.r_is_ok(&router));

        router.flags.push("Authority".to_string());
        assert!(!restriction.r_is_ok(&router));

        router.flags = vec!["Fast".to_string()];
        assert!(!restriction.r_is_ok(&router));
    }

    #[test]
    fn test_node_restriction_list() {
        use chrono::Utc;
        use stem_rs::descriptor::router_status::RouterStatusEntryType;

        let mut router = RouterStatusEntry::new(
            RouterStatusEntryType::V3,
            "test".to_string(),
            "A".repeat(40),
            Utc::now(),
            "192.0.2.1".parse().unwrap(),
            9001,
        );
        router.flags = vec![
            "Fast".to_string(),
            "Stable".to_string(),
            "Valid".to_string(),
        ];

        let restriction1 = FlagsRestriction::new(vec!["Fast".to_string()], vec![]);
        let restriction2 = FlagsRestriction::new(vec!["Stable".to_string()], vec![]);

        let list = NodeRestrictionList::new(vec![Box::new(restriction1), Box::new(restriction2)]);

        assert!(list.r_is_ok(&router));

        router.flags = vec!["Fast".to_string()];
        assert!(!list.r_is_ok(&router));
    }
}
