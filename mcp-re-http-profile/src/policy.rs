// SPDX-License-Identifier: Apache-2.0
//! Verifier-local policy: the algorithm allowlist (#415 rev 2 §13.1) and the
//! bounded clock-skew tolerance on the freshness gate (#415 rev 2 §5.1).
//!
//! Both knobs are LOCAL to the verifier and never readable from the message:
//! protected content can state which algorithm was used, but only this policy
//! decides which algorithms are acceptable, and only this policy decides how
//! much clock disagreement is tolerated. A message can never widen either —
//! that is the whole point of putting them here rather than on the wire.
//!
//! Algorithm agility (§13.1): the local allowlist IS the agility mechanism. The
//! IANA HTTP Signature Algorithms registry has grown (ML-DSA and friends), but
//! a registry entry is not deployment consent. The default allowlist stays
//! `["ed25519"]` — exactly today's behavior — and adding an algorithm is a
//! deliberate local act, not a consequence of someone else's registration.
//!
//! Clock skew (§5.1): "clock-skew policy must be explicit and bounded". Skew is
//! a TOLERANCE for honest clock disagreement, not a policy escape: it is
//! symmetric, it is capped at [`VerifierPolicy::MAX_CLOCK_SKEW_BOUND`], and a
//! configuration exceeding that cap fails closed at construction rather than
//! silently widening the freshness window.

use crate::error::HttpProfileError;
use crate::ids::ALG_ED25519;

/// The default algorithm allowlist — the profile's only signature algorithm.
/// Unchanged behavior from the hardcoded constant this replaced.
pub const DEFAULT_ALGORITHMS: [&str; 1] = [ALG_ED25519];

/// Verifier-local acceptance policy for the signature parameter gate.
///
/// Construct with [`VerifierPolicy::default`] for the profile's standard tier,
/// or [`VerifierPolicy::new`] to state an explicit bound. The fields are private
/// so a policy can never be mutated past its validated bound after construction.
#[derive(Debug, Clone)]
pub struct VerifierPolicy<'a> {
    algorithms: &'a [&'a str],
    max_clock_skew: i64,
}

impl<'a> VerifierPolicy<'a> {
    /// The default tolerance, matching the delegation-credential path
    /// (`DelegationVerifyParams.max_clock_skew`) so one deployment does not run
    /// two different notions of "close enough" on the same message.
    pub const DEFAULT_MAX_CLOCK_SKEW: i64 = 30;

    /// The hard cap on configurable skew (§5.1 "bounded"). Five minutes is the
    /// widest disagreement a deployment can declare and still call itself
    /// conforming; beyond this the freshness gate stops being a freshness gate.
    /// The strict-production tier states its own bound at or below this.
    pub const MAX_CLOCK_SKEW_BOUND: i64 = 300;

    /// Build a policy, failing closed on an out-of-bounds configuration: a
    /// negative skew (nonsensical — it would NARROW the window asymmetrically),
    /// a skew above [`Self::MAX_CLOCK_SKEW_BOUND`], or an empty allowlist (which
    /// would reject every message and read as a misconfiguration, not a policy).
    pub fn new(algorithms: &'a [&'a str], max_clock_skew: i64) -> Result<Self, HttpProfileError> {
        if algorithms.is_empty() {
            return Err(HttpProfileError::MalformedEvidence("empty algorithm allowlist"));
        }
        if !(0..=Self::MAX_CLOCK_SKEW_BOUND).contains(&max_clock_skew) {
            return Err(HttpProfileError::MalformedEvidence("clock skew out of bounds"));
        }
        Ok(VerifierPolicy {
            algorithms,
            max_clock_skew,
        })
    }

    /// Whether `alg` is allowlisted. A message that names an algorithm outside
    /// this set is rejected `unsupported_version` — identical to the hardcoded
    /// behavior this replaced.
    pub fn allows_algorithm(&self, alg: &str) -> bool {
        self.algorithms.contains(&alg)
    }

    /// The validated skew tolerance, in seconds.
    pub fn max_clock_skew(&self) -> i64 {
        self.max_clock_skew
    }
}

impl Default for VerifierPolicy<'static> {
    /// The profile's standard tier: Ed25519 only, the default bounded skew.
    fn default() -> Self {
        VerifierPolicy {
            algorithms: &DEFAULT_ALGORITHMS,
            max_clock_skew: Self::DEFAULT_MAX_CLOCK_SKEW,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ed25519_only_with_bounded_skew() {
        let p = VerifierPolicy::default();
        assert!(p.allows_algorithm("ed25519"));
        assert!(!p.allows_algorithm("Ed25519"), "the profile token is lowercase");
        assert!(!p.allows_algorithm("ml-dsa-65"), "registered is not allowlisted");
        assert_eq!(p.max_clock_skew(), VerifierPolicy::DEFAULT_MAX_CLOCK_SKEW);
    }

    #[test]
    fn out_of_bounds_configuration_fails_closed() {
        assert!(VerifierPolicy::new(&["ed25519"], -1).is_err());
        assert!(
            VerifierPolicy::new(&["ed25519"], VerifierPolicy::MAX_CLOCK_SKEW_BOUND + 1).is_err(),
            "skew above the cap is a configuration error, not a wider window"
        );
        assert!(VerifierPolicy::new(&[], 30).is_err(), "empty allowlist");
        assert!(VerifierPolicy::new(&["ed25519"], VerifierPolicy::MAX_CLOCK_SKEW_BOUND).is_ok());
        assert!(VerifierPolicy::new(&["ed25519"], 0).is_ok(), "exact-time tier");
    }

    #[test]
    fn allowlist_is_the_agility_mechanism() {
        let p = VerifierPolicy::new(&["ed25519", "ml-dsa-65"], 30).expect("valid");
        assert!(p.allows_algorithm("ml-dsa-65"));
        assert!(!p.allows_algorithm("rsa-pss-sha512"));
    }
}
