// SPDX-License-Identifier: Apache-2.0
//! Verifier-local policy: the algorithm registry (#415 rev 2 §13.1) and the
//! bounded clock-skew tolerance on the freshness gate (#415 rev 2 §5.1).
//!
//! Both knobs are LOCAL to the verifier and never readable from the message:
//! protected content can state which algorithm was used, but only this policy
//! decides which algorithms are acceptable, and only this policy decides how
//! much clock disagreement is tolerated. A message can never widen either.
//!
//! Algorithm agility (§13.1): the local policy IS the agility mechanism. The
//! IANA HTTP Signature Algorithms registry has grown (ML-DSA and friends), but
//! a registry entry is not deployment consent. The default set stays Ed25519 —
//! exactly today's behavior — and adding an algorithm is a deliberate local act.
//!
//! **The registry is typed, not a list of strings.** This is a correction, and
//! the reason matters. An allowlist of strings cannot express the one thing that
//! makes it safe: "…and this crate has a verifier for that." When it could not,
//! a policy naming `ml-dsa-65` accepted a message DECLARING `ml-dsa-65` at the
//! parameter gate, and verification then ran Ed25519 anyway — so a genuine
//! Ed25519 signature over a base declaring ML-DSA verified. That is algorithm
//! confusion, produced by the agility interface itself. A [`ProfileAlgorithm`]
//! only exists for an algorithm with an implemented verifier, so a policy that
//! could cause the confusion cannot be constructed.
//!
//! Clock skew (§5.1): "clock-skew policy must be explicit and bounded". Skew is
//! a TOLERANCE for honest clock disagreement, not a policy escape: it is
//! symmetric, it is capped at [`VerifierPolicy::MAX_CLOCK_SKEW_BOUND`], and a
//! configuration exceeding that cap fails closed at construction rather than
//! silently widening the freshness window.

use crate::error::HttpProfileError;
use crate::ids::ALG_ED25519;

/// A signature algorithm this crate can actually VERIFY.
///
/// The type is the contract: a variant exists only where an implemented verifier
/// exists, so a policy cannot name an algorithm nothing checks. Adding a variant
/// is therefore a commitment — the dispatch in `verify` matches exhaustively over
/// this enum, so a new variant does not compile until its verifier is wired.
///
/// `#[non_exhaustive]` because growing this set is a profile change: downstream
/// matches must not silently keep compiling when an algorithm appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileAlgorithm {
    /// RFC 9421 `ed25519`, verified by `mcp_re_core::verify_ed25519_with`.
    Ed25519,
}

impl ProfileAlgorithm {
    /// Resolve a wire `alg` token to an algorithm with a verifier, or `None`.
    ///
    /// `None` means "this profile cannot check that", which is the only honest
    /// answer for a registered-but-unimplemented algorithm — and the reason this
    /// returns an Option rather than a bare string comparison.
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            ALG_ED25519 => Some(ProfileAlgorithm::Ed25519),
            _ => None,
        }
    }

    /// The RFC 9421 registry token.
    pub fn token(self) -> &'static str {
        match self {
            ProfileAlgorithm::Ed25519 => ALG_ED25519,
        }
    }
}

/// The default algorithm set — the profile's only implemented algorithm.
pub const DEFAULT_ALGORITHMS: [&str; 1] = [ALG_ED25519];

/// Verifier-local acceptance policy for the signature parameter gate.
///
/// Fields are private and validated at construction, so a policy can never be
/// mutated past its validated bound afterwards.
#[derive(Debug, Clone)]
pub struct VerifierPolicy {
    algorithms: Vec<ProfileAlgorithm>,
    max_clock_skew: i64,
    /// The MCP transport/version contract (§4.1). `None` = no transport policy,
    /// which is today's behavior: `Mcp-Method` divergence is still always checked
    /// (a covered header must not lie about the body), but required-header
    /// presence, supported-version policy, and `Mcp-Name` agreement are enforced
    /// only when a deployment opts in with [`VerifierPolicy::with_mcp_transport`].
    mcp_transport: Option<crate::mcp_transport::McpTransportPolicy>,
}

impl VerifierPolicy {
    /// The default tolerance, matching the delegation-credential path
    /// (`DelegationVerifyParams.max_clock_skew`) so one deployment does not run
    /// two different notions of "close enough" on the same message.
    pub const DEFAULT_MAX_CLOCK_SKEW: i64 = 30;

    /// The hard cap on configurable skew (§5.1 "bounded"). Five minutes is the
    /// widest disagreement a deployment can declare and still call itself
    /// conforming; beyond this the freshness gate stops being a freshness gate.
    pub const MAX_CLOCK_SKEW_BOUND: i64 = 300;

    /// Build a policy, failing closed on any configuration that would be unsafe
    /// or meaningless:
    ///
    /// - an algorithm token with **no implemented verifier** — the algorithm-
    ///   confusion guard. Allowlisting `ml-dsa-65` while only Ed25519 dispatch
    ///   exists would let an Ed25519 signature be accepted under an ML-DSA claim;
    /// - a negative skew (it would NARROW the window asymmetrically) or one above
    ///   [`Self::MAX_CLOCK_SKEW_BOUND`];
    /// - an empty algorithm set, which rejects every message and reads as a
    ///   misconfiguration rather than a policy.
    pub fn new(algorithms: &[&str], max_clock_skew: i64) -> Result<Self, HttpProfileError> {
        if algorithms.is_empty() {
            return Err(HttpProfileError::MalformedEvidence("empty algorithm set"));
        }
        let mut resolved = Vec::with_capacity(algorithms.len());
        for token in algorithms {
            // The guard: a token this crate cannot verify is refused at
            // CONSTRUCTION, not silently accepted and then checked with the wrong
            // verifier. A deployment learns its policy is unimplementable when it
            // writes the policy, not when an attacker exercises it.
            let alg = ProfileAlgorithm::from_token(token)
                .ok_or(HttpProfileError::UnsupportedAlgorithm)?;
            if !resolved.contains(&alg) {
                resolved.push(alg);
            }
        }
        if !(0..=Self::MAX_CLOCK_SKEW_BOUND).contains(&max_clock_skew) {
            return Err(HttpProfileError::MalformedEvidence("clock skew out of bounds"));
        }
        Ok(VerifierPolicy {
            algorithms: resolved,
            max_clock_skew,
            mcp_transport: None,
        })
    }

    /// Attach an MCP transport/version contract (§4.1), enforced after signature
    /// verification against covered headers and the protected body.
    pub fn with_mcp_transport(mut self, transport: crate::mcp_transport::McpTransportPolicy) -> Self {
        self.mcp_transport = Some(transport);
        self
    }

    /// The active MCP transport policy, if any.
    pub fn mcp_transport(&self) -> Option<&crate::mcp_transport::McpTransportPolicy> {
        self.mcp_transport.as_ref()
    }

    /// Resolve a wire `alg` token to an accepted algorithm, or `None`.
    ///
    /// Returns the TYPED algorithm rather than a boolean so the caller must
    /// dispatch on it: "is this allowed" and "what verifies it" are answered
    /// together, and there is no way to ask the first without carrying the
    /// second. That is what closes the confusion path structurally.
    pub fn accepted_algorithm(&self, token: &str) -> Option<ProfileAlgorithm> {
        let alg = ProfileAlgorithm::from_token(token)?;
        self.algorithms.contains(&alg).then_some(alg)
    }

    /// The validated skew tolerance, in seconds.
    pub fn max_clock_skew(&self) -> i64 {
        self.max_clock_skew
    }
}

impl Default for VerifierPolicy {
    /// The profile's standard tier: Ed25519 only, the default bounded skew.
    fn default() -> Self {
        VerifierPolicy {
            algorithms: vec![ProfileAlgorithm::Ed25519],
            max_clock_skew: Self::DEFAULT_MAX_CLOCK_SKEW,
            mcp_transport: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ed25519_only_with_bounded_skew() {
        let p = VerifierPolicy::default();
        assert_eq!(p.accepted_algorithm("ed25519"), Some(ProfileAlgorithm::Ed25519));
        assert_eq!(p.accepted_algorithm("Ed25519"), None, "the profile token is lowercase");
        assert_eq!(p.max_clock_skew(), VerifierPolicy::DEFAULT_MAX_CLOCK_SKEW);
    }

    /// THE algorithm-confusion guard. A registered algorithm with no verifier in
    /// this crate cannot enter a policy at all — because if it could, the gate
    /// would accept a message declaring it and Ed25519 would be what actually ran.
    #[test]
    fn an_algorithm_without_a_verifier_cannot_be_allowlisted() {
        for registered_but_unimplemented in ["ml-dsa-65", "rsa-pss-sha512", "ecdsa-p256-sha256"] {
            assert_eq!(
                VerifierPolicy::new(&["ed25519", registered_but_unimplemented], 30).unwrap_err(),
                HttpProfileError::UnsupportedAlgorithm,
                "{registered_but_unimplemented}: allowlisting it would enable algorithm confusion"
            );
        }
        // IANA registration is not deployment consent AND not an implementation.
        assert!(ProfileAlgorithm::from_token("ml-dsa-65").is_none());
    }

    #[test]
    fn out_of_bounds_configuration_fails_closed() {
        assert!(VerifierPolicy::new(&["ed25519"], -1).is_err());
        assert!(
            VerifierPolicy::new(&["ed25519"], VerifierPolicy::MAX_CLOCK_SKEW_BOUND + 1).is_err(),
            "skew above the cap is a configuration error, not a wider window"
        );
        assert!(VerifierPolicy::new(&[], 30).is_err(), "empty algorithm set");
        assert!(VerifierPolicy::new(&["ed25519"], VerifierPolicy::MAX_CLOCK_SKEW_BOUND).is_ok());
        assert!(VerifierPolicy::new(&["ed25519"], 0).is_ok(), "strict tier");
    }

    /// The agility seam is real but narrow: it maps a token to a VERIFIER, so the
    /// only thing a deployment can turn on today is the algorithm that exists.
    #[test]
    fn the_registry_maps_tokens_to_implemented_verifiers() {
        let p = VerifierPolicy::new(&["ed25519"], 30).expect("valid");
        assert_eq!(p.accepted_algorithm("ed25519").unwrap().token(), "ed25519");
        assert_eq!(p.accepted_algorithm("ml-dsa-65"), None);
        assert!(VerifierPolicy::new(&["ed25519", "ed25519"], 30).is_ok(), "duplicates collapse");
    }
}
