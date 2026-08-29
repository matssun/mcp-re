// SPDX-License-Identifier: Apache-2.0
//! How current this deployment's belief about a request signer is — ADR-MCPRE-067 §7.
//!
//! The durable question is *how fast a key removed from the trust store stops resolving*.
//! ADR-MCPS-021 names three postures for it, and each is inhabited by different material:
//! only two need a re-read cadence, and only one can watch a networked invalidation signal.
//!
//! ```text
//! semantic role       how current a request-signer belief is
//!         ↓
//! typed selection     RequestSignerCurrencyRequest — the three ADR-MCPS-021 tiers
//!         ↓
//! per-tier material   the window T, the re-read cadence, the epoch source
//!         ↓
//! mechanism payload   TrustEpochSource
//! ```
//!
//! **What the union deleted.** The tier was a selector beside two siblings, and three
//! clauses existed to refuse combinations the shape allowed: relation X8 (an epoch source
//! under a tier that never consumes it), the epoch KEY under such a tier, and the two tiers
//! that require a cadence being given none. The cadence is a member of the tiers that need
//! one and the epoch source is a member of the only tier that reads one, so none of the
//! three has a configuration left to examine.
//!
//! **What survives is every clause about the VALUES.** A zero cadence still spins the
//! reloader, and a cadence wider than the window the tier claims still makes the claim
//! false — those are relations between numbers a tier legitimately carries.

use crate::deployment_request::TrustEpochStoreRequest;

/// Which ADR-MCPS-021 revocation posture this deployment asserts.
///
/// The variant IS the tier. `revocation_tier::RevocationTier` remains the published
/// vocabulary an operator types and an audit record quotes; this is the request shape it
/// parses into, and the configuration state projects the tier back out of its own
/// classification (ADR-MCPRE-067 §16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSignerCurrencyRequest {
    /// **Tier 1.** Cached active trust lives at most `T` seconds. The one tier whose
    /// re-read cadence is OPTIONAL: without one, `--trust` is read once at startup and the
    /// absence is itself a sub-posture.
    BoundedCache {
        /// The trust-propagation window `T`, in seconds.
        t_secs: i64,
        /// Seconds between re-reads of the trust store, where the operator asked for them.
        reload_secs: Option<u64>,
    },
    /// **Tier 2.** The store is consulted on every verification. A cadence is a member
    /// rather than a sibling: a live tier that never re-reads its store states a window it
    /// cannot deliver, so "live without a cadence" is not a request to refuse.
    Live {
        /// Seconds between re-reads of the trust store.
        reload_secs: u64,
    },
    /// **Tier 3.** Push invalidation with a bounded-`T` fallback.
    Push {
        /// The bounded-`T` fallback window, in seconds — and the ceiling an entry may live
        /// if the channel goes unhealthy and a push is missed.
        t_secs: i64,
        /// Seconds between re-reads of the trust store.
        reload_secs: u64,
        /// Where the monotonic epoch is watched. Absent is the INERT posture, whose honest
        /// guarantee is the bounded-`T` fallback and nothing more. Only this tier has the
        /// field, which is why relation X8 has nothing left to refuse.
        epoch: TrustEpochStoreRequest,
    },
}

impl Default for RequestSignerCurrencyRequest {
    /// Tier 1 at the deployment default window, reading `--trust` once — the posture an
    /// absent `--revocation-tier` has always meant.
    fn default() -> Self {
        RequestSignerCurrencyRequest::BoundedCache {
            t_secs: crate::trust_plane::DEFAULT_T_SECS,
            reload_secs: None,
        }
    }
}

impl RequestSignerCurrencyRequest {
    /// Seconds between re-reads, where this posture has a cadence at all.
    pub fn reload_secs(&self) -> Option<u64> {
        match self {
            RequestSignerCurrencyRequest::BoundedCache { reload_secs, .. } => *reload_secs,
            RequestSignerCurrencyRequest::Live { reload_secs }
            | RequestSignerCurrencyRequest::Push { reload_secs, .. } => Some(*reload_secs),
        }
    }

    /// The epoch source, where this posture can watch one.
    ///
    /// `None` under the two tiers that consume no invalidation signal is not a missing
    /// value: they have no field to carry one, which is what relation X8 used to say.
    pub fn epoch(&self) -> Option<&TrustEpochStoreRequest> {
        match self {
            RequestSignerCurrencyRequest::Push { epoch, .. } => Some(epoch),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the push tier has a field for an epoch source. Relation X8 refused one under
    /// the other two tiers; neither can carry one now.
    #[test]
    fn only_the_pushing_tier_can_name_an_epoch_source() {
        assert_eq!(RequestSignerCurrencyRequest::default().epoch(), None);
        assert_eq!(
            RequestSignerCurrencyRequest::Live { reload_secs: 30 }.epoch(),
            None
        );
        let push = RequestSignerCurrencyRequest::Push {
            t_secs: 30,
            reload_secs: 30,
            epoch: TrustEpochStoreRequest::default(),
        };
        assert!(push.epoch().is_some_and(|epoch| epoch.source.is_none()));
    }

    /// The cadence is optional under exactly one tier, and that absence is a sub-posture
    /// rather than a missing value. The other two carry it, so "requires a cadence" is not
    /// a clause any more.
    #[test]
    fn the_cadence_is_optional_under_exactly_one_tier() {
        assert_eq!(RequestSignerCurrencyRequest::default().reload_secs(), None);
        assert_eq!(
            RequestSignerCurrencyRequest::Live { reload_secs: 5 }.reload_secs(),
            Some(5)
        );
        assert_eq!(
            RequestSignerCurrencyRequest::Push {
                t_secs: 30,
                reload_secs: 7,
                epoch: TrustEpochStoreRequest::default(),
            }
            .reload_secs(),
            Some(7)
        );
    }
}
