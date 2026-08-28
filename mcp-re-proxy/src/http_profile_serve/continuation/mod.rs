// SPDX-License-Identifier: Apache-2.0
//! The multi-round-trip continuation plane (ADR-MCPS-047, MRTR).
//!
//! One fact: **a human's approval is opened, read without being spent, spent exactly once,
//! and recorded so that any replica can answer it.** The operations that make that sentence
//! true were spread across the serving assembly's stages, with the store and its TTL held
//! as two fields beside fourteen unrelated ones.
//!
//! # The two legs, and why they are separate files
//!
//! | leg | what it does | refusal |
//! |---|---|---|
//! | [`answer_leg`] | reads a live approval, then SPENDS it | free until the consume; the consume is the spend |
//! | [`open_leg`] | CREATES an approval the next leg will answer | never free — the backend has already run |
//!
//! Those are opposite consequences, and the split is at that boundary rather than at one
//! module per operation. A refusal on the answer leg's read leaves the approval intact and
//! an ordinary retry works; a refusal on the open leg happens past the execution threshold
//! and no retry can undo what the backend did.
//!
//! # What this owner keeps from being collapsed
//!
//! * a store MISS and a store OUTAGE are different facts. A miss is a statement about the
//!   caller (never opened, expired, already answered); an outage is a statement about this
//!   deployment. Flattening them reports a forged continuation every time the shared tier
//!   blips, and hides a genuine splice attempt inside an outage.
//! * the read is a `peek`, never a `consume`, so a request that is about to be refused
//!   leaves a live approval intact.
//! * retirement has FOUR outcomes, because the store's `Err` is not its `Ok(false)`.
//!
//! What this owner does NOT do is decide the refusal for a retirement outcome. That
//! decision needs the exchange machine's cross-machine state, which no stage holds; the
//! assembly reads the [`Retirement`] and states it once, where the receipt is signed.

use std::sync::Arc;

use crate::continuation_store::AsyncContinuationStore;

/// Reading a live approval and spending it — the leg that ANSWERS an elicitation.
mod answer_leg;
/// Recording a new approval so any replica can answer it — the leg that OPENS one.
mod open_leg;

pub(in crate::http_profile_serve) use answer_leg::Retirement;

/// The deployment's continuation plane: the shared correlation tier, and the bounded
/// lifetime every entry it writes runs under.
///
/// Private representation with two constructors, so *this deployment runs no store* is a
/// state of the plane rather than a `None` the assembly carries beside a TTL that then
/// means nothing. Both legs are implemented on this type in their own modules, which reach
/// the two fields as children of this one — the store is never handed out.
pub(in crate::http_profile_serve) struct ContinuationPlane {
    /// The fleet-shared tier that carries a multi-round-trip continuation across a replica
    /// switch. `None` disables MRTR: an `InputRequiredResult` is still returned, but a
    /// later answer leg carrying a continuation fails closed (no retained bases). A fleet
    /// wires the Redis store; single-replica runs may wire the in-memory one.
    store: Option<Arc<dyn AsyncContinuationStore>>,
    /// Lifetime of a recorded continuation (seconds).
    ttl_secs: i64,
}

impl ContinuationPlane {
    /// The plane of a deployment that runs no correlation store.
    pub(in crate::http_profile_serve) fn disabled() -> Self {
        ContinuationPlane {
            store: None,
            ttl_secs: super::DEFAULT_CONTINUATION_TTL_SECS,
        }
    }

    /// The plane of a deployment that wired one, with the bounded entry TTL it chose.
    pub(in crate::http_profile_serve) fn wired(
        store: Arc<dyn AsyncContinuationStore>,
        ttl_secs: i64,
    ) -> Self {
        ContinuationPlane {
            store: Some(store),
            ttl_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_plane_still_carries_the_default_lifetime() {
        // The TTL is not conditional on there being a store. Holding it here rather than
        // beside an `Option` in the assembly is what stops a deployment from configuring a
        // lifetime for entries nothing will ever write.
        let plane = ContinuationPlane::disabled();
        assert!(plane.store.is_none());
        assert_eq!(plane.ttl_secs, super::super::DEFAULT_CONTINUATION_TTL_SECS);
    }
}
