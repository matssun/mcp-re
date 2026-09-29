// SPDX-License-Identifier: Apache-2.0
//! The durability-posture decision the dispatch seam requires, and the witness it yields.
//!
//! ## What this owns
//!
//! One fact: **whether this deployment's replay store class was decided before any nonce
//! was spent.** [`DispatchConfig`] states the posture, [`DispatchConfig::admit_replay_tier`]
//! is the sole decision procedure, and [`ReplayTierAdmitted`] is what a decision produces.
//!
//! ## Why the witness is a type and not a comment
//!
//! `prepare_http_dispatch` builds the five-tuple replay key and binds any MRTR
//! continuation. Neither step is side-effecting, but both feed an admission that burns a
//! nonce against whatever store the deployment wired — so preparing a dispatch against a
//! store that self-reports [`ReplayDurabilityClass::SingleProcessReference`] under the
//! fleet-strict posture is exactly the state ADR-MCPS-020 refuses.
//!
//! The refusal existed before this module and it ran at every call site. What did not
//! exist was any reason it had to: `prepare_http_dispatch` was `pub` and took only the
//! verified request, so a third caller that skipped the check compiled, built a replay
//! key, and burned a nonce against a store that declares it cannot prevent a cross-node
//! replay. Two sites checking is call discipline; it quantifies over the sites that exist
//! and says nothing about the next one.
//!
//! So the check is the constructor. [`ReplayTierAdmitted`]'s representation is private to
//! this module — `dispatch.rs` is its PARENT and cannot name the field either — and
//! preparation is a method on it. There is no expression anywhere, in this crate or
//! outside it, that reaches `prepare_http_dispatch` without first having asked
//! [`DispatchConfig::admit_replay_tier`] and handled its refusal.
//!
//! ## Both arms are decisions
//!
//! A deployment that did not ask for the fleet-strict posture still decided something: it
//! decided the store class is not load-bearing here. That is why
//! [`DispatchConfig::admit_replay_tier`] returns a witness on both arms and why the
//! witness records WHICH arm produced it. A witness that could only mean "fleet-strict
//! cleared a durable store" would have to lie about every non-strict deployment, and a
//! value that lies about half its inhabitants is worth less than the comment it replaced.

use core::fmt;

use mcp_re_core::ReplayDurabilityClass;

use super::outcome::PreparedDispatch;
use super::DispatchError;
use super::RetainedContinuation;
use crate::verified_request::VerifiedMcpRequest;

/// Dispatcher policy knobs.
///
/// Deliberately NOT `Default`. `fleet_strict` is a security posture whose unstated value
/// would be the permissive one, so a caller that says nothing would get cross-node replay
/// exposure it never chose. Every construction states the field.
#[derive(Debug, Clone, Copy)]
pub struct DispatchConfig {
    /// Fleet-strict posture: refuse a replay cache that self-declares the
    /// single-process reference class ([`mcp_re_core::ReplayCache::is_single_process_reference`]).
    /// This is the ONLY durability signal available at the pure profile layer;
    /// the richer `ReplayDurabilityTier` gate stays in `mcp-re-proxy`.
    pub fleet_strict: bool,
}

/// Which arm of the posture decision produced a [`ReplayTierAdmitted`].
///
/// Visible only inside `crate::dispatch`: the witness's meaning is "a decision was taken",
/// and no consumer branches on which one. It is nameable in the sibling `outcome` module
/// because the dispatch products CARRY the arm — the fact was produced here and consumed
/// nowhere, which is what made it worth carrying — and nowhere else, so the arm cannot
/// become a public tag that callers switch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dispatch) enum PostureDecision {
    /// The deployment did not ask for fleet-strict, so the store's self-reported class is
    /// not load-bearing for it.
    StoreClassNotRequired,
    /// Fleet-strict, and the store's self-reported class cleared the gate.
    StoreClassAdmitted,
}

impl PostureDecision {
    /// What this arm means, as one sentence.
    ///
    /// The single source of the wording: `Display` on the witness and
    /// `DispatchOutcome::admitting_posture` are the same words, so an audit line and a
    /// diagnostic cannot describe one decision two ways.
    pub(in crate::dispatch) fn description(self) -> &'static str {
        match self {
            PostureDecision::StoreClassNotRequired => {
                "replay store class not required (posture is not fleet-strict)"
            }
            PostureDecision::StoreClassAdmitted => "replay store class admitted under fleet-strict",
        }
    }
}

/// Evidence that the replay store's durability class was decided under a stated posture.
///
/// Possessing one means [`DispatchConfig::admit_replay_tier`] ran and did not refuse. It
/// is the only key to [`ReplayTierAdmitted::prepare`], and the only producer
/// is that gate: the field is private to this module, there is no public constructor, no
/// `Default`, and no `Clone` — a decision is taken per dispatch, not stashed and reused.
#[derive(Debug)]
pub struct ReplayTierAdmitted {
    decision: PostureDecision,
}

/// What this witness means, in the words of the arm that produced it.
///
/// Hand-written rather than derived because the two arms mean materially different things
/// and an audit line that flattened them would overstate the non-strict one. The wording
/// is [`PostureDecision::description`]'s, shared with the dispatch product that carries
/// the arm forward, so the two surfaces cannot drift.
impl fmt::Display for ReplayTierAdmitted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.decision.description())
    }
}

impl DispatchConfig {
    /// Decide the replay store's durability posture — dispatch step 1, and the sole
    /// producer of [`ReplayTierAdmitted`].
    ///
    /// Takes the class the store SELF-REPORTS rather than the store, because both serving
    /// paths must reach the same rule and they hold different objects: the sync dispatcher
    /// holds a `&dyn mcp_re_core::ReplayCache`, the proxy's async data plane holds its own
    /// awaited tier. A class is what they have in common, and it is the whole input the
    /// rule reads.
    ///
    /// Pure — no store, no await, no side effect — so it refuses before anything has been
    /// spent, which is the ordering claim the seam makes.
    pub fn admit_replay_tier(
        &self,
        class: ReplayDurabilityClass,
    ) -> Result<ReplayTierAdmitted, DispatchError> {
        if !self.fleet_strict {
            return Ok(ReplayTierAdmitted {
                decision: PostureDecision::StoreClassNotRequired,
            });
        }
        if class == ReplayDurabilityClass::SingleProcessReference {
            return Err(DispatchError::NonSharedReplayTier);
        }
        Ok(ReplayTierAdmitted {
            decision: PostureDecision::StoreClassAdmitted,
        })
    }
}

impl ReplayTierAdmitted {
    /// Dispatch steps 2–3, reachable only by a holder of this witness.
    ///
    /// Delegates unchanged to `prepare_http_dispatch`, the proved unit
    /// (`http_profile.continuation_unbypassability`), which is private to the `dispatch`
    /// module so that this is the only way in from anywhere else. The proved function's
    /// own signature and specification are untouched; what happens here is that its
    /// `(key, bool)` tuple — which any caller could also have written by hand — is sealed
    /// into a [`PreparedDispatch`], the only value that means a preparation HAPPENED.
    ///
    /// Consumes the witness: one posture decision admits one preparation, and the arm that
    /// decided travels into the product rather than being discarded here.
    pub fn prepare(
        self,
        verified: &VerifiedMcpRequest,
        continuation_ctx: Option<RetainedContinuation<'_>>,
    ) -> Result<PreparedDispatch, DispatchError> {
        let (replay_key, continuation_verified) =
            super::prepare_http_dispatch(verified, continuation_ctx)?;
        Ok(PreparedDispatch::from_admitted(
            self,
            replay_key,
            continuation_verified,
        ))
    }

    /// The arm that produced this witness.
    ///
    /// `pub(in crate::dispatch)`: its one legitimate consumer is the product constructor
    /// next door, which records the posture a dispatch was admitted under. Nothing wider,
    /// because a caller that could read the arm could branch on it, and the two arms are
    /// both admissions.
    pub(in crate::dispatch) fn posture(&self) -> PostureDecision {
        self.decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict() -> DispatchConfig {
        DispatchConfig { fleet_strict: true }
    }

    fn permissive() -> DispatchConfig {
        DispatchConfig {
            fleet_strict: false,
        }
    }

    #[test]
    fn fleet_strict_refuses_a_single_process_reference_store_class() {
        let refusal = strict()
            .admit_replay_tier(ReplayDurabilityClass::SingleProcessReference)
            .expect_err("a store that cannot prevent cross-node replay is not admissible");
        assert_eq!(refusal, DispatchError::NonSharedReplayTier);
    }

    #[test]
    fn fleet_strict_admits_a_durable_store_class() {
        // The positive control. Without it the refusal above is satisfied by a gate that
        // refuses everything, which would establish nothing about admitted deployments.
        let admitted = strict()
            .admit_replay_tier(ReplayDurabilityClass::Durable)
            .expect("a durable store clears the only signal this layer reads");
        assert_eq!(admitted.decision, PostureDecision::StoreClassAdmitted);
    }

    #[test]
    fn outside_fleet_strict_the_reference_class_is_a_decision_and_not_an_absence() {
        // The arm a witness would have to lie about if it could only mean "strict
        // cleared a durable store": a non-strict deployment on the reference cache is
        // admitted, and the witness says WHY it was admitted.
        let admitted = permissive()
            .admit_replay_tier(ReplayDurabilityClass::SingleProcessReference)
            .expect("the store class is not load-bearing outside fleet-strict");
        assert_eq!(admitted.decision, PostureDecision::StoreClassNotRequired);
    }

    #[test]
    fn the_two_admitting_arms_are_distinguishable() {
        let not_required = permissive()
            .admit_replay_tier(ReplayDurabilityClass::Durable)
            .expect("admits");
        let strict_cleared = strict()
            .admit_replay_tier(ReplayDurabilityClass::Durable)
            .expect("admits");
        assert_ne!(not_required.decision, strict_cleared.decision);
        // And it says so. A witness that rendered both arms identically would let an
        // audit line claim a strict clearance for a deployment that never asked for one.
        assert_ne!(not_required.to_string(), strict_cleared.to_string());
        assert!(not_required.to_string().contains("not required"));
        assert!(strict_cleared.to_string().contains("fleet-strict"));
    }
}
