// SPDX-License-Identifier: Apache-2.0
//! HTTP-profile dispatcher seam (ADR-MCPRE-050, MCPRE-102).
//!
//! Given a *verified* request evidence context (MCPRE-100/101), enforce the two
//! remaining profile security rules that the per-message verifier deliberately
//! leaves as inert primitives:
//!
//!  1. **replay** — build the five-tuple [`HttpReplayKey`] (MCPRE-94) from the
//!     verified evidence and check-and-insert it against a caller-injected
//!     [`ReplayCache`] tier;
//!  2. **MRTR continuation** — when the request block carries an
//!     [`HttpContinuation`], verify its three standards-derived handles
//!     (previous-request base, input-required-response base, opaque
//!     `requestState`; MCPRE-97) against the bytes the caller retained for this
//!     correlation, connecting `mcp-mrt` into the dispatch path.
//!
//! ## Layering — profile semantics, not deployment machinery
//!
//! This is PROFILE-level wiring: it depends only on `mcp-re-core` and takes the
//! replay cache as a `&dyn ReplayCache`. The richer runtime tier
//! classification (`ReplayDurabilityTier` / `meets_strict_production_minimum`)
//! is a `mcp-re-proxy` deployment concern wired AROUND this seam as a follow-up,
//! never imported here. The only durability signal this layer honestly knows is
//! the core [`ReplayCache::durability_class`] self-declaration: under
//! [`DispatchConfig::fleet_strict`], a single-process reference cache is refused
//! fail-closed BEFORE any admission (an in-memory reference cache cannot prevent
//! cross-node replays; ADR-MCPS-020). That decision is owned by
//! [`DispatchConfig::admit_replay_tier`], whose product is the only way in to
//! the steps below.
//!
//! ## Fail-closed ordering
//!
//! All non-side-effecting checks run before the one side-effecting step (the
//! replay `check_and_insert`), exactly as the native pipeline defers replay to
//! last (MCP_RE_SPEC §9 step 12): a request that fails the tier gate, carries a
//! spliced continuation, or lacks the evidence to build a replay key never burns
//! a legitimate nonce.

use mcp_re_core::McpReError;
use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;

use crate::error::HttpProfileError;
use crate::replay::HttpReplayKey;
use crate::verified_request::VerifiedMcpRequest;
#[cfg(feature = "verify")]
use verus_builtin_macros::verus_spec;
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

mod outcome;
mod replay_posture;
mod retained_continuation;

pub use outcome::DispatchOutcome;
pub use outcome::PreparedDispatch;
pub use replay_posture::DispatchConfig;
pub use replay_posture::ReplayTierAdmitted;
pub use retained_continuation::RetainedContinuation;

/// A fail-closed dispatcher outcome. Wraps the profile per-message failures plus
/// the replay/tier verdicts this seam adds; every variant maps to a frozen
/// `mcp-re.*` wire token (no parallel namespace — v0.11 grill E-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// The five-tuple was already admitted: a replay. → `mcp-re.replay_detected`.
    ReplayDetected,
    /// The replay cache could not answer (operational failure). Fail closed,
    /// never an admit. → `mcp-re.replay_cache_unavailable`.
    ReplayCacheUnavailable,
    /// Fleet-strict refused the injected replay cache because it self-declares
    /// the single-process reference class — unusable where cross-node replay
    /// protection is required. Fail closed on the same frozen token as an
    /// operational outage: the replay cache offered cannot be relied upon here.
    /// → `mcp-re.replay_cache_unavailable`.
    NonSharedReplayTier,
    /// A per-message profile failure surfaced during dispatch (continuation
    /// binding, or evidence too incomplete to build a replay key). Carries the
    /// underlying [`HttpProfileError`] and delegates its `wire_code`.
    Profile(HttpProfileError),
}

impl DispatchError {
    /// The frozen `mcp-re.*` wire token this failure maps to.
    ///
    /// Derived from [`crate::error::core_projection`], which owns this crate's whole
    /// statement of what its failures mean in Core's terms. Never chosen here.
    pub fn wire_code(&self) -> &'static str {
        McpReError::from(self).wire_code()
    }
}

impl From<ReplayCacheError> for DispatchError {
    fn from(_: ReplayCacheError) -> DispatchError {
        // Every operational cache failure fails closed identically; the detail
        // string is a diagnostic, never a wire token.
        DispatchError::ReplayCacheUnavailable
    }
}

/// Drive replay and MRTR continuation for a verified full-profile request.
///
/// `verified` MUST come from [`verify_request_full`](crate::verify_request_full)
/// (the minimal proof path carries no `audience_hash` and cannot form a replay
/// key). `continuation_ctx` is `Some` iff the caller holds a pending correlation
/// for this request, and that `iff` is enforced: it is required when the request
/// block carries a continuation, and refused when it does not.
///
/// Ordering (fail closed): fleet-strict tier gate → replay-key construction →
/// continuation binding → replay `check_and_insert` LAST. The nonce is only ever
/// burned once every other check has passed.
pub fn dispatch_request(
    verified: &VerifiedMcpRequest,
    replay: &dyn ReplayCache,
    continuation_ctx: Option<RetainedContinuation<'_>>,
    config: &DispatchConfig,
) -> Result<DispatchOutcome, DispatchError> {
    // 1. Fleet-strict tier gate — refuse a non-shared cache before touching it. Its
    //    product is the only key to steps 2–3, so deleting this line does not reorder the
    //    ladder, it stops the function compiling.
    let admitted = config.admit_replay_tier(replay.durability_class())?;

    // 2–3. Replay-key construction + MRTR continuation binding (non-side-effecting).
    let prepared = admitted.prepare(verified, continuation_ctx)?;

    // 4. Replay admission LAST — the only side-effecting step. Freshness is read through
    //    the verified product's own projection, the way the async sibling reads it.
    match prepared
        .replay_key()
        .check_and_insert(replay, verified.expires())?
    {
        ReplayDecision::Fresh => {}
        ReplayDecision::Replay => return Err(DispatchError::ReplayDetected),
    }

    Ok(prepared.into_admitted_outcome())
}

/// Dispatch steps 2–3 — everything EXCEPT the one side-effecting replay admission
/// (step 4): build the five-tuple [`HttpReplayKey`] from the verified evidence and
/// verify any MRTR continuation against the caller-retained bases.
///
/// Split out so BOTH serving paths share this identical, security-critical key
/// construction + continuation binding and differ ONLY in which tier performs the
/// side-effecting admission: the sync [`dispatch_request`] admits against a
/// `&dyn ReplayCache`; the async data plane (ADR-MCPRE-051 §4) AWAITS its
/// authoritative async tier with
/// [`HttpReplayKey::to_replay_key`](crate::HttpReplayKey::to_replay_key).
///
/// Private to this module, and reached only through
/// [`ReplayTierAdmitted::prepare`]. The fleet-strict single-process refusal
/// (step 1) is [`DispatchConfig::admit_replay_tier`], whose product is that witness — so
/// no path to this function exists that has not decided the durability posture first.
///
/// Ordering is preserved: key construction, then continuation binding; the caller
/// performs admission strictly LAST, so a spliced or unbindable continuation never
/// burns a legitimate nonce.
// ADR-MCPRE-059 WP2 — continuation unbypassability. If a request carries a continuation
// and this function returns Ok, the continuation WAS verified against the caller-retained
// bases. The pair (continuation present, continuation_verified == false) is not a state
// any successful preparation can produce, which is the invariant ADR-MCPRE-056/057/058
// eliminate dynamically, stated here over every input rather than over the fixtures.
//
// The obligation is stated unconditionally. It used to be guarded by
// `request_block matches Some(block)`, which made it VACUOUS for any product whose block
// was absent — that is, for exactly the floor-verified requests this parameter type now
// excludes. An assurance ambiguity in the product had become a hole in the theorem.
// `request_block` is read as a field rather than through its accessor so the prover can
// relate the obligation to the value; both are in this crate.
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures
        out matches Ok((_key, continuation_verified)) ==>
            (verified.request_block.continuation is Some ==> continuation_verified),
))]
#[allow(clippy::redundant_closure)] // Verus `verify` lane needs the explicit closure form
fn prepare_http_dispatch(
    verified: &VerifiedMcpRequest,
    continuation_ctx: Option<RetainedContinuation<'_>>,
) -> Result<(HttpReplayKey, bool), DispatchError> {
    let replay_key = HttpReplayKey {
        profile_id: verified.floor.profile_id.clone(),
        signature_label: verified.floor.signature_label.clone(),
        actor_id: verified.floor.resolved_actor.actor_id(),
        audience_hash: verified.audience_hash.clone(),
        nonce: verified.floor.nonce.clone(),
    };

    // MRTR continuation binding (if the block carries one).
    // ADR-MCPRE-059 WP2: written as a match rather than `as_ref().and_then(..)` because
    // the pinned prover cannot relate a closure passed to `and_then` back to its receiver,
    // which is precisely the link the unbypassability theorem needs. The two forms are the
    // same expression — this is `and_then`'s own definition — and the choice is recorded as
    // mechanical proof-enablement, not as an architectural preference.
    let continuation = verified.request_block.continuation.as_ref();
    let continuation_verified = match (continuation, continuation_ctx) {
        (Some(c), Some(ctx)) => {
            c.verify(
                ctx.previous_request_evidence,
                ctx.input_required_response_evidence,
                ctx.request_state,
            )
            .map_err(|e| DispatchError::Profile(e))?;
            true
        }
        // A continuation to verify but no retained bases to verify against: we
        // cannot prove the binding, so fail closed as a continuation-binding
        // failure rather than admit an unverifiable splice.
        (Some(_), None) => {
            return Err(DispatchError::Profile(
                HttpProfileError::ContinuationBindingFailed,
            ))
        }
        // Retained bases offered for a request whose block claims NO continuation. The
        // caller believes it is resuming a correlation and the signed request does not,
        // and this seam is not the authority that can pick between them — so it refuses
        // rather than discard the bases and return an ordinary first-leg admission the
        // caller would read as a resumption. Free, like the refusal above: it precedes
        // the replay `check_and_insert`, so no nonce is burned, and it precedes the
        // caller's continuation consume and retention marker, both of which run after
        // admission.
        (None, Some(_)) => {
            return Err(DispatchError::Profile(
                HttpProfileError::ContinuationBindingFailed,
            ))
        }
        // Ordinary first-leg request: no continuation to bind, and none offered.
        (None, None) => false,
    };

    Ok((replay_key, continuation_verified))
}

// Everything below is test code. The `#[cfg(test)]` marker is the region
// `scripts/module_size_gate.py` reads, so it sits HERE, at the bottom of the file.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ActorIdentity;
    use crate::block::HttpContinuation;
    use crate::block::HttpRequestEvidenceBlock;
    use crate::block::ResolvedActor;
    use crate::block::SignerSlot;
    use crate::evidence::EvidenceRole;
    use crate::evidence::RequestEvidenceDigest;
    use crate::evidence::RequestRoleEvidence;
    use crate::AudienceTuple;
    use mcp_re_core::SigningKey;

    const PREV: &[u8] = b"previous-request-signature-base";
    const IRR: &[u8] = b"input-required-response-signature-base";
    const STATE: &[u8] = b"opaque-request-state";

    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: "verifier-1".into(),
            target_uri: "https://example.test/mcp".into(),
            route: None,
        }
    }

    /// A full-profile product, built directly: this file's own types are the unit under
    /// test, and routing through the verifier would measure the verifier instead.
    fn verified(continuation: Option<HttpContinuation>) -> VerifiedMcpRequest {
        let key = SigningKey::from_seed_bytes(&[9u8; 32]);
        VerifiedMcpRequest {
            floor: crate::verified_request::CryptographicFloorVerifiedRequest {
                profile_id: "mcp-re-http-v1".into(),
                signature_label: "mcp-re".into(),
                resolved_actor: ResolvedActor {
                    identity: ActorIdentity {
                        role: "client".into(),
                        trust_domain: "example.com".into(),
                        subject: "did:example:a".into(),
                        keyid: "client-key-1".into(),
                    },
                    verification_key: key.public_key(),
                    slot: SignerSlot::Request,
                },
                evidence: RequestRoleEvidence::from_signature_base(PREV),
                request_signature_base: PREV.to_vec(),
                content_digest: "sha-256=:AAAA:".into(),
                created: 1_000,
                expires: 2_000,
                nonce: "nonce-1".into(),
                key_id: "client-key-1".into(),
            },
            audience: audience(),
            audience_hash: audience().audience_hash(),
            request_block: HttpRequestEvidenceBlock {
                profile: "mcp-re-http-v1".into(),
                audience: audience(),
                artifact_bindings: Vec::new(),
                continuation,
                admission: None,
                admission_assertion: None,
                authorization_decision: None,
            },
        }
    }

    /// The two retained handles, minted under their own role labels as the open leg does.
    fn handles() -> (RequestEvidenceDigest, RequestEvidenceDigest) {
        (
            RequestEvidenceDigest::over_labeled(EvidenceRole::Request, PREV),
            RequestEvidenceDigest::over_labeled(EvidenceRole::Response, IRR),
        )
    }

    #[test]
    fn every_failure_this_seam_adds_maps_to_a_frozen_core_token() {
        // The taxonomy claim this file makes in its own doc comment: no parallel
        // namespace. Asserted over each variant rather than over one of them.
        assert_eq!(
            DispatchError::ReplayDetected.wire_code(),
            "mcp-re.replay_detected"
        );
        assert_eq!(
            DispatchError::ReplayCacheUnavailable.wire_code(),
            "mcp-re.replay_cache_unavailable"
        );
        assert_eq!(
            DispatchError::NonSharedReplayTier.wire_code(),
            "mcp-re.replay_cache_unavailable"
        );
        assert_eq!(
            DispatchError::Profile(HttpProfileError::ContinuationBindingFailed).wire_code(),
            "mcp-re.continuation_binding_failed"
        );
    }

    #[test]
    fn a_refused_store_and_an_unreachable_one_are_the_same_verdict_to_a_caller() {
        // Two different facts, one frozen token, deliberately: the replay cache offered
        // cannot be relied upon, and a caller can do nothing differently about which.
        assert_ne!(
            DispatchError::NonSharedReplayTier,
            DispatchError::ReplayCacheUnavailable
        );
        assert_eq!(
            DispatchError::NonSharedReplayTier.wire_code(),
            DispatchError::ReplayCacheUnavailable.wire_code()
        );
    }

    #[test]
    fn an_operational_store_failure_fails_closed_and_never_admits() {
        let refusal: DispatchError = mcp_re_core::ReplayCacheError::Unavailable {
            details: "connection refused".into(),
        }
        .into();
        assert_eq!(refusal, DispatchError::ReplayCacheUnavailable);
    }

    #[test]
    fn a_first_leg_request_prepares_with_no_continuation() {
        // The positive control for the two refusals below: an ordinary request with
        // nothing offered still prepares, and reports that it bound no continuation.
        let (_key, continuation_verified) =
            prepare_http_dispatch(&verified(None), None).expect("an ordinary first leg prepares");
        assert!(!continuation_verified);
    }

    #[test]
    fn an_answer_leg_prepares_against_the_retained_bases() {
        // The other positive control: the refusals are not satisfied by a seam that
        // refuses everything.
        let ev = verified(Some(HttpContinuation::build(PREV, IRR, STATE)));
        let (prev, irr) = handles();
        let retained = RetainedContinuation::from_correlation(&prev, &irr, STATE);
        let (_key, continuation_verified) =
            prepare_http_dispatch(&ev, Some(retained)).expect("a matching answer leg prepares");
        assert!(continuation_verified);
    }

    #[test]
    fn retained_bases_offered_for_a_request_that_claims_no_continuation_are_refused() {
        // The R12-288/289 repair. `(None, _) => false` discarded the bases and returned an
        // ordinary first-leg admission, so a caller that believed it was resuming a
        // correlation received no signal at all that it was not.
        let (prev, irr) = handles();
        let retained = RetainedContinuation::from_correlation(&prev, &irr, STATE);
        let refusal = prepare_http_dispatch(&verified(None), Some(retained))
            .expect_err("a correlation the request does not claim must not be discarded");
        assert_eq!(
            refusal,
            DispatchError::Profile(HttpProfileError::ContinuationBindingFailed)
        );
    }

    #[test]
    fn a_claimed_continuation_with_no_retained_bases_is_refused() {
        // The mirror image, and the older of the two: a binding that cannot be checked is
        // never admitted.
        let ev = verified(Some(HttpContinuation::build(PREV, IRR, STATE)));
        let refusal = prepare_http_dispatch(&ev, None)
            .expect_err("an unverifiable continuation must fail closed");
        assert_eq!(
            refusal,
            DispatchError::Profile(HttpProfileError::ContinuationBindingFailed)
        );
    }

    #[test]
    fn the_replay_key_is_built_from_the_verified_product_and_nothing_else() {
        // The five-tuple's components are the verified evidence's, not the wire's: the
        // label is the crate constant the verifier accepted under, and the actor is the
        // one trust resolution produced.
        let ev = verified(None);
        let (key, _) = prepare_http_dispatch(&ev, None).expect("prepares");
        assert_eq!(key.profile_id, ev.profile_id());
        assert_eq!(key.signature_label, crate::ids::REQUEST_LABEL);
        assert_eq!(key.actor_id, ev.resolved_actor().actor_id());
        assert_eq!(key.audience_hash, ev.audience_hash());
        assert_eq!(key.nonce, ev.nonce());
    }
}
