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
//! replay cache as a `&mut dyn ReplayCache`. The richer runtime tier
//! classification (`ReplayDurabilityTier` / `meets_strict_production_minimum`)
//! is a `mcp-re-proxy` deployment concern wired AROUND this seam as a follow-up,
//! never imported here. The only durability signal this layer honestly knows is
//! the core [`ReplayCache::is_single_process_reference`] self-declaration:
//! under [`DispatchConfig::fleet_strict`], a single-process reference cache is
//! refused fail-closed BEFORE any admission (an in-memory reference cache cannot
//! prevent cross-node replays; ADR-MCPS-020).
//!
//! ## Fail-closed ordering
//!
//! All non-side-effecting checks run before the one side-effecting step (the
//! replay `check_and_insert`), exactly as the native pipeline defers replay to
//! last (MCP_RE_SPEC §9 step 12): a request that fails the tier gate, carries a
//! spliced continuation, or lacks the evidence to build a replay key never burns
//! a legitimate nonce.

use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;

use crate::error::HttpProfileError;
use crate::replay::HttpReplayKey;
use crate::verify::VerifiedHttpRequestEvidence;

/// Dispatcher policy knobs.
#[derive(Debug, Clone, Copy, Default)]
pub struct DispatchConfig {
    /// Fleet-strict posture: refuse a replay cache that self-declares the
    /// single-process reference class ([`ReplayCache::is_single_process_reference`]).
    /// This is the ONLY durability signal available at the pure profile layer;
    /// the richer `ReplayDurabilityTier` gate stays in `mcp-re-proxy`.
    pub fleet_strict: bool,
}

/// The bytes the caller retained for a pending correlation, needed to verify an
/// MRTR continuation. The dispatcher never derives these — they are the exact
/// signature bases and opaque `requestState` the client committed to on the
/// prior legs; the caller holds them in its correlation store.
#[derive(Debug, Clone, Copy)]
pub struct RetainedContinuation<'a> {
    /// The RFC 9421 signature base of the client request that produced the
    /// `InputRequiredResult`.
    pub previous_request_base: &'a [u8],
    /// The RFC 9421 signature base of the verified `InputRequiredResult` response.
    pub input_required_response_base: &'a [u8],
    /// The opaque `requestState` bytes (never interpreted, only digest-bound).
    pub request_state: &'a [u8],
}

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
    pub fn wire_code(&self) -> &'static str {
        match self {
            DispatchError::ReplayDetected => "mcp-re.replay_detected",
            DispatchError::ReplayCacheUnavailable | DispatchError::NonSharedReplayTier => {
                "mcp-re.replay_cache_unavailable"
            }
            DispatchError::Profile(e) => e.wire_code(),
        }
    }
}

impl From<ReplayCacheError> for DispatchError {
    fn from(_: ReplayCacheError) -> DispatchError {
        // Every operational cache failure fails closed identically; the detail
        // string is a diagnostic, never a wire token.
        DispatchError::ReplayCacheUnavailable
    }
}

/// The successful product of a dispatch: the constructed replay key (for audit /
/// correlation) and whether an MRTR continuation was present and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchOutcome {
    /// The five-tuple admitted to the replay cache.
    pub replay_key: HttpReplayKey,
    /// `true` iff the request carried a continuation that verified against the
    /// retained bases; `false` for an ordinary first-leg request.
    pub continuation_verified: bool,
}

/// Drive replay and MRTR continuation for a verified full-profile request.
///
/// `verified` MUST come from [`verify_request_full`](crate::verify_request_full)
/// (the minimal proof path carries no `audience_hash` and cannot form a replay
/// key). `continuation_ctx` is `Some` iff the caller holds a pending correlation
/// for this request; it is required exactly when the request block carries a
/// continuation.
///
/// Ordering (fail closed): fleet-strict tier gate → replay-key construction →
/// continuation binding → replay `check_and_insert` LAST. The nonce is only ever
/// burned once every other check has passed.
pub fn dispatch_request(
    verified: &VerifiedHttpRequestEvidence,
    replay: &mut dyn ReplayCache,
    continuation_ctx: Option<RetainedContinuation<'_>>,
    config: &DispatchConfig,
) -> Result<DispatchOutcome, DispatchError> {
    // 1. Fleet-strict tier gate — refuse a non-shared cache before touching it.
    if config.fleet_strict && replay.is_single_process_reference() {
        return Err(DispatchError::NonSharedReplayTier);
    }

    // 2. Replay-key construction. The full profile carries audience_hash; its
    //    absence means minimal-path evidence reached the dispatcher — fail closed
    //    rather than form a degenerate key.
    let audience_hash = verified
        .audience_hash
        .clone()
        .ok_or(DispatchError::Profile(HttpProfileError::MissingEvidence(
            "audience_hash",
        )))?;
    let replay_key = HttpReplayKey {
        profile_id: verified.profile_id.clone(),
        signature_label: verified.signature_label.clone(),
        actor_id: verified.resolved_actor.actor_id(),
        audience_hash,
        nonce: verified.nonce.clone(),
    };

    // 3. MRTR continuation binding (if the block carries one).
    let continuation = verified
        .request_block
        .as_ref()
        .and_then(|b| b.continuation.as_ref());
    let continuation_verified = match (continuation, continuation_ctx) {
        (Some(c), Some(ctx)) => {
            c.verify(
                ctx.previous_request_base,
                ctx.input_required_response_base,
                ctx.request_state,
            )
            .map_err(DispatchError::Profile)?;
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
        // Ordinary first-leg request: no continuation to bind.
        (None, _) => false,
    };

    // 4. Replay admission LAST — the only side-effecting step.
    match replay_key.check_and_insert(replay, verified.expires)? {
        ReplayDecision::Fresh => {}
        ReplayDecision::Replay => return Err(DispatchError::ReplayDetected),
    }

    Ok(DispatchOutcome {
        replay_key,
        continuation_verified,
    })
}
