//! MCPRE-104 (#308) — proxy replay-tier adapter around the HTTP-profile dispatcher.
//!
//! The pure profile dispatcher ([`mcp_re_http_profile::dispatch_request`]) knows
//! only the core [`ReplayCache::is_single_process_reference`] self-declaration — a
//! runtime property of the cache object. The richer DEPLOYMENT classification,
//! [`ReplayDurabilityTier::meets_strict_production_minimum`] (redis-wait-quorum /
//! linearizable acceptable; redis-async / single-store-fail-closed sub-minimum), is
//! deliberately a `mcp-re-proxy` concern (ADR-MCPS-020) and is NOT imported into
//! the pure profile crate.
//!
//! This adapter wires that tier gate AROUND the dispatcher on the proxy serving
//! path, layered ABOVE the dispatcher's own single-process refusal:
//!
//! ```text
//!   ┌ proxy tier gate (this module) ──── operator's DEPLOYMENT declaration ┐
//!   │   fleet-strict ⇒ ReplayDurabilityTier::meets_strict_production_minimum │
//!   │   ┌ dispatch_request (pure profile) ── cache's RUNTIME self-declaration │
//!   │   │   fleet-strict ⇒ !ReplayCache::is_single_process_reference()        │
//!   │   │   → replay-key build → continuation binding → atomic admit LAST     │
//!   │   └──────────────────────────────────────────────────────────────────┘ │
//!   └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The two gates are complementary, not redundant: the tier gate is what the
//! operator DECLARES the shared store to be; the core gate is what the wired cache
//! self-reports at runtime. A deployment that declares `redis-wait-quorum` but
//! actually wires an in-memory single-process cache is still refused by the lower
//! gate — neither substitutes for the other (defense in depth, #308 AT4).
//!
//! The crate boundary is preserved: the [`ReplayDurabilityTier`] type stays here in
//! `mcp-re-proxy`; `mcp-re-http-profile` gains no dependency on the proxy.

use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use mcp_re_http_profile::dispatch_request;
use mcp_re_http_profile::prepare_http_dispatch;
use mcp_re_http_profile::DispatchConfig;
use mcp_re_http_profile::DispatchError;
use mcp_re_http_profile::DispatchOutcome;
use mcp_re_http_profile::RetainedContinuation;
use mcp_re_http_profile::VerifiedHttpRequestEvidence;

use crate::async_replay::AsyncReplayTier;
use crate::replay_tier::ReplayDurabilityTier;

/// Proxy-side dispatch policy: the profile fleet-strict posture PLUS the deployment
/// replay-durability tier the pure profile layer cannot see.
#[derive(Debug, Clone)]
pub struct ProxyDispatchConfig {
    /// Fleet-strict production posture. When set, BOTH the [`ReplayDurabilityTier`]
    /// strict-production gate (this module) AND the dispatcher's core
    /// single-process refusal apply.
    pub fleet_strict: bool,
    /// The declared durability tier of the shared replay store (ADR-MCPS-020).
    /// `None` means no shared tier was declared — refused under fleet-strict rather
    /// than admitted against an unclassified store.
    pub tier: Option<ReplayDurabilityTier>,
}

/// A fail-closed adapter outcome: the tier-gate refusals this layer adds, plus a
/// delegated dispatcher failure. Every variant maps to a frozen `mcp-re.*` wire
/// token (no parallel namespace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyDispatchError {
    /// Fleet-strict, but the declared tier is below the strict-production minimum
    /// (`REDIS_ASYNC` or `SINGLE_STORE_FAIL_CLOSED`). Fail closed on the same frozen
    /// token as an operational replay outage — the declared store cannot be relied
    /// upon here. → `mcp-re.replay_cache_unavailable`.
    SubMinimumReplayTier(ReplayDurabilityTier),
    /// Fleet-strict with NO declared shared durability tier — refuse rather than
    /// admit against an unclassified store. → `mcp-re.replay_cache_unavailable`.
    NoDeclaredReplayTier,
    /// The pure dispatcher refused beneath the tier gate (core single-process gate,
    /// replay detected, replay-cache unavailable, continuation binding, or profile
    /// evidence). Delegates its own `wire_code`.
    Dispatch(DispatchError),
}

impl ProxyDispatchError {
    /// The frozen `mcp-re.*` wire token this failure maps to.
    pub fn wire_code(&self) -> &'static str {
        match self {
            ProxyDispatchError::SubMinimumReplayTier(_)
            | ProxyDispatchError::NoDeclaredReplayTier => "mcp-re.replay_cache_unavailable",
            ProxyDispatchError::Dispatch(e) => e.wire_code(),
        }
    }
}

/// Drive a verified full-profile request through the replay-tier gate and then the
/// pure dispatcher.
///
/// Ordering (fail closed): the [`ReplayDurabilityTier`] strict-production gate FIRST
/// — refuse a sub-minimum or undeclared tier before touching the cache — then
/// [`dispatch_request`], which applies the core `is_single_process_reference` gate
/// beneath and performs the atomic replay admission LAST. `verified` MUST come from
/// [`mcp_re_http_profile::verify_request_full`]; `continuation_ctx` is `Some` iff
/// the caller holds a retained MRTR correlation for this request.
pub fn dispatch_request_with_tier_gate(
    verified: &VerifiedHttpRequestEvidence,
    replay: &dyn ReplayCache,
    continuation_ctx: Option<RetainedContinuation<'_>>,
    config: &ProxyDispatchConfig,
) -> Result<DispatchOutcome, ProxyDispatchError> {
    // 1. Deployment tier gate (proxy) — only meaningful under fleet-strict.
    if config.fleet_strict {
        match &config.tier {
            Some(tier) if tier.meets_strict_production_minimum() => {}
            Some(tier) => return Err(ProxyDispatchError::SubMinimumReplayTier(tier.clone())),
            None => return Err(ProxyDispatchError::NoDeclaredReplayTier),
        }
    }

    // 2. Pure dispatcher (core gate beneath + replay admission). fleet_strict is
    //    threaded through so the core single-process refusal still fires — defense
    //    in depth below the deployment tier gate.
    dispatch_request(
        verified,
        replay,
        continuation_ctx,
        &DispatchConfig {
            fleet_strict: config.fleet_strict,
        },
    )
    .map_err(ProxyDispatchError::Dispatch)
}

/// Drive a verified full-profile request through the replay-tier gate and then the
/// AUTHORITATIVE ASYNC replay tier (ADR-MCPRE-051 §4) — the production serving
/// path's admission. The async analogue of [`dispatch_request_with_tier_gate`]:
/// identical fail-closed ordering and identical key construction (both call
/// [`prepare_http_dispatch`]), differing ONLY in that the one side-effecting step
/// AWAITS the async tier's atomic insert-if-absent instead of a sync cache.
///
/// Ordering (fail closed): the deployment [`ReplayDurabilityTier`] strict gate and
/// the store's single-process-reference refusal FIRST (both refuse before any
/// side effect), then the non-side-effecting key construction + continuation
/// binding, then the awaited atomic admission LAST. `verified` MUST come from
/// [`mcp_re_http_profile::verify_request_full`].
pub async fn dispatch_request_with_async_tier(
    verified: &VerifiedHttpRequestEvidence,
    tier: &AsyncReplayTier,
    continuation_ctx: Option<RetainedContinuation<'_>>,
    config: &ProxyDispatchConfig,
) -> Result<DispatchOutcome, ProxyDispatchError> {
    // 1a. Deployment tier gate (proxy) — only meaningful under fleet-strict.
    if config.fleet_strict {
        match &config.tier {
            Some(tier) if tier.meets_strict_production_minimum() => {}
            Some(tier) => return Err(ProxyDispatchError::SubMinimumReplayTier(tier.clone())),
            None => return Err(ProxyDispatchError::NoDeclaredReplayTier),
        }
        // 1b. Defense in depth: the DECLARED tier may be strong, but if the wired
        //     async store self-reports the single-process reference class it cannot
        //     prevent cross-node replays — refuse on the same frozen token, exactly
        //     as the sync core gate does beneath `dispatch_request`.
        if tier.durability_class() == ReplayDurabilityClass::SingleProcessReference {
            return Err(ProxyDispatchError::Dispatch(DispatchError::NonSharedReplayTier));
        }
    }

    // 2–3. Native key construction + continuation binding (shared, non-side-effecting).
    //      The borrowed `continuation_ctx` is consumed here, BEFORE the await.
    let (replay_key, continuation_verified) =
        prepare_http_dispatch(verified, continuation_ctx).map_err(ProxyDispatchError::Dispatch)?;

    // 4. Awaited atomic admission LAST — the only side-effecting step. A store
    //    failure fails closed (`replay_cache_unavailable`), never an admit.
    let decision = tier
        .check_and_insert(&replay_key.to_core_replay_key(verified.expires))
        .await
        .map_err(|_| ProxyDispatchError::Dispatch(DispatchError::ReplayCacheUnavailable))?;
    match decision {
        ReplayDecision::Fresh => {}
        ReplayDecision::Replay => {
            return Err(ProxyDispatchError::Dispatch(DispatchError::ReplayDetected))
        }
    }

    Ok(DispatchOutcome {
        replay_key,
        continuation_verified,
    })
}
