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
use mcp_re_http_profile::VerifiedMcpRequest;

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

mod core_projection;

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
    verified: &VerifiedMcpRequest,
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
    verified: &VerifiedMcpRequest,
    tier: &AsyncReplayTier,
    continuation_ctx: Option<RetainedContinuation<'_>>,
    config: &ProxyDispatchConfig,
    now_unix: i64,
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
            return Err(ProxyDispatchError::Dispatch(
                DispatchError::NonSharedReplayTier,
            ));
        }
    }

    // 2–3. Native key construction + continuation binding (shared, non-side-effecting).
    //      The borrowed `continuation_ctx` is consumed here, BEFORE the await.
    let (replay_key, continuation_verified) =
        prepare_http_dispatch(verified, continuation_ctx).map_err(ProxyDispatchError::Dispatch)?;

    // 4. Awaited atomic admission LAST — the only side-effecting step. A store
    //    failure fails closed (`replay_cache_unavailable`), never an admit.
    let decision = tier
        .check_and_insert(&replay_key.to_core_replay_key(verified.expires()), now_unix)
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

#[cfg(test)]
mod tests {
    // This module is the file's test region: `scripts/module_size_gate.py` opens it at the
    // `#[cfg(test)]` above and stops counting production lines here.
    use super::*;
    use mcp_re_core::ReplayCacheError;
    use mcp_re_core::ReplayDurabilityClass;
    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::AudienceTuple;
    use mcp_re_http_profile::CryptographicFloorVerifiedRequest;
    use mcp_re_http_profile::HttpRequestEvidenceBlock;
    use mcp_re_http_profile::RequestEvidence;
    use mcp_re_http_profile::ResolvedActor;
    use mcp_re_http_profile::SignerSlot;
    use std::cell::Cell;

    /// A cache that records whether the dispatcher ever reached it.
    ///
    /// The tier gate's whole claim is that it refuses BEFORE the store is touched. A stub
    /// that merely returns a decision could not tell a refusal-before from a
    /// refusal-after; this one makes the side effect observable.
    struct WitnessCache {
        touched: Cell<bool>,
        class: ReplayDurabilityClass,
    }

    impl WitnessCache {
        /// Self-reports the volatile reference class, as the default `durability_class`
        /// does — so the core gate beneath the tier gate refuses it under fleet-strict.
        fn new() -> Self {
            WitnessCache {
                touched: Cell::new(false),
                class: ReplayDurabilityClass::SingleProcessReference,
            }
        }

        /// Self-reports the durable class, so only the DEPLOYMENT tier gate is under test.
        fn durable() -> Self {
            WitnessCache {
                touched: Cell::new(false),
                class: ReplayDurabilityClass::Durable,
            }
        }
    }

    impl ReplayCache for WitnessCache {
        fn check_and_insert(
            &self,
            _signer: &str,
            _audience: &str,
            _nonce: &str,
            _expires_at_unix: i64,
        ) -> Result<ReplayDecision, ReplayCacheError> {
            self.touched.set(true);
            Ok(ReplayDecision::Fresh)
        }

        fn durability_class(&self) -> ReplayDurabilityClass {
            self.class
        }
    }

    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: "aud".into(),
            target_uri: "https://example.test/mcp".into(),
            route: None,
        }
    }

    fn verified() -> VerifiedMcpRequest {
        VerifiedMcpRequest {
            floor: CryptographicFloorVerifiedRequest {
                profile_id: "p".into(),
                signature_label: "mcpre".into(),
                resolved_actor: ResolvedActor {
                    identity: ActorIdentity {
                        role: "client".into(),
                        trust_domain: "example.org".into(),
                        subject: "did:example:agent-1".into(),
                        keyid: "key-a".into(),
                    },
                    verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32])
                        .public_key(),
                    slot: SignerSlot::Request,
                },
                evidence: RequestEvidence::from_signature_base(b"base"),
                request_signature_base: b"base".to_vec(),
                content_digest: mcp_re_http_profile::content_digest_sha256(b"{}"),
                created: 1,
                expires: 2,
                nonce: "n".into(),
                key_id: "key-a".into(),
            },
            audience: audience(),
            audience_hash: audience().audience_hash(),
            request_block: HttpRequestEvidenceBlock {
                profile: "p".into(),
                audience: audience(),
                artifact_bindings: Vec::new(),
                continuation: None,
                admission: None,
                admission_assertion: None,
                authorization_decision: None,
            },
        }
    }

    /// A fleet-strict deployment that declared NO shared durability tier is refused
    /// WITHOUT the store being consulted.
    ///
    /// Refusing at all is the documented posture; refusing before any side effect is what
    /// makes it fail-closed rather than fail-after-admitting. Asserting only the error
    /// would leave a reordering that admits the nonce first indistinguishable from this.
    #[test]
    fn an_undeclared_tier_is_refused_before_the_store_is_touched() {
        let cache = WitnessCache::new();
        let err = dispatch_request_with_tier_gate(
            &verified(),
            &cache,
            None,
            &ProxyDispatchConfig {
                fleet_strict: true,
                tier: None,
            },
        )
        .expect_err("fleet-strict with no declared tier must refuse");

        assert_eq!(err, ProxyDispatchError::NoDeclaredReplayTier);
        assert!(
            !cache.touched.get(),
            "the store was consulted before refusal"
        );
    }

    /// A declared tier BELOW the strict-production minimum is refused, also without
    /// touching the store, and the refusal names the tier the operator declared.
    #[test]
    fn a_sub_minimum_tier_is_refused_before_the_store_is_touched() {
        for tier in [
            ReplayDurabilityTier::RedisAsyncBounded,
            ReplayDurabilityTier::SingleStoreFailClosed,
        ] {
            let cache = WitnessCache::new();
            let err = dispatch_request_with_tier_gate(
                &verified(),
                &cache,
                None,
                &ProxyDispatchConfig {
                    fleet_strict: true,
                    tier: Some(tier.clone()),
                },
            )
            .expect_err("a sub-minimum tier must refuse under fleet-strict");

            assert_eq!(err, ProxyDispatchError::SubMinimumReplayTier(tier));
            assert!(
                !cache.touched.get(),
                "the store was consulted before refusal"
            );
        }
    }

    /// The tier gate is only meaningful under fleet-strict: a non-fleet deployment with no
    /// declared tier passes it and reaches the dispatcher beneath.
    ///
    /// This is the negative control for the two above — without it they would also pass if
    /// the gate refused unconditionally, which would be a different bug.
    #[test]
    fn the_tier_gate_does_not_fire_outside_fleet_strict() {
        let cache = WitnessCache::new();
        let outcome = dispatch_request_with_tier_gate(
            &verified(),
            &cache,
            None,
            &ProxyDispatchConfig {
                fleet_strict: false,
                tier: None,
            },
        );

        assert!(
            !matches!(
                outcome,
                Err(ProxyDispatchError::NoDeclaredReplayTier)
                    | Err(ProxyDispatchError::SubMinimumReplayTier(_))
            ),
            "the deployment tier gate fired without fleet-strict"
        );
        assert!(
            cache.touched.get(),
            "the dispatcher beneath was not reached"
        );
    }

    /// A tier that MEETS the strict minimum passes the DEPLOYMENT gate and reaches the
    /// dispatcher, provided the wired store also self-reports a durable class.
    #[test]
    fn a_strict_minimum_tier_over_a_durable_store_reaches_the_dispatcher() {
        let cache = WitnessCache::durable();
        let _ = dispatch_request_with_tier_gate(
            &verified(),
            &cache,
            None,
            &ProxyDispatchConfig {
                fleet_strict: true,
                tier: Some(ReplayDurabilityTier::Linearizable),
            },
        );
        assert!(
            cache.touched.get(),
            "a strict-minimum tier over a durable store did not reach the dispatcher"
        );
    }

    /// The two gates are complementary, not redundant (#308 AT4): a deployment that
    /// DECLARES the strongest tier while wiring a single-process reference cache is still
    /// refused — by the core gate beneath, on the cache's own self-report.
    ///
    /// This is the case the module documentation calls defense in depth, and it is the one
    /// a declaration-only check would admit: the operator's declaration is strong and the
    /// object actually holding the nonces cannot prevent a cross-node replay.
    #[test]
    fn a_strong_declared_tier_does_not_excuse_a_single_process_store() {
        let cache = WitnessCache::new();
        let err = dispatch_request_with_tier_gate(
            &verified(),
            &cache,
            None,
            &ProxyDispatchConfig {
                fleet_strict: true,
                tier: Some(ReplayDurabilityTier::Linearizable),
            },
        )
        .expect_err("a single-process store must be refused beneath the tier gate");

        assert!(
            matches!(err, ProxyDispatchError::Dispatch(_)),
            "the refusal came from the tier gate, not the core gate beneath it"
        );
        assert!(
            !cache.touched.get(),
            "the store was consulted before refusal"
        );
    }
}
