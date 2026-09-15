// SPDX-License-Identifier: Apache-2.0
//! The sealed handover value: the established replay tier and the dispatch posture it
//! implies (ADR-MCPRE-056 §6; #78 / ADR-MCPS-020).
//!
//! # Why this is its own module
//!
//! The durability guard runs inside the producer, which makes it part of BUILDING the
//! value rather than something a producer remembers to run. That argument holds only for
//! as long as the producer is the sole one — and the representation decides that, not the
//! call sites. With public fields, `MaterializedReplay { tier, dispatch }` was an ordinary
//! expression in every module of this crate, so the guard was reachable-around by the same
//! composition root it exists to constrain; `app.rs` destructured the value, which is the
//! shape [`R-COMPOSE`](../../../../CLAUDE.md) forbids.
//!
//! `pub(crate)` seals against nobody here: every consumer lives in `mcp-re-proxy`. Module
//! privacy is the lever that works at that distance, so the representation is private to
//! THIS file and [`backends`](super::backends) is a SIBLING rather than a descendant — a
//! child module would inherit the ability to name the private fields and the sole-producer
//! claim would die with it.
//!
//! # The witness is what survives a later widening
//!
//! The operational test in `CLAUDE.md` asks whether the check can be DELETED and still
//! leave an invalid value unconstructible. Field privacy alone answers "no": restore `pub`
//! on the fields and the illegal pairing is expressible again. So the checked path returns
//! a [`DurabilityWitness`] — a type this module does not export — and the struct holds one.
//! An outside struct literal then cannot be written whatever the fields' visibility says,
//! because the witness type is unnameable there, and a `pub` field of a private type is
//! itself a `private_interfaces` diagnostic under this workspace's `-D warnings` lanes.
//! Same idiom as `DelegatedCertResolver`'s correspondence witness
//! ([`docs/dev/sealed-owners.md`](../../../../docs/dev/sealed-owners.md)).

use crate::async_replay::AsyncReplayTier;
use crate::control_runtime::ControlRuntime;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::startup_plan::{PlannedStore, ReplayPlan};

use super::backends::{establish_etcd, establish_redis};

/// Proof that [`assert_durable`] accepted the tier the value was built around.
///
/// Private to this module and deliberately unexported: it is not a fact any consumer
/// reads, it is the thing an outside construction cannot supply.
struct DurabilityWitness;

/// The established replay tier and the dispatch posture it implies.
///
/// By value: the caller moves both into the proxy through [`Self::into_parts`]. Nothing
/// here is shared back, and nothing outside this module can assemble one.
pub struct MaterializedReplay {
    /// The authoritative tier the per-core request path awaits.
    tier: AsyncReplayTier,
    /// Fleet-strict dispatch and the declared durability tier, which the serving path
    /// reports. Set together with the tier so a deployment cannot advertise a durability
    /// claim the store it actually holds does not implement.
    dispatch: ProxyDispatchConfig,
    /// See [`DurabilityWitness`]. Never read: possession is the whole content.
    _durable: DurabilityWitness,
}

impl MaterializedReplay {
    /// Establish the planned tier — the ONLY producer of this value.
    ///
    /// Every refusal raised here is a statement about the BUILD or the ENVIRONMENT — a
    /// backend that was not compiled in, a store that would not answer. Refusals knowable
    /// from configuration alone were already decided by layer A, and the plan is a
    /// projection of that decision rather than a second chance to refuse it.
    ///
    /// `control` must be present when the plan declared it needed (see
    /// `startup_plan::control_runtime_requirement`); its absence there is a wiring error in
    /// this process, not an operator mistake.
    pub fn materialize(
        plan: &ReplayPlan,
        freshness: crate::config_state::FreshnessWindow,
        control: Option<&ControlRuntime>,
    ) -> Result<Self, String> {
        // The tier is READ from the plan, never chosen beside it: the replay owner paired
        // this store with the only tier it can serve, and materialization has no standing
        // to re-pair them.
        let tier = plan.tier();
        let (established, dispatch) = match plan.store() {
            PlannedStore::Etcd { endpoint } => establish_etcd(endpoint, tier, freshness)?,
            PlannedStore::Redis { url } => establish_redis(url, tier, freshness, control)?,
        };
        Self::accept(established, dispatch)
    }

    /// The checked construction, shared by [`Self::materialize`] and the batteries that
    /// exercise the guard against an injected store.
    ///
    /// Producing the value and checking it are ONE step: there is no path from a tier and
    /// a posture to a `MaterializedReplay` that does not pass through `assert_durable`.
    fn accept(tier: AsyncReplayTier, dispatch: ProxyDispatchConfig) -> Result<Self, String> {
        let _durable = assert_durable(&tier)?;
        Ok(MaterializedReplay {
            tier,
            dispatch,
            _durable,
        })
    }

    /// The handover: both halves, moved out together.
    ///
    /// One projection rather than two accessors, because the pairing is the point. Handing
    /// out `tier()` and `dispatch()` separately would let a caller carry one half onward
    /// beside a posture from somewhere else — the terms of a validated relation passed back
    /// as independently replaceable arguments.
    pub fn into_parts(self) -> (AsyncReplayTier, ProxyDispatchConfig) {
        (self.tier, self.dispatch)
    }
}

/// #78 (ADR-MCPS-020): refuse to hand over a tier that self-declares the volatile
/// single-process reference posture.
///
/// `--replay-cache memory` never reaches here — validation refuses it outright (pinned by
/// `startup_plan`'s `the_memory_tier_is_refused_by_validation_before_planning_sees_it`) —
/// which makes this defense in depth rather than the memory tier's terminal refusal: it
/// also catches a store reached by some other selection path, and mcp-re-core's
/// `durability_class()` defaults to the single-process reference, so an UNDECLARED
/// backend is refused here too.
fn assert_durable(tier: &AsyncReplayTier) -> Result<DurabilityWitness, String> {
    if tier.durability_class() == mcp_re_core::ReplayDurabilityClass::SingleProcessReference {
        return Err(
            "the configured replay cache self-declares the volatile single-process reference \
             posture (admitted nonces are lost on restart and invisible to peer verifiers); \
             a durable replay store is required — use --replay-cache shared with an accepted \
             durability tier, or inject a cache that declares ReplayDurabilityClass::Durable"
                .into(),
        );
    }
    Ok(DurabilityWitness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay_tier::ReplayDurabilityTier;

    fn volatile_tier() -> AsyncReplayTier {
        AsyncReplayTier::new(
            std::sync::Arc::new(crate::async_replay::InMemoryAsyncAtomicReplayStore::new()),
            crate::config_state::test_support::freshness(60),
        )
    }

    /// A store that declares the cross-process posture, so the accepting half of the
    /// guard is exercised by something other than a feature-gated backend.
    struct DurableStore;

    impl crate::async_replay::AsyncAtomicReplayStore for DurableStore {
        fn atomic_insert_if_absent<'a>(
            &'a self,
            _insert: crate::async_replay::ReplayInsert<'a>,
        ) -> crate::async_replay::ReplayDecisionFuture<'a> {
            Box::pin(async move { Ok(mcp_re_core::ReplayDecision::Fresh) })
        }

        fn durability_class(&self) -> mcp_re_core::ReplayDurabilityClass {
            mcp_re_core::ReplayDurabilityClass::Durable
        }
    }

    fn linearizable_dispatch() -> ProxyDispatchConfig {
        ProxyDispatchConfig {
            fleet_strict: true,
            tier: Some(ReplayDurabilityTier::Linearizable),
        }
    }

    /// The volatile tier cannot be handed over, even though it can be constructed.
    ///
    /// No plan produces it any more — `ReplayPlan` has two variants and both are shared —
    /// so this asserts the guard directly rather than through a plan. It is the backstop
    /// that fires from inside the producer, so an INJECTED cache cannot reach the serving
    /// path without meeting it either, which is the case a configuration refusal cannot
    /// cover.
    #[test]
    fn a_volatile_tier_is_never_handed_over() {
        let err = assert_durable(&volatile_tier()).err().unwrap_or_else(|| {
            panic!("the volatile tier must be refused");
        });
        assert!(err.contains("single-process reference"), "{err}");
    }

    /// The r11 critical, stated as a test: the exact illegal pairing — a volatile store
    /// under a `fleet_strict`, `Linearizable`-advertising posture — cannot become a
    /// handover value.
    ///
    /// This is the guard's INVOCATION, not its predicate. Its companion is the
    /// REPRESENTATION: `accept` is the only producer in this module, the fields are
    /// private to this file, and the witness field's type is unnameable outside it. So the
    /// pairing is not merely refused at one call site — it is unconstructible anywhere
    /// else, which is what the same test could not say while the fields were `pub`.
    #[test]
    fn a_volatile_tier_under_a_linearizable_posture_cannot_be_built() {
        let err = match MaterializedReplay::accept(volatile_tier(), linearizable_dispatch()) {
            Ok(_) => panic!("a volatile tier must not produce a handover value"),
            Err(e) => e,
        };
        assert!(err.contains("single-process reference"), "{err}");
    }

    /// The guard admits what it is supposed to admit: a durable store yields the value
    /// with the posture it was given, so the refusal above is about durability and not a
    /// constructor that refuses everything.
    ///
    /// Read back through `into_parts`, the only projection — which is also the assertion
    /// that the seal did not cost the composition root what it actually needs.
    #[test]
    fn a_durable_tier_produces_the_handover_value_with_its_posture() {
        let durable = AsyncReplayTier::new(
            std::sync::Arc::new(DurableStore),
            crate::config_state::test_support::freshness(60),
        );
        let materialized = MaterializedReplay::accept(durable, linearizable_dispatch())
            .unwrap_or_else(|e| panic!("a durable tier must be handed over: {e}"));
        let (tier, dispatch) = materialized.into_parts();
        assert!(dispatch.fleet_strict);
        assert_eq!(dispatch.tier, Some(ReplayDurabilityTier::Linearizable));
        assert_eq!(
            tier.durability_class(),
            mcp_re_core::ReplayDurabilityClass::Durable
        );
    }

    /// A backend the build does not contain is refused by NAME. This is the refusal class
    /// that deliberately stayed with materialization: it is a fact about the build, not
    /// about the request, so planning must not raise it.
    #[test]
    fn a_backend_the_build_lacks_is_refused_and_named() {
        let etcd = MaterializedReplay::materialize(
            &crate::config_state::test_support::linearizable_replay_plan(),
            crate::config_state::test_support::freshness(60),
            None,
        );
        if cfg!(feature = "cpstore_etcd") {
            // The etcd store is lazy: establishing it contacts nothing, so a TEST-NET-3
            // endpoint still materializes. Whether it ANSWERS is a request-path fact.
            let ok = etcd.unwrap_or_else(|e| {
                panic!("the etcd tier materializes without contacting anything: {e}")
            });
            let (_, dispatch) = ok.into_parts();
            assert!(dispatch.fleet_strict, "a shared tier serves fleet-strict");
            assert_eq!(dispatch.tier, Some(ReplayDurabilityTier::Linearizable));
        } else {
            let err = match etcd {
                Ok(_) => panic!("refused without the backend"),
                Err(e) => e,
            };
            assert!(err.contains("cpstore_etcd"), "{err}");
        }

        // The redis arm's refusal is reachable without a control runtime only in a build
        // without the backend; with it, the connect would be attempted first.
        if !cfg!(feature = "redis_replay") {
            let err = match MaterializedReplay::materialize(
                &crate::config_state::test_support::redis_replay_plan(),
                crate::config_state::test_support::freshness(60),
                None,
            ) {
                Ok(_) => panic!("refused without the backend"),
                Err(e) => e,
            };
            assert!(err.contains("redis_replay"), "{err}");
        }
    }

    /// **BF-01** (atlas §D.2): with neither backend linked, EVERY plan refuses — so the
    /// build can reach no replay state at all.
    ///
    /// The test above says each arm names the feature it wants. This says what those
    /// refusals amount to TOGETHER, which is the finding: `ReplayPlan` has exactly two
    /// variants and both are shared, so a build carrying neither `redis_replay` nor
    /// `cpstore_etcd` has no reachable replay state. Layer A independently refuses every
    /// other input form — `Memory` (also the value when `--replay-cache` is omitted) and
    /// `File` — so no command line reaches a state such a build can materialize, and a
    /// default build is therefore not a serving binary. The README and the sidecar
    /// deployment guide both state this; this is where it is enforced.
    ///
    /// If this ever fails, the question to ask is which replay state became reachable.
    /// The fix is NOT to restore an in-memory arm: that would make materialization
    /// describe a state layer A refuses to represent, which is the defect CF-01 removed.
    #[test]
    fn a_build_with_no_replay_backend_can_reach_no_replay_state() {
        let etcd = crate::config_state::test_support::linearizable_replay_plan();
        let redis = crate::config_state::test_support::redis_replay_plan();
        let freshness = crate::config_state::test_support::freshness(60);

        if cfg!(feature = "cpstore_etcd") {
            // Only the etcd arm can be probed without a control runtime once its backend
            // is linked; the Redis arm CONSUMES one, and handing it `None` would assert
            // the runtime contract rather than reachability. One reachable state is
            // enough to show the build is a serving binary.
            assert!(
                MaterializedReplay::materialize(&etcd, freshness, None).is_ok(),
                "a build linking cpstore_etcd must reach the linearizable state"
            );
            return;
        }
        if cfg!(feature = "redis_replay") {
            // Redis linked, etcd not: the etcd arm refuses for want of ITS backend, which
            // says nothing about BF-01 either way. Reachability of the Redis arm needs a
            // runtime, so it is asserted where a runtime exists, not here.
            return;
        }

        for plan in [&etcd, &redis] {
            assert!(
                MaterializedReplay::materialize(plan, freshness, None).is_err(),
                "BF-01: with neither backend linked, no replay state may be reachable"
            );
        }
    }
}
