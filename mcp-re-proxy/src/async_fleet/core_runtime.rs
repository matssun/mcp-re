// SPDX-License-Identifier: Apache-2.0
//! WHICH tokio runtime one serving core gets, and how much blocking handshake work it may
//! admit onto it.
//!
//! One current-thread runtime per core is the share-nothing default (ADR-MCPRE-051 §1): no
//! work stealing, no cross-core hot-path state. Delegated TLS custody breaks the assumption
//! that runtime holds, so the choice is a decision with a security consequence rather than
//! a tuning knob, and it is made here where the reasoning can be stated once.
//!
//! The pool depth and the handshake bound are ONE decision, not two. A pool is not a bound:
//! a peer needs only as many concurrent connections as there are workers to occupy every
//! one of them, and TLS 1.3 signs `CertificateVerify` before the client's `Certificate` is
//! ever seen, so it needs no credential to do it. Sizing the bound from a constant while
//! the depth came from somewhere else is how the two stopped agreeing; [`CorePool`] is the
//! one place both are decided, from the same inputs, and [`CorePool::handshake_bound`] is
//! the only way to obtain the bound.
//!
//! Building the runtime is FALLIBLE and the failure is reported: `build` allocates threads
//! and an event loop, so a core the operating system declines must not leave the fleet
//! reporting a successful bind with one fewer server behind it.

use super::shard_depth::DelegatedTlsDepthRefusal;
use super::shard_depth::ShardDepth;
use crate::tls::ServerOptions;

/// Worker threads a core is given when the TLS handshake signature can block and the
/// operator stated no depth of their own.
///
/// Sized so a handful of concurrent stalled handshakes still leaves the core serving.
/// It is not a throughput knob: on the exported-key path the runtime stays
/// single-threaded, and raising this would not make a wedged token any less wedged —
/// it only widens the window before the pool is exhausted.
const DELEGATED_TLS_WORKERS_PER_CORE: usize = 4;

/// The most concurrent blocking handshake signatures ANY core admits — a CEILING on
/// [`CorePool::handshake_bound`], never the bound itself.
///
/// The bound is `depth - 1`, so that a core under a full handshake flood always retains a
/// worker for its accept loop, its established connections and its in-flight requests. This
/// caps that expression from above so a wide pool does not silently raise how much blocking
/// KMS or PKCS#11 work one core will carry at once: widening it is a throughput change with
/// its own argument to make, not a consequence of the operator choosing more workers.
/// Raising it re-opens exactly what the bound closes.
const DELEGATED_TLS_HANDSHAKES_PER_CORE: usize = 2;

/// How many TLS handshakes one core may have signing at once, where that signature is a
/// device or KMS round trip that occupies its worker thread outright.
///
/// [`CorePool::handshake_bound`] is the sole producer: there is no constructor, no
/// conversion and no public field, so a bound cannot be named independently of the pool
/// whose depth it must stay below. That is the property — holding one of these means it
/// was derived from a runtime that was actually built with room to spare.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeBound(Option<usize>);

impl HandshakeBound {
    /// Permits for this core's handshake semaphore; `None` where the signature is in-memory
    /// and cannot block, and bounding it would cost throughput for nothing.
    pub(crate) fn permits(self) -> Option<usize> {
        self.0
    }
}

/// One serving core's runtime shape, and what that shape lets the core admit.
///
/// The representation is private and there is exactly one producer,
/// [`CorePool::for_core`]. Downstream gets a runtime built to the shape (`build_runtime`)
/// and the handshake bound that shape supports ([`CorePool::handshake_bound`]). Nothing
/// projects the two as one destructurable record, so no consumer can pair a bound with a
/// depth that did not produce it.
pub struct CorePool {
    /// Worker threads this core's runtime gets; `None` is the share-nothing current-thread
    /// runtime, which has no pool to bound anything against.
    workers: Option<usize>,
    /// Concurrent blocking handshake signatures this core admits; `None` wherever the
    /// handshake signature cannot block.
    handshakes: Option<usize>,
}

impl CorePool {
    /// Decide one core's pool and its handshake bound together.
    ///
    /// DELEGATED TLS custody is why a pool exists at all. The handshake signature is
    /// produced by rustls' SYNCHRONOUS `Signer::sign`, which on that path is a blocking KMS
    /// round trip or a PKCS#11 `C_Sign`. On a current-thread runtime one such call freezes
    /// the core outright — its accept loop, its keep-alive connections and every in-flight
    /// signed request — for the duration, and no timer can preempt it because the future
    /// never yields. Any peer opening connections triggers it, so it is a
    /// trivially-reachable DoS.
    ///
    /// Those deployments get a small worker pool per core, so a stalled signature costs one
    /// worker rather than a whole core, AND a bound strictly below that pool, so a flood
    /// cannot occupy every worker in it. The bound is `depth - 1` capped at
    /// `DELEGATED_TLS_HANDSHAKES_PER_CORE`, which is what makes it a function of the depth
    /// this core was actually built with rather than of a constant that never saw the depth:
    /// a two-worker core admits one handshake, not two.
    ///
    /// FOUR CASES, and the depth's PROVENANCE decides between two of them. A depth of 1 is
    /// where an operator's request and the host's answer to `auto` mean different things,
    /// and [`ShardDepth`] is what keeps them apart:
    ///
    /// | custody | depth | outcome |
    /// |---|---|---|
    /// | exported key | stated 1 | the share-nothing current-thread runtime, as asked |
    /// | delegated | **stated 1** | **refused** — [`DelegatedTlsDepthRefusal`] |
    /// | delegated | derived (auto) | the safe depth is derived: `DELEGATED_TLS_WORKERS_PER_CORE` |
    /// | delegated | stated >= 2 | honoured exactly, and the bound follows the built depth |
    ///
    /// The refusal is the case with no safe shape. Serving a stated 1 under a blocking
    /// signer exposes the measured starvation; raising it to a pool serves a topology the
    /// operator was explicit about not wanting. Overriding a DERIVED 1 is neither — it
    /// fills in for a number nobody chose, which is what `auto` asks for.
    ///
    /// There is no acknowledgement flag. A deployment that wants the single-threaded
    /// runtime changes its custody, and one that wants delegated custody states a depth.
    ///
    /// The share-nothing default is unchanged for the exported-key path, where signing is
    /// in-memory and never blocks. A configured pool depth gives the shard a work-stealing
    /// runtime; see `FleetConfig::workers_per_shard` for why depth beats shard count.
    pub fn for_core(
        workers_per_shard: ShardDepth,
        options: &ServerOptions,
    ) -> Result<Self, DelegatedTlsDepthRefusal> {
        let stated_single_thread =
            workers_per_shard.is_operator_stated() && workers_per_shard.get() <= 1;
        if options.tls_signing_may_block && stated_single_thread {
            return Err(DelegatedTlsDepthRefusal);
        }
        let workers = if workers_per_shard.get() > 1 {
            Some(workers_per_shard.get())
        } else if options.tls_signing_may_block {
            Some(DELEGATED_TLS_WORKERS_PER_CORE)
        } else {
            None
        };
        // `saturating_sub` is the honest algebra AND the true one: the leftover worker is
        // what is being computed, and on this arm `depth >= 2` (a stated depth reaches it
        // only when it exceeds 1, and the override is 4), so nothing saturates.
        let handshakes = match workers {
            Some(depth) if options.tls_signing_may_block => Some(
                depth
                    .saturating_sub(1)
                    .min(DELEGATED_TLS_HANDSHAKES_PER_CORE),
            ),
            _ => None,
        };
        Ok(CorePool {
            workers,
            handshakes,
        })
    }

    /// The pool depth this core runs; `None` for the share-nothing current-thread runtime.
    ///
    /// Nothing in production needs the depth back — `build_runtime` is the only consumer of
    /// it and it holds the value already — so this exists at the narrowest level that lets
    /// its one legitimate consumer work: the crate's controls, which need both halves of
    /// the depth/bound relation nameable for that relation to be assertable at all.
    #[cfg(test)]
    pub(crate) fn worker_threads(&self) -> Option<usize> {
        self.workers
    }

    /// How many blocking handshake signatures this core admits at once.
    pub fn handshake_bound(&self) -> HandshakeBound {
        HandshakeBound(self.handshakes)
    }

    /// Build this core's tokio runtime.
    ///
    /// Class R: `build` allocates threads and an event loop, so the failure is the caller's
    /// to report — a core the OS declines must not leave the fleet reporting a successful
    /// bind with one fewer server behind it.
    pub(super) fn build_runtime(
        &self,
        core_index: usize,
    ) -> std::io::Result<tokio::runtime::Runtime> {
        match self.workers {
            Some(threads) => tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .thread_name(format!("mcp-re-serve-{core_index}-w"))
                .enable_all()
                .build(),
            None => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(tls_signing_may_block: bool) -> ServerOptions {
        ServerOptions {
            tls_signing_may_block,
            ..Default::default()
        }
    }

    fn pool(depth: ShardDepth, may_block: bool) -> CorePool {
        CorePool::for_core(depth, &options(may_block)).expect("a shape this deployment has")
    }

    // ------------------------------------------------------------------
    // Owner Ruling 7 — the four cases, one control each.
    // ------------------------------------------------------------------

    /// CASE 1 — exported key + stated 1. The operator asked for the single-threaded
    /// share-nothing runtime and the signature is in-memory, so there is nothing to
    /// protect them from: they get exactly what they asked for.
    #[test]
    fn a_share_nothing_core_has_no_pool_and_no_handshake_bound() {
        let pool = pool(ShardDepth::stated(1), false);
        assert_eq!(pool.worker_threads(), None);
        assert_eq!(pool.handshake_bound().permits(), None);
    }

    /// CASE 2 — delegated custody + stated 1. THE REFUSAL. Serving it exposes the measured
    /// unauthenticated handshake starvation, and widening it silently substitutes a
    /// topology for the one the operator was most explicit about.
    ///
    /// LOAD-BEARING: this is the case the whole slice exists for. Before it, the stated 1
    /// was overridden to four workers and nothing told the operator.
    #[test]
    fn delegated_custody_with_a_stated_single_thread_is_refused() {
        assert!(matches!(
            CorePool::for_core(ShardDepth::stated(1), &options(true)),
            Err(DelegatedTlsDepthRefusal)
        ));
        // A stated 0 is the same request written the other way and is refused identically:
        // the resolver never produces it, and a caller that hand-built one must not find a
        // gap where the refusal is not.
        assert!(matches!(
            CorePool::for_core(ShardDepth::stated(0), &options(true)),
            Err(DelegatedTlsDepthRefusal)
        ));
    }

    /// CASE 3 — delegated custody + a DERIVED depth. `auto` is the operator declining to
    /// choose, so filling in the safe depth is answering the question they asked rather
    /// than overriding one they answered. A single-cpu host derives 1, which is exactly
    /// where this matters.
    #[test]
    fn delegated_custody_over_a_derived_depth_derives_the_safe_one() {
        for derived in 1..=16 {
            let pool = pool(ShardDepth::derived(derived), true);
            let built = pool
                .worker_threads()
                .expect("a blocking signature is never served on a current-thread runtime");
            assert!(built >= 2, "derived={derived}: built a pool of {built}");
            assert!(
                pool.handshake_bound().permits().is_some(),
                "derived={derived}: a pool without a bound is not a bound"
            );
        }
        // The specific case the refusal's sibling covers: a host that can only derive 1.
        assert_eq!(
            pool(ShardDepth::derived(1), true).worker_threads(),
            Some(DELEGATED_TLS_WORKERS_PER_CORE)
        );
    }

    /// CASE 4 — delegated custody + a stated depth of 2 or more. Honoured EXACTLY, and the
    /// handshake admission is derived from that depth rather than from a constant.
    ///
    /// R12-648 is the defect inside this case: a two-worker core admitted two concurrent
    /// blocking handshakes, occupying both workers with connections that need no client
    /// credential. A constant cannot see the depth, so it cannot leave a worker spare.
    #[test]
    fn the_bound_follows_the_built_depth_and_is_capped_by_the_ceiling() {
        for stated in 2..=64 {
            let pool = pool(ShardDepth::stated(stated), true);
            assert_eq!(
                pool.worker_threads(),
                Some(stated),
                "an operator's depth is used as stated"
            );
            let permits = pool
                .handshake_bound()
                .permits()
                .expect("a blocking signature is always bounded");
            assert!(
                permits < stated,
                "stated={stated}: {permits} handshakes on {stated} workers leaves none \
                 for the accept loop"
            );
            assert!(
                permits >= 1,
                "stated={stated}: a bound of zero refuses everything"
            );
        }
        // The ceiling, from both sides: two workers admit ONE, and past the ceiling the
        // bound stops rising — more workers is not more blocking work.
        assert_eq!(
            pool(ShardDepth::stated(2), true)
                .handshake_bound()
                .permits(),
            Some(1)
        );
        assert_eq!(
            pool(ShardDepth::stated(3), true)
                .handshake_bound()
                .permits(),
            Some(DELEGATED_TLS_HANDSHAKES_PER_CORE)
        );
        assert_eq!(
            pool(ShardDepth::stated(64), true)
                .handshake_bound()
                .permits(),
            Some(DELEGATED_TLS_HANDSHAKES_PER_CORE)
        );
    }

    // ------------------------------------------------------------------
    // The custody axis, independent of the depth axis.
    // ------------------------------------------------------------------

    /// A pool the operator asked for is not a delegated-TLS pool. Bounding handshakes there
    /// would cost throughput to defend against a signature that cannot block.
    #[test]
    fn a_pool_without_delegated_tls_bounds_no_handshakes() {
        let pool = pool(ShardDepth::stated(8), false);
        assert_eq!(pool.worker_threads(), Some(8));
        assert_eq!(pool.handshake_bound().permits(), None);
    }

    /// THE REFUSAL FIRES ON THE PAIR, not on either half. An exported key with a stated 1
    /// is admitted and a delegated custody with a derived 1 is admitted; only their
    /// conjunction is refused — which is what keeps this from being a depth policy that
    /// happens to mention custody.
    #[test]
    fn neither_half_of_the_refused_pair_refuses_on_its_own() {
        assert!(CorePool::for_core(ShardDepth::stated(1), &options(false)).is_ok());
        assert!(CorePool::for_core(ShardDepth::derived(1), &options(true)).is_ok());
        assert!(CorePool::for_core(ShardDepth::stated(1), &options(true)).is_err());
    }

    /// A delegated-TLS core that IS admitted always gets a pool and always gets a bound —
    /// an override that failed to fire would leave a current-thread runtime one signature
    /// can freeze, and a pool without a bound is not a bound.
    #[test]
    fn a_delegated_tls_core_is_always_pooled_and_always_bounded() {
        let admitted = (0..=16)
            .map(ShardDepth::derived)
            .chain((2..=16).map(ShardDepth::stated));
        for depth in admitted {
            let pool = pool(depth, true);
            assert!(
                pool.worker_threads().is_some(),
                "{depth:?}: a blocking signature on a current-thread runtime freezes the core"
            );
            assert!(
                pool.handshake_bound().permits().is_some(),
                "{depth:?}: a pool without a bound is not a bound"
            );
        }
    }
}
