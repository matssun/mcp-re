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
    /// A stated depth above 1 is the operator's and is used as stated. A stated (or
    /// resolved) depth of 1 under delegated TLS is overridden to
    /// `DELEGATED_TLS_WORKERS_PER_CORE`, because a current-thread runtime has no answer to
    /// a blocking signature at all.
    ///
    /// The share-nothing default is unchanged for the exported-key path, where signing is
    /// in-memory and never blocks. A configured pool depth gives the shard a work-stealing
    /// runtime; see `FleetConfig::workers_per_shard` for why depth beats shard count.
    pub fn for_core(workers_per_shard: usize, options: &ServerOptions) -> Self {
        let workers = if workers_per_shard > 1 {
            Some(workers_per_shard)
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
        CorePool {
            workers,
            handshakes,
        }
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

    /// The exported-key path signs in memory and never blocks, so it keeps the
    /// share-nothing current-thread runtime and has nothing to bound.
    #[test]
    fn a_share_nothing_core_has_no_pool_and_no_handshake_bound() {
        let pool = CorePool::for_core(1, &options(false));
        assert_eq!(pool.worker_threads(), None);
        assert_eq!(pool.handshake_bound().permits(), None);
    }

    /// A pool the operator asked for is not a delegated-TLS pool. Bounding handshakes there
    /// would cost throughput to defend against a signature that cannot block.
    #[test]
    fn a_pool_without_delegated_tls_bounds_no_handshakes() {
        let pool = CorePool::for_core(8, &options(false));
        assert_eq!(pool.worker_threads(), Some(8));
        assert_eq!(pool.handshake_bound().permits(), None);
    }

    /// R12-648: the bound follows the depth the core was BUILT with.
    ///
    /// The defect this pins: a host resolving to a depth of 2 built a two-worker runtime and
    /// admitted two concurrent blocking handshakes onto it, occupying both workers with
    /// connections that need no client credential. Reading the bound from a constant cannot
    /// see that, because the constant never sees the depth.
    #[test]
    fn the_bound_follows_the_built_depth_and_is_capped_by_the_ceiling() {
        let bound = |depth| {
            CorePool::for_core(depth, &options(true))
                .handshake_bound()
                .permits()
        };
        // A stated 1 is overridden to a four-worker pool, so the bound is the ceiling.
        assert_eq!(bound(1), Some(2));
        // The defect, fixed: two workers admit ONE handshake.
        assert_eq!(bound(2), Some(1));
        // Three workers reach the ceiling and keep a worker spare.
        assert_eq!(bound(3), Some(2));
        // Past the ceiling the bound stops rising: more workers is not more blocking work.
        assert_eq!(bound(4), Some(2));
        assert_eq!(bound(8), Some(2));
        assert_eq!(bound(64), Some(2));
    }

    /// A delegated-TLS core always gets a pool, whatever depth it was handed — an override
    /// that failed to fire would leave a current-thread runtime one signature can freeze.
    #[test]
    fn a_delegated_tls_core_is_always_pooled_and_always_bounded() {
        for depth in 0..=16 {
            let pool = CorePool::for_core(depth, &options(true));
            assert!(
                pool.worker_threads().is_some(),
                "depth={depth}: a blocking signature on a current-thread runtime freezes the core"
            );
            assert!(
                pool.handshake_bound().permits().is_some(),
                "depth={depth}: a pool without a bound is not a bound"
            );
        }
    }
}
