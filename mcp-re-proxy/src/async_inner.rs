// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-051 §3 — the ASYNC inner-server seam.
//!
//! An already-verified, stripped, verified-context-injected request in; what the inner
//! plane actually managed to do out — AWAITED, so the per-core runtime worker is never
//! blocked on the inner round-trip. This is the seam the production inner plane
//! ([`crate::http_inner`], a per-core `hyper` client pool to stateless Streamable-HTTP
//! backends) plugs into.
//!
//! # The capability is HELD, not predicted (#741)
//!
//! The seam used to offer a read-only question, `admit`, answered from
//! `Semaphore::available_permits` — and the permit was then taken inside `dispatch`,
//! after the exchange had already crossed its execution threshold. That is an
//! observational TOCTOU on a security boundary: between the answer and the acquisition
//! another core could take the last permit, and the exchange learned it from the far
//! side of the threshold. It was reported as `NotDispatched`, honestly, but by then the
//! floor had moved and the request had already written a durable marker asserting it
//! crossed.
//!
//! [`AsyncInnerServer::prepare`] replaces the prediction with the thing itself. It takes
//! the real in-flight permit, selects and claims the backend, and builds the transport
//! request — and transmits nothing. What comes back is a [`PreparedInnerDispatch`]: a
//! value that HOLDS the capability to begin a dispatch, whose only operation is to
//! consume itself transmitting. Dropping one instead releases everything it took, so a
//! refusal taken between `prepare` and the dispatch costs the plane nothing and needs no
//! release call to remember.
//!
//! The consequence for the model is what the whole change is for:
//!
//! ```text
//! before commitment   NotAdmitted            nothing was transmitted
//! after commitment    DispatchedOutcome      three facts, all compatible with execution
//! ```
//!
//! There is no post-commitment outcome meaning *nothing happened*, because
//! [`DispatchedOutcome`] has no such case to construct.
//!
//! # Why the outcome is not bytes (ADR-MCPRE-058 §10, ruling D4)
//!
//! It used to return `Vec<u8>`, unconditionally, and turned every failure into a
//! synthesized JSON-RPC error *response* that the proxy signed at HTTP 200. The intent was
//! sound — a hostile or dead inner must never suppress the signature — but the shape
//! destroyed the one fact the exchange machine most needs:
//!
//! ```text
//! in-flight permit exhausted    NOTHING was transmitted   -> refused by `prepare`
//! every backend ejected         NOTHING was transmitted   -> refused by `prepare`
//! unbuildable transport request NOTHING was transmitted   -> refused by `prepare`
//! per-request timeout           transmitted, no answer    -> execution is UNKNOWN
//! connection reset              transmitted, no answer    -> execution is UNKNOWN
//! non-2xx status                the backend ANSWERED      -> it executed; unusable answer
//! non-JSON / SSE body           the backend ANSWERED      -> it executed; unusable answer
//! ```
//!
//! All seven produced identical bytes — `-32603 "inner server unavailable"` — which are
//! also indistinguishable from the backend genuinely replying with that error. A security
//! proxy that collapses "we know it did not run" and "we do not know whether it ran" before
//! deriving retry semantics has destroyed information nothing downstream can reconstruct,
//! and it served the unknown case as a signed success.
//!
//! The fail-closed posture is unchanged: every outcome below still becomes SIGNED bytes the
//! client receives, never an unsigned pass-through and never a silent allow. What changed is
//! that the exchange machine gets to know which one it is, and that the first three are now
//! decided where refusing is still free.

use std::future::Future;
use std::pin::Pin;

/// What the inner plane did once the dispatch was committed.
///
/// Three facts, and every one of them is compatible with the action having executed. The
/// fourth case a reader might expect — *nothing was transmitted* — is deliberately absent:
/// it is decided before commitment, by [`AsyncInnerServer::prepare`], and reported as
/// [`NotAdmitted`]. A post-commitment value that could say it would let a caller walk an
/// exchange's consequence back after the threshold, which is the one direction the
/// exchange machine may never move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchedOutcome {
    /// The backend answered with a 2xx JSON body. Whether that body is a LEGAL response is
    /// a separate question, decided by the envelope validator — this says only that the
    /// bytes are the backend's own.
    Replied(Vec<u8>),
    /// The request was transmitted and the transport then failed — timeout, reset,
    /// truncation. **Whether the action executed is unknown**, and the honest answer is to
    /// say so rather than to pick the flattering reading.
    Indeterminate(&'static str),
    /// The backend answered, and its answer cannot be used: a non-2xx status, a
    /// non-JSON media type (an SSE stream, an HTML error page), an unreadable or
    /// over-cap body.
    ///
    /// Separate from [`Indeterminate`](Self::Indeterminate) because the backend DID act,
    /// and separate from [`Replied`](Self::Replied) because there is nothing here to
    /// classify as an MCP response.
    InvalidUpstream(&'static str),
}

/// Why a dispatch cannot begin, decided WITHOUT transmitting anything.
///
/// Returned by [`AsyncInnerServer::prepare`] so the serving path can refuse on the
/// retry-safe side of the execution threshold. That is the entire point: local saturation
/// is a fact about this proxy, and answering it after the threshold turns a
/// definitely-not-executed outage into an exchange that must claim `possibly_executed`
/// forever after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAdmitted(pub &'static str);

/// The boxed, `Send` future a committed dispatch resolves through.
pub type InnerResponseFuture<'a> = Pin<Box<dyn Future<Output = DispatchedOutcome> + Send + 'a>>;

/// The real capability to begin one inner dispatch, held and not merely predicted.
///
/// Holding one means the plane has already taken everything transmitting requires — the
/// in-flight permit, the selected backend and any recovery-probe claim over it, the built
/// transport request — and has transmitted nothing. It is the pre-dispatch product the
/// serving path carries across its remaining pre-dispatch stages.
///
/// Its only operation consumes it, so the capability cannot be used twice and cannot be
/// used without being surrendered. Dropping one instead is the rescind path and needs no
/// call: whatever the plane captured is released when the value goes, so a refusal taken
/// after `prepare` — for any reason, on any path, including a cancelled request future —
/// returns the capacity without anything having to remember to.
pub struct PreparedInnerDispatch<'a> {
    /// The one thing a prepared dispatch can do. Built by the plane that took the
    /// capability, so the capability is CAPTURED here rather than looked up again at the
    /// dispatch — which is exactly the re-lookup that made the old seam observational.
    transmit: Box<dyn FnOnce() -> InnerResponseFuture<'a> + Send + 'a>,
}

impl std::fmt::Debug for PreparedInnerDispatch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedInnerDispatch")
    }
}

impl<'a> PreparedInnerDispatch<'a> {
    /// Wrap what an inner plane took, as the capability to transmit it exactly once.
    ///
    /// The closure is not run here and must not transmit before it is called: `prepare`
    /// is asked while refusing is still free, and a plane that acted at that point would
    /// have moved the execution threshold to the wrong side of the reservation.
    pub fn over(
        transmit: impl FnOnce() -> InnerResponseFuture<'a> + Send + 'a,
    ) -> PreparedInnerDispatch<'a> {
        PreparedInnerDispatch {
            transmit: Box::new(transmit),
        }
    }

    /// **The execution threshold.** Surrender the capability and transmit.
    ///
    /// Consuming, and the only way out. Past this call no exit can claim nothing
    /// happened — which is why it yields a [`DispatchedOutcome`], a type with no case
    /// for it.
    pub fn dispatch(self) -> InnerResponseFuture<'a> {
        (self.transmit)()
    }
}

/// An unmodified inner MCP server reached over an ASYNC transport (ADR-MCPRE-051 §3).
pub trait AsyncInnerServer: Send + Sync {
    /// Take everything a dispatch of `request` requires, and transmit nothing.
    ///
    /// A fast-fail on the retry-safe side of the threshold, and — unlike the `admit` it
    /// replaces — a claim rather than an observation. Local saturation, a fully ejected
    /// backend set and an unbuildable transport request are all facts about THIS process,
    /// knowable without putting a byte on the wire; deciding them here is what lets them
    /// be refused as genuinely retry-safe instead of as an exchange that may have
    /// executed.
    ///
    /// `request` is borrowed: an implementation that needs the bytes past this call owns
    /// them, so the prepared value never depends on the caller keeping the buffer alive
    /// across its own remaining pre-dispatch stages.
    fn prepare<'a>(&'a self, request: &[u8]) -> Result<PreparedInnerDispatch<'a>, NotAdmitted>;
}

/// Any `Fn(&[u8]) -> Vec<u8>` is an async inner server that always replies: the
/// (synchronous) closure is evaluated when the dispatch is committed and its result
/// returned as a ready future. Ergonomic for tests and embedding — an in-process echo/stub
/// inner plugs into the async path without a bespoke type. Real transports (the `hyper`
/// pool) implement the trait directly, genuinely await I/O, and can report the other two
/// outcomes.
///
/// The closure is called from [`PreparedInnerDispatch::dispatch`] and never from
/// `prepare`. An in-process inner IS the backend, so calling it at preparation time would
/// execute the request while the serving path still believed refusing was free.
impl<F> AsyncInnerServer for F
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync,
{
    fn prepare<'a>(&'a self, request: &[u8]) -> Result<PreparedInnerDispatch<'a>, NotAdmitted> {
        let request = request.to_vec();
        Ok(PreparedInnerDispatch::over(move || {
            let response = self(&request);
            Box::pin(async move { DispatchedOutcome::Replied(response) })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    /// The three post-commitment outcomes are three values. Stated as a test because the
    /// property that matters is exactly that they do not compare equal — the original seam
    /// made every failure the same bytes, and every downstream reader inherited that.
    #[test]
    fn the_post_commitment_outcomes_are_distinguishable() {
        let outcomes = [
            DispatchedOutcome::Replied(b"{}".to_vec()),
            DispatchedOutcome::Indeterminate("timeout"),
            DispatchedOutcome::InvalidUpstream("non-2xx status"),
        ];
        for (i, a) in outcomes.iter().enumerate() {
            for (j, b) in outcomes.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a:?} vs {b:?}");
            }
        }
    }

    /// A closure inner always replies, and says so — it has no transport to fail.
    #[tokio::test]
    async fn a_closure_inner_reports_a_backend_reply() {
        let inner = |_: &[u8]| b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".to_vec();
        let prepared = inner
            .prepare(b"{}")
            .expect("a closure inner always prepares");
        let out = prepared.dispatch().await;
        assert!(matches!(out, DispatchedOutcome::Replied(_)));
    }

    /// Preparing must not run the backend.
    ///
    /// The control for the ordering the whole seam rests on: `prepare` is asked while a
    /// refusal is still free, and the retention reservation is taken AFTER it. An inner
    /// that acted at preparation time would have executed the request before the exchange
    /// recorded that it was about to — which is the ordering ADR-MCPRE-054 exists to fix,
    /// reintroduced through the seam.
    #[tokio::test]
    async fn preparing_transmits_nothing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = {
            let calls = Arc::clone(&calls);
            move |_: &[u8]| {
                calls.fetch_add(1, Ordering::SeqCst);
                b"{}".to_vec()
            }
        };
        let prepared = counted.prepare(b"{}").expect("prepares");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "prepare ran the backend");
        let _ = prepared.dispatch().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Dropping a prepared dispatch does not transmit, and releases what it took.
    ///
    /// This is the rescind path, and the property is that it is not a call. A serving
    /// path that refuses between `prepare` and the dispatch — for any reason, including
    /// its request future being cancelled — drops the value, and the backend is untouched.
    #[test]
    fn dropping_a_prepared_dispatch_transmits_nothing_and_releases_what_it_held() {
        let calls = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicUsize::new(0));

        struct Capability(Arc<AtomicUsize>);
        impl Drop for Capability {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let counted = {
            let calls = Arc::clone(&calls);
            move |_: &[u8]| {
                calls.fetch_add(1, Ordering::SeqCst);
                b"{}".to_vec()
            }
        };
        {
            let held = Capability(Arc::clone(&released));
            let prepared = counted.prepare(b"{}").expect("prepares");
            // The capability a real plane captures — a permit, a probe claim — modelled
            // as something whose release is observable.
            let prepared = PreparedInnerDispatch::over(move || {
                let _held = held;
                prepared.dispatch()
            });
            drop(prepared);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0, "a dropped dispatch ran");
        assert_eq!(
            released.load(Ordering::SeqCst),
            1,
            "a dropped dispatch kept what it took"
        );
    }
}
