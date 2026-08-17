// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-051 §3 — the ASYNC inner-server seam.
//!
//! An already-verified, stripped, verified-context-injected request in; what the inner
//! plane actually managed to do out — AWAITED, so the per-core runtime worker is never
//! blocked on the inner round-trip. This is the seam the production inner plane
//! ([`crate::http_inner`], a per-core `hyper` client pool to stateless Streamable-HTTP
//! backends) plugs into.
//!
//! # Why this returns an outcome and not bytes (ADR-MCPRE-058 §10, ruling D4)
//!
//! It used to return `Vec<u8>`, unconditionally, and turned every failure into a
//! synthesized JSON-RPC error *response* that the proxy signed at HTTP 200. The intent was
//! sound — a hostile or dead inner must never suppress the signature — but the shape
//! destroyed the one fact the exchange machine most needs:
//!
//! ```text
//! in-flight permit exhausted    NOTHING was transmitted   -> the call did not execute
//! every backend ejected         NOTHING was transmitted   -> the call did not execute
//! per-request timeout           transmitted, no answer    -> execution is UNKNOWN
//! connection reset              transmitted, no answer    -> execution is UNKNOWN
//! non-2xx status                the backend ANSWERED      -> it executed; the answer is unusable
//! non-JSON / SSE body           the backend ANSWERED      -> it executed; the answer is unusable
//! ```
//!
//! All six produced identical bytes — `-32603 "inner server unavailable"` — which are also
//! indistinguishable from the backend genuinely replying with that error. A security proxy
//! that collapses "we know it did not run" and "we do not know whether it ran" before
//! deriving retry semantics has destroyed information nothing downstream can reconstruct,
//! and it served the unknown case as a signed success.
//!
//! The fail-closed posture is unchanged: every outcome below still becomes SIGNED bytes the
//! client receives, never an unsigned pass-through and never a silent allow. What changed is
//! that the exchange machine gets to know which one it is.

use std::future::Future;
use std::pin::Pin;

/// What the inner plane managed to do, as the four epistemically distinct outcomes.
///
/// Not an ordering and not a `Result`: these are four different facts about the world, and
/// three of them are failures with three different consequences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerOutcome {
    /// The backend answered with a 2xx JSON body. Whether that body is a LEGAL response is
    /// a separate question, decided by the envelope validator — this says only that the
    /// bytes are the backend's own.
    Replied(Vec<u8>),
    /// The dispatch never began: no permit, no eligible backend, or the request could not
    /// be built. **Nothing was transmitted.**
    ///
    /// Reported honestly even when discovered late. The serving path asks
    /// [`AsyncInnerServer::admit`] BEFORE the execution threshold precisely so this is
    /// usually a pre-dispatch fact; a `NotDispatched` seen after the threshold is a lost
    /// race, and the exchange still reports `possibly_executed` because the floor is
    /// already set. Monotone consequence is not negotiable against a more precise late
    /// observation.
    NotDispatched(&'static str),
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
/// Returned by [`AsyncInnerServer::admit`] so the serving path can refuse on the retry-safe
/// side of the execution threshold. That is the entire point: local saturation is a fact
/// about this proxy, and answering it after the threshold turns a definitely-not-executed
/// outage into an exchange that must claim `possibly_executed` forever after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAdmitted(pub &'static str);

/// The boxed, `Send` future an [`AsyncInnerServer`] returns.
pub type InnerResponseFuture<'a> = Pin<Box<dyn Future<Output = InnerOutcome> + Send + 'a>>;

/// An unmodified inner MCP server reached over an ASYNC transport (ADR-MCPRE-051 §3).
pub trait AsyncInnerServer: Send + Sync {
    /// Can a dispatch begin at all?
    ///
    /// Answered without transmitting anything and without reserving anything: this is a
    /// fast-fail, not a permit. A dispatch may still fail to begin after `admit` says yes —
    /// the last in-flight slot can be taken by another core in between — and that residual
    /// race is resolved PESSIMISTICALLY, as a post-dispatch failure, because by then the
    /// exchange has crossed the threshold and may not walk its consequence back.
    ///
    /// The default admits everything, so an in-process test inner needs no implementation:
    /// it has no capacity to run out of.
    fn admit(&self) -> Result<(), NotAdmitted> {
        Ok(())
    }

    /// Dispatch one (already verified + stripped + context-injected) request to the inner
    /// server, awaiting what became of it.
    fn dispatch<'a>(&'a self, request: &'a [u8]) -> InnerResponseFuture<'a>;
}

/// Any `Fn(&[u8]) -> Vec<u8>` is an async inner server that always replies: the
/// (synchronous) closure is evaluated eagerly and its result returned as a ready future.
/// Ergonomic for tests and embedding — an in-process echo/stub inner plugs into the async
/// path without a bespoke type. Real transports (the `hyper` pool) implement the trait
/// directly, genuinely await I/O, and can report the other three outcomes.
impl<F> AsyncInnerServer for F
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync,
{
    fn dispatch<'a>(&'a self, request: &'a [u8]) -> InnerResponseFuture<'a> {
        let response = InnerOutcome::Replied(self(request));
        Box::pin(async move { response })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four outcomes are four values. Stated as a test because the property that
    /// matters is exactly that they do not compare equal — the previous seam made all four
    /// the same bytes, and every downstream reader inherited that.
    #[test]
    fn the_four_outcomes_are_distinguishable() {
        let outcomes = [
            InnerOutcome::Replied(b"{}".to_vec()),
            InnerOutcome::NotDispatched("no permit"),
            InnerOutcome::Indeterminate("timeout"),
            InnerOutcome::InvalidUpstream("non-2xx status"),
        ];
        for (i, a) in outcomes.iter().enumerate() {
            for (j, b) in outcomes.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a:?} vs {b:?}");
            }
        }
    }

    /// A closure inner always replies, and says so — it has no transport to fail.
    #[tokio::test]
    async fn a_closure_inner_always_reports_a_backend_reply() {
        let inner = |_: &[u8]| b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".to_vec();
        let out = inner.dispatch(b"{}").await;
        assert!(matches!(out, InnerOutcome::Replied(_)));
        assert!(inner.admit().is_ok());
    }
}
