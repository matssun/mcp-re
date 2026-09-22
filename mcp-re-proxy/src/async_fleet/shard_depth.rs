// SPDX-License-Identifier: Apache-2.0
//! WHOSE number a shard's pool depth is, and the one configuration that has no safe shape.
//!
//! One fact: **a resolved pool depth carries whether the operator stated it or the host
//! answered for it.**
//!
//! The distinction is load-bearing exactly once, and that once is a security decision. An
//! explicit `--workers-per-shard 1` is how an operator asks for the single-threaded
//! share-nothing runtime (ADR-MCPRE-051 §1). Under DELEGATED TLS custody the handshake
//! signature is a blocking KMS or PKCS#11 round trip inside rustls' synchronous
//! `Signer::sign`, and on a current-thread runtime one such call freezes the core outright
//! — accept loop, keep-alive connections and every in-flight request — for a peer that
//! needs no credential to trigger it.
//!
//! So that pair has two wrong answers and one right one. Serving it as asked exposes the
//! measured unauthenticated handshake starvation. Quietly widening it to a worker pool
//! serves a topology the operator did not ask for and did not consent to, on the axis they
//! were most explicit about. The right answer is to refuse the configuration and say which
//! two settings disagree, which is what [`ShardDepth`] makes possible: a bare `usize` has
//! already lost the fact the refusal turns on.
//!
//! What the type does NOT decide is the refusal itself. `CorePool::for_core` owns that,
//! because the other half of the condition is the signing custody, which lives on
//! `ServerOptions` and is not this value's to hold.

use std::fmt;

/// One shard's resolved pool depth, and whose number it is.
///
/// The representation is private and both producers are named, so a depth cannot reach the
/// runtime decision having lost its provenance — which is the shape the defect had: the
/// resolver collapsed `0 = auto` into a concrete count, and from there an operator's
/// deliberate `1` and a single-cpu host's derived `1` were the same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardDepth {
    depth: usize,
    operator_stated: bool,
}

impl ShardDepth {
    /// The depth the operator wrote on the command line.
    pub fn stated(depth: usize) -> Self {
        ShardDepth {
            depth,
            operator_stated: true,
        }
    }

    /// The depth this host answered `auto` with.
    ///
    /// A derived depth is a starting point rather than a request, so a runtime decision may
    /// raise it where the deployment's signing custody needs more room. An operator's may
    /// not be raised — see [`crate::async_fleet::CorePool::for_core`].
    pub fn derived(depth: usize) -> Self {
        ShardDepth {
            depth,
            operator_stated: false,
        }
    }

    /// The number itself.
    pub fn get(self) -> usize {
        self.depth
    }

    /// Whether raising this depth would override the operator rather than fill in for them.
    pub(crate) fn is_operator_stated(self) -> bool {
        self.operator_stated
    }
}

/// The one topology this deployment has no safe shape for: an operator-stated
/// single-threaded shard under a signing custody whose handshake can block.
///
/// A unit struct, deliberately. There are no variants because there is one condition, and
/// it carries no operator input because everything it would carry is already in the
/// operator's own configuration — a refusal that echoed the settings back would be naming
/// what the reader is looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegatedTlsDepthRefusal;

impl fmt::Display for DelegatedTlsDepthRefusal {
    /// Names BOTH settings and BOTH ways out. A refusal that named only the depth would
    /// send an operator to change the number, which is one of the two answers and not
    /// necessarily the one their deployment wants.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "--workers-per-shard 1 asks for the single-threaded share-nothing runtime, and \
             this deployment's TLS custody is DELEGATED: the handshake signature is a \
             blocking KMS/PKCS#11 call inside rustls' synchronous signer, so one \
             handshake freezes the whole core — its accept loop, its established \
             connections and every in-flight request — and any peer can open one without \
             presenting a credential. Serving this as configured is the measured \
             unauthenticated handshake starvation, and widening it silently would serve a \
             topology you did not ask for. Either raise --workers-per-shard to 2 or more \
             (or drop it for the host-derived depth), or move TLS to an exported key, \
             where the signature is in-memory and the single-threaded runtime is safe.",
        )
    }
}

impl std::error::Error for DelegatedTlsDepthRefusal {}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE WHOLE POINT OF THE TYPE: the same number, two provenances, and they are not
    /// interchangeable. A single-cpu host derives 1 and an operator can state 1, and only
    /// one of those may be raised.
    #[test]
    fn the_same_depth_from_two_provenances_is_two_values() {
        assert_eq!(ShardDepth::stated(1).get(), ShardDepth::derived(1).get());
        assert_ne!(ShardDepth::stated(1), ShardDepth::derived(1));
        assert!(ShardDepth::stated(1).is_operator_stated());
        assert!(!ShardDepth::derived(1).is_operator_stated());
    }

    /// The refusal names both settings and both exits. An operator reading it must be able
    /// to act without consulting the source — and must not be told the depth is the only
    /// thing they can change.
    #[test]
    fn the_refusal_names_both_settings_and_both_ways_out() {
        let refusal = DelegatedTlsDepthRefusal.to_string();
        assert!(refusal.contains("--workers-per-shard"), "{refusal}");
        assert!(refusal.contains("DELEGATED"), "{refusal}");
        assert!(refusal.contains("exported key"), "{refusal}");
        assert!(refusal.contains("2 or more"), "{refusal}");
    }
}
