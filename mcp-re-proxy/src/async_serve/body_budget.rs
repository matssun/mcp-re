// SPDX-License-Identifier: Apache-2.0
//! The BYTE half of per-core admission.
//!
//! `max_in_flight_requests` bounds how many requests a core serves at once, and was
//! reasoned about as if that bounded memory. It does not: each admitted slot may buffer a
//! whole `max_body_bytes` body, and the permit is taken BEFORE the body is read, so the
//! per-core product is `max_in_flight_requests x max_body_bytes` (256 x 16 MiB = 4 GiB by
//! default) and the fleet product multiplies that by the core count. A peer holding a valid
//! client certificate and NO valid signing key — one that cannot get a single request past
//! the verifier — can drive all of it.
//!
//! This owner is the bound. It is its own module because it owns four things the listener
//! does not: the ceiling, the atomic accounting, the RAII release, and what a peer is told
//! when the budget refuses. The listener asks it for a charge and holds the guard; it never
//! reads or adjusts the counter.
//!
//! **Charged as the body arrives, never from `Content-Length`.** A chunked or HTTP/2 body
//! declares no length, and a declared one is the peer's claim about what it is about to
//! send.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Limited;
use hyper::body::Incoming;

/// The per-core ceiling on request-body bytes buffered before verification, expressed as
/// a multiple of `max_body_bytes`.
///
/// The in-flight ceiling bounds request COUNT, and was reasoned about as if that bounded
/// memory. It does not: each admitted slot may buffer a whole `max_body_bytes` body, and
/// the permit is taken before the body is read, so the per-core product is
/// `max_in_flight_requests x max_body_bytes` (256 x 16 MiB = 4 GiB by default) and the
/// fleet product multiplies that by the core count. A peer holding a valid client
/// certificate and NO valid signing key — one that cannot get a single request past the
/// verifier — can drive all of it.
///
/// A multiple of `max_body_bytes` rather than an absolute number, so a deployment that
/// raises the body limit gets a proportional budget and a single maximum-size request is
/// always admissible. Four is enough that ordinary traffic (JSON-RPC bodies orders of
/// magnitude below the cap) never meets it, and small enough that the fleet total scales
/// with cores instead of with cores x 256.
pub(super) const BUFFERED_BODY_BUDGET_MULTIPLE: usize = 4;

/// A per-core ceiling on request-body bytes resident before verification.
///
/// Charged as the body arrives rather than from a declared `Content-Length`, so a
/// chunked or HTTP/2 body with no declared length is bounded by the same budget, and a
/// peer cannot understate what it is about to send.
pub(super) struct BodyByteBudget {
    ceiling: usize,
    charged: AtomicUsize,
}

impl BodyByteBudget {
    pub(super) fn new(ceiling: usize) -> Self {
        BodyByteBudget {
            ceiling,
            charged: AtomicUsize::new(0),
        }
    }

    /// Reserve `bytes`, or `None` when the core is already holding its ceiling. The
    /// returned guard releases on every path, including an aborted body read.
    pub(super) fn charge(self: &Arc<Self>, bytes: usize) -> Option<BodyBytes> {
        let mut current = self.charged.load(Ordering::Acquire);
        loop {
            if current.saturating_add(bytes) > self.ceiling {
                return None;
            }
            match self.charged.compare_exchange_weak(
                current,
                current + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(BodyBytes {
                        budget: Arc::clone(self),
                        bytes,
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }
}

/// Bytes charged against a [`BodyByteBudget`], returned on drop.
pub(super) struct BodyBytes {
    budget: Arc<BodyByteBudget>,
    bytes: usize,
}

impl BodyBytes {
    /// Fold `other` into this reservation, so a streamed body holds one guard rather
    /// than one per frame.
    fn absorb(&mut self, mut other: BodyBytes) {
        self.bytes += other.bytes;
        // `other`'s bytes are now this guard's; it must not release them twice.
        other.bytes = 0;
    }
}

impl Drop for BodyBytes {
    fn drop(&mut self) {
        self.budget.charged.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Why a request body could not be buffered.
///
/// The two are distinct on the wire because they mean different things to the peer. A
/// body that is too large, unreadable or too slow is that peer's own request being
/// refused (`413`). A body the core has no budget for is the core saying "not now" to a
/// request that may be perfectly well formed (`503`), which is a retry-safe shed.
pub(super) enum BodyReadError {
    /// The core is already holding its ceiling of pre-verification body bytes.
    BudgetExhausted,
    /// Over `max_body_bytes`, or the connection failed part-way through the body.
    Unreadable,
}

/// Buffer a request body under BOTH the per-request size cap and the core's aggregate
/// byte budget, charging as the bytes arrive.
///
/// Charging per frame rather than from `Content-Length` is what makes the budget hold: a
/// chunked or HTTP/2 body declares no length, and a declared one is the peer's claim
/// about what it is about to send. The returned [`BodyBytes`] holds the whole charge for
/// as long as the caller holds the bytes, and releases it on drop — including on a body
/// read that is abandoned part-way.
pub(super) async fn collect_body(
    body: Incoming,
    max_body: usize,
    budget: &Arc<BodyByteBudget>,
) -> Result<(Bytes, BodyBytes), BodyReadError> {
    // `Limited` enforces `max_body_bytes` with the same semantics the whole serving path
    // is documented to have; the budget is the aggregate bound layered over it.
    let limited = Limited::new(body, max_body);
    let mut limited = std::pin::pin!(limited);
    // A zero-byte charge always succeeds and gives an empty body a guard to return.
    let mut charge = budget.charge(0).ok_or(BodyReadError::BudgetExhausted)?;
    let mut collected: Vec<u8> = Vec::new();
    while let Some(frame) = limited.frame().await {
        let frame = frame.map_err(|_| BodyReadError::Unreadable)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        // Charged BEFORE the bytes are copied into `collected`, so the ceiling bounds
        // what is resident rather than trailing it by one frame.
        charge.absorb(
            budget
                .charge(data.len())
                .ok_or(BodyReadError::BudgetExhausted)?,
        );
        collected.extend_from_slice(&data);
    }
    Ok((Bytes::from(collected), charge))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R7-C060/C061: the in-flight ceiling bounds request COUNT, not bytes.
    ///
    /// Each admitted slot may buffer a whole `max_body_bytes` body and the permit is
    /// taken before the body is read, so the per-core product was
    /// `max_in_flight_requests x max_body_bytes` (256 x 16 MiB = 4 GiB) and the fleet
    /// product multiplied that by the core count. A peer holding a valid client
    /// certificate and no valid signing key — one that cannot get a single request past
    /// the verifier — could drive all of it. The budget is what turns that into a bound.
    #[test]
    fn the_core_budget_admits_a_maximum_size_body_and_refuses_past_the_ceiling() {
        let max_body = 16 * 1024 * 1024usize;
        let budget = Arc::new(BodyByteBudget::new(
            max_body * BUFFERED_BODY_BUDGET_MULTIPLE,
        ));

        // A single maximum-size request is always admissible: the budget is a multiple
        // of the per-request cap precisely so raising the cap cannot make one legal
        // request unservable.
        let held: Vec<BodyBytes> = (0..BUFFERED_BODY_BUDGET_MULTIPLE)
            .map(|i| {
                budget
                    .charge(max_body)
                    .unwrap_or_else(|| panic!("body {i} within the budget"))
            })
            .collect();

        assert!(
            budget.charge(1).is_none(),
            "the core is at its ceiling: one more byte of attacker-supplied body must \
             be refused, not buffered"
        );

        drop(held);
        assert!(
            budget.charge(max_body).is_some(),
            "the charge is released when the bytes are, so the ceiling is a bound on \
             what is RESIDENT rather than a lifetime quota"
        );
    }

    /// The charge is returned on every path, including a body read abandoned part-way.
    #[test]
    fn an_abandoned_body_read_returns_its_charge() {
        let budget = Arc::new(BodyByteBudget::new(100));
        {
            let mut charge = budget.charge(10).expect("first frame");
            charge.absorb(budget.charge(20).expect("second frame"));
            assert!(budget.charge(71).is_none(), "30 bytes are held");
        }
        assert!(
            budget.charge(100).is_some(),
            "dropping the guard mid-read returns everything it had charged"
        );
    }

    /// Folding frames into one guard must not double-release: the absorbed guard's
    /// bytes belong to the survivor.
    #[test]
    fn absorbing_a_frame_does_not_release_its_bytes_twice() {
        let budget = Arc::new(BodyByteBudget::new(10));
        let mut charge = budget.charge(4).expect("first");
        charge.absorb(budget.charge(6).expect("second"));
        assert!(
            budget.charge(1).is_none(),
            "all ten bytes are held by one guard"
        );
        drop(charge);
        assert!(budget.charge(10).is_some(), "and exactly ten come back");
    }
}
