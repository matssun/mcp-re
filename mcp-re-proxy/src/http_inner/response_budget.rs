// SPDX-License-Identifier: Apache-2.0
//! The process-wide ceiling on inner-response bytes being read.
//!
//! One authority: the shared byte pool the inner plane draws on while it buffers a
//! backend's answer. Each data frame is charged to the pool BEFORE it is appended, never
//! from a declared `Content-Length`, and the charge is an RAII guard released when the
//! read ends. The per-response cap stays with the caller; this module owns only the
//! ceiling shared by every core, so `in_flight x MAX_INNER_RESPONSE_BYTES` is not the
//! memory bound.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::sync::Semaphore;

/// The pool is this many maximum-size responses, so one maximum response is always
/// admissible on an otherwise idle pool.
pub(super) const INNER_RESPONSE_BUDGET_MULTIPLE: usize = 8;

/// Process-wide ceiling on inner-response bytes being read; the pool is shared by every
/// core, so the ceiling is too.
pub(super) const INNER_RESPONSE_BUDGET_BYTES: usize =
    super::MAX_INNER_RESPONSE_BYTES * INNER_RESPONSE_BUDGET_MULTIPLE;

/// How a charged read of an inner response body ended.
pub(super) enum ResponseRead {
    /// The whole body, within the per-response cap and the process budget.
    Body(Vec<u8>),
    /// The body stream broke or passed the per-response cap: a fact about the backend.
    Unreadable,
    /// The process budget could not cover the next frame: a fact about this process.
    BudgetExhausted,
}

/// Read `body` to its end, charging each data frame to `budget` before it is buffered.
/// The charge is held until the read ends and returned to the pool on every exit.
pub(super) async fn collect_charged<B>(body: B, max: usize, budget: &Arc<Semaphore>) -> ResponseRead
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut body = Box::pin(http_body_util::Limited::new(body, max));
    let Ok(mut guard) = Arc::clone(budget).try_acquire_many_owned(0) else {
        return ResponseRead::BudgetExhausted;
    };
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return ResponseRead::Unreadable;
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let Ok(len) = u32::try_from(data.len()) else {
            return ResponseRead::BudgetExhausted;
        };
        let Ok(permit) = Arc::clone(budget).try_acquire_many_owned(len) else {
            return ResponseRead::BudgetExhausted;
        };
        guard.merge(permit);
        collected.extend_from_slice(&data);
    }
    ResponseRead::Body(collected)
}

#[cfg(test)]
mod tests {
    use http_body_util::Full;

    use super::*;

    #[tokio::test]
    async fn a_response_past_the_process_budget_is_refused_and_its_charge_returned() {
        let budget = Arc::new(Semaphore::new(8));
        let body = Full::new(Bytes::from_static(&[7u8; 9]));
        let read = collect_charged(body, 1024, &budget).await;
        assert!(matches!(read, ResponseRead::BudgetExhausted));
        assert_eq!(budget.available_permits(), 8);
    }

    #[tokio::test]
    async fn a_charge_held_elsewhere_bounds_the_next_read_and_is_returned_after_it() {
        let budget = Arc::new(Semaphore::new(8));
        let held = Arc::clone(&budget).try_acquire_many_owned(6).unwrap();
        let body = || Full::new(Bytes::from_static(&[1u8; 4]));
        assert!(matches!(
            collect_charged(body(), 1024, &budget).await,
            ResponseRead::BudgetExhausted
        ));
        drop(held);
        match collect_charged(body(), 1024, &budget).await {
            ResponseRead::Body(b) => assert_eq!(b.len(), 4),
            _ => panic!("the freed budget must admit the read"),
        }
        assert_eq!(budget.available_permits(), 8);
    }

    #[tokio::test]
    async fn the_per_response_cap_still_refuses_as_unreadable() {
        let budget = Arc::new(Semaphore::new(1024));
        let body = Full::new(Bytes::from_static(&[2u8; 10]));
        assert!(matches!(
            collect_charged(body, 4, &budget).await,
            ResponseRead::Unreadable
        ));
    }
}
