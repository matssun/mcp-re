// SPDX-License-Identifier: Apache-2.0
//! The Redis replay protocol the async store speaks: the clock it reads, and as pure
//! functions the `PX` arithmetic and the `REDIS_WAIT_QUORUM` decision. The pure half has
//! no clock and no I/O, so the TTL window and the fail-closed shortfall mapping are
//! unit-testable without a live Redis.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::shared_replay::ReplayStoreError;
use mcp_re_core::ReplayDecision;

/// A monotone-ish source of the CURRENT Unix time (seconds) for deriving the
/// server-side TTL. This is the proxy's IMPURE edge: `mcp-re-core` carries no
/// clock (the pure `ReplayCache` trait has none), so the *store*
/// owns its clock here. Production injects [`system_clock`]; tests inject a fixed
/// clock so the TTL arithmetic is deterministic.
pub type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// The production [`UnixClock`]: reads the system clock. An unreadable (pre-epoch)
/// clock reads as the latest representable instant, so every retain-until is already
/// past and the pre-store staleness guard refuses every insert (`Unavailable`)
/// instead of a zero `now` deriving a decades-long `PX`.
pub fn system_clock() -> UnixClock {
    Box::new(|| unix_seconds(SystemTime::now().duration_since(UNIX_EPOCH)))
}

fn unix_seconds(since_epoch: Result<Duration, std::time::SystemTimeError>) -> i64 {
    since_epoch.map_or(i64::MAX, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Compute the Redis `PX` TTL (milliseconds) from the already-skew-folded
/// retain-until instant and the CURRENT Unix time.
///
/// Factored out as a PURE function (no clock, no I/O) so the TTL arithmetic is
/// unit-testable everywhere without a live Redis: it is the load-bearing proof
/// that the H-8/H-9 `now = 0` bug is gone — with a real `now`, the TTL is the
/// intended `retain_until - now` WINDOW (seconds × 1000), not the absolute Unix
/// epoch (~1.78e12 ms ≈ 56 years).
///
/// Clamps to a non-negative duration. The seconds→ms multiply saturates so a
/// pathological retain-until cannot overflow the `PX` argument.
///
/// NOTE: in production this function is only ever reached for a STRICTLY-POSITIVE
/// remaining window — the store rejects a non-positive window pre-store via
/// [`is_stale_pre_store`](crate::shared_replay::is_stale_pre_store) (MCPS-08).
/// Because the remaining window is measured in WHOLE SECONDS, any admitted window
/// is `>= 1 s`, so the result is `>= 1000 ms`; the trailing `.max(1)` is therefore
/// an unreachable defensive floor for an admitted nonce. It only takes effect if
/// this pure function is called directly with a non-positive window (as the unit
/// test does), and never admits an already-stale nonce into the store.
pub(crate) fn compute_ttl_ms(expires_at_unix: i64, now_unix: i64) -> u64 {
    let ttl_secs = expires_at_unix.saturating_sub(now_unix).max(0);
    (ttl_secs as u64).saturating_mul(1000).max(1)
}

/// WAIT durability parameters for the `REDIS_WAIT_QUORUM` tier (ADR-MCPS-020):
/// after a fresh insert, require `quorum` replica acknowledgements within
/// `timeout_ms` before reporting `Fresh`, else fail closed (the nonce is not
/// durably replicated, so a failover could lose it → replay window).
#[derive(Clone, Copy)]
pub(crate) struct WaitQuorum {
    pub(crate) quorum: u32,
    pub(crate) timeout_ms: u64,
}

/// Whether a Redis `WAIT` reply (the number of replicas that acknowledged the
/// write) satisfies the configured quorum. Pure, so the
/// fail-closed-on-insufficient-acks decision (ADR-MCPS-020) is unit-testable
/// without a live multi-replica Redis; the command execution is proven by the
/// gated live-Redis e2e.
fn wait_quorum_satisfied(acked_replicas: i64, quorum: u32) -> bool {
    acked_replicas >= i64::from(quorum)
}

/// The `REDIS_WAIT_QUORUM` tier decision for a freshly-inserted nonce (ADR-MCPS-020),
/// given the `WAIT` ack count. Pure, so the fail-closed shortfall mapping is
/// unit-testable without a live multi-replica Redis.
///
/// - `acked >= quorum` ⇒ durably replicated ⇒ [`ReplayDecision::Fresh`].
/// - `acked < quorum` ⇒ **fail closed** with [`ReplayStoreError::Unavailable`].
///
/// On a shortfall the nonce IS present on the primary but is not durably replicated.
/// It is deliberately not compensating-`DEL`ed: the write may already have reached some
/// replicas, and dropping it under that uncertainty could reopen a replay window. The
/// cost is an availability edge — re-submitting the SAME signed request may be rejected
/// as `Replay` until the `PX` window elapses — so the contract is that a client treats
/// `replay_cache_unavailable` as retry-with-a-fresh-nonce.
pub(crate) fn classify_wait_acks(
    acked: i64,
    quorum: u32,
    timeout_ms: u64,
) -> Result<ReplayDecision, ReplayStoreError> {
    if wait_quorum_satisfied(acked, quorum) {
        Ok(ReplayDecision::Fresh)
    } else {
        Err(ReplayStoreError::Unavailable {
            details: format!(
                "redis WAIT got {acked} replica ack(s), need {quorum} within {timeout_ms}ms \
                 (fail closed; nonce not durably replicated; retry with a FRESH nonce — the \
                 same signed request may be rejected as replay until the TTL window elapses)"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    use super::classify_wait_acks;
    use super::compute_ttl_ms;
    use super::unix_seconds;
    use super::wait_quorum_satisfied;
    use super::ReplayDecision;
    use super::ReplayStoreError;
    use crate::shared_replay::is_stale_pre_store;

    /// A BUILD-capability assertion, no Redis needed: this binary can open a
    /// `rediss://` endpoint, so an operator can encrypt and authenticate the hop that
    /// carries admitted replay nonces and the trust-epoch counter. Without a TLS
    /// feature on the redis crate the scheme is rejected before any connection is
    /// attempted, and no configuration can encrypt that traffic. `Client::open` only
    /// parses, so this proves the capability without a server.
    #[test]
    fn the_build_can_open_a_tls_redis_endpoint() {
        assert!(
            redis::Client::open("rediss://mcp-re-redis:6379").is_ok(),
            "the redis crate must be built with a TLS feature or `rediss://` is \
             unusable and the replay/trust-epoch hop cannot be encrypted"
        );
    }

    /// PURE, no-Redis proof of the REDIS_WAIT_QUORUM fail-closed boundary
    /// (ADR-MCPS-020): the configured `quorum` is met only when at least that many
    /// replicas acknowledge; fewer acks (a `WAIT` timeout returns the partial
    /// count) is NOT satisfied → the store fails closed.
    #[test]
    fn wait_quorum_is_met_only_with_enough_acks() {
        assert!(
            wait_quorum_satisfied(2, 2),
            "exactly quorum acks is satisfied"
        );
        assert!(wait_quorum_satisfied(3, 2), "more than quorum is satisfied");
        assert!(
            !wait_quorum_satisfied(1, 2),
            "fewer than quorum fails closed"
        );
        assert!(!wait_quorum_satisfied(0, 1), "zero acks fails closed");
    }

    /// PURE, no-Redis proof of the WAIT-quorum-shortfall contract (ADR-MCPS-020):
    /// enough acks ⇒ Fresh; a shortfall ⇒ Unavailable, and the message states that the
    /// nonce is not durably replicated and that the client must retry with a FRESH nonce.
    #[test]
    fn wait_quorum_shortfall_fails_closed_with_fresh_nonce_contract() {
        assert_eq!(
            classify_wait_acks(2, 2, 100),
            Ok(ReplayDecision::Fresh),
            "meeting quorum must report Fresh"
        );
        match classify_wait_acks(1, 2, 100) {
            Err(ReplayStoreError::Unavailable { details }) => {
                assert!(
                    details.contains("not durably replicated"),
                    "message must explain the durability shortfall: {details}"
                );
                assert!(
                    details.contains("FRESH nonce"),
                    "message must state the retry-with-fresh-nonce contract: {details}"
                );
            }
            Ok(_) => panic!("a WAIT shortfall must NOT report Fresh"),
        }
        assert!(matches!(
            classify_wait_acks(0, 1, 100),
            Err(ReplayStoreError::Unavailable { .. })
        ));
    }

    /// PURE, no-Redis proof that the H-8/H-9 `now = 0` bug is gone: with a real
    /// `now`, the TTL is the intended `retain_until - now` WINDOW (seconds × 1000),
    /// NOT the absolute Unix epoch (~1.78e12 ms ≈ 56 years). Runs EVERYWHERE — it
    /// is the primary machine-checked proof; the live-Redis PTTL test only
    /// confirms it end-to-end. Deterministic: no clock, no I/O.
    #[test]
    fn ttl_ms_is_window_not_absolute_epoch() {
        // A realistic skew-folded retain-until (~2026) and a `now` 600s earlier.
        let retain_until: i64 = 1_779_998_730;
        let now: i64 = retain_until - 600;

        let ttl_ms = compute_ttl_ms(retain_until, now);

        // The whole bug in one assert: ttl_secs == retain_until - now.
        assert_eq!(
            ttl_ms,
            600 * 1000,
            "TTL must be the (retain_until - now) window, not the absolute epoch"
        );
        // And it is NOWHERE NEAR the absolute-epoch range the now=0 bug produced.
        let absolute_epoch_ms = (retain_until as u64) * 1000;
        assert!(
            ttl_ms < absolute_epoch_ms / 1000,
            "window TTL ({ttl_ms} ms) must be vastly smaller than the now=0 \
             absolute-epoch TTL ({absolute_epoch_ms} ms ≈ 56 years)"
        );
    }

    /// `compute_ttl_ms` itself still floors a non-positive raw window to a minimal
    /// positive TTL (never 0, never negative) — exercised here by calling the pure
    /// function directly. In production it is only ever REACHED for a
    /// strictly-positive window, because the store rejects a non-positive window
    /// pre-store (see `is_stale_pre_store` and the regression test below);
    /// an admitted whole-second window is `>= 1000 ms`, so the `.max(1)` floor is
    /// an unreachable defensive guard for an admitted nonce.
    #[test]
    fn ttl_ms_clamps_to_minimal_when_already_expired() {
        assert_eq!(compute_ttl_ms(1_000, 1_000), 1, "exactly-now → 1ms");
        assert_eq!(
            compute_ttl_ms(900, 1_000),
            1,
            "already-past → 1ms, not 0/neg"
        );
    }

    /// MCPS-08 regression (finding #142) — PURE, no-Redis proof of the pre-store
    /// staleness boundary. A NON-POSITIVE remaining window (`retain_until <= now`)
    /// must be flagged stale so the store rejects it BEFORE the SET NX,
    /// while a strictly-positive window is admitted to the store. WITHOUT the fix
    /// `compute_ttl_ms` clamped an already-expired window up to 1 ms and the store
    /// still SET NX'd it and returned `Fresh`; this predicate is the gate that now
    /// fails closed instead.
    #[test]
    fn nonpositive_window_is_flagged_stale_pre_store() {
        // Boundary: retain_until exactly at now is non-positive → reject.
        assert!(
            is_stale_pre_store(1_000, 1_000),
            "exactly-now is non-positive → reject"
        );
        // Already past → reject.
        assert!(
            is_stale_pre_store(900, 1_000),
            "already-past is non-positive → reject"
        );
        // A strictly-positive window (1s remaining) is admitted to the store.
        assert!(
            !is_stale_pre_store(1_001, 1_000),
            "a positive window is admitted"
        );
        // An epoch-anchored `now`: a real future retain-until is a huge positive
        // window (NOT stale) — the guard must not over-fire.
        assert!(
            !is_stale_pre_store(1_779_998_730, 0),
            "future retain-until is not stale"
        );
    }

    /// A pre-epoch clock reads as the latest instant, so every insert is stale.
    #[test]
    fn an_unreadable_clock_refuses_every_insert_pre_store() {
        let pre_epoch = UNIX_EPOCH.duration_since(UNIX_EPOCH + Duration::from_secs(1));
        assert!(pre_epoch.is_err(), "the probe must reach the error arm");
        assert!(is_stale_pre_store(1_779_998_730, unix_seconds(pre_epoch)));
    }
}
