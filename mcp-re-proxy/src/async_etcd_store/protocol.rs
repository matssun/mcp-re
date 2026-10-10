// SPDX-License-Identifier: Apache-2.0
//! The etcd v3 JSON-gateway protocol the async store speaks: the clock it reads, and as
//! pure functions the lease-TTL arithmetic, the lease-grant and put-if-absent transaction
//! bodies, and the two reply readers. The pure half has no clock and no I/O, so the wire
//! shape and the decision mapping are unit-testable without a live etcd.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde_json::json;
use serde_json::Value;

use crate::shared_replay::ReplayStoreError;
use mcp_re_core::ReplayDecision;

/// A source of the CURRENT Unix time (seconds) for deriving the lease TTL. The
/// proxy's IMPURE edge: `mcp-re-core` carries no clock (the pure `ReplayCache`
/// trait has none), so the *store* owns its clock here. Production
/// injects [`system_clock`]; tests inject a fixed clock so the TTL arithmetic is
/// deterministic.
pub type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// The production [`UnixClock`]: reads the system clock. A clock that predates the
/// Unix epoch (impossible on a sane host) clamps to 0 rather than panicking.
pub fn system_clock() -> UnixClock {
    Box::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// Compute the etcd lease TTL (SECONDS) from the already-skew-folded retain-until
/// instant and the CURRENT Unix time.
///
/// Factored out as a PURE function (no clock, no I/O) so the TTL arithmetic is
/// unit-testable everywhere without a live etcd: it is the load-bearing proof
/// that the MCPS-090 `now = 0` bug is gone — with a real `now`, the TTL is the
/// intended `retain_until - now` WINDOW (seconds), not the absolute Unix epoch
/// (~1.78e9 s ≈ 56 years, which would make leases never expire → unbounded
/// keyspace growth / DoS).
///
/// The `.max(1)` floor is defensive to this pure function only: the store rejects a
/// non-positive window via `shared_replay::is_stale_pre_store` before reaching it,
/// and etcd rejects a non-positive lease TTL.
pub(crate) fn compute_ttl_secs(expires_at_unix: i64, now_unix: i64) -> i64 {
    expires_at_unix.saturating_sub(now_unix).max(1)
}

/// The etcd lease-grant request body for `POST /v3/lease/grant`: a `TTL` in
/// seconds and `ID: 0` (let etcd assign the lease id). Pure, so the wire shape is
/// unit-testable without a live etcd.
pub(crate) fn build_lease_grant_body(ttl_secs: i64) -> Value {
    json!({ "TTL": ttl_secs, "ID": 0 })
}

/// The etcd put-if-absent transaction body for `POST /v3/kv/txn`.
///
/// `compare`: the key's `CREATE` revision equals `0` — true IFF the key does not
/// yet exist (a never-created key has create_revision 0). On success
/// (`succeeded`) the key is absent, so `success` PUTs it under the granted lease;
/// `failure` is empty (the key already exists ⇒ Replay). etcd v3 JSON encodes
/// keys/values as STANDARD base64. The lease is passed as a STRING (etcd's JSON
/// gateway encodes 64-bit ints as strings to survive JS number precision).
pub(crate) fn build_txn_body(key_b64: &str, value_b64: &str, lease_id: i64) -> Value {
    json!({
        "compare": [{
            "key": key_b64,
            "target": "CREATE",
            "result": "EQUAL",
            "create_revision": "0"
        }],
        "success": [{
            "request_put": {
                "key": key_b64,
                "value": value_b64,
                "lease": lease_id.to_string()
            }
        }],
        "failure": []
    })
}

/// Parse the lease id from an etcd `lease/grant` response. The JSON gateway
/// returns `{ "ID": "<int-as-string>", "TTL": "<int-as-string>", ... }` (64-bit
/// ints as strings). A missing/non-positive/unparseable id is an operational failure →
/// fail closed (an unleased put would never expire — the very DoS we guard).
pub(crate) fn parse_lease_id(resp: &Value) -> Result<i64, ReplayStoreError> {
    let raw = resp
        .get("ID")
        .ok_or_else(|| ReplayStoreError::Unavailable {
            details: "etcd lease/grant response missing ID".to_string(),
        })?;
    // The gateway encodes the id as a string; tolerate a raw number too.
    let id = match raw {
        Value::String(s) => s.parse::<i64>().ok(),
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
    .ok_or_else(|| ReplayStoreError::Unavailable {
        details: format!("etcd lease/grant ID not an integer: {raw}"),
    })?;
    if id <= 0 {
        return Err(ReplayStoreError::Unavailable {
            details:
                "etcd lease/grant returned a non-positive lease id (etcd issues only positive ids)"
                    .to_string(),
        });
    }
    Ok(id)
}

/// Map an etcd txn response to a [`ReplayDecision`]. etcd sets `succeeded: true`
/// when the compare held — i.e. the key was absent and the put landed ⇒ `Fresh`.
/// `succeeded: false` (or absent, which etcd uses for a false compare) means the
/// key already existed ⇒ `Replay`. Pure, so the decision mapping is unit-testable
/// without a live etcd.
pub(crate) fn decision_from_txn(resp: &Value) -> ReplayDecision {
    // etcd omits `succeeded` (defaults false) when the compare fails.
    let succeeded = resp
        .get("succeeded")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if succeeded {
        ReplayDecision::Fresh
    } else {
        ReplayDecision::Replay
    }
}

#[cfg(test)]
mod tests {
    use super::build_lease_grant_body;
    use super::build_txn_body;
    use super::compute_ttl_secs;
    use super::decision_from_txn;
    use super::parse_lease_id;
    use super::ReplayDecision;
    use super::ReplayStoreError;
    use serde_json::json;

    /// PURE, no-etcd proof that the MCPS-090 `now = 0` bug is gone: with a real
    /// `now`, the lease TTL is the intended `retain_until - now` WINDOW (seconds),
    /// NOT the absolute Unix epoch (~1.78e9 s ≈ 56 years). Deterministic.
    #[test]
    fn ttl_secs_is_window_not_absolute_epoch() {
        let retain_until: i64 = 1_779_998_730;
        let now: i64 = retain_until - 600;
        let ttl = compute_ttl_secs(retain_until, now);
        assert_eq!(
            ttl, 600,
            "TTL must be the (retain_until - now) window in seconds"
        );
        // Nowhere near the absolute-epoch range the now=0 bug produced.
        let now_zero_bug = compute_ttl_secs(retain_until, 0);
        assert_eq!(
            now_zero_bug, retain_until,
            "the now=0 bug would make TTL the absolute epoch"
        );
        assert!(
            ttl < now_zero_bug / 1000,
            "window TTL must be vastly smaller than the now=0 epoch TTL"
        );
    }

    /// The pure function's floor: a retain-until at/before `now` clamps to 1s. The
    /// store rejects such a window pre-store, so this is unreachable from it.
    #[test]
    fn ttl_secs_clamps_to_minimal_when_already_expired() {
        assert_eq!(compute_ttl_secs(1_000, 1_000), 1, "exactly-now → 1s");
        assert_eq!(
            compute_ttl_secs(900, 1_000),
            1,
            "already-past → 1s, not 0/neg"
        );
    }

    /// The lease-grant body carries the bounded TTL and ID 0 (etcd assigns the id).
    #[test]
    fn lease_grant_body_carries_bounded_ttl() {
        let body = build_lease_grant_body(600);
        assert_eq!(body["TTL"], json!(600));
        assert_eq!(body["ID"], json!(0));
    }

    /// The txn body is a linearizable put-if-absent: compare CREATE == 0 (key
    /// absent), success PUTs the value under the lease, failure is empty.
    #[test]
    fn txn_body_is_put_if_absent_under_lease() {
        let body = build_txn_body("a2V5", "dmFs", 42);
        let cmp = &body["compare"][0];
        assert_eq!(cmp["target"], json!("CREATE"));
        assert_eq!(cmp["result"], json!("EQUAL"));
        assert_eq!(
            cmp["create_revision"],
            json!("0"),
            "absent <=> create_revision 0"
        );
        assert_eq!(cmp["key"], json!("a2V5"));
        let put = &body["success"][0]["request_put"];
        assert_eq!(put["key"], json!("a2V5"));
        assert_eq!(put["value"], json!("dmFs"));
        assert_eq!(
            put["lease"],
            json!("42"),
            "lease id is a string (JSON gateway 64-bit encoding)"
        );
        assert_eq!(
            body["failure"],
            json!([]),
            "key-present branch is a no-op (Replay)"
        );
    }

    /// `succeeded: true` ⇒ the compare held (key absent, put landed) ⇒ Fresh.
    #[test]
    fn txn_succeeded_is_fresh() {
        assert_eq!(
            decision_from_txn(&json!({ "succeeded": true })),
            ReplayDecision::Fresh
        );
    }

    /// `succeeded: false` AND an omitted `succeeded` (etcd's false-compare shape)
    /// both mean the key already existed ⇒ Replay (fail-safe default).
    #[test]
    fn txn_not_succeeded_is_replay() {
        assert_eq!(
            decision_from_txn(&json!({ "succeeded": false })),
            ReplayDecision::Replay
        );
        assert_eq!(
            decision_from_txn(&json!({ "header": { "revision": "7" } })),
            ReplayDecision::Replay,
            "an omitted `succeeded` (false compare) must default to Replay, never Fresh"
        );
    }

    /// The lease id is parsed from the JSON gateway's STRING encoding (and a raw
    /// number is tolerated).
    #[test]
    fn parse_lease_id_accepts_string_and_number() {
        assert_eq!(
            parse_lease_id(&json!({ "ID": "7587880697336124931" })).unwrap(),
            7587880697336124931
        );
        assert_eq!(parse_lease_id(&json!({ "ID": 1234 })).unwrap(), 1234);
    }

    /// A missing / zero / unparseable lease id is an operational failure → fail
    /// closed: an unleased put would never expire (the MCPS-090 DoS we guard).
    #[test]
    fn parse_lease_id_fails_closed_on_missing_zero_or_garbage() {
        assert!(matches!(
            parse_lease_id(&json!({ "TTL": "600" })),
            Err(ReplayStoreError::Unavailable { .. })
        ));
        assert!(matches!(
            parse_lease_id(&json!({ "ID": "0" })),
            Err(ReplayStoreError::Unavailable { .. })
        ));
        for negative in [json!({ "ID": "-7" }), json!({ "ID": -7 })] {
            assert!(matches!(
                parse_lease_id(&negative),
                Err(ReplayStoreError::Unavailable { .. })
            ));
        }
        assert!(matches!(
            parse_lease_id(&json!({ "ID": "not-an-int" })),
            Err(ReplayStoreError::Unavailable { .. })
        ));
    }
}
