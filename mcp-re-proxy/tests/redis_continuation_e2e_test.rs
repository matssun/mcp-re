//! Live proof of the MRTR continuation store's Redis backing (ADR-MCPS-047).
//!
//! Compiled ONLY under the `redis_replay` feature (the same feature that compiles
//! [`RedisContinuationStore`]), and gated at runtime on `MCP_RE_TEST_REDIS_URL`:
//! unset ⇒ print a skip notice and return successfully, so the default lane stays
//! green without Redis. `MCP_RE_REQUIRE_LIVE_INFRA` turns a skip into a failure for
//! CI jobs that DO bring up Redis.
//!
//! **Why this file exists.** The store's three ops are three raw Redis commands, and
//! the serving path's safety properties are properties OF those commands:
//!
//!   * `peek` must be non-destructive (`GET`), or a request that is about to fail the
//!     continuation binding destroys a live approval leg on its way out;
//!   * `consume` must report whether IT removed the entry (`DEL`'s count), because
//!     that count — not the read — is what makes a continuation answerable at most
//!     once across replicas;
//!   * `store` must apply a bounded TTL, so an unanswered continuation does not
//!     linger forever.
//!
//! None of that is observable from the in-memory store, and the serving-path tests
//! (`mrt_continuation_serving_test.rs`) run against the in-memory one. Until this
//! file, `RedisContinuationStore` had no test at all — its only reference in the tree
//! is the wiring in `app.rs`.
#![cfg(feature = "redis_replay")]

use mcp_re_proxy::continuation_store::continuation_key;
use mcp_re_proxy::continuation_store::AsyncContinuationStore;
use mcp_re_proxy::continuation_store::RetainedBases;
use mcp_re_proxy::redis_continuation_store::RedisContinuationStore;

const ACTOR_A: &str = "client:example.com:did:example:host-a:client-key-1";
const ACTOR_B: &str = "client:example.com:did:example:host-b:client-key-2";

/// A per-run suffix so each run targets a key space of its own: entries live for
/// their TTL, and these tests assert a first `peek` finds what this run stored.
fn run_id() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos()
}

fn require_live_infra() -> bool {
    std::env::var("MCP_RE_REQUIRE_LIVE_INFRA")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
}

fn redis_url() -> Option<String> {
    let url = std::env::var("MCP_RE_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && require_live_infra() {
        panic!(
            "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable \
             — this live e2e MUST run under CI, not skip"
        );
    }
    url
}

fn bases(tag: &str) -> RetainedBases {
    RetainedBases {
        previous_request_base: format!("prev-base-{tag}").into_bytes(),
        input_required_response_base: format!("irr-base-{tag}").into_bytes(),
    }
}

/// Two INDEPENDENT connections to the same Redis — replica A and replica B, which is
/// the whole point of the shared tier.
async fn two_replicas(url: &str) -> (RedisContinuationStore, RedisContinuationStore) {
    let a = RedisContinuationStore::connect(url)
        .await
        .expect("replica A connects to Redis");
    let b = RedisContinuationStore::connect(url)
        .await
        .expect("replica B connects to Redis");
    (a, b)
}

#[tokio::test]
async fn peek_is_non_destructive_and_consume_is_one_shot_across_replicas() {
    let Some(url) = redis_url() else {
        eprintln!("SKIP: MCP_RE_TEST_REDIS_URL unset — live Redis continuation proof skipped");
        return;
    };
    let (a, b) = two_replicas(&url).await;
    let state = format!("state-{}", run_id());
    let key = continuation_key(ACTOR_A, state.as_bytes());
    let expected = bases("one-shot");

    // OPEN on A.
    a.store(&key, &expected, 300)
        .await
        .expect("A records the open leg");

    // B — which never saw the open leg — reads it. Repeatedly: reading is what the
    // binding check does, and it must not consume, or a request about to be REJECTED
    // would take a live continuation down with it.
    for i in 0..3 {
        assert_eq!(
            b.peek(&key).await.expect("peek"),
            Some(expected.clone()),
            "peek #{i} must not have consumed the entry"
        );
    }
    // A can still see it too — no replica's read affects another's.
    assert_eq!(a.peek(&key).await.expect("peek"), Some(expected.clone()));

    // Exactly one replica is told it removed the entry. That count IS the one-shot
    // decision: the loser must fail its answer leg closed.
    let b_won = b.consume(&key).await.expect("B consumes");
    let a_won = a.consume(&key).await.expect("A consumes");
    assert!(b_won, "the first consume removed the live entry");
    assert!(
        !a_won,
        "the second consume removed nothing — the continuation is one-shot"
    );

    assert_eq!(
        b.peek(&key).await.expect("peek"),
        None,
        "the entry is gone after it was consumed"
    );
}

#[tokio::test]
async fn one_actors_continuation_is_not_reachable_by_another() {
    // The serving path derives the key from the VERIFIER-RESOLVED actor, so a second
    // verified peer presenting the same requestState addresses a key that does not
    // exist. Proven here against real Redis, not just the in-memory map.
    let Some(url) = redis_url() else {
        eprintln!("SKIP: MCP_RE_TEST_REDIS_URL unset — live Redis continuation proof skipped");
        return;
    };
    let (a, b) = two_replicas(&url).await;
    let state = format!("state-{}", run_id());
    let a_key = continuation_key(ACTOR_A, state.as_bytes());
    let b_key = continuation_key(ACTOR_B, state.as_bytes());
    assert_ne!(
        a_key, b_key,
        "the same requestState under two actors is two keys"
    );

    a.store(&a_key, &bases("scoped"), 300)
        .await
        .expect("A records");

    // The intruder can neither read nor destroy it.
    assert_eq!(b.peek(&b_key).await.expect("peek"), None);
    assert!(
        !b.consume(&b_key).await.expect("consume"),
        "nothing to remove"
    );
    assert_eq!(
        a.peek(&a_key).await.expect("peek"),
        Some(bases("scoped")),
        "the victim's open leg is untouched and still answerable"
    );

    a.consume(&a_key).await.expect("cleanup");
}

#[tokio::test]
async fn a_recorded_continuation_carries_a_bounded_ttl() {
    // An unanswered continuation must not linger forever. A 1s TTL is observable
    // within a test; the production TTL is `DEFAULT_CONTINUATION_TTL_SECS`.
    let Some(url) = redis_url() else {
        eprintln!("SKIP: MCP_RE_TEST_REDIS_URL unset — live Redis continuation proof skipped");
        return;
    };
    let store = RedisContinuationStore::connect(&url)
        .await
        .expect("connects to Redis");
    let state = format!("state-{}", run_id());
    let key = continuation_key(ACTOR_A, state.as_bytes());

    store
        .store(&key, &bases("ttl"), 1)
        .await
        .expect("records with a 1s TTL");
    assert!(
        store.peek(&key).await.expect("peek").is_some(),
        "live immediately after"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    assert_eq!(
        store.peek(&key).await.expect("peek"),
        None,
        "Redis expired the entry — an unanswered continuation does not linger"
    );
}
