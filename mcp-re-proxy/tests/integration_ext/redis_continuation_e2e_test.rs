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
//!   * `create` must apply a bounded TTL, so an unanswered continuation does not
//!     linger forever, and must refuse a LIVE key rather than overwrite it — the
//!     atomicity of that refusal is the create script's, which no in-memory tier can
//!     witness;
//!   * `create` must refuse a new key once the live set holds the store's capacity, and
//!     expiry and consumption must return slots, across replicas racing for the last one.
//!
//! None of that is observable from the in-memory store, and the serving-path tests
//! (`mrt_continuation_serving_test.rs`) run against the in-memory one. Until this
//! file, `RedisContinuationStore` had no test at all — its only reference in the tree
//! is the wiring in `app.rs`.
#![cfg(feature = "redis_replay")]

use mcp_re_proxy::continuation_store::AsyncContinuationStore;
use mcp_re_proxy::continuation_store::Consumption;
use mcp_re_proxy::continuation_store::ContinuationCapacity;
use mcp_re_proxy::continuation_store::ContinuationKey;
use mcp_re_proxy::continuation_store::Creation;
use mcp_re_proxy::continuation_store::RetainedHandles;
use mcp_re_proxy::redis_continuation_store::RedisContinuationStore;

/// The dispatch boundary the continuation key is scoped to; a second deployment on
/// the same shared Redis has a different one, and therefore a different namespace.
const AUD: &str = "did:example:server-1";

/// A verification product whose resolved actor is `subject`/`keyid`: a continuation key
/// exists only for the actor a verification resolved.
///
/// Produced by the request verifier over a request signed here, through a resolver that
/// trusts `keyid` for `subject` alone.
fn verified_as(subject: &str, keyid: &str) -> mcp_re_http_profile::VerifiedMcpRequest {
    use mcp_re_http_profile::{ArtifactBinding, ArtifactType, ResolvedActor, SignerSlot};
    const TARGET: &str = "https://example.test/mcp";
    const TOKEN: &str = "e2e-access-token";
    let key = mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32]);
    let block = mcp_re_http_profile::HttpRequestEvidenceBlock {
        profile: mcp_re_http_profile::PROFILE_TAG.into(),
        audience: mcp_re_http_profile::AudienceTuple {
            audience_id: AUD.into(),
            target_uri: TARGET.into(),
            route: None,
        },
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            TOKEN.as_bytes(),
        )],
        continuation: None,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    };
    let mut request = mcp_re_http_profile::HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {TOKEN}")),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
    };
    mcp_re_http_profile::sign_request_full(
        &mut request,
        &block,
        &key,
        keyid,
        1_700_000_000,
        1_700_000_300,
        "n",
    )
    .expect("the e2e request signs");
    let public = key.public_key();
    let resolve = |presented: &str, slot: SignerSlot| {
        (presented == keyid && slot == SignerSlot::Request).then(|| ResolvedActor {
            identity: mcp_re_http_profile::ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: subject.into(),
                keyid: keyid.into(),
            },
            verification_key: public.clone(),
            slot,
        })
    };
    let policy = mcp_re_http_profile::VerifierPolicy::default();
    mcp_re_http_profile::Verifier::new(&policy, &resolve)
        .verify_request(
            &request,
            &block.audience,
            &|_: &ArtifactBinding| None,
            1_700_000_100,
        )
        .expect("the e2e request verifies")
}

fn actor_a() -> mcp_re_http_profile::VerifiedMcpRequest {
    verified_as("did:example:host-a", "client-key-1")
}

fn actor_b() -> mcp_re_http_profile::VerifiedMcpRequest {
    verified_as("did:example:host-b", "client-key-2")
}

/// A per-run suffix so each run targets a key space of its own: entries live for
/// their TTL, and these tests assert a first `peek` finds what this run stored. Each test
/// also names its own state, because tests run in parallel and two can read one instant.
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

fn bases(tag: &str) -> RetainedHandles {
    RetainedHandles::over(
        format!("prev-base-{tag}").as_bytes(),
        format!("irr-base-{tag}").as_bytes(),
    )
}

/// Two INDEPENDENT connections to the same Redis — replica A and replica B, which is
/// the whole point of the shared tier.
async fn two_replicas(url: &str) -> (RedisContinuationStore, RedisContinuationStore) {
    let a = RedisContinuationStore::connect(url, ContinuationCapacity::DEFAULT)
        .await
        .expect("replica A connects to Redis");
    let b = RedisContinuationStore::connect(url, ContinuationCapacity::DEFAULT)
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
    let state = format!("state-one-shot-{}", run_id());
    let key = ContinuationKey::for_request(AUD, &actor_a(), state.as_bytes());
    let expected = bases("one-shot");

    // OPEN on A.
    a.create(&key, &expected, 300)
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
    assert_eq!(
        b_won,
        Consumption::Consumed,
        "the first consume removed the live entry"
    );
    assert_eq!(
        a_won,
        Consumption::NoLiveEntry,
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
    let state = format!("state-scoped-{}", run_id());
    let a_key = ContinuationKey::for_request(AUD, &actor_a(), state.as_bytes());
    let b_key = ContinuationKey::for_request(AUD, &actor_b(), state.as_bytes());
    assert_ne!(
        a_key, b_key,
        "the same requestState under two actors is two keys"
    );

    a.create(&a_key, &bases("scoped"), 300)
        .await
        .expect("A records");

    // The intruder can neither read nor destroy it.
    assert_eq!(b.peek(&b_key).await.expect("peek"), None);
    assert_eq!(
        b.consume(&b_key).await.expect("consume"),
        Consumption::NoLiveEntry,
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
    let store = RedisContinuationStore::connect(&url, ContinuationCapacity::DEFAULT)
        .await
        .expect("connects to Redis");
    let state = format!("state-ttl-{}", run_id());
    let key = ContinuationKey::for_request(AUD, &actor_a(), state.as_bytes());

    store
        .create(&key, &bases("ttl"), 1)
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

/// R11-348 CONTROL 5, live: two replicas opening the SAME key yield exactly one
/// `Stored`, and the loser never displaces the winner's bases.
///
/// The in-memory twin measures the same rule under a mutex, which is a different
/// mechanism: there the atomicity is the lock's, here it is `SET NX`'s, evaluated inside
/// a single-threaded Redis against writers in two processes that cannot see each other.
/// That is the arrangement the cross-replica deployment actually runs, and it is the only
/// one in which a read-then-write implementation would visibly fail.
#[tokio::test]
async fn two_replicas_opening_one_key_yield_exactly_one_stored() {
    let Some(url) = redis_url() else {
        return;
    };
    let (a, b) = two_replicas(&url).await;
    let state = format!("state-race-{}", run_id());
    let key = ContinuationKey::for_request(AUD, &actor_a(), state.as_bytes());

    let winner = bases("replica-a");
    let loser = bases("replica-b");

    let first = a.create(&key, &winner, 300).await.expect("A's open leg");
    let second = b.create(&key, &loser, 300).await.expect("B's open leg");

    assert_eq!(first, Creation::Stored, "the first open leg establishes it");
    assert_eq!(
        second,
        Creation::Collision,
        "a live key is not the second leg's to take"
    );

    // The bases a later answer leg binds against are the WINNER's, on either replica.
    assert_eq!(a.peek(&key).await.expect("A peeks"), Some(winner.clone()));
    assert_eq!(b.peek(&key).await.expect("B peeks"), Some(winner));

    // And the approval in flight is still answerable exactly once.
    assert_eq!(
        b.consume(&key).await.expect("B consumes"),
        Consumption::Consumed
    );
}

/// The same server on logical database 15, which only the capacity proof uses: the live
/// set is one per database, and the other tests here leave 300-second entries in theirs.
fn capacity_database(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("a redis URL");
    let authority = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{authority}/15")
}

/// R27-3, live: the live set is a hard global bound across replicas.
///
/// Sequential on purpose — one database, emptied first — so the counts below are this
/// test's alone. Twelve open legs race from two replicas for eight slots and exactly eight
/// are stored; a refused key was recorded nowhere; consuming one entry returns its slot;
/// and entries that expire return theirs without anything consuming them.
#[tokio::test]
async fn the_live_set_bounds_open_legs_across_replicas_and_frees_on_consume_and_expiry() {
    let Some(url) = redis_url() else {
        eprintln!("SKIP: MCP_RE_TEST_REDIS_URL unset — live Redis continuation proof skipped");
        return;
    };
    let url = capacity_database(&url);
    let mut admin = redis::Client::open(url.as_str())
        .expect("client")
        .get_multiplexed_async_connection()
        .await
        .expect("admin connects");
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut admin)
        .await
        .expect("database 15 emptied");

    let capacity = ContinuationCapacity::new(8).expect("in range");
    let a = std::sync::Arc::new(
        RedisContinuationStore::connect(&url, capacity)
            .await
            .expect("A"),
    );
    let b = std::sync::Arc::new(
        RedisContinuationStore::connect(&url, capacity)
            .await
            .expect("B"),
    );
    let key = |i: u32| ContinuationKey::for_request(AUD, &actor_a(), format!("cap-{i}").as_bytes());

    let mut legs = tokio::task::JoinSet::new();
    for i in 0..12 {
        let store = if i % 2 == 0 { a.clone() } else { b.clone() };
        legs.spawn(async move { (i, store.create(&key(i), &bases("cap"), 300).await) });
    }
    let mut stored = Vec::new();
    let mut refused = Vec::new();
    while let Some(joined) = legs.join_next().await {
        match joined.expect("leg ran") {
            (i, Ok(Creation::Stored)) => stored.push(i),
            (i, Ok(Creation::AtCapacity)) => refused.push(i),
            other => panic!("a fresh key is stored or refused for capacity, got {other:?}"),
        }
    }
    assert_eq!(
        stored.len(),
        8,
        "exactly the capacity is stored: {stored:?}"
    );
    assert_eq!(refused.len(), 4, "the rest are refused: {refused:?}");
    for i in &refused {
        assert_eq!(
            a.peek(&key(*i)).await.expect("peek"),
            None,
            "a refused key holds nothing"
        );
    }

    // Consuming returns a slot; the next new key fits, and the one after it does not.
    assert_eq!(
        a.consume(&key(stored[0])).await.expect("consume"),
        Consumption::Consumed
    );
    assert_eq!(
        b.create(&key(100), &bases("cap"), 1).await.expect("create"),
        Creation::Stored
    );
    assert_eq!(
        b.create(&key(101), &bases("cap"), 1).await.expect("create"),
        Creation::AtCapacity
    );

    // Expiry returns a slot with nothing consuming it.
    tokio::time::sleep(std::time::Duration::from_millis(1_400)).await;
    assert_eq!(
        a.create(&key(102), &bases("cap"), 300)
            .await
            .expect("create"),
        Creation::Stored
    );

    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut admin)
        .await
        .expect("cleanup");
}
