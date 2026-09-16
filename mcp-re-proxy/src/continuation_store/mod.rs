// SPDX-License-Identifier: Apache-2.0
//! MRTR continuation correlation store (ADR-MCPS-047) — the fleet-shared tier that
//! carries a multi-round-trip continuation across a REPLICA SWITCH.
//!
//! The MRT flow is two independent signed legs (ADR-MCPS-024): a client opens an
//! `InputRequiredResult` on one replica, then answers it — with a fresh nonce and a
//! signed `HttpContinuation` — on ANY replica. The answer leg carries only DIGESTS
//! of the three bound handles (previous-request base, input-required-response base,
//! opaque `requestState`); to verify them the serving replica needs the exact BYTES
//! the open leg produced. Because the two legs may land on different replicas and
//! the proxy holds no per-session state, those bytes travel through this shared
//! store — the same durable tier (Redis) that backs cross-replica replay coherence
//! and the trust epoch.
//!
//! Design (stateless replicas, shared correlation tier):
//!   * OPEN leg on replica A: after A delegated-signs an `InputRequiredResult`, it
//!     records `{previous_request_base, input_required_response_base}` under the
//!     key `H(actor_id, requestState)`, with a bounded TTL.
//!   * ANSWER leg on replica B: B reads `requestState` from the request, derives the
//!     same key from the state and ITS OWN resolved actor, `peek`s the retained
//!     bases, and drives the EXISTING pure continuation binding
//!     ([`mcp_re_http_profile::RetainedContinuation`] +
//!     [`mcp_re_http_profile::dispatch`]): the retained bases are hashed and MUST
//!     equal the digests the client committed to under its signature. A missing
//!     entry (never opened, expired, or already answered) means no retained bases,
//!     so the pure dispatcher fails closed `continuation_binding_failed` — a splice
//!     or replayed continuation never admits. Only once the answer leg has been
//!     admitted does B `consume` the entry.
//!
//! **The key is scoped to the resolved actor, and the read is not destructive.**
//! Both properties exist for the same reason: `requestState` is minted by the inner
//! application, MCP-RE treats it as opaque, and nothing in the profile requires it to
//! be unguessable.
//!
//! The actor scope is what makes the answer leg the OPEN leg's actor's to give. The
//! continuation binding alone does not decide that: it compares digests of the open
//! leg's two signature bases, and those digests are not secrets — they are public
//! values derived from the exchange, held by the proxy and visible to anyone who saw
//! it. A second verified actor that knows them can therefore present a
//! correctly-binding answer leg, and without scoping the store hands it the victim's
//! retained bases and its approval completes. That is not a denial of service; it is
//! another actor answering a human-approval round trip. Deriving the key from the
//! actor the VERIFIER resolved — never from anything the request asserts — puts the
//! entry out of reach: a different actor derives a different key, which does not
//! exist.
//!
//! The peek/consume split is what keeps a refused request from destroying a live
//! entry. A destructive read ran before the binding was checked, so merely naming
//! another actor's `requestState` — or hitting a transient store failure on one's own
//! — deleted the retained bases permanently, and an approval round trip cannot be
//! re-opened.
//!
//! One-shot survives the split: `consume` reports whether IT removed the entry, so of
//! two concurrent answer legs exactly one is admitted and the other fails closed.
//!
//! **A live entry is never overwritten.** `requestState` is minted by the inner application
//! and treated as opaque, so two approvals open for one actor under one `requestState` are
//! whatever that application does; recording the second over the first destroys bases the
//! first still needs. The contract this replaced said "a fresh open leg supersedes a stale
//! one", which asserts an ORDER nothing establishes — the legs may be concurrent, and both
//! carry the same key and TTL shape. Whether a live entry EXISTS is decidable, so that is
//! the rule. See [`Creation`] and [`AsyncContinuationStore::create`].
//!
//! It is not a uniqueness assumption about `requestState`: the store refuses a collision it
//! can observe in its own keyspace, and assumes nothing about how the value was minted.
//!
//! **What the store is trusted for.** PROVENANCE — that an entry
//! under `mcp-re:cont:` was written by an open leg of this deployment. The dispatcher
//! compares the client's signed digests against the bytes this store returned, and
//! nothing establishes that those bytes came from an `InputRequiredResult` this fleet
//! signed; so a party able to WRITE the store plants bases under a key derived from
//! its OWN resolved actor, signs an answer leg over their digests, and the binding
//! passes — a completed human-approval round trip nobody approved. ASM-0047 registers
//! that premise and ASM-0048 what the Redis mechanism's replies mean. The client's RFC
//! 9421 signature carries the other half independently, so what rests on the store is
//! the human-approval property and not the caller's identity.
//!
//! **Confidentiality is claimed by nothing here.** A base carries the VALUE of every
//! component its message covered, and the profile's closed allowlist admits `authorization`
//! and `dpop` (`verify/floor/covered_components.rs`) — so a deployment whose clients cover
//! either retains a bearer credential at rest for the continuation TTL. ASM-0047 constrains
//! who may WRITE the tier and says nothing about who may read it.

use std::future::Future;
use std::pin::Pin;

mod in_memory;
mod key;

pub use in_memory::InMemoryContinuationStore;
// Re-exported rather than relocated: the key and the contract are one public surface to
// every consumer, and both legs reach for them together.
pub use key::continuation_key;
pub use key::CONTINUATION_KEY_PREFIX;

/// The retained open-leg signature bases an answer leg binds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedBases {
    /// The RFC 9421 signature base of the client's request that opened the
    /// `InputRequiredResult` (the open leg).
    pub previous_request_base: Vec<u8>,
    /// The RFC 9421 signature base of the delegated-signed `InputRequiredResult`
    /// response the open leg returned.
    pub input_required_response_base: Vec<u8>,
}

/// A fail-closed continuation-store failure. An operational outage is always safe
/// to treat as "no retained continuation" (fail closed) on the answer leg; on the
/// open leg it means the continuation could not be recorded, so the reply cannot be
/// honoured cross-replica and is failed closed rather than returned as answerable.
#[derive(Debug, Clone)]
pub enum ContinuationStoreError {
    /// The shared store could not be reached or answered.
    Unavailable { details: String },
}

impl std::fmt::Display for ContinuationStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContinuationStoreError::Unavailable { details } => {
                write!(f, "continuation store unavailable: {details}")
            }
        }
    }
}

/// What establishing a continuation entry found.
///
/// Two named outcomes and not a `bool`: at this boundary a boolean reads as "did it work",
/// which both arms answer yes to. Deliberately not a [`ContinuationStoreError`] variant
/// either — a collision is the store answering correctly, and folding it into the error arm
/// would make it indistinguishable from an outage at the one site that must tell them
/// apart: an outage may be retried, a taken key never will be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Creation {
    /// No live entry existed; this call established one.
    Stored,
    /// A live entry already exists under this key. It was NOT replaced.
    Collision,
}

/// A boxed store future (the store's ops are `async`, awaited on the serving path).
pub type ContinuationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ContinuationStoreError>> + Send + 'a>>;

/// The fleet-shared MRTR continuation correlation tier.
///
/// `create` establishes the open-leg bases under `key` (an actor-scoped `requestState`
/// digest) with a bounded TTL, refusing to disturb a live entry; `peek` reads them
/// without side effects; `consume` atomically removes them and reports whether it was
/// the caller that did so.
/// Implementations MUST be non-blocking — all three are awaited on the per-core
/// request path.
///
/// The read and the removal are separate on purpose. Removal is a side effect, and
/// the serving path's ordering invariant is that side effects happen only after the
/// request has been admitted: a destructive read would let an unadmitted request —
/// one whose continuation binding is about to fail — destroy a live entry.
pub trait AsyncContinuationStore: Send + Sync {
    /// Establish the retained bases under `key` with a `ttl_secs` lifetime, WITHOUT
    /// disturbing a live entry:
    ///
    /// ```text
    /// absent or expired key  ->  Ok(Creation::Stored)
    /// live key               ->  Ok(Creation::Collision), existing value unchanged
    /// backing failure        ->  Err(Unavailable)
    /// ```
    ///
    /// Implementations MUST make the test-and-set ATOMIC. A read followed by a write is
    /// two operations with a window between them, and the shape this refuses — two open
    /// legs racing on one key — is precisely the shape that lands in that window. Redis
    /// has the primitive (`SET key value NX PX ttl`); the single-process tier holds its
    /// map lock across both halves.
    ///
    /// The outcome is a VALUE rather than an error because `Collision` is not a failure
    /// of the store. The store did exactly what it was asked and is reporting what it
    /// found, and the caller's response differs from its response to an outage: an
    /// outage may be retried, a collision may not — the key will still be taken.
    fn create<'a>(
        &'a self,
        key: &'a str,
        bases: &'a RetainedBases,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, Creation>;

    /// Read the retained bases for `key` WITHOUT removing them. `Ok(None)` means no
    /// live entry (never opened, expired, or already answered) — the answer leg then
    /// fails closed on the continuation binding.
    fn peek<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, Option<RetainedBases>>;

    /// Atomically remove the entry for `key`, returning whether THIS call removed a
    /// live one.
    ///
    /// This is where the one-shot rule is enforced: of two concurrent answer legs
    /// that both peeked the same entry and both bound successfully, exactly one gets
    /// `true`. The other MUST be failed closed — it is answering a continuation that
    /// has already been answered.
    fn consume<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatch boundary the key is scoped to; a second deployment on the same
    /// shared store has a different one.
    const AUD: &str = "did:example:server-1";

    const ACTOR_A: &str = "client:example.com:did:example:host-a:client-key-1";
    const ACTOR_B: &str = "client:example.com:did:example:host-b:client-key-2";

    fn bases() -> RetainedBases {
        RetainedBases {
            previous_request_base: b"prev-base".to_vec(),
            input_required_response_base: b"irr-base".to_vec(),
        }
    }

    #[tokio::test]
    async fn peek_does_not_consume_and_consume_is_one_shot() {
        let store = InMemoryContinuationStore::new();
        let key = continuation_key(AUD, ACTOR_A, b"state-1");
        store.create(&key, &bases(), 300).await.unwrap();

        // Reading is free of side effects: the binding is checked against these bytes
        // BEFORE anything is removed, so a request that fails the binding cannot
        // destroy a live entry.
        assert_eq!(store.peek(&key).await.unwrap(), Some(bases()));
        assert_eq!(store.peek(&key).await.unwrap(), Some(bases()));

        // Removal is where one-shot lives: exactly one caller is told it removed it.
        assert!(store.consume(&key).await.unwrap());
        assert!(!store.consume(&key).await.unwrap());
        assert_eq!(store.peek(&key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn one_actors_entry_is_not_reachable_by_another() {
        // The cross-actor denial this scoping exists to stop: B naming A's requestState.
        let store = InMemoryContinuationStore::new();
        let a_key = continuation_key(AUD, ACTOR_A, b"state-1");
        store.create(&a_key, &bases(), 300).await.unwrap();

        let b_key = continuation_key(AUD, ACTOR_B, b"state-1");
        assert_ne!(a_key, b_key);
        assert_eq!(store.peek(&b_key).await.unwrap(), None);
        assert!(!store.consume(&b_key).await.unwrap());
        // A's open leg is untouched and still answerable.
        assert_eq!(store.peek(&a_key).await.unwrap(), Some(bases()));
    }

    // ----------------------------------------------------------------- R11-348 controls
    //
    // The contract `create` states, measured on the tier any test can run. The Redis twin
    // carries the same contract through `SET NX PX`, and its wire evidence is asserted in
    // `redis_continuation_store` — a mechanism-level fact these cannot see.

    /// CONTROL 1 — the first live open establishes the entry.
    ///
    /// The vacuity guard for everything below it: a `create` that refused unconditionally
    /// would satisfy controls 2, 3 and 4 while making the store useless.
    #[tokio::test]
    async fn the_first_open_leg_stores() {
        let store = InMemoryContinuationStore::new();
        let key = continuation_key(AUD, ACTOR_A, b"state-1");
        assert_eq!(
            store.create(&key, &bases(), 300).await.unwrap(),
            Creation::Stored
        );
        assert_eq!(store.peek(&key).await.unwrap(), Some(bases()));
    }

    /// CONTROL 2, 3 and 4 — a second open on a live key is refused, changes nothing, and
    /// leaves the incumbent answerable.
    ///
    /// One test because they are one event seen from three sides, and separating them
    /// would let the interesting one pass while another silently stopped holding: the
    /// refusal is only worth anything if the incumbent's bases SURVIVE it, and surviving
    /// is only worth anything if the incumbent can still be answered.
    #[tokio::test]
    async fn a_second_open_on_a_live_key_is_refused_and_changes_nothing() {
        let store = InMemoryContinuationStore::new();
        let key = continuation_key(AUD, ACTOR_A, b"state-1");
        store.create(&key, &bases(), 300).await.unwrap();

        let intruder = RetainedBases {
            previous_request_base: b"second-leg-prev".to_vec(),
            input_required_response_base: b"second-leg-irr".to_vec(),
        };
        // CONTROL 2.
        assert_eq!(
            store.create(&key, &intruder, 300).await.unwrap(),
            Creation::Collision,
        );
        // CONTROL 3. The bytes the FIRST approval will be answered against are the ones
        // still there — the defect this replaces is precisely that they were not.
        assert_eq!(store.peek(&key).await.unwrap(), Some(bases()));
        assert_ne!(store.peek(&key).await.unwrap(), Some(intruder));
        // CONTROL 4. And it is still answerable: one-shot consumption still succeeds, so
        // the human approval in flight completes rather than failing at the binding.
        assert!(store.consume(&key).await.unwrap());
    }

    /// CONTROL 5 — concurrent creators across the shared-store seam: exactly one Stored.
    ///
    /// Driven through `Arc<dyn AsyncContinuationStore>` rather than the concrete type,
    /// because the seam is where a caller could reintroduce a test-then-set: the property
    /// belongs to the trait, not to one implementation's internals.
    ///
    /// Two is the number the defect needs. A wider fan-out would measure the same thing
    /// with more scheduling noise; what must be impossible is that BOTH are told they
    /// stored, because both would then believe their bases are the ones retained.
    #[tokio::test]
    async fn concurrent_creators_yield_exactly_one_stored() {
        let store: std::sync::Arc<dyn AsyncContinuationStore> =
            std::sync::Arc::new(InMemoryContinuationStore::new());
        let key = continuation_key(AUD, ACTOR_A, b"state-1");

        let mut outcomes = Vec::new();
        for _ in 0..2 {
            let store = store.clone();
            let key = key.clone();
            outcomes.push(tokio::spawn(async move {
                store.create(&key, &bases(), 300).await.unwrap()
            }));
        }
        let mut stored = 0;
        let mut collided = 0;
        for handle in outcomes {
            match handle.await.expect("the task completed") {
                Creation::Stored => stored += 1,
                Creation::Collision => collided += 1,
            }
        }
        assert_eq!((stored, collided), (1, 1));
    }

    /// CONTROL 6 — an expired key may be established again.
    ///
    /// Expiry is the one thing that frees a key, and it needs no exception in `create`:
    /// an expired entry is not a live one. Without this the refusal would be permanent
    /// for any `requestState` an application reuses across approvals, which would turn a
    /// safety property into an outage.
    #[tokio::test]
    async fn an_expired_key_may_be_established_again() {
        let store = InMemoryContinuationStore::new();
        let key = continuation_key(AUD, ACTOR_A, b"state-1");
        // A TTL already in the past: the entry is written and is immediately not live.
        store.create(&key, &bases(), -1).await.unwrap();
        assert_eq!(store.peek(&key).await.unwrap(), None, "already expired");

        let next = RetainedBases {
            previous_request_base: b"later-prev".to_vec(),
            input_required_response_base: b"later-irr".to_vec(),
        };
        assert_eq!(
            store.create(&key, &next, 300).await.unwrap(),
            Creation::Stored
        );
        assert_eq!(store.peek(&key).await.unwrap(), Some(next));
    }

    /// CONTROL 7 — a backing-store failure stays `Unavailable` and never reads as a
    /// collision.
    ///
    /// The two have opposite consequences at the open leg: an outage is transient and is
    /// retried, a collision is permanent and is not. Folding a fault into `Collision`
    /// would fail a leg that a retry would have recorded; folding a collision into a
    /// fault would spend the retry budget and then overwrite nothing — but would also
    /// report the wrong cause for a continuation that can never be opened.
    #[tokio::test]
    async fn a_backing_failure_is_unavailable_and_never_a_collision() {
        struct BrokenStore;

        impl AsyncContinuationStore for BrokenStore {
            fn create<'a>(
                &'a self,
                _key: &'a str,
                _bases: &'a RetainedBases,
                _ttl_secs: i64,
            ) -> ContinuationFuture<'a, Creation> {
                Box::pin(async {
                    Err(ContinuationStoreError::Unavailable {
                        details: "the shared tier is down".to_owned(),
                    })
                })
            }
            fn peek<'a>(&'a self, _key: &'a str) -> ContinuationFuture<'a, Option<RetainedBases>> {
                Box::pin(async { Ok(None) })
            }
            fn consume<'a>(&'a self, _key: &'a str) -> ContinuationFuture<'a, bool> {
                Box::pin(async { Ok(false) })
            }
        }

        let outcome = BrokenStore.create("k", &bases(), 300).await;
        assert!(
            matches!(outcome, Err(ContinuationStoreError::Unavailable { .. })),
            "a tier that could not answer must not be reported as a taken key"
        );
    }
}
