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
//! One store serves one dispatch boundary, so the audience adds no separation the
//! actor does not already give.
//!
//! One-shot survives the split: `consume` reports whether IT removed the entry, so of
//! two concurrent answer legs exactly one is admitted and the other fails closed.
//!
//! The store is CONTENT-CORRELATION only: it holds public signature-base bytes (not
//! secret) keyed by an actor-scoped requestState digest, and its entries are
//! one-shot. It is never a trust root — trust comes from the client's RFC 9421
//! signature over the answer leg (incl. the continuation digests) and the digest
//! equality the dispatcher enforces against these bytes.

use std::future::Future;
use std::pin::Pin;

mod in_memory;
mod resolved_actor_id;
pub use in_memory::InMemoryContinuationStore;
pub use resolved_actor_id::ResolvedActorId;

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

/// A boxed store future (the store's ops are `async`, awaited on the serving path).
pub type ContinuationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ContinuationStoreError>> + Send + 'a>>;

/// The fleet-shared MRTR continuation correlation tier.
///
/// `store` records the open-leg bases under `key` (an actor-scoped `requestState`
/// digest) with a bounded TTL; `peek` reads them without side effects; `consume`
/// atomically removes them and reports whether it was the caller that did so.
/// Implementations MUST be non-blocking — all three are awaited on the per-core
/// request path.
///
/// The read and the removal are separate on purpose. Removal is a side effect, and
/// the serving path's ordering invariant is that side effects happen only after the
/// request has been admitted: a destructive read would let an unadmitted request —
/// one whose continuation binding is about to fail — destroy a live entry.
pub trait AsyncContinuationStore: Send + Sync {
    /// Record the retained bases under `key` with a `ttl_secs` lifetime. Overwrites
    /// any prior entry for the same key (a fresh open leg supersedes a stale one).
    fn store<'a>(
        &'a self,
        key: &'a str,
        bases: &'a RetainedBases,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, ()>;

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

/// The key prefix for a continuation correlation entry in the shared store.
pub const CONTINUATION_KEY_PREFIX: &str = "mcp-re:cont:";

/// Domain separator, so this digest cannot collide with any other SHA-256 the
/// profile computes over the same bytes.
const CONTINUATION_KEY_DOMAIN: &[u8] = b"mcp-re/continuation-key/v1";

/// Derive the shared-store key for a continuation from the RESOLVED ACTOR and the
/// opaque `requestState` bytes:
/// `mcp-re:cont:<base64url(SHA-256(domain || len(actor) || actor || requestState))>`.
///
/// Both legs derive it the same way — the open leg from the state it minted into the
/// reply, the answer leg from the state the client re-presents — and both use the
/// actor the VERIFIER resolved, never anything the request asserts. A matching answer
/// from the same actor therefore lands on the exact entry the open leg wrote, and an
/// answer from any other actor lands on a key that does not exist.
///
/// The AUDIENCE is in the key too, as it is in the replay composite key.
///
/// Without it two MCP-RE deployments — different audiences, different inner backends —
/// pointed at one Redis share a single continuation namespace, and nothing in config
/// or code enforced the assumption that they would not be. An actor trusted by both
/// could then open a leg against one dispatch boundary and answer it against the
/// other. The audience is what makes a signed request valid HERE and nowhere else, so
/// it belongs in any key that crosses a shared store.
///
/// Every field is length-prefixed so no tuple can be spelled as a different one by
/// moving a boundary between them.
///
/// `actor_id` is `role:trust_domain:subject:keyid`, so the scope is the KEY, not the
/// subject: both legs must be signed with the same key. This is a narrower identity than
/// the replay tier's `principal`, which drops the keyid deliberately
/// (`mcp_re_http_profile::replay`) — the two co-located designs do not use one notion of
/// "the same actor", and the difference is load-bearing in both directions. Here it is
/// what keeps a second key from collecting a human approval it did not ask for; there it
/// is what keeps one subject's rotation from reading as several budgets.
pub fn continuation_key(audience_id: &str, actor: &ResolvedActorId, state: &[u8]) -> String {
    use sha2::Digest;
    let actor_id = actor.as_str();
    let mut hasher = sha2::Sha256::new();
    hasher.update(CONTINUATION_KEY_DOMAIN);
    hasher.update((audience_id.len() as u64).to_be_bytes());
    hasher.update(audience_id.as_bytes());
    hasher.update((actor_id.len() as u64).to_be_bytes());
    hasher.update(actor_id.as_bytes());
    hasher.update(state);
    format!(
        "{CONTINUATION_KEY_PREFIX}{}",
        mcp_re_core::b64url_encode(&hasher.finalize())
    )
}

// ---- In-memory store (unit tests / single-process only) ---------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatch boundary the key is scoped to; a second deployment on the same
    /// shared store has a different one.
    const AUD: &str = "did:example:server-1";

    /// Two deployments sharing one Redis must not share one continuation namespace.
    /// The audience is what makes a signed request valid at THIS dispatch boundary,
    /// so an actor trusted by both cannot open a leg against one and answer it
    /// against the other.
    #[test]
    fn the_key_is_scoped_to_the_audience() {
        let here = continuation_key(AUD, &actor_a(), b"state-1");
        let elsewhere = continuation_key("did:example:server-2", &actor_a(), b"state-1");
        assert_ne!(here, elsewhere);
    }

    /// A resolved actor, as the verifier would hand one over.
    ///
    /// The tests go through [`ResolvedActorId::of`] because that is the only way to obtain
    /// the operand at all. A test that could spell an actor id directly would be measuring
    /// a key function that accepts strings, which is precisely the shape this type removes.
    fn resolved(subject: &str, keyid: &str) -> mcp_re_http_profile::ResolvedActor {
        mcp_re_http_profile::ResolvedActor {
            identity: mcp_re_http_profile::ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: subject.into(),
                keyid: keyid.into(),
            },
            verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32]).public_key(),
            slot: mcp_re_http_profile::SignerSlot::Request,
        }
    }

    fn actor_a() -> ResolvedActorId {
        ResolvedActorId::of(&resolved("did:example:host-a", "client-key-1"))
    }

    fn actor_b() -> ResolvedActorId {
        ResolvedActorId::of(&resolved("did:example:host-b", "client-key-2"))
    }

    fn bases() -> RetainedBases {
        RetainedBases {
            previous_request_base: b"prev-base".to_vec(),
            input_required_response_base: b"irr-base".to_vec(),
        }
    }

    #[tokio::test]
    async fn peek_does_not_consume_and_consume_is_one_shot() {
        let store = InMemoryContinuationStore::new();
        let key = continuation_key(AUD, &actor_a(), b"state-1");
        store.store(&key, &bases(), 300).await.unwrap();

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
        let a_key = continuation_key(AUD, &actor_a(), b"state-1");
        store.store(&a_key, &bases(), 300).await.unwrap();

        let b_key = continuation_key(AUD, &actor_b(), b"state-1");
        assert_ne!(a_key, b_key);
        assert_eq!(store.peek(&b_key).await.unwrap(), None);
        assert!(!store.consume(&b_key).await.unwrap());
        // A's open leg is untouched and still answerable.
        assert_eq!(store.peek(&a_key).await.unwrap(), Some(bases()));
    }

    #[test]
    fn key_is_stable_and_specific_to_both_inputs() {
        assert_eq!(
            continuation_key(AUD, &actor_a(), b"abc"),
            continuation_key(AUD, &actor_a(), b"abc")
        );
        assert_ne!(
            continuation_key(AUD, &actor_a(), b"abc"),
            continuation_key(AUD, &actor_a(), b"abd")
        );
        assert_ne!(
            continuation_key(AUD, &actor_a(), b"abc"),
            continuation_key(AUD, &actor_b(), b"abc")
        );
        assert!(continuation_key(AUD, &actor_a(), b"abc").starts_with(CONTINUATION_KEY_PREFIX));
    }

    #[test]
    fn the_actor_state_boundary_cannot_be_moved() {
        // Without the length prefix the two actors below feed the hasher the same bytes:
        // one's id ends where the other's `requestState` begins. An actor could then name
        // another's entry by spelling the split differently.
        let shorter = ResolvedActorId::of(&resolved("did:example:host", "k"));
        let longer = ResolvedActorId::of(&resolved("did:example:host", "kx"));
        assert_eq!(
            format!("{}{}", shorter.as_str(), "xy"),
            format!("{}{}", longer.as_str(), "y"),
            "the two spellings must genuinely collide, or this control proves nothing"
        );
        assert_ne!(
            continuation_key(AUD, &shorter, b"xy"),
            continuation_key(AUD, &longer, b"y")
        );
    }
}
