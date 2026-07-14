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
//!     key `H(requestState)`, with a bounded TTL.
//!   * ANSWER leg on replica B: B reads `requestState` from the request, derives the
//!     same key, `take`s (get-and-delete — one-shot) the retained bases, and drives
//!     the EXISTING pure continuation binding
//!     ([`mcp_re_http_profile::RetainedContinuation`] +
//!     [`mcp_re_http_profile::dispatch`]): the retained bases are hashed and MUST
//!     equal the digests the client committed to under its signature. A missing
//!     entry (never opened, expired, or already answered) means no retained bases,
//!     so the pure dispatcher fails closed `continuation_binding_failed` — a splice
//!     or replayed continuation never admits.
//!
//! The store is CONTENT-CORRELATION only: it holds public signature-base bytes (not
//! secret) keyed by a requestState digest, and its entries are one-shot. It is never
//! a trust root — trust comes from the client's RFC 9421 signature over the answer
//! leg (incl. the continuation digests) and the digest equality the dispatcher
//! enforces against these bytes.

use std::future::Future;
use std::pin::Pin;

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
/// `store` records the open-leg bases under `key` (a `requestState` digest) with a
/// bounded TTL; `take` atomically reads AND removes them (one-shot). Implementations
/// MUST be non-blocking — both are awaited on the per-core request path.
pub trait AsyncContinuationStore: Send + Sync {
    /// Record the retained bases under `key` with a `ttl_secs` lifetime. Overwrites
    /// any prior entry for the same key (a fresh open leg supersedes a stale one).
    fn store<'a>(
        &'a self,
        key: &'a str,
        bases: &'a RetainedBases,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, ()>;

    /// Atomically read AND delete the retained bases for `key`. `Ok(None)` means no
    /// live entry (never opened, expired, or already answered) — the answer leg then
    /// fails closed on the continuation binding. `take` is the ONE-SHOT semantics: a
    /// given continuation can be answered at most once.
    fn take<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, Option<RetainedBases>>;
}

/// The key prefix for a continuation correlation entry in the shared store.
pub const CONTINUATION_KEY_PREFIX: &str = "mcp-re:cont:";

/// Derive the shared-store key for a continuation from the opaque `requestState`
/// bytes: `mcp-re:cont:<base64url(SHA-256(requestState))>`. Both legs derive it the
/// same way (the open leg from the state it minted into the reply, the answer leg
/// from the state the client re-presents), so a matching answer lands on the exact
/// entry the open leg wrote.
pub fn continuation_key(request_state: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(request_state);
    format!("{CONTINUATION_KEY_PREFIX}{}", mcp_re_core::b64url_encode(&digest))
}

// ---- In-memory store (unit tests / single-process only) ---------------------

/// A single-process in-memory continuation store — for unit tests and single-replica
/// runs ONLY. It cannot carry a continuation across replicas (each process has its
/// own map), so a fleet MUST wire the Redis store; this exists so the serving path
/// has a non-`None` store in tests without a Redis dependency.
#[derive(Default)]
pub struct InMemoryContinuationStore {
    entries: std::sync::Mutex<std::collections::HashMap<String, RetainedBases>>,
}

impl InMemoryContinuationStore {
    /// A fresh empty in-memory store.
    pub fn new() -> Self {
        InMemoryContinuationStore {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl AsyncContinuationStore for InMemoryContinuationStore {
    fn store<'a>(
        &'a self,
        key: &'a str,
        bases: &'a RetainedBases,
        _ttl_secs: i64,
    ) -> ContinuationFuture<'a, ()> {
        let key = key.to_string();
        let bases = bases.clone();
        Box::pin(async move {
            self.entries
                .lock()
                .expect("continuation map poisoned")
                .insert(key, bases);
            Ok(())
        })
    }

    fn take<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, Option<RetainedBases>> {
        let key = key.to_string();
        Box::pin(async move {
            Ok(self
                .entries
                .lock()
                .expect("continuation map poisoned")
                .remove(&key))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_then_take_is_one_shot() {
        let store = InMemoryContinuationStore::new();
        let key = continuation_key(b"state-1");
        let bases = RetainedBases {
            previous_request_base: b"prev-base".to_vec(),
            input_required_response_base: b"irr-base".to_vec(),
        };
        store.store(&key, &bases, 300).await.unwrap();
        assert_eq!(store.take(&key).await.unwrap(), Some(bases));
        // Second take finds nothing — one-shot.
        assert_eq!(store.take(&key).await.unwrap(), None);
    }

    #[test]
    fn key_is_stable_and_state_specific() {
        assert_eq!(continuation_key(b"abc"), continuation_key(b"abc"));
        assert_ne!(continuation_key(b"abc"), continuation_key(b"abd"));
        assert!(continuation_key(b"abc").starts_with(CONTINUATION_KEY_PREFIX));
    }
}
