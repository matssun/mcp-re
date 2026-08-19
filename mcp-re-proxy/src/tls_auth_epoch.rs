// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-055 — the trust epoch that governs TLS session resumption.
//!
//! rustls runs client authentication — chain building, CRL consultation, the
//! certificate's own validity window — on a FULL handshake only. A resumed session
//! restores the stored peer chain verbatim and skips all three, so an authentication
//! result outlives the trust it was derived from.
//!
//! Two of the three are recovered per request elsewhere: the validity window and
//! revocation ([`client_revocation`](crate::client_revocation), one hash-set lookup on
//! an issuer and serial already extracted from the leaf). CHAIN BUILDING is not, and
//! cannot be cheaply — it is the ECDSA work that dominates a full handshake.
//!
//! So resumption is gated on a digest of the inputs chain building depends on. Resume
//! only while that digest is unchanged; on any change, the stored session stops being a
//! shortcut and the peer takes a full handshake against the current trust.
//!
//! # What the epoch covers, and what it deliberately does not
//!
//! It covers the trusted client-CA set. It EXCLUDES CRL contents and every CRL
//! timestamp, and it excludes client revocation policy — unknown revocation status is
//! denied unconditionally, so there is no policy dimension left to digest.
//!
//! That exclusion is the whole reason this is affordable. Revocation is already
//! enforced on every request against the live index, so a newly revoked certificate is
//! refused on its next request whether or not the session resumed — invalidating
//! sessions would buy nothing. Meanwhile a CRL is routinely re-signed on the
//! `--client-crl-reload-secs` cadence with an unchanged revoked set: hashing its bytes
//! would move the epoch on every reload, and because TLS 1.3 has no renegotiation an
//! epoch change is connection-fatal. That is a fleet-wide teardown every reload
//! interval — strictly worse than refusing resumption outright.
//!
//! With CRL data excluded the epoch moves only when an operator changes trusted CAs:
//! rare, deliberate, and exactly the event on which an old authentication result must
//! stop being honoured.
//!
//! # Why a digest and not a counter
//!
//! A counter can regress — a restored backup, a reset store, two replicas that never
//! agreed one — and a stale ticket matching a REUSED epoch number is precisely the hole
//! this closes. The digest is the identity; a counter, if ever added, is ordering and
//! observability only.

use std::sync::Arc;
use std::sync::RwLock;

use rustls::server::StoresServerSessions;
use rustls_pki_types::CertificateDer;
use sha2::Digest;
use sha2::Sha256;

/// Domain separation, so this digest can never collide with another SHA-256 in the
/// tree that happens to run over the same anchor bytes.
///
/// `v2` is the anchor-set-only definition. `v1` additionally hashed a client-auth
/// policy byte that had exactly one legal production value; removing a component
/// changes what the digest means, so it gets a new domain rather than a silently
/// redefined `v1`. Sessions are process-local, so no stored digest needed preserving.
const EPOCH_DOMAIN: &[u8] = b"mcp-re/tls-auth-epoch/v2";

/// The digest of everything that decides whether a previously built chain is still
/// acceptable. Equality means a stored session may resume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TlsAuthEpoch([u8; 32]);

impl TlsAuthEpoch {
    /// Compute the epoch from the trust anchors.
    ///
    /// Anchors are hashed individually, then SORTED and DEDUPLICATED, so the epoch is a
    /// property of the anchor SET rather than of the order a config file happened to
    /// list it in. Each component is length-delimited: without that, moving a byte from
    /// one field to the next would leave the concatenation — and so the digest —
    /// unchanged.
    ///
    /// The FULL anchor DER is hashed rather than just its public key. Two certificates
    /// sharing a key can still differ in name constraints, validity or basic
    /// constraints, and those change which chains build. Hashing the bytes rustls
    /// actually trusts is the conservative direction: it can only ever move the epoch
    /// more often than strictly required, never less.
    ///
    /// # Why client revocation policy is not an input
    ///
    /// Unknown revocation status is unconditionally denied by MCP-RE and is therefore not
    /// a configurable input to the authentication epoch. If that policy ever becomes
    /// variable, it must become an explicit owned fact and the epoch definition must be
    /// revised.
    pub fn compute(client_ca: &[CertificateDer<'_>]) -> Self {
        let mut anchors: Vec<[u8; 32]> = client_ca
            .iter()
            .map(|anchor| {
                let mut out = [0u8; 32];
                out.copy_from_slice(Sha256::digest(anchor.as_ref()).as_slice());
                out
            })
            .collect();
        anchors.sort_unstable();
        anchors.dedup();

        let mut hasher = Sha256::new();
        hasher.update((EPOCH_DOMAIN.len() as u64).to_be_bytes());
        hasher.update(EPOCH_DOMAIN);
        hasher.update((anchors.len() as u64).to_be_bytes());
        for anchor in &anchors {
            hasher.update(anchor);
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_slice());
        Self(out)
    }

    /// The raw digest, for tagging a stored session or a live connection.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Short hex prefix for diagnostics. Never a security comparison — equality is
    /// always the full 32 bytes.
    pub fn short(&self) -> String {
        self.0[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The currently-in-force epoch, swapped atomically by a trust reload.
///
/// Same shape as [`SharedClientRevocation`](crate::client_revocation::SharedClientRevocation)
/// and [`config_snapshot`](crate::config_snapshot): an `RwLock<Arc<…>>` whose read path
/// clones the `Arc` under a short read lock, so an in-flight handshake never blocks on a
/// reload and a reload never waits on the request path.
#[derive(Debug)]
pub struct SharedTlsAuthEpoch {
    current: RwLock<Arc<TlsAuthEpoch>>,
}

impl SharedTlsAuthEpoch {
    pub fn new(epoch: TlsAuthEpoch) -> Self {
        Self {
            current: RwLock::new(Arc::new(epoch)),
        }
    }

    /// The epoch in force right now.
    pub fn load(&self) -> Arc<TlsAuthEpoch> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// Publish a new epoch. Returns the previous value when it CHANGED, so the caller
    /// can emit the audit event; `None` when a reload produced identical trust, which
    /// is the common case and is not worth a log line.
    pub fn store(&self, epoch: TlsAuthEpoch) -> Option<TlsAuthEpoch> {
        let mut guard = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = **guard;
        if previous == epoch {
            return None;
        }
        *guard = Arc::new(epoch);
        Some(previous)
    }
}

/// A session store that hands back a stored session only while the epoch it was stored
/// under is still in force.
///
/// A stale session is NOT an authorization failure — it is simply the absence of a
/// shortcut, and the peer completes a full handshake against current trust. Returning an
/// error instead would turn an operator's CA rotation into an outage.
///
/// The store OUTLIVES any one `ServerConfig`. A rebuild — the `--client-crl-reload-secs`
/// cadence is the one that happens in a running process — installs THIS store again and
/// republishes the epoch computed from that rebuild's trust inputs, so the cache the
/// fleet filled survives the reload and the epoch is a live value rather than a constant
/// fixed at construction.
#[derive(Debug)]
pub struct EpochBoundSessionStore {
    epoch: Arc<SharedTlsAuthEpoch>,
    inner: Arc<dyn StoresServerSessions + Send + Sync>,
}

impl EpochBoundSessionStore {
    pub fn new(
        epoch: Arc<SharedTlsAuthEpoch>,
        inner: Arc<dyn StoresServerSessions + Send + Sync>,
    ) -> Self {
        Self { epoch, inner }
    }

    /// A store over a bounded in-memory session cache, seeded with `epoch`.
    ///
    /// One of these per listener, handed to every `ServerConfig` build for that
    /// listener. Constructing one per build would pair a brand-new epoch with a
    /// brand-new empty cache, which discards every resumable session on each rebuild
    /// and leaves the epoch with no way to move.
    pub fn memory_backed(epoch: TlsAuthEpoch, entries: usize) -> Self {
        EpochBoundSessionStore::new(
            Arc::new(SharedTlsAuthEpoch::new(epoch)),
            rustls::server::ServerSessionMemoryCache::new(entries),
        )
    }

    /// Publish the epoch a freshly built `ServerConfig` computed from its trust inputs.
    /// Returns the previous epoch when it CHANGED, so the caller can tell the operator
    /// that every stored session has just stopped being a shortcut.
    pub fn republish(&self, epoch: TlsAuthEpoch) -> Option<TlsAuthEpoch> {
        self.epoch.store(epoch)
    }

    /// The epoch in force, for diagnostics and for the tests that pin the transition.
    pub fn epoch(&self) -> Arc<TlsAuthEpoch> {
        self.epoch.load()
    }

    /// Split a stored value into its epoch tag and the session rustls stored.
    ///
    /// A value too short to carry a tag is treated as a mismatch rather than unwrapped:
    /// the only way to produce one is a store this type did not write.
    fn unwrap_if_current(&self, stored: Vec<u8>) -> Option<Vec<u8>> {
        if stored.len() < 32 {
            return None;
        }
        let current = self.epoch.load();
        if &stored[..32] != current.as_bytes().as_slice() {
            return None;
        }
        Some(stored[32..].to_vec())
    }
}

impl StoresServerSessions for EpochBoundSessionStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let current = self.epoch.load();
        let mut tagged = Vec::with_capacity(32 + value.len());
        tagged.extend_from_slice(current.as_bytes());
        tagged.extend_from_slice(&value);
        self.inner.put(key, tagged)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let stored = self.inner.get(key)?;
        match self.unwrap_if_current(stored) {
            Some(value) => Some(value),
            None => {
                // Evict on mismatch. `get` leaves the entry in place, so without this a
                // session stored under withdrawn trust would sit in the cache being
                // re-read and re-rejected until it aged out.
                self.inner.take(key);
                None
            }
        }
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        // `take` already removed it, so a mismatch needs no extra eviction: the stale
        // session is gone either way, which is the intended outcome.
        let stored = self.inner.take(key)?;
        self.unwrap_if_current(stored)
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::server::ServerSessionMemoryCache;

    fn anchor(byte: u8) -> CertificateDer<'static> {
        CertificateDer::from(vec![byte; 64])
    }

    fn store_with(epoch: &Arc<SharedTlsAuthEpoch>) -> EpochBoundSessionStore {
        EpochBoundSessionStore::new(Arc::clone(epoch), ServerSessionMemoryCache::new(64))
    }

    #[test]
    fn the_epoch_is_a_property_of_the_anchor_set_not_its_order() {
        let forward = TlsAuthEpoch::compute(&[anchor(1), anchor(2)]);
        let reversed = TlsAuthEpoch::compute(&[anchor(2), anchor(1)]);
        assert_eq!(forward, reversed);
    }

    #[test]
    fn a_duplicated_anchor_does_not_change_the_epoch() {
        let once = TlsAuthEpoch::compute(&[anchor(1)]);
        let twice = TlsAuthEpoch::compute(&[anchor(1), anchor(1)]);
        assert_eq!(once, twice);
    }

    #[test]
    fn withdrawing_an_anchor_changes_the_epoch() {
        let both = TlsAuthEpoch::compute(&[anchor(1), anchor(2)]);
        let withdrawn = TlsAuthEpoch::compute(&[anchor(1)]);
        assert_ne!(both, withdrawn);
    }

    /// The `v1` epoch hashed a client-auth policy byte after the anchors, and a test here
    /// asserted the two policy values produced different epochs. That proposition is gone
    /// with the policy: unknown revocation status is denied unconditionally, so the anchor
    /// set is the epoch's only input. What replaces it is the stronger statement — the
    /// digest is a FUNCTION of the anchor set, so the same anchors always agree and no
    /// other in-process state can move them apart.
    #[test]
    fn the_anchor_set_alone_determines_the_epoch() {
        let anchors = [anchor(1), anchor(2), anchor(3)];
        let first = TlsAuthEpoch::compute(&anchors);
        let second = TlsAuthEpoch::compute(&anchors);
        assert_eq!(
            first, second,
            "the epoch must be a pure function of the anchor set"
        );
        for withheld in 0..anchors.len() {
            let smaller: Vec<_> = anchors
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != withheld)
                .map(|(_, a)| a.clone())
                .collect();
            assert_ne!(
                first,
                TlsAuthEpoch::compute(&smaller),
                "dropping anchor {withheld} must move the epoch"
            );
        }
    }

    /// The domain separator is part of the digest's identity, not decoration: `v1` and
    /// `v2` define different functions of the same anchors. Pinning it here means a future
    /// change to what the epoch covers cannot silently reuse the current domain.
    #[test]
    fn the_epoch_domain_names_the_current_definition() {
        assert_eq!(EPOCH_DOMAIN, b"mcp-re/tls-auth-epoch/v2");
    }

    #[test]
    fn a_session_stored_under_the_current_epoch_resumes() {
        let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&[anchor(1)])));
        let store = store_with(&epoch);
        assert!(store.put(b"key".to_vec(), b"session".to_vec()));
        assert_eq!(store.take(b"key"), Some(b"session".to_vec()));
    }

    #[test]
    fn a_session_stored_under_a_withdrawn_anchor_does_not_resume() {
        let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&[
            anchor(1),
            anchor(2),
        ])));
        let store = store_with(&epoch);
        assert!(store.put(b"key".to_vec(), b"session".to_vec()));
        epoch.store(TlsAuthEpoch::compute(&[anchor(1)]));
        assert_eq!(store.take(b"key"), None, "a stale session must not resume");
    }

    #[test]
    fn a_stale_session_is_evicted_by_get_not_left_to_be_re_rejected() {
        let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&[
            anchor(1),
            anchor(2),
        ])));
        let store = store_with(&epoch);
        assert!(store.put(b"key".to_vec(), b"session".to_vec()));
        epoch.store(TlsAuthEpoch::compute(&[anchor(1)]));
        assert_eq!(store.get(b"key"), None);
        // Restoring the original trust must NOT resurrect it: the entry is gone.
        epoch.store(TlsAuthEpoch::compute(&[anchor(1), anchor(2)]));
        assert_eq!(store.get(b"key"), None, "the stale entry was not evicted");
    }

    /// A store handed to a second `ServerConfig` build keeps what the first one cached,
    /// and republishing the SAME trust leaves those sessions resumable.
    ///
    /// The broken implementation this catches: building the store inside each
    /// `ServerConfig` builder, so every CRL reload swaps in an empty cache and the whole
    /// peer fleet takes full handshakes on the reload cadence.
    #[test]
    fn a_rebuild_that_republishes_the_same_trust_keeps_the_cache() {
        let store = EpochBoundSessionStore::memory_backed(TlsAuthEpoch::compute(&[anchor(1)]), 64);
        assert!(store.put(b"key".to_vec(), b"session".to_vec()));
        assert_eq!(
            store.republish(TlsAuthEpoch::compute(&[anchor(1)])),
            None,
            "identical trust is not an epoch change"
        );
        assert_eq!(store.take(b"key"), Some(b"session".to_vec()));
    }

    /// A rebuild that republishes DIFFERENT trust reports the change and the sessions
    /// stored under the old trust stop resuming.
    #[test]
    fn a_rebuild_with_withdrawn_trust_advances_the_epoch_and_stops_resumption() {
        let first = TlsAuthEpoch::compute(&[anchor(1), anchor(2)]);
        let store = EpochBoundSessionStore::memory_backed(first, 64);
        assert!(store.put(b"key".to_vec(), b"session".to_vec()));
        let second = TlsAuthEpoch::compute(&[anchor(1)]);
        assert_eq!(store.republish(second), Some(first));
        assert_eq!(*store.epoch(), second);
        assert_eq!(store.take(b"key"), None);
    }

    #[test]
    fn storing_an_identical_epoch_reports_no_change() {
        let epoch = SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&[anchor(1)]));
        assert_eq!(epoch.store(TlsAuthEpoch::compute(&[anchor(1)])), None);
    }

    #[test]
    fn storing_a_different_epoch_reports_the_previous_one() {
        let first = TlsAuthEpoch::compute(&[anchor(1)]);
        let epoch = SharedTlsAuthEpoch::new(first);
        let second = TlsAuthEpoch::compute(&[anchor(2)]);
        assert_eq!(epoch.store(second), Some(first));
        assert_eq!(*epoch.load(), second);
    }
}
