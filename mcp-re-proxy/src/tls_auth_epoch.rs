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
//! It covers the trusted client-CA set and the client-auth policy that governs chain
//! acceptance. It EXCLUDES CRL contents and every CRL timestamp.
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
//! With CRL data excluded the epoch moves only when an operator changes trusted CAs or
//! client-auth policy: rare, deliberate, and exactly the event on which an old
//! authentication result must stop being honoured.
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
const EPOCH_DOMAIN: &[u8] = b"mcp-re/tls-auth-epoch/v1";

/// The digest of everything that decides whether a previously built chain is still
/// acceptable. Equality means a stored session may resume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TlsAuthEpoch([u8; 32]);

impl TlsAuthEpoch {
    /// Compute the epoch from the trust anchors and the client-auth policy.
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
    pub fn compute(
        client_ca: &[CertificateDer<'_>],
        allow_unknown_revocation_status: bool,
    ) -> Self {
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
        hasher.update([u8::from(allow_unknown_revocation_status)]);

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
        let forward = TlsAuthEpoch::compute(&[anchor(1), anchor(2)], false);
        let reversed = TlsAuthEpoch::compute(&[anchor(2), anchor(1)], false);
        assert_eq!(forward, reversed);
    }

    #[test]
    fn a_duplicated_anchor_does_not_change_the_epoch() {
        let once = TlsAuthEpoch::compute(&[anchor(1)], false);
        let twice = TlsAuthEpoch::compute(&[anchor(1), anchor(1)], false);
        assert_eq!(once, twice);
    }

    #[test]
    fn withdrawing_an_anchor_changes_the_epoch() {
        let both = TlsAuthEpoch::compute(&[anchor(1), anchor(2)], false);
        let withdrawn = TlsAuthEpoch::compute(&[anchor(1)], false);
        assert_ne!(both, withdrawn);
    }

    #[test]
    fn the_client_auth_policy_is_part_of_the_epoch() {
        let deny = TlsAuthEpoch::compute(&[anchor(1)], false);
        let allow = TlsAuthEpoch::compute(&[anchor(1)], true);
        assert_ne!(deny, allow);
    }

    #[test]
    fn a_session_stored_under_the_current_epoch_resumes() {
        let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(
            &[anchor(1)],
            false,
        )));
        let store = store_with(&epoch);
        assert!(store.put(b"key".to_vec(), b"session".to_vec()));
        assert_eq!(store.take(b"key"), Some(b"session".to_vec()));
    }

    #[test]
    fn a_session_stored_under_a_withdrawn_anchor_does_not_resume() {
        let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(
            &[anchor(1), anchor(2)],
            false,
        )));
        let store = store_with(&epoch);
        assert!(store.put(b"key".to_vec(), b"session".to_vec()));
        epoch.store(TlsAuthEpoch::compute(&[anchor(1)], false));
        assert_eq!(store.take(b"key"), None, "a stale session must not resume");
    }

    #[test]
    fn a_stale_session_is_evicted_by_get_not_left_to_be_re_rejected() {
        let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(
            &[anchor(1), anchor(2)],
            false,
        )));
        let store = store_with(&epoch);
        assert!(store.put(b"key".to_vec(), b"session".to_vec()));
        epoch.store(TlsAuthEpoch::compute(&[anchor(1)], false));
        assert_eq!(store.get(b"key"), None);
        // Restoring the original trust must NOT resurrect it: the entry is gone.
        epoch.store(TlsAuthEpoch::compute(&[anchor(1), anchor(2)], false));
        assert_eq!(store.get(b"key"), None, "the stale entry was not evicted");
    }

    #[test]
    fn storing_an_identical_epoch_reports_no_change() {
        let epoch = SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&[anchor(1)], false));
        assert_eq!(
            epoch.store(TlsAuthEpoch::compute(&[anchor(1)], false)),
            None
        );
    }

    #[test]
    fn storing_a_different_epoch_reports_the_previous_one() {
        let first = TlsAuthEpoch::compute(&[anchor(1)], false);
        let epoch = SharedTlsAuthEpoch::new(first);
        let second = TlsAuthEpoch::compute(&[anchor(2)], false);
        assert_eq!(epoch.store(second), Some(first));
        assert_eq!(*epoch.load(), second);
    }
}
