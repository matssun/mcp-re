// SPDX-License-Identifier: Apache-2.0
//! [`TlsListenerSecurityState`] — the security state ONE listener is built around, for the
//! whole of its lifetime (ADR-MCPRE-061 §2, ADR-MCPRE-055).
//!
//! # The relationship this type makes unsplittable
//!
//! ```text
//!   trusted client CAs ──digest──> authentication epoch ──tags──> session cache
//!                                                                 signing budget
//! ```
//!
//! Four facts that must survive a `ServerConfig` rebuild TOGETHER. The anchors are the
//! epoch's only input, the epoch tags the cache, and the budget bounds a rate rather than a
//! window — so a per-build cache empties on every reload cadence and a per-build bucket
//! refills on it.
//!
//! A build is a method ON the state. The anchors and the store are never separately
//! passable, so the forbidden combination — a fresh cache beside an unrelated epoch — is
//! unconstructible rather than detectable. The census that found it is `EX-004` in
//! `docs/architecture/review-dispositions.md`.
//!
//! # What this owner does NOT claim
//!
//! Three propositions are easy to run together and are kept apart, because only the first
//! is a property of the store and only the third is what production relies on:
//!
//! | | proposition | established by |
//! |---|---|---|
//! | 1 | if the current epoch changes, sessions tagged with the old one are not returned | [`auth_epoch`], and the real-handshake controls in [`resumption_acceptance`] |
//! | 2 | a production listener's epoch advances when its anchors change | **nothing — the anchor set is immutable for this owner's lifetime** |
//! | 3 | replacing the anchor set replaces the listener, and therefore the store | this type |
//!
//! Proposition 1 must never be read as evidence for proposition 2. Within one listener the
//! anchors do not change, so the epoch does not advance; what protects an anchor-set change
//! is that no cache crosses it.
//!
//! ADR-MCPRE-055's text anticipates a live-epoch lifecycle. Which lifecycle MCP-RE promises
//! is under separate adjudication, so this type exposes NO epoch mutation: adding a seam
//! would invent an operational capability so an existing mechanism could exercise its
//! change branch.
//!
//! # Sealing
//!
//! By MODULE PRIVACY — the only lever that binds inside one crate — and the seal is the
//! module TREE, not this file:
//!
//! ```text
//! tls_listener_state            the only construction authority (pub)
//!   ├── assembly                what the serving config IS
//!   ├── auth_epoch              the epoch VALUE is pub; the store and the mutable
//!   │                           wrapper are pub(super)
//!   ├── client_verifier         what a valid client certificate is
//!   ├── resumption_binding      whether a stored session is still a shortcut
//!   └── resumption_acceptance   the real-handshake controls, inside the boundary
//! ```
//!
//! These were `pub(crate)` in `tls.rs` and a `pub` sibling module, which sealed against
//! nobody: every consumer lives in this crate. `docs/dev/sealed-owners.md` records what the
//! seal covers and its one residual limit — `rustls::ServerConfig::session_storage` is a
//! public field of a foreign type, so what is unconstructible is BUILDING a mispaired
//! config, not overwriting one that exists.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::PrivateKeyDer;

use crate::delegated_tls::DelegatedCertResolver;
use crate::delegated_tls::RawEd25519TlsSigner;
use crate::delegated_tls::TlsHandshakeSignBudget;
use crate::tls::TlsError;

mod assembly;
mod auth_epoch;
mod client_verifier;
mod resumption_acceptance;
mod resumption_binding;

use auth_epoch::EpochBoundSessionStore;

/// The trust-anchor digest an epoch-bound store is tagged with.
///
/// Re-exported because it is a VALUE — computing one confers no authority — and the
/// startup posture line and the plane's own tests name it. The capabilities that could
/// pair a store with the wrong one stay private to this subtree.
pub use auth_epoch::TlsAuthEpoch;

/// Entries the per-listener TLS session cache retains.
const TLS_SESSION_CACHE_ENTRIES: usize = 4096;

/// The client-authentication security state of one TLS listener, for its lifetime.
///
/// Holding one means: these anchors, the epoch they digest to, a session cache created
/// under that epoch, and a handshake-signature budget, all belong to the same listener and
/// were established together. Every `ServerConfig` for that listener is built through it.
pub struct TlsListenerSecurityState {
    /// The trusted client-CA set every build of this listener is bound to. Immutable for
    /// the listener's lifetime: a different anchor set is a different listener.
    client_ca: Vec<CertificateDer<'static>>,
    /// The session cache, tagged with the epoch `client_ca` digests to.
    resumption: Arc<EpochBoundSessionStore>,
    /// Bounds how fast unauthenticated peers can drive a remote, billed,
    /// account-throttled TLS handshake signer. Listener-lifetime for the same reason the
    /// cache is: a bucket refilled on every reload bounds a window rather than a rate.
    sign_budget: Arc<TlsHandshakeSignBudget>,
}

impl TlsListenerSecurityState {
    /// Establish the state a listener will be built and rebuilt against.
    ///
    /// The epoch and the cache are derived HERE, from these anchors, which is what makes
    /// "the store was established from these trust anchors" true by construction rather
    /// than by a caller passing two arguments that happen to agree.
    pub fn new(client_ca: Vec<CertificateDer<'static>>) -> Self {
        let resumption = Arc::new(EpochBoundSessionStore::memory_backed(
            TlsAuthEpoch::compute(&client_ca),
            TLS_SESSION_CACHE_ENTRIES,
        ));
        TlsListenerSecurityState {
            client_ca,
            resumption,
            sign_budget: Arc::new(TlsHandshakeSignBudget::default()),
        }
    }

    /// The authentication epoch in force, as a READ.
    ///
    /// There is deliberately no setter. See the module note: within this owner's lifetime
    /// the anchors are immutable, so the epoch is a construction-time constant, and a
    /// mutation seam here would advertise a lifecycle production does not implement.
    pub fn epoch(&self) -> Arc<TlsAuthEpoch> {
        self.resumption.epoch()
    }

    /// Build a serving config under EXPORTED key custody.
    ///
    /// The anchors and the resumption store are not parameters: they are this state's, and
    /// that is the whole point of the method living here.
    pub fn build_exported_key_config(
        &self,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<ServerConfig, TlsError> {
        let config = assembly::assemble_exported_key_config(
            server_chain,
            server_key,
            self.client_ca.clone(),
            crls,
        )?;
        Ok(self.bind_resumption(config))
    }

    /// Build a serving config under DELEGATED key custody (ADR-MCPS-028 §G): the server's
    /// TLS private key never leaves the device/KMS.
    ///
    /// The Ed25519-only and cert-matches-signer preconditions are validated before any
    /// server starts; an unsafe credential is refused here rather than surfacing as an
    /// opaque handshake failure at runtime.
    pub fn build_delegated_config(
        &self,
        server_chain: Vec<CertificateDer<'static>>,
        signer: Arc<dyn RawEd25519TlsSigner>,
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<ServerConfig, TlsError> {
        let resolver = self.delegated_resolver(server_chain, signer)?;
        self.build_delegated_resolver_config(resolver, crls)
    }

    /// Build a serving config around a caller-supplied certificate resolver.
    ///
    /// The escape hatch for custody arrangements this crate does not model. It performs no
    /// credential validation of its own — [`Self::build_delegated_config`] is the path that
    /// does — and it is still bound to this listener's anchors, epoch and cache.
    pub fn build_delegated_resolver_config(
        &self,
        cert_resolver: Arc<dyn rustls::server::ResolvesServerCert>,
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<ServerConfig, TlsError> {
        let config =
            assembly::assemble_delegated_config(cert_resolver, self.client_ca.clone(), crls)?;
        Ok(self.bind_resumption(config))
    }

    /// Validate a delegated credential and pair it with THIS listener's signing budget.
    ///
    /// The seam `build_delegated_config` goes through, and the reason it returns the
    /// concrete resolver: the budget is the fourth thing that must survive a rebuild, and
    /// `DelegatedCertResolver::budget()` is the only handle on which budget a build
    /// actually used. A `dyn ResolvesServerCert` would erase it, leaving the conjunct
    /// asserted in prose and probed by nothing.
    fn delegated_resolver(
        &self,
        server_chain: Vec<CertificateDer<'static>>,
        signer: Arc<dyn RawEd25519TlsSigner>,
    ) -> Result<Arc<DelegatedCertResolver>, TlsError> {
        crate::tls::validated_delegated_resolver(
            server_chain,
            signer,
            Arc::clone(&self.sign_budget),
        )
    }

    /// Install this listener's epoch-tagged store on a freshly assembled config.
    ///
    /// `republish` is handed the epoch the store ALREADY holds, so it is an
    /// invariant-preserving no-op by construction. The mechanism is kept rather than
    /// removed because deleting it would adjudicate ADR-MCPRE-055's lifecycle rather than
    /// fix ownership.
    ///
    /// It reads the store's epoch instead of recomputing `TlsAuthEpoch::compute(&self.client_ca)`,
    /// which would be the same value derived a second time. One derivation site is the
    /// point: with two, a probe that corrupted the constructor's epoch was silently
    /// CORRECTED by the first build, so the constructor looked load-bearing only until a
    /// config was built through it.
    fn bind_resumption(&self, config: ServerConfig) -> ServerConfig {
        let epoch = *self.resumption.epoch();
        resumption_binding::epoch_bound_resumption(config, &self.resumption, epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca() -> CertificateDer<'static> {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "listener-state-test-ca");
        params.self_signed(&key).expect("ca").der().clone()
    }

    fn credential() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        use rustls::pki_types::PrivatePkcs8KeyDer;
        let key = rcgen::KeyPair::generate().expect("server key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("server cert");
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    /// The epoch is derived from the anchors the owner holds, not from anything a caller
    /// supplied alongside them.
    #[test]
    fn the_epoch_digests_the_anchors_this_state_owns() {
        let anchors = vec![ca(), ca()];
        let state = TlsListenerSecurityState::new(anchors.clone());
        assert_eq!(*state.epoch(), TlsAuthEpoch::compute(&anchors));
        assert_ne!(*state.epoch(), TlsAuthEpoch::compute(&[]));
    }

    /// The property the owner exists for: a rebuild keeps the SAME cache, so an
    /// established session survives the CRL cadence.
    ///
    /// Before the owner, a caller could reach the builder family that made its own state
    /// per build; that emptied the cache on every reload. There is no such builder now —
    /// a config can only be built through a state, and a state's store is created once.
    #[test]
    fn a_rebuild_keeps_the_cache_and_the_epoch_of_the_state_it_was_built_through() {
        let anchors = vec![ca()];
        let (chain, key) = credential();
        let state = TlsListenerSecurityState::new(anchors.clone());

        let first = state
            .build_exported_key_config(chain.clone(), key.clone_key(), Vec::new())
            .expect("initial build");
        assert!(first
            .session_storage
            .put(b"ticket".to_vec(), b"session".to_vec()));
        let after_first = *state.epoch();

        let second = state
            .build_exported_key_config(chain, key, Vec::new())
            .expect("rebuild");
        assert_eq!(*state.epoch(), TlsAuthEpoch::compute(&anchors));
        assert_eq!(
            after_first,
            *state.epoch(),
            "re-reading CRLs is not an anchor change"
        );
        assert_eq!(
            second.session_storage.take(b"ticket"),
            Some(b"session".to_vec()),
            "the rebuilt config must serve from the cache the first build populated"
        );
    }

    /// A different anchor set is a different LISTENER: it gets its own state, its own
    /// epoch and — the part that matters — its own empty store. No session authenticated
    /// under one anchor set can exist in a cache governed by another.
    ///
    /// This is proposition 3 in the module table, and it is the one production relies on.
    /// It is NOT proposition 2: nothing here advances an epoch.
    #[test]
    fn a_different_anchor_set_is_a_different_state_with_its_own_empty_cache() {
        let (chain, key) = credential();
        let first_state = TlsListenerSecurityState::new(vec![ca()]);
        let first = first_state
            .build_exported_key_config(chain.clone(), key.clone_key(), Vec::new())
            .expect("build");
        assert!(first
            .session_storage
            .put(b"ticket".to_vec(), b"session".to_vec()));

        let second_state = TlsListenerSecurityState::new(vec![ca()]);
        assert_ne!(*first_state.epoch(), *second_state.epoch());
        let second = second_state
            .build_exported_key_config(chain, key, Vec::new())
            .expect("build");
        assert_eq!(
            second.session_storage.take(b"ticket"),
            None,
            "a cache governed by another anchor set must not hold the first listener's session"
        );
    }

    /// A local-key delegated signer standing in for the device/KMS, so a delegated build
    /// can be exercised without one.
    struct LocalSigner(mcp_re_core::SigningKey);

    impl RawEd25519TlsSigner for LocalSigner {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, crate::KeyError> {
            Ok(mcp_re_core::b64url_decode(&self.0.sign(message)).expect("valid b64url"))
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, crate::KeyError> {
            let mut der = crate::kms_keysource::ED25519_SPKI_PREFIX.to_vec();
            der.extend_from_slice(&self.0.public_key().to_bytes());
            Ok(der)
        }
    }

    /// A delegated credential whose leaf certificate carries the SIGNER's own key, which
    /// is what `validated_delegated_resolver` insists on.
    ///
    /// The seed is lifted out of rcgen's PKCS#8: RFC 8410 Ed25519 puts the 32-byte seed at
    /// bytes `[16..48]`, immediately after a fixed 16-byte prefix ending `04 22 04 20`.
    fn delegated_credential() -> (Vec<CertificateDer<'static>>, Arc<dyn RawEd25519TlsSigner>) {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key");
        let pkcs8 = pair.serialize_der();
        assert_eq!(
            &pkcs8[12..16],
            &[0x04, 0x22, 0x04, 0x20],
            "rcgen's Ed25519 PKCS#8 prefix moved; the seed offset below is no longer right"
        );
        let seed: [u8; 32] = pkcs8[16..48].try_into().expect("ed25519 pkcs8 seed");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&pair).expect("delegated leaf");
        (
            vec![cert.der().clone()],
            Arc::new(LocalSigner(mcp_re_core::SigningKey::from_seed_bytes(&seed))),
        )
    }

    /// The FOURTH thing the owner establishes together: the handshake-signature budget.
    ///
    /// It bounds how fast unauthenticated peers can drive a remote, billed,
    /// account-throttled signer. A budget created per build is refilled on every reload
    /// cadence, so it bounds a WINDOW rather than a rate — the census's phrasing, and the
    /// reason this conjunct is not decoration.
    ///
    /// The observable is the budget the BUILD used, not the field this state holds: a
    /// mutation that creates a fresh bucket inside the build would leave the field
    /// untouched and this control green. `delegated_resolver` is the seam
    /// `build_delegated_config` goes through, and it returns the concrete resolver so
    /// `budget()` is reachable.
    #[test]
    fn a_delegated_rebuild_reuses_the_listeners_signing_budget() {
        let (chain, signer) = delegated_credential();
        let state = TlsListenerSecurityState::new(vec![ca()]);

        let first = state
            .delegated_resolver(chain.clone(), Arc::clone(&signer))
            .expect("initial delegated build");
        let second = state.delegated_resolver(chain, signer).expect("rebuild");

        assert!(
            Arc::ptr_eq(first.budget(), second.budget()),
            "a rebuild must reuse the listener's budget; a fresh bucket bounds a reload \
             window rather than a rate"
        );
    }

    /// Stateless tickets stay disabled on every path out of this owner. They are a SECOND
    /// resumption mechanism that bypasses the store entirely, so a build that enabled them
    /// would bypass the epoch tag and everything claimed above with it.
    #[test]
    fn no_config_this_owner_builds_can_resume_outside_the_store() {
        let (chain, key) = credential();
        let state = TlsListenerSecurityState::new(vec![ca()]);
        let config = state
            .build_exported_key_config(chain, key, Vec::new())
            .expect("build");
        assert!(!config.ticketer.enabled());
        assert_eq!(config.max_early_data_size, 0);
    }
}
