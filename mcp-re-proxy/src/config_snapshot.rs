//! ADR-MCPRE-051 §6 (MCPRE-116) — versioned, atomically-swapped serving-config
//! snapshots; the in-process CRL hot-reloader (subsumes MCPS-66 / #246).
//!
//! The blocking serve loop and the (opt-in) async data plane read the current
//! rustls [`ServerConfig`] per connection from a [`ServerConfigSnapshot`] instead
//! of a fixed `Arc`. A background reload task rebuilds the config — picking up a
//! refreshed `--client-crl` WITHOUT a restart — and swaps it atomically; a failed
//! reload keeps the last-good config, and once the last-good CRL passes its
//! `nextUpdate` the rustls verifier (`enforce_revocation_expiration`) fails new
//! handshakes closed by construction. This removes the "restart before nextUpdate"
//! requirement the old static-snapshot posture carried (tls.rs `crl_freshness`
//! note).
//!
//! The swap is `ArcSwap`-shaped but dependency-free: a `RwLock<Arc<ServerConfig>>`
//! whose read path (`load`) clones the `Arc` under a short read lock and hands the
//! caller an owned handle, so an in-flight handshake keeps serving on the config it
//! captured even while a writer swaps in a newer one. No lock is held across the
//! handshake.
//!
//! The reload DECISION is pure and clock-injected ([`reload_once`]), so the
//! last-good / swap / fail-closed behavior is deterministically testable with no
//! files and no wall clock.

use std::sync::Arc;
use std::sync::RwLock;

use rustls::ServerConfig;

use crate::config_state::PrivateKeyExposure;

/// An atomically-swappable [`ServerConfig`] read per connection by the serve path.
///
/// Cloning the held `Arc` on [`load`](Self::load) is the whole read cost; the read
/// lock is released immediately, so a concurrent [`store`](ServerConfigPublisher::store) never blocks
/// an in-flight handshake and vice versa.
///
/// It also carries the custody of the server key every config it holds signs with,
/// stated once where the first config is built: a swap rebuilds the verifier over the
/// SAME key material, so the custody cannot change while the snapshot lives. A serve
/// path that needs to know whether a handshake signature may block reads it here, from
/// the snapshot it serves, rather than from a flag supplied beside it.
pub struct ServerConfigSnapshot {
    current: RwLock<Arc<ServerConfig>>,
    key_exposure: PrivateKeyExposure,
}

impl ServerConfigSnapshot {
    /// Seed a snapshot that is never swapped: no publisher exists for it. `key_exposure`
    /// is the custody of the key `initial` signs handshakes with.
    pub fn new(initial: Arc<ServerConfig>, key_exposure: PrivateKeyExposure) -> Self {
        ServerConfigSnapshot {
            current: RwLock::new(initial),
            key_exposure,
        }
    }

    /// The custody of the server key this snapshot's configs sign with. `NonExporting`
    /// means the handshake signature is produced by a KMS or a token, synchronously, so
    /// producing it may block.
    pub fn key_exposure(&self) -> PrivateKeyExposure {
        self.key_exposure
    }

    /// The current config. Clones the `Arc` under a short read lock (a poisoned
    /// lock still yields the last value — the serve path must never panic on a
    /// writer that paniced mid-swap).
    pub fn load(&self) -> Arc<ServerConfig> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Seed a snapshot with the startup config and return it with the one
    /// [`ServerConfigPublisher`] that can swap it.
    pub fn establish(
        initial: Arc<ServerConfig>,
        key_exposure: PrivateKeyExposure,
    ) -> (Arc<Self>, ServerConfigPublisher) {
        let snapshot = Arc::new(Self::new(initial, key_exposure));
        let publisher = ServerConfigPublisher {
            snapshot: Arc::clone(&snapshot),
        };
        (snapshot, publisher)
    }
}

/// The one capability to swap a [`ServerConfigSnapshot`], returned only by
/// [`ServerConfigSnapshot::establish`] and deliberately not `Clone`.
///
/// `pub` because the `integration_async` test crate drives a swap; holding one writes
/// only the snapshot it was established with.
pub struct ServerConfigPublisher {
    snapshot: Arc<ServerConfigSnapshot>,
}

impl ServerConfigPublisher {
    /// Swap in a newer config. Subsequent [`load`](ServerConfigSnapshot::load)s observe
    /// it; already handed-out handles keep serving on their captured config.
    pub fn store(&self, next: Arc<ServerConfig>) {
        match self.snapshot.current.write() {
            Ok(mut guard) => *guard = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }
}

/// The outcome of one reload attempt — for the operator log and for tests.
#[derive(Debug, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The config was rebuilt and swapped in.
    Swapped,
    /// The rebuild failed (unreadable/parse/build error); the last-good config is
    /// retained. Once its CRL passes `nextUpdate`, the verifier fails closed on its
    /// own — a failed reload never widens what is accepted.
    KeptLastGood {
        /// Human-readable diagnostic (never a secret); goes to the operator log.
        reason: String,
    },
}

/// Attempt one reload: call `rebuild` to construct a fresh [`ServerConfig`] from the
/// current CRL/key material; on success swap it in through `publisher` and report
/// [`ReloadOutcome::Swapped`]; on any failure keep the last-good config and report
/// [`ReloadOutcome::KeptLastGood`].
///
/// Pure of I/O and wall clock itself — the caller's `rebuild` closure owns the file
/// reads, and staleness enforcement lives in the rustls verifier — so the
/// swap/keep-last-good decision is deterministically testable.
///
/// `reload_once` swaps in whatever `rebuild` returns, so that a SUCCESSFUL reload never
/// widens acceptance is the rebuild's to establish: the client-CRL reload builds only
/// evidence that succeeds the set in force (`ClientCrlEvidence::succeeds`: no issuer
/// dropped, no crlNumber regressed, no crlNumber reused with other bytes).
pub fn reload_once<F>(publisher: &ServerConfigPublisher, rebuild: F) -> ReloadOutcome
where
    F: FnOnce() -> Result<Arc<ServerConfig>, String>,
{
    match rebuild() {
        Ok(next) => {
            publisher.store(next);
            ReloadOutcome::Swapped
        }
        Err(reason) => ReloadOutcome::KeptLastGood { reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ring;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    /// A minimal, self-signed server-only `ServerConfig` (no client auth — the
    /// snapshot mechanics are transport-agnostic) built purely in-process, so the
    /// swap behavior is exercised without cert fixtures. Two calls yield DISTINCT
    /// `Arc`s so a swap is observable by pointer identity.
    fn dummy_config() -> Arc<ServerConfig> {
        let key = rcgen::KeyPair::generate().expect("key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-signed");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        Arc::new(config)
    }

    #[test]
    fn load_returns_current_and_store_swaps() {
        let a = dummy_config();
        let b = dummy_config();
        let (snapshot, publisher) =
            ServerConfigSnapshot::establish(Arc::clone(&a), PrivateKeyExposure::ProcessReadable);
        assert!(
            Arc::ptr_eq(&snapshot.load(), &a),
            "load returns the seeded config"
        );
        publisher.store(Arc::clone(&b));
        assert!(
            Arc::ptr_eq(&snapshot.load(), &b),
            "load returns the swapped config"
        );
    }

    #[test]
    fn a_handle_taken_before_a_swap_keeps_serving_its_config() {
        let a = dummy_config();
        let b = dummy_config();
        let (snapshot, publisher) =
            ServerConfigSnapshot::establish(Arc::clone(&a), PrivateKeyExposure::ProcessReadable);
        // An in-flight handshake captured `a` before the swap.
        let in_flight = snapshot.load();
        publisher.store(Arc::clone(&b));
        assert!(
            Arc::ptr_eq(&in_flight, &a),
            "the captured handle is unaffected by the swap"
        );
        assert!(
            Arc::ptr_eq(&snapshot.load(), &b),
            "new connections see the swapped config"
        );
    }

    #[test]
    fn reload_swaps_on_successful_rebuild() {
        let a = dummy_config();
        let b = dummy_config();
        let (snapshot, publisher) =
            ServerConfigSnapshot::establish(Arc::clone(&a), PrivateKeyExposure::ProcessReadable);
        let outcome = reload_once(&publisher, || Ok(Arc::clone(&b)));
        assert_eq!(outcome, ReloadOutcome::Swapped);
        assert!(
            Arc::ptr_eq(&snapshot.load(), &b),
            "a successful reload swaps in the new config"
        );
    }

    #[test]
    fn a_poisoned_lock_still_loads_the_last_config_and_still_swaps() {
        let a = dummy_config();
        let b = dummy_config();
        let (snapshot, publisher) =
            ServerConfigSnapshot::establish(Arc::clone(&a), PrivateKeyExposure::ProcessReadable);
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                let _g = snapshot.current.write().unwrap();
                panic!("writer panics mid-swap");
            });
            assert!(h.join().is_err());
        });
        assert!(
            snapshot.current.is_poisoned(),
            "the probe must have poisoned the lock"
        );
        assert!(
            Arc::ptr_eq(&snapshot.load(), &a),
            "a poisoned lock still loads the last config"
        );
        publisher.store(Arc::clone(&b));
        assert!(
            Arc::ptr_eq(&snapshot.load(), &b),
            "a poisoned lock still swaps"
        );
    }

    #[test]
    fn reload_keeps_last_good_on_failure() {
        let a = dummy_config();
        let (snapshot, publisher) =
            ServerConfigSnapshot::establish(Arc::clone(&a), PrivateKeyExposure::ProcessReadable);
        let outcome = reload_once(&publisher, || Err("client CRL unreadable".to_string()));
        assert_eq!(
            outcome,
            ReloadOutcome::KeptLastGood {
                reason: "client CRL unreadable".to_string()
            },
        );
        assert!(
            Arc::ptr_eq(&snapshot.load(), &a),
            "a failed reload must NOT swap — the last-good config is retained (never widens acceptance)",
        );
    }
}
