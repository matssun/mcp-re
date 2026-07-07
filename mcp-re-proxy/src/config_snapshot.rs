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

/// An atomically-swappable [`ServerConfig`] read per connection by the serve path.
///
/// Cloning the held `Arc` on [`load`](Self::load) is the whole read cost; the read
/// lock is released immediately, so a concurrent [`store`](Self::store) never blocks
/// an in-flight handshake and vice versa.
pub struct ServerConfigSnapshot {
    current: RwLock<Arc<ServerConfig>>,
}

impl ServerConfigSnapshot {
    /// Seed the snapshot with the startup config.
    pub fn new(initial: Arc<ServerConfig>) -> Self {
        ServerConfigSnapshot {
            current: RwLock::new(initial),
        }
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

    /// Swap in a newer config. Subsequent [`load`](Self::load)s observe it; already
    /// handed-out handles keep serving on their captured config.
    pub fn store(&self, next: Arc<ServerConfig>) {
        match self.current.write() {
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
/// current CRL/key material; on success swap it into `snapshot` and report
/// [`ReloadOutcome::Swapped`]; on any failure keep the last-good config and report
/// [`ReloadOutcome::KeptLastGood`].
///
/// Pure of I/O and wall clock itself — the caller's `rebuild` closure owns the file
/// reads, and staleness enforcement lives in the rustls verifier — so the
/// swap/keep-last-good decision is deterministically testable.
pub fn reload_once<F>(snapshot: &ServerConfigSnapshot, rebuild: F) -> ReloadOutcome
where
    F: FnOnce() -> Result<Arc<ServerConfig>, String>,
{
    match rebuild() {
        Ok(next) => {
            snapshot.store(next);
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
        let snapshot = ServerConfigSnapshot::new(Arc::clone(&a));
        assert!(Arc::ptr_eq(&snapshot.load(), &a), "load returns the seeded config");
        snapshot.store(Arc::clone(&b));
        assert!(Arc::ptr_eq(&snapshot.load(), &b), "load returns the swapped config");
    }

    #[test]
    fn a_handle_taken_before_a_swap_keeps_serving_its_config() {
        let a = dummy_config();
        let b = dummy_config();
        let snapshot = ServerConfigSnapshot::new(Arc::clone(&a));
        // An in-flight handshake captured `a` before the swap.
        let in_flight = snapshot.load();
        snapshot.store(Arc::clone(&b));
        assert!(Arc::ptr_eq(&in_flight, &a), "the captured handle is unaffected by the swap");
        assert!(Arc::ptr_eq(&snapshot.load(), &b), "new connections see the swapped config");
    }

    #[test]
    fn reload_swaps_on_successful_rebuild() {
        let a = dummy_config();
        let b = dummy_config();
        let snapshot = ServerConfigSnapshot::new(Arc::clone(&a));
        let outcome = reload_once(&snapshot, || Ok(Arc::clone(&b)));
        assert_eq!(outcome, ReloadOutcome::Swapped);
        assert!(Arc::ptr_eq(&snapshot.load(), &b), "a successful reload swaps in the new config");
    }

    #[test]
    fn reload_keeps_last_good_on_failure() {
        let a = dummy_config();
        let snapshot = ServerConfigSnapshot::new(Arc::clone(&a));
        let outcome = reload_once(&snapshot, || Err("client CRL unreadable".to_string()));
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
