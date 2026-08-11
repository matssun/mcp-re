//! Delegated TLS handshake signing (ADR-MCPS-028 §G).
//!
//! Closes the last key-export gap: even on the PKCS#11 / KMS object-signing paths,
//! the TLS *server* private key was still read from a file and handed to rustls
//! (`KeySource::tls_server_key`). This module lets the TLS handshake be signed by a
//! non-exporting device/KMS instead — a custom [`rustls::sign::SigningKey`] whose
//! signing operation forwards the to-be-signed handshake transcript to a
//! [`RawEd25519TlsSigner`] (a PKCS#11 token or AWS/GCP KMS), so the TLS private key
//! never leaves the device.
//!
//! Ed25519 only: rustls calls [`rustls::sign::Signer::sign`] with the full message
//! to be signed and, for `SignatureScheme::ED25519`, expects a PureEdDSA signature
//! over those exact bytes — precisely the "sign raw bytes with Ed25519" primitive
//! the KMS/PKCS#11 backends expose. The TLS server certificate MUST therefore be an
//! Ed25519 certificate whose key lives in the device/KMS. A non-Ed25519 TLS cert is
//! a deployment error (the handshake fails closed: no scheme is offered).
//!
//! The TLS key is a SEPARATE key from the response-signing key — both can be
//! non-exporting, but they are distinct credentials (distinct KMS key ids / token
//! objects). This module is transport-agnostic: it only needs the raw-sign closure.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::sign::Signer;
use rustls::sign::SigningKey;
use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls_pki_types::CertificateDer;

use crate::key_source::KeyError;

/// The single operation a delegated TLS signer needs: a PureEdDSA (Ed25519, no
/// pre-hash) signature over the raw `message`, returning the raw 64-byte signature.
/// Implemented by the PKCS#11 token (CKM_EDDSA) and the AWS/GCP KMS backends
/// (`Sign` / `asymmetricSign` over RAW data) — the same primitive used for response
/// signing, but keyed by the TLS certificate's key.
pub trait RawEd25519TlsSigner: Send + Sync {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;

    /// The DER `SubjectPublicKeyInfo` (RFC 8410) of the Ed25519 public key paired
    /// with the delegated signing key. This is exportable even from a non-exporting
    /// device/KMS (it is what relying parties verify against). The validated
    /// delegated build path (issue #58, ADR-MCPS-028 §G) uses it to FAIL CLOSED at
    /// config construction when the signer's key does not match the leaf TLS
    /// certificate's `SubjectPublicKeyInfo` — so a key/cert mismatch is rejected
    /// before any server starts, never left to a failed handshake at runtime.
    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError>;
}

const ED25519_SIGNATURE_LEN: usize = 64;

/// The sustained ceiling, in handshake signatures per second, on how fast unauthenticated
/// peers can drive the delegated TLS signer.
///
/// Sized against what legitimate traffic needs: session resumption is refused by design,
/// so every connection costs one signature, and `ServerLimits::max_connection_age`
/// (300s) with `max_concurrent_connections` (256 per core) puts the steady-state
/// re-handshake rate near one signature per core per second. 100/s leaves a large
/// multiple of that for connection churn and rolling deploys while staying well inside a
/// KMS account's cryptographic-operation quota.
pub const DEFAULT_TLS_SIGN_RATE_PER_SEC: u32 = 100;

/// The burst allowance — how many signatures may be drawn back-to-back before the
/// sustained rate binds. One rolling deploy reconnects a whole fleet at once, so a burst
/// well above the sustained rate is legitimate; twice the per-second rate absorbs that
/// without letting a flood accumulate credit.
pub const DEFAULT_TLS_SIGN_BURST: u32 = 200;

/// A token bucket bounding how many TLS handshake signatures unauthenticated peers can
/// force out of a remote, billed, account-throttled signer.
///
/// In TLS 1.3 the server signs the handshake transcript BEFORE it has seen the client
/// certificate, so `Signer::sign` is reachable by anything that can complete a
/// ClientHello — no credential, no client cert. On the delegated custody paths that
/// signature is a blocking KMS `Sign` round trip or a PKCS#11 `C_Sign`, and session
/// resumption is refused by design, so each connection costs exactly one. Without a
/// bound, cheap inbound TCP converts 1:1 into paid, quota-limited signing calls against
/// the SAME account and key material the cold-path delegated-key issuer uses — so a
/// handshake flood throttles credential issuance and the fleet fails closed at its
/// keys' `exp`.
///
/// Refusing the handshake is the fail-closed direction: a refused connection costs the
/// peer a retry, whereas an exhausted KMS quota is a fleet-wide outage.
#[derive(Debug)]
pub struct TlsHandshakeSignBudget {
    /// Bucket capacity (the burst allowance), in tokens.
    capacity: f64,
    /// Sustained refill rate, in tokens per second.
    refill_per_sec: f64,
    /// `(tokens available, last refill instant)`. A short uncontended lock per
    /// handshake, which is orders of magnitude cheaper than the signature it guards.
    state: Mutex<(f64, Instant)>,
    /// How many signatures this budget has refused, for the operator-facing posture.
    refused: AtomicU64,
}

impl TlsHandshakeSignBudget {
    /// A budget of `rate_per_sec` sustained signatures with a `burst` allowance. Both
    /// are clamped to at least 1 so a mis-set value cannot disable the signer outright.
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        TlsHandshakeSignBudget {
            capacity: f64::from(burst.max(1)),
            refill_per_sec: f64::from(rate_per_sec.max(1)),
            state: Mutex::new((f64::from(burst.max(1)), Instant::now())),
            refused: AtomicU64::new(0),
        }
    }

    /// The sustained rate this budget enforces, for the startup posture line.
    pub fn rate_per_sec(&self) -> u32 {
        self.refill_per_sec as u32
    }

    /// The burst allowance, for the startup posture line.
    pub fn burst(&self) -> u32 {
        self.capacity as u32
    }

    /// Signatures refused so far because the budget was exhausted.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Take one token, or report that the budget is exhausted.
    ///
    /// A poisoned lock is treated as exhausted: the only writer is this method, so a
    /// poisoned lock means a panic inside it, and continuing to sign off state that is
    /// not known good is the direction this exists to prevent.
    fn try_acquire(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let now = Instant::now();
        let elapsed = now.duration_since(state.1).as_secs_f64();
        state.1 = now;
        state.0 = (state.0 + elapsed * self.refill_per_sec).min(self.capacity);
        if state.0 >= 1.0 {
            state.0 -= 1.0;
            true
        } else {
            drop(state);
            self.refused.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

impl Default for TlsHandshakeSignBudget {
    fn default() -> Self {
        TlsHandshakeSignBudget::new(DEFAULT_TLS_SIGN_RATE_PER_SEC, DEFAULT_TLS_SIGN_BURST)
    }
}

/// A [`rustls::sign::SigningKey`] that delegates Ed25519 handshake signing to a
/// non-exporting [`RawEd25519TlsSigner`].
pub struct DelegatedEd25519SigningKey {
    signer: Arc<dyn RawEd25519TlsSigner>,
    budget: Arc<TlsHandshakeSignBudget>,
}

impl std::fmt::Debug for DelegatedEd25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material or backend internals.
        f.write_str("DelegatedEd25519SigningKey(<non-exporting Ed25519>)")
    }
}

impl DelegatedEd25519SigningKey {
    /// A signing key guarded by the default handshake-signature budget
    /// ([`DEFAULT_TLS_SIGN_RATE_PER_SEC`] / [`DEFAULT_TLS_SIGN_BURST`]).
    pub fn new(signer: Arc<dyn RawEd25519TlsSigner>) -> Self {
        DelegatedEd25519SigningKey::with_budget(signer, Arc::new(TlsHandshakeSignBudget::default()))
    }

    /// A signing key guarded by a caller-supplied budget, so an embedder sized against a
    /// different KMS quota (or several servers sharing one account) can hand the same
    /// budget to each.
    pub fn with_budget(
        signer: Arc<dyn RawEd25519TlsSigner>,
        budget: Arc<TlsHandshakeSignBudget>,
    ) -> Self {
        DelegatedEd25519SigningKey { signer, budget }
    }

    /// The budget guarding this key's remote signer.
    pub fn budget(&self) -> &Arc<TlsHandshakeSignBudget> {
        &self.budget
    }
}

impl SigningKey for DelegatedEd25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Only Ed25519 — fail closed (no signer) if the peer does not offer it, so a
        // non-Ed25519 negotiation never silently proceeds with the wrong algorithm.
        if offered.contains(&SignatureScheme::ED25519) {
            Some(Box::new(DelegatedEd25519Signer {
                signer: self.signer.clone(),
                budget: Arc::clone(&self.budget),
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct DelegatedEd25519Signer {
    signer: Arc<dyn RawEd25519TlsSigner>,
    budget: Arc<TlsHandshakeSignBudget>,
}

impl std::fmt::Debug for DelegatedEd25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DelegatedEd25519Signer(<non-exporting Ed25519>)")
    }
}

impl Signer for DelegatedEd25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // The peer is still unauthenticated here (TLS 1.3 signs before the client
        // certificate is seen), so the budget is checked BEFORE the remote signer is
        // touched. Refusing the handshake costs the peer a retry; spending the KMS quota
        // costs the fleet its ability to issue delegated credentials at all.
        if !self.budget.try_acquire() {
            return Err(rustls::Error::General(
                "delegated TLS handshake-signature budget exhausted; this connection is \
                 refused so unauthenticated peers cannot spend the signing quota the \
                 delegated-key issuer depends on"
                    .to_string(),
            ));
        }
        let sig = self
            .signer
            .sign_tls_ed25519(message)
            .map_err(|e| rustls::Error::General(format!("delegated TLS Ed25519 sign: {e}")))?;
        // A wrong-length signature would corrupt the handshake; fail closed.
        if sig.len() != ED25519_SIGNATURE_LEN {
            return Err(rustls::Error::General(format!(
                "delegated TLS Ed25519 sign returned {} bytes; expected {ED25519_SIGNATURE_LEN}",
                sig.len()
            )));
        }
        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// A fixed-certificate [`ResolvesServerCert`] pairing the (public) Ed25519 server
/// certificate chain with a [`DelegatedEd25519SigningKey`]. Used via
/// `ServerConfig::builder(...).with_cert_resolver(...)` so rustls drives the
/// handshake signature through the device/KMS.
#[derive(Debug)]
pub struct DelegatedCertResolver {
    certified: Arc<CertifiedKey>,
    budget: Arc<TlsHandshakeSignBudget>,
}

impl DelegatedCertResolver {
    /// Pair the server certificate chain (public; loaded from a file) with the
    /// delegated signer for its key, guarded by the default handshake-signature budget.
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        signer: Arc<dyn RawEd25519TlsSigner>,
    ) -> Arc<Self> {
        DelegatedCertResolver::with_budget(
            cert_chain,
            signer,
            Arc::new(TlsHandshakeSignBudget::default()),
        )
    }

    /// As [`new`](Self::new), with a caller-supplied budget.
    pub fn with_budget(
        cert_chain: Vec<CertificateDer<'static>>,
        signer: Arc<dyn RawEd25519TlsSigner>,
        budget: Arc<TlsHandshakeSignBudget>,
    ) -> Arc<Self> {
        let key = Arc::new(DelegatedEd25519SigningKey::with_budget(
            signer,
            Arc::clone(&budget),
        ));
        Arc::new(DelegatedCertResolver {
            certified: Arc::new(CertifiedKey::new(cert_chain, key)),
            budget,
        })
    }

    /// The budget bounding how fast unauthenticated peers can drive the remote signer.
    pub fn budget(&self) -> &Arc<TlsHandshakeSignBudget> {
        &self.budget
    }
}

impl ResolvesServerCert for DelegatedCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }
}

#[cfg(test)]
mod tests {
    use mcp_re_core::b64url_decode;
    use mcp_re_core::SigningKey as McpReSigningKey;

    use super::*;

    /// A local-key delegated signer (stands in for the device/KMS): signs the raw
    /// message with a local Ed25519 key, exactly as a KMS RAW `Sign` would.
    struct LocalEd25519(McpReSigningKey);
    impl RawEd25519TlsSigner for LocalEd25519 {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
            Ok(b64url_decode(&self.0.sign(message)).expect("local sig is valid b64url"))
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
            let mut der = crate::kms_keysource::ED25519_SPKI_PREFIX.to_vec();
            der.extend_from_slice(&self.0.public_key().to_bytes());
            Ok(der)
        }
    }

    #[test]
    fn offers_ed25519_only() {
        let key = DelegatedEd25519SigningKey::new(Arc::new(LocalEd25519(
            McpReSigningKey::from_seed_bytes(&[1u8; 32]),
        )));
        assert_eq!(key.algorithm(), SignatureAlgorithm::ED25519);
        assert!(key.choose_scheme(&[SignatureScheme::ED25519]).is_some());
        // No Ed25519 on offer → fail closed (no signer), never a wrong algorithm.
        assert!(key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .is_none());
    }

    #[test]
    fn signer_scheme_is_ed25519_and_signature_is_64_bytes() {
        let key = DelegatedEd25519SigningKey::new(Arc::new(LocalEd25519(
            McpReSigningKey::from_seed_bytes(&[2u8; 32]),
        )));
        let signer = key
            .choose_scheme(&[SignatureScheme::ED25519])
            .expect("signer");
        assert_eq!(signer.scheme(), SignatureScheme::ED25519);
        let sig = signer.sign(b"tls handshake transcript").expect("sign");
        assert_eq!(sig.len(), 64);
    }

    /// A wrong-length raw signature (a misconfigured non-Ed25519 backend) corrupts
    /// the handshake — the signer fails closed rather than emitting it.
    #[test]
    fn wrong_length_signature_fails_closed() {
        struct ShortSig;
        impl RawEd25519TlsSigner for ShortSig {
            fn sign_tls_ed25519(&self, _m: &[u8]) -> Result<Vec<u8>, KeyError> {
                Ok(vec![0u8; 63])
            }
            fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
                Ok(crate::kms_keysource::ED25519_SPKI_PREFIX.to_vec())
            }
        }
        let key = DelegatedEd25519SigningKey::new(Arc::new(ShortSig));
        let signer = key.choose_scheme(&[SignatureScheme::ED25519]).unwrap();
        assert!(signer.sign(b"x").is_err());
    }

    /// Counts how many times the remote signer was actually reached, which is what the
    /// budget exists to bound — a status-only assertion would pass while every
    /// ClientHello still bought a KMS `Sign`.
    #[derive(Default)]
    struct CountingSigner {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl RawEd25519TlsSigner for CountingSigner {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let key = McpReSigningKey::from_seed_bytes(&[7u8; 32]);
            Ok(b64url_decode(&key.sign(message)).expect("local sig is valid b64url"))
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
            Ok(crate::kms_keysource::ED25519_SPKI_PREFIX.to_vec())
        }
    }

    /// An unauthenticated handshake flood must not reach the remote signer once the
    /// budget is spent: the refused handshakes cost ZERO signer invocations.
    #[test]
    fn handshake_signature_budget_bounds_remote_signer_invocations() {
        let counting = Arc::new(CountingSigner::default());
        // A tiny budget with a slow refill, so the burst is the whole allowance here.
        let budget = Arc::new(TlsHandshakeSignBudget::new(1, 3));
        let key = DelegatedEd25519SigningKey::with_budget(counting.clone(), Arc::clone(&budget));
        let mut ok = 0usize;
        let mut refused = 0usize;
        for _ in 0..50 {
            let signer = key
                .choose_scheme(&[SignatureScheme::ED25519])
                .expect("signer");
            match signer.sign(b"transcript") {
                Ok(_) => ok += 1,
                Err(_) => refused += 1,
            }
        }
        // The burst is 3 and the refill is 1/s, so a tight loop draws at most the burst
        // plus whatever fraction of a second the loop takes.
        assert!(ok >= 3, "the burst allowance must be usable, got {ok}");
        assert!(ok < 10, "the flood must be bounded, got {ok} signatures");
        assert!(
            refused > 0,
            "the flood must be refused once the budget is spent"
        );
        assert_eq!(
            counting.calls.load(Ordering::Relaxed),
            ok,
            "a refused handshake must never reach the remote signer"
        );
        assert_eq!(budget.refused(), refused as u64);
    }

    /// Two resolvers built around ONE budget draw from one bucket.
    ///
    /// This is what makes the budget survive a `ServerConfig` rebuild: the TLS plane
    /// creates the budget once and hands the same one to every build, including the
    /// `--client-crl-reload-secs` rebuild. The broken implementation this catches is
    /// `DelegatedCertResolver::new` on the reload path, which mints a fresh full bucket
    /// on every cadence — turning a sustained rate limit into a per-interval window.
    #[test]
    fn resolvers_sharing_a_budget_share_one_bucket() {
        let counting = Arc::new(CountingSigner::default());
        let budget = Arc::new(TlsHandshakeSignBudget::new(1, 2));
        let first = DelegatedCertResolver::with_budget(
            vec![CertificateDer::from(vec![1u8; 8])],
            counting.clone(),
            Arc::clone(&budget),
        );
        let second = DelegatedCertResolver::with_budget(
            vec![CertificateDer::from(vec![1u8; 8])],
            counting.clone(),
            Arc::clone(&budget),
        );
        assert!(Arc::ptr_eq(first.budget(), second.budget()));
        // Spend the whole burst through the first resolver's key.
        assert!(budget.try_acquire());
        assert!(budget.try_acquire());
        // The rebuilt resolver must NOT start from a full bucket.
        let signer = second
            .certified
            .key
            .choose_scheme(&[SignatureScheme::ED25519])
            .expect("signer");
        assert!(
            signer.sign(b"transcript").is_err(),
            "a rebuilt resolver must inherit the spent bucket, not a fresh one"
        );
        assert_eq!(
            counting.calls.load(Ordering::Relaxed),
            0,
            "a refused handshake must never reach the remote signer"
        );
    }

    /// The budget refills, so a bounded rate is a RATE and not a one-shot quota.
    #[test]
    fn handshake_signature_budget_refills_over_time() {
        let budget = TlsHandshakeSignBudget::new(1000, 1);
        assert!(budget.try_acquire());
        assert!(!budget.try_acquire());
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(budget.try_acquire(), "the bucket must refill with time");
    }
}
