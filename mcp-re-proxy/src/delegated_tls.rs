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

use rustls::sign::Signer;
use rustls::sign::SigningKey;
use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;

use crate::key_source::KeyError;

mod resolver;
pub use resolver::DelegatedCertResolver;

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
    /// How many times a poisoned lock has been recovered here.
    ///
    /// Separate from [`Self::refused`] because they are different operator facts and only
    /// one of them is about this budget: `refused` means the deployment's own rate limit
    /// did its job, which is ordinary and expected under load; this means a thread panicked
    /// while holding the bucket, which is a bug and is reported nowhere else. Recovery makes
    /// the panic invisible, so it is counted where an operator can see it.
    poison_observed: AtomicU64,
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
            poison_observed: AtomicU64::new(0),
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

    /// Distinct poison events observed so far. A non-zero value means a thread panicked
    /// while holding the bucket and is a bug to investigate, not a load signal.
    pub fn poison_observed(&self) -> u64 {
        self.poison_observed.load(Ordering::Relaxed)
    }

    /// Take one token, or report that the budget is exhausted.
    ///
    /// # What a poisoned lock means here
    ///
    /// It is recovered, counted on [`Self::poison_observed`], and the bucket is used. The
    /// budget bounds the RATE at which handshakes may reach the signer; it is not the
    /// authority that decides whether they may — the key is. So the worst an unwind inside
    /// the guarded region can do is leave the bucket credited but not debited, which
    /// over-grants exactly one signature; and nothing in that region can actually panic,
    /// since `f64` arithmetic is total and [`Instant::duration_since`] saturates.
    ///
    /// Refusing stickily would trade that bounded over-grant for a permanent loss of
    /// handshake signing on this listener, which is the outage the budget exists to
    /// prevent one cause of. [`crate::handshake_quota::HandshakeQuotaWindow`], the sibling
    /// throttle one layer out, recovers for the same reason and states it the same way.
    fn try_acquire(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| {
            self.poison_observed.fetch_add(1, Ordering::Relaxed);
            // Clear the flag so the counter measures PANICS and not calls. Left sticky, a
            // single panic makes every later handshake increment it, and the number an
            // operator reads would track traffic rather than faults.
            self.state.clear_poison();
            poisoned.into_inner()
        });
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
    /// A signing key guarded by the budget its caller was given.
    ///
    /// Reachable only inside [`crate::delegated_tls`], which has exactly one producer:
    /// [`resolver::DelegatedCertResolver::materialize`], the correspondence gate. This
    /// wraps a live capability to invoke a non-exporting KMS or PKCS#11 key, and a
    /// published constructor for it was MCP-RE's own shortcut past that gate — a
    /// delegated-shaped handshake signer that had been checked against no credential and
    /// drew on whatever bucket the caller chose.
    ///
    /// Narrowing does not make an unbudgeted delegated signer unconstructible, and is not
    /// claimed to: `rustls::sign::SigningKey` and [`RawEd25519TlsSigner`] are public
    /// traits, so an embedder can write its own. What it removes is this crate publishing
    /// the shortcut and then documenting elsewhere that the gate is the only way in.
    ///
    /// The budget-free sibling is gone with it. It minted
    /// `TlsHandshakeSignBudget::default()` per key, so two keys built that way shared no
    /// bucket — the opposite of what the listener's budget is for — and its only callers
    /// were this module's own tests.
    pub(in crate::delegated_tls) fn with_budget(
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
#[cfg(test)]
mod tests {
    use mcp_re_core::b64url_decode;
    use mcp_re_core::SigningKey as McpReSigningKey;
    use rustls_pki_types::CertificateDer;

    use super::*;

    /// Real corresponding material: an Ed25519 leaf certificate and a delegated signer
    /// holding exactly the key that certificate presents.
    ///
    /// Minted rather than faked, because after ADR-MCPRE-063 Slice 3 a resolver cannot come
    /// into existence unless its credential and signer correspond — so a test that wants a
    /// resolver has to present material that does.
    /// The PKCS#8 v1 wrapper for a raw Ed25519 seed (RFC 5958 / RFC 8410): the fixed
    /// sixteen-byte header, then the thirty-two seed bytes.
    const PKCS8_ED25519_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];

    /// A self-signed Ed25519 leaf presenting the public key of `seed`.
    ///
    /// The certificate and the signer are derived from ONE seed, which is what makes the
    /// material correspond — after Slice 3 a resolver cannot exist unless it does, so a
    /// test that wants a resolver has to mint a matching pair rather than a plausible one.
    pub(super) fn leaf_for_seed(seed: &[u8; 32]) -> CertificateDer<'static> {
        let mut pkcs8 = PKCS8_ED25519_PREFIX.to_vec();
        pkcs8.extend_from_slice(seed);
        let key = rcgen::KeyPair::try_from(pkcs8.as_slice()).expect("ed25519 pkcs8");
        let params = rcgen::CertificateParams::new(vec!["delegated.example.org".to_string()])
            .expect("params");
        params
            .self_signed(&key)
            .expect("self-signed leaf")
            .der()
            .clone()
    }

    /// A leaf and a delegated signer for the same key.
    pub(super) fn corresponding_material(
    ) -> (Vec<CertificateDer<'static>>, Arc<dyn RawEd25519TlsSigner>) {
        let seed = [11u8; 32];
        (
            vec![leaf_for_seed(&seed)],
            Arc::new(LocalEd25519(McpReSigningKey::from_seed_bytes(&seed)))
                as Arc<dyn RawEd25519TlsSigner>,
        )
    }

    /// A local-key delegated signer (stands in for the device/KMS): signs the raw
    /// message with a local Ed25519 key, exactly as a KMS RAW `Sign` would.
    pub(super) struct LocalEd25519(pub McpReSigningKey);
    impl RawEd25519TlsSigner for LocalEd25519 {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
            Ok(b64url_decode(&self.0.sign(message)).expect("local sig is valid b64url"))
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
            let der = crate::communication_assurance::Ed25519PublicKeyValue::spki_der_for_point(
                self.0.public_key().to_bytes(),
            );
            Ok(der)
        }
    }

    #[test]
    fn offers_ed25519_only() {
        let key = DelegatedEd25519SigningKey::with_budget(
            Arc::new(LocalEd25519(McpReSigningKey::from_seed_bytes(&[1u8; 32]))),
            Arc::new(TlsHandshakeSignBudget::default()),
        );
        assert_eq!(key.algorithm(), SignatureAlgorithm::ED25519);
        assert!(key.choose_scheme(&[SignatureScheme::ED25519]).is_some());
        // No Ed25519 on offer → fail closed (no signer), never a wrong algorithm.
        assert!(key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .is_none());
    }

    #[test]
    fn signer_scheme_is_ed25519_and_signature_is_64_bytes() {
        let key = DelegatedEd25519SigningKey::with_budget(
            Arc::new(LocalEd25519(McpReSigningKey::from_seed_bytes(&[2u8; 32]))),
            Arc::new(TlsHandshakeSignBudget::default()),
        );
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
                Ok(
                    crate::communication_assurance::Ed25519PublicKeyValue::spki_der_for_point(
                        [0u8; 32],
                    ),
                )
            }
        }
        let key = DelegatedEd25519SigningKey::with_budget(
            Arc::new(ShortSig),
            Arc::new(TlsHandshakeSignBudget::default()),
        );
        let signer = key.choose_scheme(&[SignatureScheme::ED25519]).unwrap();
        assert!(signer.sign(b"x").is_err());
    }

    /// Counts how many times the remote signer was actually reached, which is what the
    /// budget exists to bound — a status-only assertion would pass while every
    /// ClientHello still bought a KMS `Sign`.
    #[derive(Default)]
    pub(super) struct CountingSigner {
        pub(super) calls: std::sync::atomic::AtomicUsize,
    }
    impl RawEd25519TlsSigner for CountingSigner {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let key = McpReSigningKey::from_seed_bytes(&COUNTING_SIGNER_SEED);
            Ok(b64url_decode(&key.sign(message)).expect("local sig is valid b64url"))
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
            // The key it actually signs with. A signer exporting one key and signing with
            // another is precisely what correspondence refuses, so a test fake that did
            // that could no longer be used to build a resolver at all.
            let key = McpReSigningKey::from_seed_bytes(&COUNTING_SIGNER_SEED);
            Ok(
                crate::communication_assurance::Ed25519PublicKeyValue::spki_der_for_point(
                    key.public_key().to_bytes(),
                ),
            )
        }
    }

    /// The seed `CountingSigner` signs with, and the seed its certificate presents.
    pub(super) const COUNTING_SIGNER_SEED: [u8; 32] = [7u8; 32];

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

    /// The budget refills, so a bounded rate is a RATE and not a one-shot quota.
    #[test]
    fn handshake_signature_budget_refills_over_time() {
        let budget = TlsHandshakeSignBudget::new(1000, 1);
        assert!(budget.try_acquire());
        assert!(!budget.try_acquire());
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(budget.try_acquire(), "the bucket must refill with time");
    }

    /// A poisoned bucket keeps signing, counts the panic, and does not call it a throttle.
    ///
    /// Poison is sticky, and this budget sits on the TLS handshake path: a single panic
    /// under the guard would otherwise refuse every later handshake signature for the
    /// process lifetime — the listener stops serving — in exchange for preventing a
    /// one-token over-grant. The budget bounds the rate at which handshakes reach the
    /// signer, not whether they may, so the trade is the wrong way round.
    ///
    /// The count is asserted to be per PANIC rather than per call, which is what
    /// `clear_poison` buys; and `refused` is asserted not to move, because an operator
    /// reading it needs "the rate limit did its job" to stay distinguishable from "a thread
    /// died holding the bucket".
    #[test]
    fn a_poisoned_budget_lock_still_signs_and_counts_the_panic_once() {
        let budget = Arc::new(TlsHandshakeSignBudget::new(1000, 100));
        let poisoner = Arc::clone(&budget);
        let unwound = std::thread::spawn(move || {
            let _guard = poisoner.state.lock().expect("uncontended");
            panic!("a panic under the budget guard");
        })
        .join();
        assert!(unwound.is_err(), "the poisoning thread must have unwound");

        assert!(
            budget.try_acquire(),
            "a poisoned bucket must not cost the listener its handshake signing"
        );
        assert_eq!(budget.poison_observed(), 1);
        assert_eq!(
            budget.refused(),
            0,
            "a recovered panic is not a throttled signature"
        );

        // The flag was cleared, so the next handshake is an ordinary one.
        assert!(budget.try_acquire());
        assert_eq!(
            budget.poison_observed(),
            1,
            "the counter must measure panics, not calls that followed one"
        );
        assert_eq!(budget.refused(), 0);
    }
}
