//! Ed25519 signing and verification primitives (MCPS_SPEC §3 / ADR-004).
//!
//! The MCP-S signing rule is: canonicalize the protected JSON-RPC object (with
//! `signature.value` removed) to RFC 8785 bytes, then sign/verify those bytes
//! DIRECTLY with Ed25519 — NO pre-hash (Ed25519ph is forbidden). All signature
//! values are Base64URL-no-pad.
//!
//! # Error mapping (deliberate)
//! - A resolved-but-malformed verification key (bad length / not a valid point)
//!   is a trust-binding failure, so [`VerificationKey::from_bytes`] /
//!   [`VerificationKey::from_b64url`] map to [`McpsError::ActorBindingFailed`]
//!   (MCPS_SPEC §6).
//! - On the request path, ANY verification failure (bad b64, wrong length, bad
//!   point, or a cryptographic mismatch) maps to [`McpsError::InvalidSignature`]
//!   via [`verify_ed25519`]. The response path needs the SAME failure to surface
//!   as [`McpsError::ResponseSigInvalid`]; rather than duplicate the logic we
//!   expose a single error-agnostic core, [`verify_ed25519_with`], that takes the
//!   error to return, and provide the thin [`verify_ed25519`] request wrapper.
//!   Response-side callers (MCPS-008) call `verify_ed25519_with(.., ResponseSigInvalid)`.

use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey as DalekSigningKey;
use ed25519_dalek::VerifyingKey as DalekVerifyingKey;

use crate::encoding::b64url_decode;
use crate::encoding::b64url_encode;
use crate::error::McpsError;

/// Raw Ed25519 signature length in bytes.
const SIGNATURE_LEN: usize = 64;

/// An Ed25519 verification (public) key.
///
/// Constructed from 32 raw bytes or a Base64URL-no-pad string. A malformed key
/// is a trust-binding failure ([`McpsError::ActorBindingFailed`]) per spec §6.
#[derive(Debug, Clone)]
pub struct VerificationKey {
    inner: DalekVerifyingKey,
}

impl VerificationKey {
    /// Build a verification key from exactly 32 raw bytes. Malformed (not a valid
    /// curve point) → [`McpsError::ActorBindingFailed`].
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, McpsError> {
        let inner =
            DalekVerifyingKey::from_bytes(bytes).map_err(|_| McpsError::ActorBindingFailed)?;
        Ok(VerificationKey { inner })
    }

    /// Build a verification key from a Base64URL-no-pad string. Bad encoding,
    /// wrong length, or invalid point → [`McpsError::ActorBindingFailed`].
    pub fn from_b64url(s: &str) -> Result<Self, McpsError> {
        let decoded = b64url_decode(s).map_err(|_| McpsError::ActorBindingFailed)?;
        let array: [u8; 32] = decoded
            .try_into()
            .map_err(|_| McpsError::ActorBindingFailed)?;
        Self::from_bytes(&array)
    }

    /// The 32 raw public-key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// The Base64URL-no-pad encoding of the 32 public-key bytes.
    pub fn to_b64url(&self) -> String {
        b64url_encode(&self.inner.to_bytes())
    }
}

/// An Ed25519 signing (private) key.
///
/// Pure and I/O-free: signing belongs in the library (it has no side effects)
/// and is needed to generate reproducible conformance vectors (MCPS-002). It is
/// NOT a purity violation.
///
/// # Custody boundary (MCPS-076, ADR-MCPS-028)
/// This is the IN-PROCESS SOFTWARE signer. PRODUCTION key custody (no soft-key
/// fallback; non-exporting HSM / cloud-KMS only) is enforced OUTSIDE this crate,
/// at the proxy/host signer layer: production routes through the
/// `ResponseSigner` / `KeySource` seam (`mcps-proxy`'s PKCS#11 / AWS-KMS /
/// GCP-KMS backends), which sign on the device and never reconstruct a raw seed.
/// `from_seed_bytes` is reached only on test, conformance, and the gated dev
/// `--key-source file` / `--allow-env-keysource` paths.
///
/// # Secret hygiene
/// The secret scalar lives inside dalek's `DalekSigningKey`, which is
/// `ZeroizeOnDrop` (the `zeroize` feature is enabled workspace-wide), so it is
/// scrubbed on drop. There is deliberately NO seed/key EXPORT method (no
/// `to_bytes` / `to_seed`) and no separate raw `[u8; 32]` copy is retained.
/// `Clone` is intentionally NOT derived — a private key should not be silently
/// duplicated. `Debug` is derived but dalek redacts the secret (prints just
/// `"SigningKey"`), so it cannot leak the key into logs.
#[derive(Debug)]
pub struct SigningKey {
    inner: DalekSigningKey,
}

impl SigningKey {
    /// Build a signing key from a 32-byte seed. Infallible (every 32-byte seed
    /// is a valid Ed25519 secret scalar seed).
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        SigningKey {
            inner: DalekSigningKey::from_bytes(seed),
        }
    }

    /// Derive the matching public verification key.
    pub fn public_key(&self) -> VerificationKey {
        VerificationKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign `preimage` directly (no pre-hash) and return the Base64URL-no-pad
    /// signature.
    pub fn sign(&self, preimage: &[u8]) -> String {
        let signature: Signature = self.inner.sign(preimage);
        b64url_encode(&signature.to_bytes())
    }
}

/// Verify an Ed25519 signature over `preimage` (DIRECTLY, no pre-hash),
/// returning `on_error` (cloned) on ANY failure: bad Base64URL, wrong length, or
/// cryptographic mismatch.
///
/// This is the error-agnostic core. Request-side callers use the
/// [`verify_ed25519`] wrapper ([`McpsError::InvalidSignature`]); response-side
/// callers pass [`McpsError::ResponseSigInvalid`].
pub fn verify_ed25519_with(
    preimage: &[u8],
    signature_b64url: &str,
    key: &VerificationKey,
    on_error: McpsError,
) -> Result<(), McpsError> {
    let bytes = match b64url_decode(signature_b64url) {
        Ok(b) => b,
        Err(_) => return Err(on_error),
    };
    let array: [u8; SIGNATURE_LEN] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => return Err(on_error),
    };
    let signature = Signature::from_bytes(&array);
    // verify_strict rejects weak/small-order keys and non-canonical encodings.
    match key.inner.verify_strict(preimage, &signature) {
        Ok(()) => Ok(()),
        Err(_) => Err(on_error),
    }
}

/// Request-path Ed25519 verification: any failure → [`McpsError::InvalidSignature`].
pub fn verify_ed25519(
    preimage: &[u8],
    signature_b64url: &str,
    key: &VerificationKey,
) -> Result<(), McpsError> {
    verify_ed25519_with(
        preimage,
        signature_b64url,
        key,
        McpsError::InvalidSignature,
    )
}

#[cfg(test)]
mod tests {
    use super::verify_ed25519;
    use super::verify_ed25519_with;
    use super::SigningKey;
    use super::VerificationKey;
    use crate::error::McpsError;

    // A fixed, documented test seed so signatures are reproducible.
    const SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn sign_then_verify_round_trip() {
        let sk = SigningKey::from_seed_bytes(&SEED);
        let vk = sk.public_key();
        let preimage = b"canonical preimage bytes";
        let sig = sk.sign(preimage);
        assert!(verify_ed25519(preimage, &sig, &vk).is_ok());
    }

    #[test]
    fn signature_is_deterministic_for_fixed_seed() {
        let sk = SigningKey::from_seed_bytes(&SEED);
        let preimage = b"hello";
        // Ed25519 is deterministic; same seed + message -> same signature.
        assert_eq!(sk.sign(preimage), sk.sign(preimage));
    }

    #[test]
    fn tamper_preimage_fails() {
        let sk = SigningKey::from_seed_bytes(&SEED);
        let vk = sk.public_key();
        let preimage = b"original preimage";
        let sig = sk.sign(preimage);

        let mut tampered = preimage.to_vec();
        tampered[0] ^= 0x01;
        assert_eq!(
            verify_ed25519(&tampered, &sig, &vk).unwrap_err(),
            McpsError::InvalidSignature
        );
    }

    #[test]
    fn wrong_key_fails() {
        let sk = SigningKey::from_seed_bytes(&SEED);
        let preimage = b"payload";
        let sig = sk.sign(preimage);

        let other = SigningKey::from_seed_bytes(&[9u8; 32]).public_key();
        assert_eq!(
            verify_ed25519(preimage, &sig, &other).unwrap_err(),
            McpsError::InvalidSignature
        );
    }

    #[test]
    fn malformed_signature_base64_fails() {
        let vk = SigningKey::from_seed_bytes(&SEED).public_key();
        assert_eq!(
            verify_ed25519(b"x", "not base64 !!!", &vk).unwrap_err(),
            McpsError::InvalidSignature
        );
    }

    #[test]
    fn wrong_length_signature_fails() {
        let vk = SigningKey::from_seed_bytes(&SEED).public_key();
        // Valid base64url but only a few bytes -> not 64.
        assert_eq!(
            verify_ed25519(b"x", "AAAA", &vk).unwrap_err(),
            McpsError::InvalidSignature
        );
    }

    #[test]
    fn response_variant_maps_to_response_sig_invalid() {
        let sk = SigningKey::from_seed_bytes(&SEED);
        let vk = sk.public_key();
        let preimage = b"response preimage";
        let sig = sk.sign(preimage);
        // Valid on the response path too.
        assert!(verify_ed25519_with(preimage, &sig, &vk, McpsError::ResponseSigInvalid).is_ok());
        // Tampered -> ResponseSigInvalid (not InvalidSignature).
        let mut tampered = preimage.to_vec();
        tampered[1] ^= 0x10;
        assert_eq!(
            verify_ed25519_with(&tampered, &sig, &vk, McpsError::ResponseSigInvalid).unwrap_err(),
            McpsError::ResponseSigInvalid
        );
    }

    #[test]
    fn verification_key_round_trips_bytes_and_b64url() {
        let vk = SigningKey::from_seed_bytes(&SEED).public_key();
        let bytes = vk.to_bytes();
        let from_bytes = VerificationKey::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(from_bytes.to_bytes(), bytes);

        let b64 = vk.to_b64url();
        let from_b64 = VerificationKey::from_b64url(&b64).expect("from_b64url");
        assert_eq!(from_b64.to_bytes(), bytes);
    }

    #[test]
    fn malformed_key_bytes_map_to_actor_binding_failed() {
        // Find a 32-byte encoding that is NOT a valid compressed Edwards point
        // (not every random pattern is — many y-coordinates have no curve point)
        // and assert it maps to ActorBindingFailed rather than constructing a key.
        let mut bad = [0u8; 32];
        let mut found = false;
        for seed in 0u8..=255 {
            bad = [seed; 32];
            if VerificationKey::from_bytes(&bad).is_err() {
                found = true;
                break;
            }
        }
        assert!(found, "expected at least one invalid 32-byte point encoding");
        assert_eq!(
            VerificationKey::from_bytes(&bad).unwrap_err(),
            McpsError::ActorBindingFailed
        );
    }

    #[test]
    fn malformed_key_b64url_maps_to_actor_binding_failed() {
        // Wrong length (3 bytes decoded, not 32).
        assert_eq!(
            VerificationKey::from_b64url("AAAA").unwrap_err(),
            McpsError::ActorBindingFailed
        );
        // Not valid base64url at all.
        assert_eq!(
            VerificationKey::from_b64url("!!!!").unwrap_err(),
            McpsError::ActorBindingFailed
        );
    }
}
