// SPDX-License-Identifier: Apache-2.0
//! RFC 7638 JWK thumbprint keyids (#415 rev 2 §1.5).
//!
//! The profile's `keyid` convention is the base64url-no-pad SHA-256 JWK
//! thumbprint of the signing key, aligning with the Web Bot Auth / WIMSE
//! conventions. A keyid remains a SELECTOR, never a trust input: deriving it
//! from the key material makes it self-describing and collision-resistant, but
//! the trust seam still decides whether the key it selects is trusted for the
//! slot (CONTEXT.md anchor rule). A verifier MUST NOT skip resolution because a
//! presented keyid happens to match the key the message carries.
//!
//! Thumbprint construction (RFC 7638 §3): the JWK's REQUIRED members only, with
//! no whitespace, members in lexicographic order of their names, then SHA-256.
//! For an Ed25519 OKP key (RFC 8037 §2) the required members are `crv`, `kty`,
//! and `x` — already lexicographic in that order.

use mcp_re_core::b64url_encode;
use sha2::Digest;
use sha2::Sha256;

use crate::delegation::JWK_CRV_ED25519;
use crate::delegation::JWK_KTY_OKP;

/// The RFC 7638 canonical JWK form for an Ed25519 public key: required members
/// only, lexicographic, no whitespace. `x` is the base64url-no-pad public key.
///
/// Built by direct formatting rather than through `serde_json` because RFC 7638
/// requires an exact byte form — a serializer that reorders members or emits
/// whitespace would silently change every derived keyid.
fn canonical_ed25519_jwk(public_key_b64url: &str) -> String {
    format!(
        r#"{{"crv":"{JWK_CRV_ED25519}","kty":"{JWK_KTY_OKP}","x":"{public_key_b64url}"}}"#
    )
}

/// Derive the profile keyid for an Ed25519 public key: the base64url-no-pad
/// SHA-256 RFC 7638 thumbprint of its JWK.
///
/// `public_key_b64url` is the key's base64url-no-pad `x` coordinate — the same
/// encoding `mcp_re_core::VerificationKey` and the delegation credential's
/// `cnf.jwk.x` use.
pub fn jwk_thumbprint_ed25519(public_key_b64url: &str) -> String {
    b64url_encode(&Sha256::digest(
        canonical_ed25519_jwk(public_key_b64url).as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 §A.3 pins the thumbprint of the RFC 8037 §A.1 example Ed25519
    /// public key. A third-party KAT, not this implementation's own opinion.
    #[test]
    fn rfc8037_a3_known_answer() {
        let x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        assert_eq!(
            jwk_thumbprint_ed25519(x),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn canonical_form_is_lexicographic_and_unspaced() {
        let jwk = canonical_ed25519_jwk("AAAA");
        assert_eq!(jwk, r#"{"crv":"Ed25519","kty":"OKP","x":"AAAA"}"#);
        assert!(!jwk.contains(' '), "RFC 7638 forbids whitespace");
    }

    #[test]
    fn thumbprint_is_deterministic_and_key_bound() {
        let a = jwk_thumbprint_ed25519("AAAA");
        assert_eq!(a, jwk_thumbprint_ed25519("AAAA"));
        assert_ne!(a, jwk_thumbprint_ed25519("AAAB"));
        assert!(!a.ends_with('='), "base64url no-pad");
    }
}
