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
    format!(r#"{{"crv":"{JWK_CRV_ED25519}","kty":"{JWK_KTY_OKP}","x":"{public_key_b64url}"}}"#)
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

    /// The half of selector injectivity that is a property of THIS code.
    ///
    /// Two distinct keys have distinct canonical forms, because the form is a fixed prefix,
    /// the operand verbatim, and a fixed suffix. Concatenation with fixed affixes is
    /// injective on any input at all, so no `x` — however chosen — can produce another
    /// `x`'s form. The claim needs no assumption about the operand's alphabet, which is
    /// what makes it hold for the delegated-credential path too.
    #[test]
    fn the_canonical_form_embeds_its_operand_verbatim_between_fixed_affixes() {
        const PREFIX: &str = r#"{"crv":"Ed25519","kty":"OKP","x":""#;
        const SUFFIX: &str = r#""}"#;
        for x in [
            "",
            "AAAA",
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            // Adversarial: JSON metacharacters. The form is not escaped, so a caller could
            // in principle nest structure here — and it still cannot COLLIDE, because the
            // affixes pin where the operand starts and ends.
            r#"A","x":"B"#,
            "\\",
        ] {
            let form = canonical_ed25519_jwk(x);
            assert_eq!(form, format!("{PREFIX}{x}{SUFFIX}"));
            assert_eq!(
                form.strip_prefix(PREFIX)
                    .and_then(|r| r.strip_suffix(SUFFIX)),
                Some(x),
                "the operand is recoverable, so distinct operands have distinct forms"
            );
        }
    }

    /// Distinct operands give distinct canonical forms, asked directly over a corpus that
    /// includes the pairs a naive concatenation would confuse.
    #[test]
    fn distinct_operands_never_share_a_canonical_form() {
        let corpus = [
            "",
            "A",
            "AA",
            "AAAA",
            "AAAB",
            r#"A","x":"B"#,
            r#"B","x":"A"#,
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        ];
        for (i, a) in corpus.iter().enumerate() {
            for b in corpus.iter().skip(i + 1) {
                assert_ne!(
                    canonical_ed25519_jwk(a),
                    canonical_ed25519_jwk(b),
                    "{a:?} and {b:?} share a canonical form"
                );
            }
        }
    }

    /// The other half of the derivation that is ours: the digest encoding does not merge
    /// distinct digests. base64url-no-pad is injective over fixed-width inputs, and the
    /// keyid is always a 32-byte SHA-256 output.
    #[test]
    fn the_keyid_encoding_is_injective_over_the_digest_width() {
        let mut seen = std::collections::BTreeSet::new();
        for byte in 0u8..=255 {
            let digest = [byte; 32];
            assert!(
                seen.insert(b64url_encode(&digest)),
                "two distinct digests encoded to the same keyid"
            );
        }
        assert_eq!(seen.len(), 256);
    }
}
