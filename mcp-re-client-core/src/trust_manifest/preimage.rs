// SPDX-License-Identifier: Apache-2.0
//! WHAT a trust-anchor manifest signature is over.
//!
//! One authority, and an injective encoding is the whole of it: a domain separator so these
//! bytes cannot be replayed as any other signature this system makes, and a LENGTH PREFIX
//! on `signer_kid` so no two `(signer_kid, manifest)` pairs can produce the same preimage
//! by moving the boundary between them. `signer_kid` is inside it because it is not
//! decoration — it names who vouched for these anchors, and a signature that did not cover
//! it would let one signer's manifest be re-attributed to another.
//!
//! It also owns the envelope those bytes travel in, because the envelope's `manifest` member
//! IS the signed bytes: the signer writes them there and the verifier reads them back.
//!
//! The manifest part of the preimage is the manifest's BYTES: the signer's serialization
//! when signing, and the `manifest` member exactly as received when verifying. A verifier
//! never rebuilds them from what it parsed, so the document it acts on is the document the
//! signature covers, byte for byte.

use serde::Deserialize;
use serde::Serialize;
use serde_json::value::RawValue;

use mcp_re_core::SigningKey;

use super::TrustAnchorManifest;

/// Domain separator for the manifest signing preimage, so these bytes cannot be
/// mistaken for — or replayed as — any other signature this profile produces.
const MANIFEST_SIGNING_DOMAIN: &[u8] = b"mcp-re/trust-anchor-manifest/v1";

/// The serialization a signer signs and distributes: `serde_json` over the manifest's fixed
/// field order. Only the signer calls it.
pub(super) fn manifest_body(manifest: &TrustAnchorManifest) -> serde_json::Result<String> {
    serde_json::to_string(manifest)
}

/// The exact bytes the org/admin signature covers:
/// `domain || u64be(len(signer_kid)) || signer_kid || manifest_bytes`.
///
/// `signer_kid` is inside the preimage because it is not decoration — it names who
/// published this trust picture, and it selects which pinned org key the verifier
/// checks against. Left outside, it is an unauthenticated field: the signature still
/// fails whenever two pinned kids map to distinct keys, but a deployment that ever
/// resolves two kids to the SAME key material (an org-key rename, a rotation overlap)
/// would accept a manifest under a signer identity its real holder never asserted,
/// and any provenance derived from `signer_kid` would be unauthenticated.
///
/// Length-prefixed so no `(signer_kid, manifest)` pair can be spelled as a different
/// one by moving the boundary between them.
pub(super) fn manifest_signing_preimage(manifest_bytes: &[u8], signer_kid: &str) -> Vec<u8> {
    // Class C: capacity only, over slice lengths plus the eight-byte length prefix.
    #[allow(clippy::arithmetic_side_effects)]
    let capacity = MANIFEST_SIGNING_DOMAIN.len() + 8 + signer_kid.len() + manifest_bytes.len();
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(MANIFEST_SIGNING_DOMAIN);
    preimage.extend_from_slice(&(signer_kid.len() as u64).to_be_bytes());
    preimage.extend_from_slice(signer_kid.as_bytes());
    preimage.extend_from_slice(manifest_bytes);
    preimage
}

/// A manifest plus the org/admin signature over its bytes.
///
/// `manifest` is held as the bytes the signer serialized and the reader received, never as
/// a parsed struct: the signature is checked over exactly those bytes, and only a manifest
/// whose bytes verified is parsed. Writing the envelope emits them verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTrustAnchorManifest {
    pub(super) manifest: Box<RawValue>,
    /// The org/admin manifest-signing key id the verifier must pin. **Covered by
    /// `signature`** — see [`manifest_signing_preimage`].
    pub(super) signer_kid: String,
    /// base64url-no-pad Ed25519 signature over [`manifest_signing_preimage`].
    pub(super) signature: String,
}

/// Sign a manifest with the org/admin key, producing the distributable envelope.
pub fn sign_manifest(
    manifest: &TrustAnchorManifest,
    org_key: &SigningKey,
    signer_kid: impl Into<String>,
) -> SignedTrustAnchorManifest {
    let signer_kid = signer_kid.into();
    // Class A: `serde_json` over a `TrustAnchorManifest`, a plain `Serialize` struct of owned
    // strings and integers, and the JSON text it just produced — assertions about this
    // crate's own types, never about an input. Verifiers parse received bytes fallibly.
    #[allow(clippy::expect_used)]
    let body = RawValue::from_string(
        manifest_body(manifest).expect("this crate's own manifest type serializes"),
    )
    .expect("serde_json output is JSON");
    let signature = org_key.sign(&manifest_signing_preimage(
        body.get().as_bytes(),
        &signer_kid,
    ));
    // SigningKey::sign returns base64url-no-pad.
    SignedTrustAnchorManifest {
        manifest: body,
        signer_kid,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signer_kid_manifest_boundary_cannot_be_moved() {
        // Without the length prefix, ("ab", <manifest>) and ("a", "b"+<manifest>) would
        // hash the same bytes. The manifest is JSON, so the shifted spelling is not
        // constructible here — the prefix is what makes that true by construction
        // rather than by luck.
        let m = TrustAnchorManifest {
            manifest_version: 1,
            profile: "mcp-re-http-v1".to_owned(),
            current_issuers: Vec::new(),
            retiring_issuers: Vec::new(),
            revoked_issuers: Vec::new(),
            issued_at: 0,
            expires_at: 5_000,
        };
        let body = manifest_body(&m).expect("body");
        let a = manifest_signing_preimage(body.as_bytes(), "ab");
        let b = manifest_signing_preimage(body.as_bytes(), "a");
        assert_ne!(a, b);
        assert!(a.starts_with(MANIFEST_SIGNING_DOMAIN) && b.starts_with(MANIFEST_SIGNING_DOMAIN));
    }

    #[test]
    fn the_preimage_carries_the_manifest_bytes_unaltered() {
        // Two spellings of one parsed manifest are two preimages: nothing here normalises.
        let compact = br#"{"a":1}"#;
        let spaced = br#"{ "a": 1 }"#;
        assert_ne!(
            manifest_signing_preimage(compact, "k"),
            manifest_signing_preimage(spaced, "k")
        );
        assert!(manifest_signing_preimage(spaced, "k").ends_with(spaced));
    }
}
