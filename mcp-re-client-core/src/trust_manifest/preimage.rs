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
//! Both the signer and every verifier build the preimage HERE. That is the point of the
//! module: two constructions of the same bytes are two chances to disagree.

use super::TrustAnchorManifest;
use super::TrustManifestError;

/// Domain separator for the manifest signing preimage, so these bytes cannot be
/// mistaken for — or replayed as — any other signature this profile produces.
const MANIFEST_SIGNING_DOMAIN: &[u8] = b"mcp-re/trust-anchor-manifest/v1";

/// The exact bytes the org/admin signature covers:
/// `domain || u64be(len(signer_kid)) || signer_kid || serde_json(manifest)`.
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
pub(super) fn manifest_signing_preimage(
    manifest: &TrustAnchorManifest,
    signer_kid: &str,
) -> Result<Vec<u8>, TrustManifestError> {
    let body = serde_json::to_vec(manifest)
        .map_err(|_| TrustManifestError::Malformed("manifest serialize"))?;
    // Class C: capacity only, over slice lengths plus the eight-byte length prefix.
    #[allow(clippy::arithmetic_side_effects)]
    let capacity = MANIFEST_SIGNING_DOMAIN.len() + 8 + signer_kid.len() + body.len();
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(MANIFEST_SIGNING_DOMAIN);
    preimage.extend_from_slice(&(signer_kid.len() as u64).to_be_bytes());
    preimage.extend_from_slice(signer_kid.as_bytes());
    preimage.extend_from_slice(&body);
    Ok(preimage)
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
        let a = manifest_signing_preimage(&m, "ab").expect("preimage");
        let b = manifest_signing_preimage(&m, "a").expect("preimage");
        assert_ne!(a, b);
        assert!(a.starts_with(MANIFEST_SIGNING_DOMAIN) && b.starts_with(MANIFEST_SIGNING_DOMAIN));
    }
}
