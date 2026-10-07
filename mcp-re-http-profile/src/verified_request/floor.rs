// SPDX-License-Identifier: Apache-2.0
//! The cryptographic floor proposition — ADR-MCPRE-061 §2 class 9.
//!
//! The weaker of the two request verification products. What a successful floor
//! verification establishes, and — just as importantly — what it does not: nothing here
//! says the request was addressed to this deployment, and nothing says an artifact binding
//! was checked. Those belong to [`VerifiedMcpRequest`](super::VerifiedMcpRequest), which is
//! a different type for exactly that reason.
//!
//! # What is sealed, and against whom
//!
//! The fields are `pub`, because Verus rejects private fields on a transparent datatype and
//! the only way around that is `external_body`, which makes the type OPAQUE and its
//! postconditions unstatable. **A Verus-proved postcondition outranks a seal**
//! (`docs/dev/sealed-owners.md`). The same trade was made for
//! [`crate::admission::VerifiedAdmission`].
//!
//! The type is `#[non_exhaustive]`, which Verus accepts, so no crate but this one can write
//! one as a struct expression: outside this crate the verifier is the only producer. A
//! holder of a real value can still assign its fields, so every sentence below is phrased
//! over what a SUCCESSFUL VERIFIER RETURN establishes, never over what holding a value means.

use crate::block::ResolvedActor;
use crate::RequestRoleEvidence;

/// A request whose **cryptographic floor** has been established.
///
/// A successful `verify_request_floor` establishes: the covered `Content-Digest` agreed
/// with the body, the RFC 9421 signature verified over the reconstructed base under an
/// algorithm the verifier's own policy allows, the freshness window was current, and the
/// presented keyid resolved through the trust seam in the `Request` slot.
///
/// It does **not** mean the request is addressed to this deployment, and it does not mean
/// any artifact binding was checked. Those are [`VerifiedMcpRequest`].
///
/// Another crate cannot write one, every field supplied:
///
/// ```compile_fail
/// use mcp_re_http_profile::{CryptographicFloorVerifiedRequest, RequestRoleEvidence, ResolvedActor};
/// fn forge(resolved_actor: ResolvedActor, evidence: RequestRoleEvidence) -> CryptographicFloorVerifiedRequest {
///     CryptographicFloorVerifiedRequest { profile_id: String::new(), signature_label: String::new(), resolved_actor, evidence, request_signature_base: Vec::new(), content_digest: String::new(), created: 0, expires: 0, nonce: String::new(), key_id: String::new() }
/// }
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct CryptographicFloorVerifiedRequest {
    pub profile_id: String,
    pub signature_label: String,
    pub resolved_actor: ResolvedActor,
    pub evidence: RequestRoleEvidence,
    pub request_signature_base: Vec<u8>,
    pub content_digest: String,
    pub created: i64,
    pub expires: i64,
    pub nonce: String,
    pub key_id: String,
}

/// Hand-written because the signature base concatenates every covered component's value,
/// and a covered `authorization` or `dpop` header is a component, so a derived impl would
/// print a live bearer token through every `{:?}` of this type and of `VerifiedMcpRequest`,
/// whose derived `Debug` composes this one.
impl std::fmt::Debug for CryptographicFloorVerifiedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptographicFloorVerifiedRequest")
            .field("profile_id", &self.profile_id)
            .field("signature_label", &self.signature_label)
            .field("resolved_actor", &self.resolved_actor)
            .field("evidence", &self.evidence)
            .field(
                "request_signature_base",
                &format_args!("<{} bytes redacted>", self.request_signature_base.len()),
            )
            .field("content_digest", &self.content_digest)
            .field("created", &self.created)
            .field("expires", &self.expires)
            .field("nonce", &self.nonce)
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl CryptographicFloorVerifiedRequest {
    /// The profile id (`tag`) the signature was accepted under.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    /// The RFC 9421 dictionary label of the verified signature.
    pub fn signature_label(&self) -> &str {
        &self.signature_label
    }
    /// The resolved signing actor — identity, key, and vouched slot. This, not
    /// [`Self::key_id`], is the identity replay and audit bind to.
    pub fn resolved_actor(&self) -> &ResolvedActor {
        &self.resolved_actor
    }
    /// The request signature-base handle: `SHA-256` over the reconstructed base.
    pub fn evidence(&self) -> &RequestRoleEvidence {
        &self.evidence
    }
    /// The exact bytes the signature verified over. Credential-bearing: they carry every
    /// covered component's value, including a covered `authorization` or DPoP credential.
    /// Consumers derive a handle from them (the continuation store keeps only
    /// `RetainedHandles`) and must not log or retain the bytes; only the
    /// evidence/transparency archive retains them.
    pub fn request_signature_base(&self) -> &[u8] {
        &self.request_signature_base
    }
    /// The verified `Content-Digest` header value covered by the signature.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Whether `body` is the body this signature covered.
    ///
    /// The pairing question, answered by the owner of the digest rather than by a caller
    /// that reads [`content_digest`](Self::content_digest) and re-derives the comparison.
    /// Two consumers doing that is two copies of one security semantic (R-COMPOSE), and the
    /// header is an RFC 9530 dictionary — a caller comparing it to a freshly serialized
    /// digest string would refuse a legitimate multi-algorithm value.
    pub fn covers_body(&self, body: &[u8]) -> bool {
        crate::digest::verify_content_digest_sha256(&self.content_digest, body).is_ok()
    }
    /// Signature creation time.
    pub fn created(&self) -> i64 {
        self.created
    }
    /// Signature expiry.
    pub fn expires(&self) -> i64 {
        self.expires
    }
    /// The signature nonce.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    /// The presented keyid — a wire selector, not a trust-resolution output.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{ActorIdentity, SignerSlot};
    use mcp_re_core::SigningKey;

    #[test]
    fn debug_never_renders_the_signature_base_or_its_credentials() {
        let key = SigningKey::from_seed_bytes(&[7u8; 32]);
        let f = CryptographicFloorVerifiedRequest {
            profile_id: "p".into(),
            signature_label: "mcpre".into(),
            resolved_actor: ResolvedActor {
                identity: ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:a".into(),
                    keyid: "k".into(),
                },
                verification_key: key.public_key(),
                slot: SignerSlot::Request,
            },
            evidence: RequestRoleEvidence::from_signature_base(b"base"),
            request_signature_base: b"\"authorization\": Bearer tok-SECRET-1\n\"@method\": POST"
                .to_vec(),
            content_digest: "sha-256=:x:".into(),
            created: 1,
            expires: 2,
            nonce: "n".into(),
            key_id: "key-id-visible".into(),
        };
        let dbg = format!("{f:?}");
        assert!(!dbg.contains(&format!("{:?}", f.request_signature_base)));
        assert!(!dbg.contains("tok-SECRET-1"));
        assert!(dbg.contains("CryptographicFloorVerifiedRequest"));
        assert!(dbg.contains("key-id-visible"));
        assert!(dbg.contains("bytes redacted"));
    }
}
