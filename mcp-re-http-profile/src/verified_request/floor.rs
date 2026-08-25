// SPDX-License-Identifier: Apache-2.0
//! The cryptographic floor proposition — ADR-MCPRE-061 §2 class 9.
//!
//! The weaker of the two request verification products. What a successful floor
//! verification establishes, and — just as importantly — what it does not: nothing here
//! says the request was addressed to this deployment, and nothing says an artifact binding
//! was checked. Those belong to [`VerifiedMcpRequest`](super::VerifiedMcpRequest), which is
//! a different type for exactly that reason.
//!
//! # Why this is not sealed
//!
//! It carries `pub` fields, so it does not seal against forgery. That is the documented
//! trade this project already made for [`crate::admission::VerifiedAdmission`], for the
//! same reason: Verus rejects private fields on a transparent datatype, and the only way to
//! seal is `external_body`, which makes the type OPAQUE and its postconditions unstatable.
//! **A Verus-proved postcondition outranks a seal** (`docs/dev/sealed-owners.md`).
//!
//! So every sentence below is phrased over what a SUCCESSFUL VERIFIER RETURN establishes,
//! never over what holding a value means.

use crate::block::ResolvedActor;
use crate::RequestEvidence;

/// A request whose **cryptographic floor** has been established.
///
/// A successful `verify_request_floor` establishes: the covered `Content-Digest` agreed
/// with the body, the RFC 9421 signature verified over the reconstructed base under an
/// algorithm the verifier's own policy allows, the freshness window was current, and the
/// presented keyid resolved through the trust seam in the `Request` slot.
///
/// It does **not** mean the request is addressed to this deployment, and it does not mean
/// any artifact binding was checked. Those are [`VerifiedMcpRequest`].
#[derive(Debug, Clone)]
pub struct CryptographicFloorVerifiedRequest {
    pub profile_id: String,
    pub signature_label: String,
    pub resolved_actor: ResolvedActor,
    pub evidence: RequestEvidence,
    pub request_signature_base: Vec<u8>,
    pub content_digest: String,
    pub created: i64,
    pub expires: i64,
    pub nonce: String,
    pub key_id: String,
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
    pub fn evidence(&self) -> &RequestEvidence {
        &self.evidence
    }
    /// The exact RFC 9421 signature-base bytes the signature verified over. Retained so
    /// the MRTR continuation store can record the base an answer leg binds to; not
    /// secret, being derived from the public message.
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
