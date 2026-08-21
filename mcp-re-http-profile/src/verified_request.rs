// SPDX-License-Identifier: Apache-2.0
//! The two request verification products, as distinct types — ADR-MCPRE-061 §2 class 9.
//!
//! A cryptographic floor and full MCP-RE semantic verification are different propositions,
//! and one type carrying both said neither: the single product discriminated them by which
//! public function had built it, with `Option` fields documented "`None` on the minimal
//! proof path" — a type admitting it proves two things. Here the TYPE states which
//! proposition a successful verification established:
//!
//! - [`CryptographicFloorVerifiedRequest`] — the content digest agreed, the RFC 9421
//!   signature verified under an allowed algorithm, and trust resolved in the correct slot.
//! - [`VerifiedMcpRequest`] — all of the above, **and** audience equality and artifact
//!   binding under the full profile.
//!
//! # Why these are not sealed
//!
//! Both products carry `pub` fields, so neither seals against forgery. That is the
//! documented trade this project already made for [`crate::admission::VerifiedAdmission`]
//! and it is made for the same reason: THM-0009's postcondition is stated over
//! `VerifiedMcpRequest::request_block`, and Verus rejects private fields on a transparent
//! datatype — the only way to seal is `external_body`, which makes the type OPAQUE and
//! the postcondition unstatable. **A Verus-proved postcondition outranks a seal**
//! (`docs/dev/sealed-owners.md`).
//!
//! So a caller could assemble either product by hand: every sentence below is therefore
//! phrased over what a SUCCESSFUL VERIFIER RETURN establishes, never over what holding a
//! value means — as THM-0014/THM-0015 are. What the types DO establish is the assurance
//! split, which is not a seal question: the two propositions are different types, so no
//! consumer requiring the full one can be handed the floor one, by the compiler.

use crate::block::HttpRequestEvidenceBlock;
use crate::block::ResolvedActor;
use crate::AudienceTuple;
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

/// A request verified under the **full MCP-RE profile**.
///
/// A successful `verify_request` establishes everything [`CryptographicFloorVerifiedRequest`]
/// does, and in addition that the request's audience tuple equalled the verifier's own and
/// agreed with `@target-uri`, and that every declared artifact binding was resolved and
/// verified.
///
/// There is no conversion from the floor product. A consumer that requires the full
/// proposition cannot accept a floor value by accident, because it cannot accept one at
/// all:
///
/// ```compile_fail
/// use mcp_re_http_profile::{CryptographicFloorVerifiedRequest, VerifiedMcpRequest};
/// fn needs_full(_: &VerifiedMcpRequest) {}
/// fn from_floor(floor: &CryptographicFloorVerifiedRequest) {
///     needs_full(floor);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedMcpRequest {
    /// The floor proposition this product also establishes.
    ///
    pub floor: CryptographicFloorVerifiedRequest,
    /// The verified audience tuple from the request evidence block.
    pub audience: AudienceTuple,
    /// `audience_hash` over the canonical audience tuple — the replay-key component.
    pub audience_hash: String,
    /// The parsed, validated request evidence block.
    pub request_block: HttpRequestEvidenceBlock,
}

impl VerifiedMcpRequest {
    /// The floor proposition this product also establishes.
    pub fn floor(&self) -> &CryptographicFloorVerifiedRequest {
        &self.floor
    }
    /// The verified audience tuple from the request evidence block.
    pub fn audience(&self) -> &AudienceTuple {
        &self.audience
    }
    /// `audience_hash` over the canonical audience tuple — the replay-key component.
    /// Present unconditionally: it is a full-profile fact, and this is the full product.
    pub fn audience_hash(&self) -> &str {
        &self.audience_hash
    }
    /// The parsed, validated request evidence block, carried so replay and MRTR wiring
    /// need not re-parse the body.
    pub fn request_block(&self) -> &HttpRequestEvidenceBlock {
        &self.request_block
    }

    // Floor facts, delegated. A full product is a floor product plus more, and reading a
    // floor fact through it is not a widening — `floor()` remains available where a
    // caller genuinely wants the weaker value.
    /// See [`CryptographicFloorVerifiedRequest::profile_id`].
    pub fn profile_id(&self) -> &str {
        self.floor.profile_id()
    }
    /// See [`CryptographicFloorVerifiedRequest::signature_label`].
    pub fn signature_label(&self) -> &str {
        self.floor.signature_label()
    }
    /// See [`CryptographicFloorVerifiedRequest::resolved_actor`].
    pub fn resolved_actor(&self) -> &ResolvedActor {
        self.floor.resolved_actor()
    }
    /// See [`CryptographicFloorVerifiedRequest::evidence`].
    pub fn evidence(&self) -> &RequestEvidence {
        self.floor.evidence()
    }
    /// See [`CryptographicFloorVerifiedRequest::request_signature_base`].
    pub fn request_signature_base(&self) -> &[u8] {
        self.floor.request_signature_base()
    }
    /// See [`CryptographicFloorVerifiedRequest::content_digest`].
    pub fn content_digest(&self) -> &str {
        self.floor.content_digest()
    }
    /// See [`CryptographicFloorVerifiedRequest::created`].
    pub fn created(&self) -> i64 {
        self.floor.created()
    }
    /// See [`CryptographicFloorVerifiedRequest::expires`].
    pub fn expires(&self) -> i64 {
        self.floor.expires()
    }
    /// See [`CryptographicFloorVerifiedRequest::nonce`].
    pub fn nonce(&self) -> &str {
        self.floor.nonce()
    }
    /// See [`CryptographicFloorVerifiedRequest::key_id`].
    pub fn key_id(&self) -> &str {
        self.floor.key_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ActorIdentity;
    use crate::block::SignerSlot;
    use mcp_re_core::SigningKey;

    fn floor() -> CryptographicFloorVerifiedRequest {
        let key = SigningKey::from_seed_bytes(&[7u8; 32]);
        CryptographicFloorVerifiedRequest {
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
            evidence: RequestEvidence::from_signature_base(b"base"),
            request_signature_base: b"base".to_vec(),
            content_digest: "sha-256=:x:".into(),
            created: 1,
            expires: 2,
            nonce: "n".into(),
            key_id: "k".into(),
        }
    }

    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: "aud".into(),
            target_uri: "https://example.test/mcp".into(),
            route: None,
        }
    }

    fn full() -> VerifiedMcpRequest {
        VerifiedMcpRequest {
            floor: floor(),
            audience: audience(),
            audience_hash: audience().audience_hash(),
            request_block: HttpRequestEvidenceBlock {
                profile: "p".into(),
                audience: audience(),
                artifact_bindings: Vec::new(),
                continuation: None,
                admission: None,
                admission_assertion: None,
            },
        }
    }

    #[test]
    fn a_full_product_reports_the_floor_facts_it_also_establishes() {
        let f = floor();
        let full = full();
        assert_eq!(full.key_id(), f.key_id());
        assert_eq!(full.evidence(), f.evidence());
        assert_eq!(full.floor().nonce(), f.nonce());
        assert_eq!(full.request_signature_base(), f.request_signature_base());
    }

    #[test]
    fn the_full_product_states_its_audience_without_an_option() {
        // The assurance level is carried by the type, so there is no absent case for a
        // consumer to interpret and no degenerate replay key to guard against at runtime.
        let full = full();
        assert_eq!(full.audience(), &audience());
        assert_eq!(full.audience_hash(), audience().audience_hash());
    }

    #[test]
    fn the_floor_product_carries_the_slot_trust_resolved_it_in() {
        assert_eq!(floor().resolved_actor().slot, SignerSlot::Request);
    }
}
