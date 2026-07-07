// SPDX-License-Identifier: Apache-2.0
//! Body evidence blocks for the HTTP profile (ADR-MCPRE-050 §Resolved-owner
//! ruling 1, MCPRE-93).
//!
//! No new HTTP header fields are minted (v0.11 grill E-3): all MCP-specific
//! evidence rides in the JSON-RPC body under a `_meta` key and is protected
//! because `content-digest` is a covered component of the RFC 9421 signature.
//! These are **semantic evidence** blocks — not a custom crypto envelope — and
//! carry **no raw secrets**: authorization artifacts appear only as digests or
//! references (`digest_alg`/`digest_value`, `reference_*`), never token bytes.
//!
//! Two identifiers are pinned here for the replay key (MCPRE-94) and audit:
//!
//! - [`ActorIdentity::actor_id`] — the canonical identity of the signing actor
//!   AFTER trust resolution, including role and trusted key identity (not a raw
//!   keyid alone). Serialized `role:trust_domain:subject:keyid` with each
//!   component escaped so the join is injective.
//! - [`AudienceTuple::audience_hash`] — SHA-256 over the canonical audience
//!   tuple bytes, not merely `@target-uri`, so replay prevention never merges
//!   different MCP audiences that share one HTTP endpoint.

use mcp_re_core::b64url_encode;
use mcp_re_core::VerificationKey;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use crate::error::HttpProfileError;
use crate::ids::EVIDENCE_DIGEST_ALG;

/// The resolved signing-actor identity. Built by the verifier from what the
/// TrustResolver returned for the presented keyid — role and trusted key
/// identity, never the raw keyid alone (MCPRE-93/94 pin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorIdentity {
    /// Trust role the resolver assigned (e.g. `host`, `server`, `client`).
    pub role: String,
    /// Trust domain the subject belongs to.
    pub trust_domain: String,
    /// Resolved subject identity (e.g. a DID or service id — may itself contain
    /// `:`, which is why components are escaped before joining).
    pub subject: String,
    /// The RFC 9421 keyid the signature was verified under.
    pub keyid: String,
}

impl ActorIdentity {
    /// The canonical, injective `actor_id` string used as a replay-key
    /// component. Each field is escaped (`%`→`%25`, `:`→`%3A`) before the
    /// `role:trust_domain:subject:keyid` join, so distinct identities never
    /// collapse to the same key even when a subject contains colons.
    pub fn actor_id(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            field_escape(&self.role),
            field_escape(&self.trust_domain),
            field_escape(&self.subject),
            field_escape(&self.keyid),
        )
    }
}

/// Escape a single actor-id component so `:` joins stay unambiguous. `%` first
/// (so the escape is reversible), then `:`.
fn field_escape(s: &str) -> String {
    s.replace('%', "%25").replace(':', "%3A")
}

/// The signing slot a keyid is resolved FOR. Passed INTO the trust seam so
/// role authorization is a decision of trust resolution, never inferred from a
/// role string after the fact (MCPRE-100): a key may be cryptographically valid
/// yet not trusted to sign in this slot, and that must fail
/// `actor_binding_failed` exactly like an unknown keyid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerSlot {
    /// The client/request-signer slot — [`crate::verify_request`].
    Request,
    /// The server/response-signer slot — [`crate::verify_response`],
    /// `verify_response_unbound`, and signed rejections.
    Response,
}

/// Trust-resolution output for a presented keyid: the resolved actor identity,
/// its verification key, and the slot the trust layer vouched this actor for.
/// The seam returns this ONLY when the key is trusted for the requested slot; a
/// wrong-slot key resolves to `None`, indistinguishable at the public error
/// layer from an unknown keyid (`mcp-re.actor_binding_failed`).
///
/// `keyid` is NOT `actor_id`: `actor_id` (see [`ActorIdentity::actor_id`]) is
/// the trust-resolution output that replay keys, response/body-block validation,
/// and audit consume — a keyid alone never introduces trust.
///
/// Not `PartialEq`/`Eq`: `VerificationKey` is opaque key material with no value
/// equality. Compare `identity` (or `actor_id()`) and `slot` instead.
#[derive(Debug, Clone)]
pub struct ResolvedActor {
    /// The resolved identity (role, trust domain, subject, keyid → `actor_id`).
    pub identity: ActorIdentity,
    /// The verification key trust resolution bound to this actor.
    pub verification_key: VerificationKey,
    /// The slot the trust layer authorized this actor for. The verifier asserts
    /// this equals the slot it requested — a typed defense-in-depth cross-check
    /// atop the seam's primary enforcement, never a role-string comparison.
    pub slot: SignerSlot,
}

impl ResolvedActor {
    /// The canonical `actor_id` of the resolved signer (delegates to
    /// [`ActorIdentity::actor_id`]).
    pub fn actor_id(&self) -> String {
        self.identity.actor_id()
    }
}

/// The MCP-RE audience tuple — richer than `@target-uri` (v0.11 grill E-3).
/// It names the intended verifier identity AND the concrete target URI (plus an
/// optional route discriminator) so audience binding is not aliased by a shared
/// HTTP endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceTuple {
    /// Intended verifier identity (mirrors the native envelope `audience`).
    pub audience_id: String,
    /// The absolute target URI the request is bound to (`@target-uri`).
    pub target_uri: String,
    /// Optional route/tenant discriminator for endpoints that multiplex
    /// several logical audiences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

impl AudienceTuple {
    /// Canonical byte serialization: the three slots joined by the unit
    /// separator `0x1F`, always three slots (empty route is an empty slot) so
    /// the encoding is fixed-arity and injective. `0x1F` cannot appear in a URI
    /// or identity token, so no field can forge a separator.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let route = self.route.as_deref().unwrap_or("");
        let joined = format!(
            "{}\u{1f}{}\u{1f}{}",
            self.audience_id, self.target_uri, route
        );
        joined.into_bytes()
    }

    /// `base64url-no-pad(SHA-256(canonical audience tuple bytes))` — the
    /// `audience_hash` replay-key component.
    pub fn audience_hash(&self) -> String {
        b64url_encode(&Sha256::digest(self.canonical_bytes()))
    }
}

/// The seven artifact-type registry tokens (ADR-MCPRE-050 §Resolved Q5 / grill
/// E-8). DPoP, mTLS, and RAR get typed verification in MCPRE-95; the other four
/// bind via digest/reference until a consumer appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactType {
    #[serde(rename = "oauth-dpop")]
    OauthDpop,
    #[serde(rename = "oauth-mtls")]
    OauthMtls,
    #[serde(rename = "oauth-rar")]
    OauthRar,
    #[serde(rename = "pdp-decision")]
    PdpDecision,
    #[serde(rename = "dtr-approval")]
    DtrApproval,
    #[serde(rename = "classifier-result")]
    ClassifierResult,
    #[serde(rename = "human-approval")]
    HumanApproval,
}

/// How an artifact is bound. Both forms are digest-carrying — the digest, never
/// the artifact bytes, is the cryptographic binding (mirrors the native
/// `AuthorizationBinding` split). Typed OAuth proofs (`ath`, `x5t#S256`) layer
/// on top of `opaque-digest`/`reference-digest` in MCPRE-95.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingType {
    /// The digest is over the decoded artifact bytes, held locally.
    #[serde(rename = "opaque-digest")]
    OpaqueDigest,
    /// The digest is produced by an external system named by the reference
    /// fields; the record stays verifiable independent of that system's live
    /// state.
    #[serde(rename = "reference-digest")]
    ReferenceDigest,
}

/// One `artifact_bindings[]` entry: the `artifact_type`/`binding_type` axis
/// split plus the digest (and reference metadata for the reference form). No
/// field can hold a raw secret — only digests and cross-audit references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub artifact_type: ArtifactType,
    pub binding_type: BindingType,
    /// Digest algorithm token; `"sha256"` in v0.11.
    pub digest_alg: String,
    /// `base64url-no-pad` digest — bare, no prefix (v0.11 grill E-5).
    pub digest_value: String,
    /// External authorization-system namespace (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_system_id: Option<String>,
    /// The external scheme: what `reference_value` means and how the digest was
    /// produced (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_scheme_id: Option<String>,
    /// Decision/grant handle for cross-audit (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_value: Option<String>,
}

impl ArtifactBinding {
    /// Producer side: build an `opaque-digest` binding whose digest is
    /// `base64url-no-pad(SHA-256(credential))`. This is how a client mints a
    /// DPoP `ath` / mTLS `x5t#S256` / RAR binding from the credential surface —
    /// the credential bytes are hashed, never stored.
    pub fn opaque_digest(artifact_type: ArtifactType, credential: &[u8]) -> Self {
        ArtifactBinding {
            artifact_type,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: b64url_encode(&Sha256::digest(credential)),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        }
    }

    /// Structural validation, fail-closed. The digest must be a non-empty
    /// base64url token; the reference fields are all-present for
    /// `reference-digest` and all-absent for `opaque-digest`.
    pub fn validate(&self) -> Result<(), HttpProfileError> {
        if self.digest_alg != EVIDENCE_DIGEST_ALG {
            return Err(HttpProfileError::MalformedEvidence("artifact digest_alg"));
        }
        if self.digest_value.is_empty() || !is_b64url_no_pad(&self.digest_value) {
            return Err(HttpProfileError::MalformedEvidence("artifact digest_value"));
        }
        let has_ref = self.authorization_system_id.is_some()
            || self.reference_scheme_id.is_some()
            || self.reference_value.is_some();
        let all_ref = self.authorization_system_id.is_some()
            && self.reference_scheme_id.is_some()
            && self.reference_value.is_some();
        match self.binding_type {
            BindingType::OpaqueDigest if has_ref => Err(HttpProfileError::MalformedEvidence(
                "opaque binding carries reference fields",
            )),
            BindingType::ReferenceDigest if !all_ref => Err(HttpProfileError::MalformedEvidence(
                "reference binding missing reference fields",
            )),
            _ => Ok(()),
        }
    }
}

/// MRTR continuation carried in the request evidence block. Three standards-
/// derived handles (ADR-MCPRE-050 §Resolved-owner ruling 7): the derivation and
/// verification land in MCPRE-97; the schema is defined here so the block is
/// complete. `requestState` stays opaque but is now digest-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpContinuation {
    /// Continuation kind; `"mcp-mrt"` (kept MCP-specific).
    #[serde(rename = "type")]
    pub continuation_type: String,
    /// SHA-256 over the previous client request's RFC 9421 signature base.
    pub previous_request_evidence: RequestEvidenceDigest,
    /// SHA-256 over the verified `InputRequiredResult` response signature base.
    pub input_required_response_evidence: RequestEvidenceDigest,
    /// SHA-256 over the opaque `requestState` bytes — opaque-but-digest-bound.
    pub request_state_digest: RequestEvidenceDigest,
}

/// A split-form digest handle (`digest_alg`/`digest_value`) as used across the
/// HTTP profile's body evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEvidenceDigest {
    pub digest_alg: String,
    pub digest_value: String,
}

impl RequestEvidenceDigest {
    /// Derive the handle as `base64url-no-pad(SHA-256(bytes))` over the mandated
    /// input (a signature base, or the opaque `requestState`).
    pub fn over(bytes: &[u8]) -> Self {
        RequestEvidenceDigest {
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: b64url_encode(&Sha256::digest(bytes)),
        }
    }

    /// Constant-shape check that this handle commits to `bytes`.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.digest_alg == EVIDENCE_DIGEST_ALG
            && self.digest_value == b64url_encode(&Sha256::digest(bytes))
    }
}

/// The `mcp-mrt` continuation type token (kept MCP-specific).
pub const CONTINUATION_TYPE_MCP_MRT: &str = "mcp-mrt";

impl HttpContinuation {
    /// Build the three-handle continuation (MCPRE-97) from the mandated inputs:
    /// the previous client request's signature base, the verified
    /// `InputRequiredResult` response's signature base, and the opaque
    /// `requestState` bytes. All three are hashed — `requestState` stays opaque
    /// (never interpreted) but is now digest-bound.
    pub fn build(
        previous_request_base: &[u8],
        input_required_response_base: &[u8],
        request_state: &[u8],
    ) -> Self {
        HttpContinuation {
            continuation_type: CONTINUATION_TYPE_MCP_MRT.to_owned(),
            previous_request_evidence: RequestEvidenceDigest::over(previous_request_base),
            input_required_response_evidence: RequestEvidenceDigest::over(
                input_required_response_base,
            ),
            request_state_digest: RequestEvidenceDigest::over(request_state),
        }
    }

    /// Verify the continuation against the exact bytes the client re-presents.
    /// A wrong type is malformed; any handle that does not commit to its input
    /// is a continuation-binding failure (a splice across the continuation
    /// boundary, or a tampered `requestState`).
    pub fn verify(
        &self,
        previous_request_base: &[u8],
        input_required_response_base: &[u8],
        request_state: &[u8],
    ) -> Result<(), HttpProfileError> {
        if self.continuation_type != CONTINUATION_TYPE_MCP_MRT {
            return Err(HttpProfileError::MalformedEvidence("continuation type"));
        }
        if !self
            .previous_request_evidence
            .matches(previous_request_base)
            || !self
                .input_required_response_evidence
                .matches(input_required_response_base)
            || !self.request_state_digest.matches(request_state)
        {
            return Err(HttpProfileError::ContinuationBindingFailed);
        }
        Ok(())
    }
}

/// The request-side body evidence block (`se.syncom/mcp-re.http.request`).
/// `profile`, `audience`, and a non-empty `artifact_bindings` are required;
/// `continuation` is present only on a continuation request (like the native
/// envelope), so it is optional in presence but part of the schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestEvidenceBlock {
    /// The signed profile id; cross-checked against the RFC 9421 `tag`.
    pub profile: String,
    /// The audience tuple (richer than `@target-uri`).
    pub audience: AudienceTuple,
    /// Required, non-empty. Generalizes the draft-02 `authorization_binding`.
    pub artifact_bindings: Vec<ArtifactBinding>,
    /// MRTR continuation (present only on continuation requests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<HttpContinuation>,
}

impl HttpRequestEvidenceBlock {
    /// Structural validation, fail-closed: profile tag matches, at least one
    /// artifact binding, every binding structurally valid.
    pub fn validate(&self, expected_profile: &str) -> Result<(), HttpProfileError> {
        if self.profile != expected_profile {
            return Err(HttpProfileError::UnknownProfileTag);
        }
        if self.artifact_bindings.is_empty() {
            return Err(HttpProfileError::MalformedEvidence(
                "empty artifact_bindings",
            ));
        }
        for b in &self.artifact_bindings {
            b.validate()?;
        }
        Ok(())
    }
}

/// A base64url-no-pad token: URL-safe alphabet, no `=` padding, non-empty.
fn is_b64url_no_pad(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::PROFILE_TAG;

    fn dpop_binding() -> ArtifactBinding {
        ArtifactBinding {
            artifact_type: ArtifactType::OauthDpop,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: "sha256".into(),
            digest_value: "abcdEF012_-".into(),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        }
    }

    fn block() -> HttpRequestEvidenceBlock {
        HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.into(),
            audience: AudienceTuple {
                audience_id: "did:example:server".into(),
                target_uri: "https://mcp.example.com/mcp".into(),
                route: None,
            },
            artifact_bindings: vec![dpop_binding()],
            continuation: None,
        }
    }

    #[test]
    fn block_round_trips() {
        let b = block();
        let json = serde_json::to_string(&b).unwrap();
        let back: HttpRequestEvidenceBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
        b.validate(PROFILE_TAG).expect("valid");
    }

    #[test]
    fn unknown_field_fails_closed() {
        let json = r#"{"profile":"mcp-re-http-v1","audience":{"audience_id":"a","target_uri":"u"},"artifact_bindings":[],"surprise":1}"#;
        let err = serde_json::from_str::<HttpRequestEvidenceBlock>(json);
        assert!(
            err.is_err(),
            "deny_unknown_fields must reject stray members"
        );
    }

    #[test]
    fn empty_artifact_bindings_fails_closed() {
        let mut b = block();
        b.artifact_bindings.clear();
        assert_eq!(
            b.validate(PROFILE_TAG).unwrap_err(),
            HttpProfileError::MalformedEvidence("empty artifact_bindings")
        );
    }

    #[test]
    fn foreign_profile_fails_closed() {
        let mut b = block();
        b.profile = "someone-elses-profile".into();
        assert_eq!(
            b.validate(PROFILE_TAG).unwrap_err(),
            HttpProfileError::UnknownProfileTag
        );
    }

    // ----- actor_id determinism + injectivity -----

    #[test]
    fn actor_id_is_deterministic_and_pinned() {
        let a = ActorIdentity {
            role: "host".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:host".into(),
            keyid: "client-key-1".into(),
        };
        // Golden: subject colons are escaped so the join stays unambiguous.
        assert_eq!(
            a.actor_id(),
            "host:example.com:did%3Aexample%3Ahost:client-key-1"
        );
        assert_eq!(a.actor_id(), a.actor_id());
    }

    #[test]
    fn actor_id_is_injective_across_colon_boundaries() {
        // Without escaping, ("a:b","c") and ("a","b:c") would collide.
        let x = ActorIdentity {
            role: "r".into(),
            trust_domain: "d".into(),
            subject: "a:b".into(),
            keyid: "c".into(),
        };
        let y = ActorIdentity {
            role: "r".into(),
            trust_domain: "d".into(),
            subject: "a".into(),
            keyid: "b:c".into(),
        };
        assert_ne!(x.actor_id(), y.actor_id());
    }

    // ----- audience_hash determinism + discrimination -----

    #[test]
    fn audience_hash_is_deterministic_and_b64url() {
        let a = AudienceTuple {
            audience_id: "did:example:server".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            route: None,
        };
        assert_eq!(a.audience_hash(), a.audience_hash());
        assert!(!a.audience_hash().contains('='), "base64url no-pad");
        assert!(!a.audience_hash().contains(':'), "bare digest, no prefix");
    }

    #[test]
    fn different_audiences_on_one_endpoint_hash_differently() {
        let base = "https://mcp.example.com/mcp";
        let a = AudienceTuple {
            audience_id: "did:example:server-a".into(),
            target_uri: base.into(),
            route: None,
        };
        let b = AudienceTuple {
            audience_id: "did:example:server-b".into(),
            target_uri: base.into(),
            route: None,
        };
        // Same HTTP endpoint, different verifier identity -> different hash.
        assert_ne!(a.audience_hash(), b.audience_hash());
        // Route discriminator also separates.
        let c = AudienceTuple {
            route: Some("tenant-1".into()),
            ..a.clone()
        };
        assert_ne!(a.audience_hash(), c.audience_hash());
    }

    #[test]
    fn separator_cannot_be_forged_across_fields() {
        // audience_id "x" + target "y" must differ from audience_id "x\u{1f}y".
        let a = AudienceTuple {
            audience_id: "x".into(),
            target_uri: "y".into(),
            route: None,
        };
        let b = AudienceTuple {
            audience_id: "x\u{1f}y".into(),
            target_uri: "".into(),
            route: None,
        };
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    // ----- no raw secrets -----

    #[test]
    fn artifact_binding_carries_only_digest_and_reference_never_token_bytes() {
        // A DPoP artifact is expressed as a digest, not the token. The serialized
        // form has no field able to hold raw token/secret bytes.
        let json = serde_json::to_string(&dpop_binding()).unwrap();
        assert!(json.contains("digest_value"));
        for forbidden in ["token", "jwt", "secret", "private", "access_token"] {
            assert!(
                !json.contains(forbidden),
                "no raw-secret field: {forbidden}"
            );
        }
    }

    #[test]
    fn opaque_binding_with_reference_fields_fails_closed() {
        let mut b = dpop_binding();
        b.reference_value = Some("grant-123".into());
        assert!(b.validate().is_err());
    }

    #[test]
    fn reference_binding_missing_fields_fails_closed() {
        let b = ArtifactBinding {
            artifact_type: ArtifactType::OauthRar,
            binding_type: BindingType::ReferenceDigest,
            digest_alg: "sha256".into(),
            digest_value: "abcd".into(),
            authorization_system_id: Some("authz".into()),
            reference_scheme_id: None,
            reference_value: None,
        };
        assert!(b.validate().is_err());
    }

    // ----- MRTR continuation (three handles) -----

    const PREV_BASE: &[u8] = b"previous-request-signature-base";
    const IRR_BASE: &[u8] = b"input-required-response-signature-base";
    const REQ_STATE: &[u8] = b"opaque-request-state-blob";

    #[test]
    fn continuation_round_trips_and_verifies() {
        let c = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
        let json = serde_json::to_string(&c).unwrap();
        let back: HttpContinuation = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        c.verify(PREV_BASE, IRR_BASE, REQ_STATE)
            .expect("binds its inputs");
        // The type token is the MCP-specific mcp-mrt.
        assert_eq!(c.continuation_type, "mcp-mrt");
    }

    #[test]
    fn tampered_request_state_breaks_the_digest() {
        // requestState stays opaque (never interpreted) but IS digest-bound.
        let c = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
        let err = c
            .verify(PREV_BASE, IRR_BASE, b"opaque-request-state-TAMPERED")
            .unwrap_err();
        assert_eq!(err, HttpProfileError::ContinuationBindingFailed);
        assert_eq!(err.wire_code(), "mcp-re.continuation_binding_failed");
    }

    #[test]
    fn splice_across_continuation_boundary_fails() {
        // A continuation presented against a DIFFERENT previous request (a
        // splice) must not verify.
        let c = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
        assert_eq!(
            c.verify(b"some-other-request-base", IRR_BASE, REQ_STATE)
                .unwrap_err(),
            HttpProfileError::ContinuationBindingFailed
        );
        // Likewise a different input-required response.
        assert_eq!(
            c.verify(PREV_BASE, b"other-irr-base", REQ_STATE)
                .unwrap_err(),
            HttpProfileError::ContinuationBindingFailed
        );
    }

    #[test]
    fn wrong_continuation_type_is_malformed() {
        let mut c = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
        c.continuation_type = "some-other-continuation".into();
        assert_eq!(
            c.verify(PREV_BASE, IRR_BASE, REQ_STATE).unwrap_err(),
            HttpProfileError::MalformedEvidence("continuation type")
        );
    }
}
