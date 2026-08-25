// SPDX-License-Identifier: Apache-2.0
//! What a caller supplies for one signed request, and the evidence block it authors.
//!
//! Split from the builders that consume it: this type is the client's model of the
//! HTTP-profile request evidence block, and every capability the profile gains — a
//! continuation, admission evidence, an authorization decision — arrives here as a named
//! constructor rather than as another positional argument on five build functions.

use mcp_re_http_profile::AdmissionBinding;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::PROFILE_TAG;

/// The already-resolved inputs for one RFC 9421 signed request.
///
/// Every field is a value the mode-specific layer has already produced: the signer
/// key id (from the key-custody layer), the resolved [`AudienceTuple`] (audience
/// id + `@target-uri` + optional route — MCPS-43), the required, non-empty
/// artifact bindings (from an authorization-binding provider — MCPS-45), and the
/// freshness triple `nonce`/`created`/`expires` (RFC 9421 signature parameters,
/// Unix seconds).
#[derive(Debug, Clone)]
pub struct RequestSigningInputs {
    /// Identifier of the signing key (named in the RFC 9421 `keyid`; never the key).
    pub key_id: String,
    /// The resolved audience tuple (verifier id + absolute `@target-uri` + route).
    pub audience: AudienceTuple,
    /// The authorization/artifact bindings bound into the signed evidence block.
    /// Required, non-empty — a request with no binding fails validation closed.
    pub artifact_bindings: Vec<ArtifactBinding>,
    /// Opaque anti-replay nonce (>= 128 bits entropy), already drawn (RFC 9421
    /// `nonce`).
    pub nonce: String,
    /// Signature creation time, Unix seconds (RFC 9421 `created`).
    pub created: i64,
    /// Signature expiry time, Unix seconds (RFC 9421 `expires`).
    pub expires: i64,
    /// Optional multi-round-trip continuation binding (ADR-MCPS-047). `None` for an
    /// ordinary first-round request. Set via [`RequestSigningInputs::with_continuation`].
    pub continuation: Option<HttpContinuation>,
    /// Additional request headers to include (and cover) in the signed HTTP request
    /// — e.g. `Authorization: Bearer <token>` whose bytes an OAuth-DPoP artifact
    /// binding digests. Empty by default. Set via [`RequestSigningInputs::with_headers`].
    pub extra_headers: Vec<(String, String)>,
    /// The §7 admission evidence this call acts under: the binding, plus the
    /// authority-signed assertion it commits to. Both or neither — a binding the
    /// verifier cannot check against an assertion enforces nothing. Set via
    /// [`RequestSigningInputs::with_admission`].
    pub admission: Option<(AdmissionBinding, String)>,
    /// The ADR-MCPRE-065 authorization decision this call presents: the `pdp-decision`
    /// binding, plus the authority-signed decision document it commits to.
    ///
    /// Both or neither, for the same reason admission is: a binding the verifier cannot
    /// check against a document enforces nothing, and a document bound to nothing is an
    /// authority's statement about no call. Set via
    /// [`with_authorization_decision`](Self::with_authorization_decision), which mints the
    /// binding from the document so the two cannot disagree.
    pub authorization_decision: Option<(ArtifactBinding, String)>,
}

impl RequestSigningInputs {
    /// Build inputs for an ordinary first-round request.
    pub fn new(
        key_id: impl Into<String>,
        audience: AudienceTuple,
        artifact_bindings: Vec<ArtifactBinding>,
        nonce: impl Into<String>,
        created: i64,
        expires: i64,
    ) -> Self {
        RequestSigningInputs {
            key_id: key_id.into(),
            audience,
            artifact_bindings,
            nonce: nonce.into(),
            created,
            expires,
            continuation: None,
            extra_headers: Vec::new(),
            admission: None,
            authorization_decision: None,
        }
    }

    /// Add request headers to include AND cover in the signature (e.g. an
    /// `Authorization: Bearer` header an OAuth-DPoP artifact binding digests).
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    /// Bind this request to the verified `InputRequiredResult` it answers
    /// (ADR-MCPS-047): the continuation rides inside the signed evidence block.
    pub fn with_continuation(mut self, continuation: HttpContinuation) -> Self {
        self.continuation = Some(continuation);
        self
    }

    /// Declare the admission this call acts under (#414 §4.3 / #415 §7): the
    /// binding and the authority-signed assertion it commits to, both inside the
    /// signed evidence block.
    ///
    /// The assertion travels with the call rather than being fetched by the
    /// verifier, exactly as the delegation credential does on the response side.
    /// What it proves is what an authority SAID, at a generation; whether that is
    /// still true is the PEP's currency check, against authoritative state this
    /// client never sees.
    pub fn with_admission(
        mut self,
        binding: AdmissionBinding,
        assertion_jws: impl Into<String>,
    ) -> Self {
        self.admission = Some((binding, assertion_jws.into()));
        self
    }

    /// Present the authorization decision this call acts under (ADR-MCPRE-065 Slice 2).
    ///
    /// The caller supplies the compact JWS an authorization authority issued; the BINDING is
    /// minted here, from those exact bytes. A caller that could supply both could supply a
    /// binding over one document and carry another — and the digest is the only thing tying
    /// them together, so the two must not be independently settable.
    ///
    /// The decision travels with the call rather than being fetched by the verifier, exactly
    /// as the admission assertion and the delegation credential do. What it proves is what an
    /// authority DECIDED; whether this deployment trusts that authority, and whether the
    /// decision is about this request, are the PEP's.
    pub fn with_authorization_decision(mut self, decision_jws: impl Into<String>) -> Self {
        let jws = decision_jws.into();
        let binding = ArtifactBinding::opaque_digest(
            mcp_re_http_profile::ArtifactType::PdpDecision,
            jws.as_bytes(),
        );
        self.artifact_bindings.push(binding.clone());
        self.authorization_decision = Some((binding, jws));
        self
    }

    /// The HTTP-profile request evidence block this input set authors.
    ///
    /// `pub(crate)` so the builders next door compose it; no crate outside can author a
    /// block, which is what keeps the both-or-neither pairings this type owns from being
    /// assembled around it.
    pub(crate) fn evidence_block(&self) -> HttpRequestEvidenceBlock {
        HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.to_owned(),
            audience: self.audience.clone(),
            artifact_bindings: self.artifact_bindings.clone(),
            continuation: self.continuation.clone(),
            admission: self.admission.as_ref().map(|(b, _)| b.clone()),
            admission_assertion: self.admission.as_ref().map(|(_, jws)| jws.clone()),
            authorization_decision: self
                .authorization_decision
                .as_ref()
                .map(|(_, jws)| jws.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RequestSigningInputs;
    use mcp_re_http_profile::ArtifactBinding;
    use mcp_re_http_profile::ArtifactType;
    use mcp_re_http_profile::AudienceTuple;
    use mcp_re_http_profile::BindingType;

    const DECISION: &str = "aGVhZGVy.Y2xhaW1z.c2ln";

    fn inputs() -> RequestSigningInputs {
        RequestSigningInputs::new(
            "key-1",
            AudienceTuple {
                audience_id: "verifier-1".into(),
                target_uri: "https://example.test/mcp".into(),
                route: None,
            },
            vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthDpop,
                b"tok",
            )],
            "nonce-0001",
            1,
            2,
        )
    }

    #[test]
    fn a_decision_mints_its_own_binding_over_the_exact_bytes() {
        // The caller cannot supply the binding, so it cannot commit to one document and
        // carry another — the digest is the only thing tying the two together.
        let block = inputs()
            .with_authorization_decision(DECISION)
            .evidence_block();
        assert_eq!(block.authorization_decision.as_deref(), Some(DECISION));
        let minted: Vec<_> = block
            .artifact_bindings
            .iter()
            .filter(|b| b.artifact_type == ArtifactType::PdpDecision)
            .collect();
        assert_eq!(minted.len(), 1, "exactly one applicable binding");
        assert_eq!(minted[0].binding_type, BindingType::OpaqueDigest);
        assert_eq!(
            minted[0].digest_value,
            ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, DECISION.as_bytes())
                .digest_value
        );
        block
            .validate(mcp_re_http_profile::PROFILE_TAG)
            .expect("legal");
    }

    #[test]
    fn a_caller_that_presents_no_decision_authors_a_block_without_one() {
        let block = inputs().evidence_block();
        assert!(block.authorization_decision.is_none());
        assert!(block
            .artifact_bindings
            .iter()
            .all(|b| b.artifact_type != ArtifactType::PdpDecision));
        block
            .validate(mcp_re_http_profile::PROFILE_TAG)
            .expect("legal");
    }
}
