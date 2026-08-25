// SPDX-License-Identifier: Apache-2.0
//! The typed `pdp-decision` verifier — ADR-MCPRE-065 Slice 2.
//!
//! Separate from [`crate::artifact::verify_artifact_binding`] on purpose. That function
//! carries a proved postcondition — *an `Ok` result is one of the three OAuth types in the
//! opaque-digest form* — and dispatching a fourth type through it would weaken a theorem to
//! save a match arm. Its refusal of `PdpDecision` was, and remains, the honest statement that
//! the OAuth dispatcher has no verifier for it.
//!
//! # What this proves, and what it does not
//!
//! It proves EXACT-BYTE correspondence: the digest the signed request committed to is the
//! digest of these decision bytes. That is one link of the chain and it is not authorization:
//!
//! ```text
//! digest correspondence      <- here
//!        v
//! authority trust + JWS authentication
//!        v
//! actor relation
//!        v
//! action relation
//!        v
//! audience + validity
//!        v
//! explicit Allow             <- only now is anything authorized
//! ```
//!
//! Each step earns the next proposition. A verifier that collapsed them would be unable to
//! say which one failed, and every one of them is a different thing for an operator to do.

use mcp_re_core::b64url_encode;
use sha2::Digest;
use sha2::Sha256;

use crate::block::ArtifactBinding;
use crate::block::ArtifactType;
use crate::block::BindingType;
use crate::block::HttpRequestEvidenceBlock;

/// Why a decision document does not correspond to its binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdpBindingRefusal {
    /// The entry is not a `pdp-decision` in the `opaque-digest` form.
    ///
    /// **A `reference-digest` entry lands here**, and must. That form is decision LINKAGE:
    /// the call names an external decision MCP-RE neither authenticates nor interprets, and
    /// letting it stand in for carried evidence would let a request claim an enforcement
    /// decision it never presented. Identical digest bytes do not make it the same claim.
    NotTheEvidenceForm,
    /// The binding is structurally malformed.
    Malformed,
    /// The digest does not equal the digest of the presented decision bytes.
    DigestMismatch,
}

/// Establish that `decision` is the document this binding committed to.
///
/// Over the EXACT compact-JWS bytes as transmitted — not a re-serialization, not a
/// normalized form. The digest was taken over what the issuer emitted, and anything that
/// rewrites those bytes would make a genuine decision fail and, worse, could make two
/// different documents agree.
pub fn verify_pdp_decision_binding(
    binding: &ArtifactBinding,
    decision: &str,
) -> Result<(), PdpBindingRefusal> {
    if binding.artifact_type != ArtifactType::PdpDecision
        || binding.binding_type != BindingType::OpaqueDigest
    {
        return Err(PdpBindingRefusal::NotTheEvidenceForm);
    }
    binding
        .validate()
        .map_err(|_| PdpBindingRefusal::Malformed)?;
    if b64url_encode(&Sha256::digest(decision.as_bytes())) != binding.digest_value {
        return Err(PdpBindingRefusal::DigestMismatch);
    }
    Ok(())
}

/// The inline decision this binding commits to, when the binding is the ADR-MCPRE-065
/// evidence form and the block carries one.
///
/// Lives beside the verifier it feeds rather than in the request verifier: which binding
/// forms carry their artifact is a fact about the BINDING, and the request verifier reading
/// it out of its own copy of the rule is how the two come to disagree.
///
/// `None` for the `reference-digest` LINKAGE form, deliberately: that form names an external
/// decision MCP-RE authenticates nothing about, so it has no material here and continues to
/// be refused by the typed dispatcher. Mode-1 linkage is not made servable by this slice.
pub fn pdp_decision_evidence<'a>(
    binding: &ArtifactBinding,
    block: &'a HttpRequestEvidenceBlock,
) -> Option<&'a str> {
    (binding.artifact_type == ArtifactType::PdpDecision
        && binding.binding_type == BindingType::OpaqueDigest)
        .then_some(block.authorization_decision.as_deref())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::verify_pdp_decision_binding;
    use super::PdpBindingRefusal;
    use crate::block::ArtifactBinding;
    use crate::block::ArtifactType;
    use crate::block::BindingType;
    use mcp_re_core::b64url_encode;
    use sha2::Digest;
    use sha2::Sha256;

    const DECISION: &str = "aGVhZGVy.Y2xhaW1z.c2ln";

    fn opaque_over(bytes: &str) -> ArtifactBinding {
        ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, bytes.as_bytes())
    }

    #[test]
    fn the_exact_transmitted_bytes_correspond() {
        verify_pdp_decision_binding(&opaque_over(DECISION), DECISION).expect("corresponds");
    }

    #[test]
    fn a_different_document_does_not() {
        assert_eq!(
            verify_pdp_decision_binding(&opaque_over(DECISION), "b3RoZXI.Y2xhaW1z.c2ln"),
            Err(PdpBindingRefusal::DigestMismatch)
        );
    }

    #[test]
    fn a_reference_binding_can_never_satisfy_the_evidence_form() {
        // THE structural negative. A reference-digest entry carrying the very same digest
        // string as a valid opaque one must still be refused: the two forms are different
        // claims, and only the opaque one means "the decision travelled with this request".
        let reference = ArtifactBinding {
            artifact_type: ArtifactType::PdpDecision,
            binding_type: BindingType::ReferenceDigest,
            digest_alg: "sha256".into(),
            digest_value: b64url_encode(&Sha256::digest(DECISION.as_bytes())),
            authorization_system_id: Some("urn:example:pdp".into()),
            reference_scheme_id: Some("urn:example:scheme".into()),
            reference_value: Some("decision-1".into()),
        };
        assert_eq!(
            verify_pdp_decision_binding(&reference, DECISION),
            Err(PdpBindingRefusal::NotTheEvidenceForm)
        );
    }

    #[test]
    fn another_artifact_type_with_a_matching_digest_is_refused() {
        // A DPoP binding whose digest happens to equal the decision's is not a decision.
        let dpop = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, DECISION.as_bytes());
        assert_eq!(
            verify_pdp_decision_binding(&dpop, DECISION),
            Err(PdpBindingRefusal::NotTheEvidenceForm)
        );
    }
}
