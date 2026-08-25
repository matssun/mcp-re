// SPDX-License-Identifier: Apache-2.0
//! The decision document, proved to be the one this request committed to.
//!
//! # The proposition
//!
//! Possession of [`BoundDecisionEvidence`] means:
//!
//! > This verified request carried exactly one `pdp-decision` / `opaque-digest` binding, and
//! > these are the decision bytes whose digest that binding committed to.
//!
//! That is digest correspondence and nothing else. It says nothing about who signed the
//! decision, whether the issuer is trusted, or what the decision permits — those are the
//! next three links, and each earns its own proposition. A type that meant all four at once
//! could not report which one failed.
//!
//! # Why the request produces it, and not a caller
//!
//! Both operands come out of ONE [`VerifiedMcpRequest`]: the binding from its evidence
//! block, the document from the body field beside it. A constructor taking a binding and a
//! document as separate arguments would let a caller pair a real binding with a real
//! decision from different requests — the L-5 shape ADR-MCPRE-063 names, where two honest
//! facts state a false relation because the caller did the pairing.

use mcp_re_http_profile::pdp_decision::verify_pdp_decision_binding;
use mcp_re_http_profile::pdp_decision::PdpBindingRefusal;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::BindingType;
use mcp_re_http_profile::VerifiedMcpRequest;

/// A decision document and the verified request binding that commits to it.
///
/// Sealed: the representation and the constructor are private to this module, so the only
/// inhabitants are the ones [`bound_decision_evidence`] proved correspond.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundDecisionEvidence {
    document: String,
}

impl BoundDecisionEvidence {
    /// The compact JWS, as transmitted. Handed on to the profile verifier, which
    /// authenticates it — this type has established only that it is the right bytes.
    pub fn document(&self) -> &str {
        &self.document
    }
}

/// Why a request's decision evidence cannot be established.
///
/// `None` from [`bound_decision_evidence`] is a different thing again: the request carried
/// no decision at all, which is a fact about the CALLER, and whether it is fatal is the
/// deployment's policy rather than this authority's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionEvidenceRefusal {
    /// A decision document was carried with no `pdp-decision` / `opaque-digest` binding to
    /// commit to it, or with more than one.
    ///
    /// Unreachable through the verifier, which refuses both shapes structurally. Represented
    /// anyway because this authority is total over its input and must not depend on an
    /// ordering it cannot see.
    NoSinglePairing,
    /// The bytes are not the ones the binding committed to.
    DigestMismatch,
    /// The paired entry is not the evidence form. A `reference-digest` binding lands here:
    /// it NAMES an external decision rather than carrying one, and MCP-RE authenticates
    /// nothing about what it names.
    NotTheEvidenceForm,
}

/// Establish the decision evidence a verified request carries, if it carries any.
///
/// `Ok(None)` — no decision was presented. `Ok(Some(_))` — exactly one binding committed to
/// exactly these bytes.
pub fn bound_decision_evidence(
    verified: &VerifiedMcpRequest,
) -> Result<Option<BoundDecisionEvidence>, DecisionEvidenceRefusal> {
    let block = verified.request_block();
    let Some(document) = block.authorization_decision.as_deref() else {
        return Ok(None);
    };
    // The evidence form only. A reference binding is deliberately NOT a candidate here, so
    // it cannot be selected and then rejected downstream — it never enters.
    let mut candidates = block.artifact_bindings.iter().filter(|b| {
        b.artifact_type == ArtifactType::PdpDecision && b.binding_type == BindingType::OpaqueDigest
    });
    let (Some(binding), None) = (candidates.next(), candidates.next()) else {
        return Err(DecisionEvidenceRefusal::NoSinglePairing);
    };
    match verify_pdp_decision_binding(binding, document) {
        Ok(()) => Ok(Some(BoundDecisionEvidence {
            document: document.to_owned(),
        })),
        Err(PdpBindingRefusal::DigestMismatch) => Err(DecisionEvidenceRefusal::DigestMismatch),
        Err(PdpBindingRefusal::NotTheEvidenceForm | PdpBindingRefusal::Malformed) => {
            Err(DecisionEvidenceRefusal::NotTheEvidenceForm)
        }
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::bound_decision_evidence;
    use super::DecisionEvidenceRefusal;
    use crate::authorization::action_harness::verified_over;
    use mcp_re_http_profile::ArtifactBinding;
    use mcp_re_http_profile::ArtifactType;
    use mcp_re_http_profile::BindingType;
    use mcp_re_http_profile::VerifiedMcpRequest;

    const BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    const DECISION: &str = "aGVhZGVy.Y2xhaW1z.c2ln";

    fn with(bindings: Vec<ArtifactBinding>, decision: Option<&str>) -> VerifiedMcpRequest {
        let mut v = verified_over(BODY);
        v.request_block.artifact_bindings = bindings;
        v.request_block.authorization_decision = decision.map(str::to_owned);
        v
    }

    fn evidence_binding_over(doc: &str) -> ArtifactBinding {
        ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, doc.as_bytes())
    }

    fn linkage_binding_over(doc: &str) -> ArtifactBinding {
        ArtifactBinding {
            binding_type: BindingType::ReferenceDigest,
            authorization_system_id: Some("urn:example:pdp".into()),
            reference_scheme_id: Some("urn:example:scheme".into()),
            reference_value: Some("decision-1".into()),
            ..evidence_binding_over(doc)
        }
    }

    #[test]
    fn a_request_carrying_no_decision_is_not_a_refusal() {
        assert_eq!(
            bound_decision_evidence(&with(vec![evidence_binding_over(DECISION)], None)),
            Ok(None)
        );
    }

    #[test]
    fn one_binding_over_these_exact_bytes_corresponds() {
        let got =
            bound_decision_evidence(&with(vec![evidence_binding_over(DECISION)], Some(DECISION)))
                .expect("corresponds")
                .expect("present");
        assert_eq!(got.document(), DECISION);
    }

    #[test]
    fn a_document_from_another_request_cannot_be_paired_with_this_binding() {
        assert_eq!(
            bound_decision_evidence(&with(
                vec![evidence_binding_over("b3RoZXI.Y2xhaW1z.c2ln")],
                Some(DECISION),
            )),
            Err(DecisionEvidenceRefusal::DigestMismatch)
        );
    }

    #[test]
    fn a_reference_binding_never_becomes_evidence_even_with_the_same_digest() {
        // THE structural negative this slice exists to hold. The linkage form carries the
        // identical digest string, and must still be incapable of producing evidence: it
        // names an external decision MCP-RE authenticates nothing about.
        assert_eq!(
            bound_decision_evidence(&with(vec![linkage_binding_over(DECISION)], Some(DECISION))),
            Err(DecisionEvidenceRefusal::NoSinglePairing),
            "a reference binding is not even a candidate, so it cannot be selected"
        );
    }

    #[test]
    fn two_evidence_bindings_leave_the_pairing_ambiguous_and_are_refused() {
        // With two, a caller supplying one matching and one non-matching entry would pass
        // whichever check happened to be written first.
        assert_eq!(
            bound_decision_evidence(&with(
                vec![
                    evidence_binding_over(DECISION),
                    evidence_binding_over("b3RoZXI.Y2xhaW1z.c2ln"),
                ],
                Some(DECISION),
            )),
            Err(DecisionEvidenceRefusal::NoSinglePairing)
        );
    }

    #[test]
    fn a_decision_with_no_binding_at_all_is_refused() {
        assert_eq!(
            bound_decision_evidence(&with(
                vec![ArtifactBinding::opaque_digest(
                    ArtifactType::OauthDpop,
                    b"tok"
                )],
                Some(DECISION),
            )),
            Err(DecisionEvidenceRefusal::NoSinglePairing)
        );
    }
}
