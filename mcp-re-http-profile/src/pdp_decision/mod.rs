// SPDX-License-Identifier: Apache-2.0
//! The PDP-decision authorization profile — ADR-MCPRE-065 Slice 2.
//!
//! An external authorization authority decides permission; MCP-RE enforces it. This module
//! is the wire artifact that carries the decision and the verification that says what an
//! authority actually stated.
//!
//! # The proposition
//!
//! A successful [`verify_authorization_decision`] establishes:
//!
//! > A configured and trusted authorization authority issued this decision, for this
//! > profile and this verifier's audience, within its validity window.
//!
//! It does **not** establish that the decision is about the request in hand. Matching the
//! decision's actor and action against the verified request is the ADAPTER's job
//! (`mcp_re_proxy::authorization::pdp`), and keeping the two apart is deliberate: this
//! function answers *what did the authority say*, exactly as
//! [`verify_admission_assertion`](crate::admission::verify_admission_assertion) does, and a
//! function that also decided relevance would make the comparison unstatable as its own
//! property.
//!
//! # Why the decision travels with the request
//!
//! `docs/spec/ema-composition.md` gives `pdp-decision` a `reference-digest` form: bind a
//! stable `decision_id`, do not interpret. That form is unchanged and is still right for an
//! EMA composition where the backend enforces. It cannot carry THIS proposition — a
//! reference has no actor, no action and no signature, so a verifier holding one can refuse
//! neither a decision replayed by another actor nor one that was never authenticated.
//!
//! The `opaque-digest` form, which `ArtifactBinding::validate` has always permitted, carries
//! the decision DOCUMENT: the digest goes in `artifact_bindings[]` and the compact JWS rides
//! in the body beside it, protected by the covered `content-digest`. The same shape, and the
//! same reasoning, as the inline admission assertion — an evidence artifact the verifier must
//! have in hand travels with the message rather than being fetched, and grill E-3 admits a
//! new header only where the message shape leaves no alternative.
//!
//! Carrying it is also what keeps the product from implying the authority is reachable now.
//! A deployment that had to resolve a reference would be down when its PDP was.
//!
//! # What binds the decision to an actor — a SIGNED, closed scope
//!
//! ADR-MCPRE-065 Law A-2 says the boundary supplies every verified dimension and each
//! PROFILE states which ones its grant semantics use. This profile offers two, as a closed
//! choice carried by the decision itself:
//!
//! ```text
//! principal    ->  trust_domain + subject
//!                  survives a signing-key rotation; the trust seam already decided that
//!                  the presented key legitimately represents that subject
//!
//! credential   ->  trust_domain + subject + keyid
//!                  scoped to ONE signing credential; a rotation voids it
//! ```
//!
//! Three properties follow from making it a closed, signed choice rather than an optional
//! `keyid` claim:
//!
//! 1. **The illegal combination is unrepresentable.** A principal-scoped decision has no
//!    `keyid` field to omit and a credential-scoped one cannot lack it, so there is no
//!    "check skipped because the field was absent" — *a check that is skipped when a field
//!    is absent is a check an attacker omits.*
//! 2. **Meaning is fixed by the document, not by the reader.** The scope discriminator is
//!    inside the signed claims, so one JWS cannot acquire a different meaning by being
//!    presented to a differently configured deployment. Configuration decides only what it
//!    ACCEPTS.
//! 3. **The refusal can name the dimension.** Each dimension is its own claim rather than a
//!    serialized `actor_id()`, so nothing parses a composite back into components — the
//!    defect ADR-MCPRE-064 Slice 4 removed from the transport binding.
//!
//! Without the actor a decision is a BEARER TOKEN: anyone whose own key the PEP resolves — a
//! lower-privilege tenant, a compromised sibling workload, anything that read one authorized
//! request body or request log — could copy it into their own signed evidence block and be
//! authorized by it. The gate would then prove "some principal was permitted this action",
//! not "this caller was".

pub mod binding;
pub mod claims;
pub mod issue;
pub mod verify;

pub use binding::pdp_decision_evidence;
pub use binding::verify_pdp_decision_binding;
pub use binding::PdpBindingRefusal;
pub use claims::DecidedActor;
pub use claims::DecisionScope;
pub use claims::PdpDecisionClaims;
pub use claims::PdpDecisionHeader;
pub use claims::PdpDecisionOutcome;
pub use claims::MAX_AUTHORIZATION_DECISION_LEN;
pub use claims::PDP_DECISION_ALG;
pub use claims::PDP_DECISION_TYP;
pub use issue::issue_authorization_decision;
pub use verify::verify_authorization_decision;
pub use verify::PdpDecisionFreshness;
pub use verify::PdpDecisionRefusal;

#[cfg(test)]
mod tests {
    //! The module's own claim: the two `pdp-decision` binding forms are different claims,
    //! and only one of them is evidence this enforcement point can act on.

    use super::binding::verify_pdp_decision_binding;
    use super::binding::PdpBindingRefusal;
    use crate::block::ArtifactBinding;
    use crate::block::ArtifactType;
    use crate::block::BindingType;

    #[test]
    fn the_linkage_form_and_the_evidence_form_are_not_interchangeable() {
        let decision = "aGVhZGVy.Y2xhaW1z.c2ln";
        let evidence =
            ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, decision.as_bytes());
        assert!(verify_pdp_decision_binding(&evidence, decision).is_ok());

        let linkage = ArtifactBinding {
            binding_type: BindingType::ReferenceDigest,
            authorization_system_id: Some("urn:example:pdp".into()),
            reference_scheme_id: Some("urn:example:scheme".into()),
            reference_value: Some("decision-1".into()),
            ..evidence
        };
        assert_eq!(
            verify_pdp_decision_binding(&linkage, decision),
            Err(PdpBindingRefusal::NotTheEvidenceForm),
            "a reference binding names a decision; it does not carry one"
        );
    }
}
