// SPDX-License-Identifier: Apache-2.0
//! Which exact decision evidence this deployment verified and acted on.
//!
//! # Two coordinates, two questions
//!
//! A decision has an identifier the AUTHORITY gave it and an identity the BYTES have, and
//! they answer different forensic questions:
//!
//! ```text
//! jti     "which decision does the authorization authority say this was?"
//! digest  "which exact decision evidence did MCP-RE verify and act upon?"
//! ```
//!
//! The first is authenticated and authority-owned, and belongs with the rest of the
//! attribution ([`GrantAttribution`](super::grant::GrantAttribution)). It is **not** a
//! content identity: an issuer can, deliberately or by accident, put the same `jti` on two
//! different documents, and a `jti` that both documents carry cannot distinguish which one
//! was enforced. This type is the second coordinate, and conflating the two into one
//! `evidence_id` would produce a record that looks like a cross-audit chain and is not one.
//!
//! # It is preserved, never recomputed
//!
//! The digest is not derived here. It is the value the request's `pdp-decision` /
//! `opaque-digest` binding stated, kept by the authority that VERIFIED the correspondence
//! at the moment it verified it. Recomputing it downstream would be a second derivation of
//! a fact an owner already established — and one taken over bytes whose relation to the
//! binding would then rest on the recomputation agreeing, which is the thing the original
//! check exists to decide.

/// The identity of the decision evidence a mechanism authenticated.
///
/// # The contract, and where the seal actually is
///
/// This constructor is `pub`, and that is a decision rather than an oversight.
/// [`AuthorizationEvaluator`](super::evaluator::AuthorizationEvaluator) is a **public
/// trusted mechanism seam**: a mechanism may be implemented outside this crate, and it must
/// be able to return the evidence identity it established. A private constructor would only
/// force a public one taking the same two strings with the same absence of checking — see
/// [`docs/dev/sealed-owners.md`](https://github.com/matssun/mcp-re/blob/main/docs/dev/sealed-owners.md)
/// on why privacy past an external seam is theatre.
///
/// **What a caller undertakes.** Constructing one is a claim, and the claim is:
///
/// > I am the authority that verified the correspondence between this digest and the
/// > decision document I decided from, and this is that digest as the binding stated it.
///
/// A digest computed anywhere else — over bytes nobody related to a binding, or recomputed
/// after the fact — satisfies the type and falsifies the claim, producing a record that
/// names evidence nobody checked was the evidence acted upon. The type cannot detect that;
/// the mechanism's implementer owns it. `if this value is wrong, whose bug is it?` —
/// whoever implemented the seam, which is exactly why the check does not live here.
///
/// **What is nonetheless unforgeable.** An audit attribution cannot be manufactured
/// directly. An identity reaches a record only by way of
/// [`AuthorizedRequestFacts`](super::posture::AuthorizedRequestFacts), which nothing but
/// [`authorize`](super::decide::authorize) constructs and only from an evaluator's `Ok`, and
/// whose only projection is
/// [`audit_attribution`](super::posture::AuthorizedRequestFacts::audit_attribution). So no
/// record path — and in particular no audit site — can mint an identity, pair one decision's
/// evidence with another's attribution, or report an identity for a request no mechanism
/// authorized. That is the seal this design relies on; the constructor is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEvidenceIdentity {
    alg: String,
    value: String,
}

impl DecisionEvidenceIdentity {
    /// Keep the digest a verified binding stated.
    ///
    /// The name is the contract: the caller must be the authority that has just VERIFIED
    /// the correspondence between this digest and the document it decided from. Passing a
    /// digest computed anywhere else produces a record that names evidence nobody checked
    /// was the evidence acted on.
    pub fn from_verified_binding(alg: &str, value: &str) -> Self {
        DecisionEvidenceIdentity {
            alg: alg.to_owned(),
            value: value.to_owned(),
        }
    }

    /// The digest algorithm the binding declared.
    pub fn alg(&self) -> &str {
        &self.alg
    }

    /// The digest value the binding committed to.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// `<alg>:<value>` — the one rendering, so two records cannot spell one identity
    /// two ways.
    pub fn rendered(&self) -> String {
        format!("{}:{}", self.alg, self.value)
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::DecisionEvidenceIdentity;

    #[test]
    fn the_rendering_carries_the_algorithm_because_a_bare_digest_names_no_function() {
        let identity = DecisionEvidenceIdentity::from_verified_binding("sha-256", "abc");
        assert_eq!(identity.rendered(), "sha-256:abc");
    }

    #[test]
    fn two_identities_are_equal_only_when_both_coordinates_are() {
        let a = DecisionEvidenceIdentity::from_verified_binding("sha-256", "abc");
        assert_eq!(
            a,
            DecisionEvidenceIdentity::from_verified_binding("sha-256", "abc")
        );
        assert_ne!(
            a,
            DecisionEvidenceIdentity::from_verified_binding("sha-512", "abc")
        );
        assert_ne!(
            a,
            DecisionEvidenceIdentity::from_verified_binding("sha-256", "abd")
        );
    }
}
