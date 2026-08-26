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
/// # Where the seal actually is
///
/// Not on this constructor. [`AuthorizationEvaluator`](super::evaluator::AuthorizationEvaluator)
/// is a public seam — a mechanism can be implemented outside this crate — so a mechanism
/// must be able to name the evidence it verified, and a private constructor would only
/// force a public one taking the same two strings with the same absence of checking.
/// Privacy here would be theatre.
///
/// The seal that holds is downstream: an identity reaches a record only through
/// [`AuthorizedRequestFacts`](super::posture::AuthorizedRequestFacts), which nothing but
/// [`authorize`](super::decide::authorize) constructs and only from an evaluator's `Ok`.
/// So the audit site cannot mint one, and the obligation that the digest be the verified
/// one sits where it belongs: on whoever implements the mechanism.
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
