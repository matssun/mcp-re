// SPDX-License-Identifier: Apache-2.0
//! Who granted an authorization, and what this slice does NOT claim about it.

/// The policy authority a grant is attributable to.
///
/// A decision nobody can attribute is a decision nobody can revisit: an operator asking
/// *why was this permitted* needs the authority, the version of the policy that answered,
/// and which of that authority's decisions this was — and none of the three survives
/// evaluation unless the mechanism states it.
///
/// # `authority_decision_id` is the authority's identifier, not a content identity
///
/// It is the authenticated `jti`, which the PDP profile defines as tying the decision to the
/// authority's own decision record for cross-audit. It says WHICH DECISION the authority
/// says this was. It does not identify the bytes: an issuer can put one `jti` on two
/// documents, deliberately or by accident, and then the `jti` cannot say which was enforced.
/// The bytes are named by
/// [`DecisionEvidenceIdentity`](super::decision_evidence::DecisionEvidenceIdentity), which
/// travels beside this rather than inside it.
///
/// # What this deliberately does not carry
///
/// **No expiry, and no invalidation condition.** ADR-MCPRE-065 §6 asks a success product to
/// say what invalidates it, and the honest answer is still that no mechanism produces one.
/// An `Option<expiry>` here would be a field whose `None` means BOTH *this grant never
/// expires* and *this mechanism did not say* — the shape ADR-MCPRE-064 Slice 3 removed from
/// credential currency. It arrives typed by what a mechanism can actually establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAttribution {
    authority: String,
    version: String,
    authority_decision_id: String,
}

impl GrantAttribution {
    /// Name the policy authority, the policy version, and the authority's own identifier
    /// for the decision that granted this request.
    pub fn new(
        authority: impl Into<String>,
        version: impl Into<String>,
        authority_decision_id: impl Into<String>,
    ) -> Self {
        GrantAttribution {
            authority: authority.into(),
            version: version.into(),
            authority_decision_id: authority_decision_id.into(),
        }
    }

    /// The authority's own identifier for this decision — its `jti`, for cross-audit
    /// against the authority's decision record. Not an identity for the decision BYTES.
    pub fn authority_decision_id(&self) -> &str {
        &self.authority_decision_id
    }

    /// The policy authority that decided.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The version of that authority's policy the decision was taken under.
    pub fn version(&self) -> &str {
        &self.version
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::GrantAttribution;

    #[test]
    fn a_grant_names_the_authority_the_version_and_the_authoritys_own_decision_id() {
        let g = GrantAttribution::new("conformance", "1", "decision-1");
        assert_eq!(g.authority(), "conformance");
        assert_eq!(g.version(), "1");
        assert_eq!(g.authority_decision_id(), "decision-1");
    }

    #[test]
    fn two_versions_of_one_authority_are_different_attributions() {
        // The version is part of the attribution, not decoration: "the policy said yes" is
        // not answerable later unless WHICH policy said yes is part of the record.
        assert_ne!(
            GrantAttribution::new("conformance", "1", "decision-1"),
            GrantAttribution::new("conformance", "2", "decision-1")
        );
    }

    #[test]
    fn two_decisions_of_one_policy_version_are_different_attributions() {
        // And the decision id is part of it for the same reason one step further in: an
        // operator asking WHICH decision permitted this cannot be answered by a version
        // that a thousand decisions share.
        assert_ne!(
            GrantAttribution::new("conformance", "1", "decision-1"),
            GrantAttribution::new("conformance", "1", "decision-2")
        );
    }
}
