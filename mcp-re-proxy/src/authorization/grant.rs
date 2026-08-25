// SPDX-License-Identifier: Apache-2.0
//! Who granted an authorization, and what this slice does NOT claim about it.

/// The policy authority a grant is attributable to.
///
/// A decision nobody can attribute is a decision nobody can revisit: an operator asking
/// *why was this permitted* needs the authority and the version of the policy that answered,
/// and neither survives evaluation unless the mechanism states it.
///
/// # What this deliberately does not carry
///
/// **No expiry, and no invalidation condition.** ADR-MCPRE-065 §6 asks a success product to
/// say what invalidates it, and the honest answer for this slice is that no mechanism
/// produces one yet. An `Option<expiry>` here would be a field whose `None` means BOTH *this
/// grant never expires* and *this mechanism did not say* — the shape ADR-MCPRE-064 Slice 3
/// removed from credential currency. It arrives with the first production mechanism, typed
/// by what that mechanism can actually establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAttribution {
    authority: String,
    version: String,
}

impl GrantAttribution {
    /// Name the policy authority and version that granted this request.
    pub fn new(authority: impl Into<String>, version: impl Into<String>) -> Self {
        GrantAttribution {
            authority: authority.into(),
            version: version.into(),
        }
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
    fn a_grant_names_the_authority_and_the_version_it_was_taken_under() {
        let g = GrantAttribution::new("conformance", "1");
        assert_eq!(g.authority(), "conformance");
        assert_eq!(g.version(), "1");
    }

    #[test]
    fn two_versions_of_one_authority_are_different_attributions() {
        // The version is part of the attribution, not decoration: "the policy said yes" is
        // not answerable later unless WHICH policy said yes is part of the record.
        assert_ne!(
            GrantAttribution::new("conformance", "1"),
            GrantAttribution::new("conformance", "2")
        );
    }
}
