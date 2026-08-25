// SPDX-License-Identifier: Apache-2.0
//! Why a provider list is not a legal contribution to a signed request, and how that
//! reason is rendered onto the frozen wire vocabulary.
//!
//! Kept beside the conversion rather than inside it because the two are different
//! facts: which shapes are legal is the rule, and which frozen token each refusal is
//! reported as is a lossy projection of it that the vocabulary — not this crate —
//! decides.

use mcp_re_http_profile::HttpProfileError;

/// Why a provider list is not a legal contribution to a signed request.
///
/// Rendered onto the frozen `mcp-re-core` vocabulary by [`Self::wire_code`]; the variants
/// exist so the reason survives inside this crate even where the wire token cannot
/// express it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingSpecRefusal {
    /// The provider list is not a JSON array of specs.
    NotSpecJson,
    /// `material_b64url` is not base64url without padding.
    MaterialNotBase64Url,
    /// **The narrowing.** A generic opaque provider asked to mint a `pdp-decision`
    /// binding. That is half of a Mode-2 pair: the binding without the document the
    /// verifier checks it against.
    OpaqueBindingIsHalfOfADecision,
    /// The authorization-decision form was used for some other artifact type. The form
    /// names one thing — an authority's decision — and `pdp-decision` is what that is.
    DecisionFormIsNotThisArtifactType,
    /// The decision material is not a compact JWS: it is not even UTF-8 text.
    DecisionNotText,
    /// The decision form carries reference fields, which describe an external system's
    /// grant handle and say nothing about a carried document.
    DecisionCarriesReferenceFields,
    /// More than one decision was presented. A request acts under ONE decision; two
    /// would leave the verifier to choose which authority spoke for it.
    MoreThanOneDecision,
    /// The resulting binding is not structurally valid for its form.
    Malformed(HttpProfileError),
}

impl BindingSpecRefusal {
    /// The frozen wire token this refusal is reported as.
    ///
    /// Lossy on purpose: the four decision-shaped refusals are all "the spec is not a
    /// legal authorization binding", which the vocabulary spells
    /// `authorization_binding_malformed`, and the narrowing is reported as the artifact
    /// type not being supported IN THIS FORM — which is exactly what it is, and is the
    /// same token the wrapper classes raise when they reject earlier.
    pub fn wire_code(&self) -> &'static str {
        match self {
            BindingSpecRefusal::OpaqueBindingIsHalfOfADecision
            | BindingSpecRefusal::DecisionFormIsNotThisArtifactType => {
                "mcp-re.authorization_binding_type_unsupported"
            }
            BindingSpecRefusal::NotSpecJson
            | BindingSpecRefusal::MaterialNotBase64Url
            | BindingSpecRefusal::DecisionNotText
            | BindingSpecRefusal::DecisionCarriesReferenceFields
            | BindingSpecRefusal::MoreThanOneDecision => "mcp-re.authorization_binding_malformed",
            BindingSpecRefusal::Malformed(e) => e.wire_code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BindingSpecRefusal;
    use mcp_re_http_profile::HttpProfileError;

    #[test]
    fn the_narrowing_reports_the_type_as_unsupported_in_this_form() {
        // The same token the wrapper classes raise when they reject earlier, so the two
        // layers do not tell a caller two different stories about one rule.
        for refusal in [
            BindingSpecRefusal::OpaqueBindingIsHalfOfADecision,
            BindingSpecRefusal::DecisionFormIsNotThisArtifactType,
        ] {
            assert_eq!(
                refusal.wire_code(),
                "mcp-re.authorization_binding_type_unsupported"
            );
        }
    }

    #[test]
    fn shape_refusals_report_a_malformed_binding() {
        for refusal in [
            BindingSpecRefusal::NotSpecJson,
            BindingSpecRefusal::MaterialNotBase64Url,
            BindingSpecRefusal::DecisionNotText,
            BindingSpecRefusal::DecisionCarriesReferenceFields,
            BindingSpecRefusal::MoreThanOneDecision,
        ] {
            assert_eq!(
                refusal.wire_code(),
                "mcp-re.authorization_binding_malformed"
            );
        }
    }

    #[test]
    fn a_carrier_refusal_keeps_the_carriers_own_token() {
        // The profile decided this one; re-spelling it here would hide which layer spoke.
        let inner = HttpProfileError::MalformedEvidence("artifact digest_value");
        assert_eq!(
            BindingSpecRefusal::Malformed(inner.clone()).wire_code(),
            inner.wire_code()
        );
    }
}
