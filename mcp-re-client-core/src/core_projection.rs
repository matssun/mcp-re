// SPDX-License-Identifier: Apache-2.0
//! What this crate's refusals mean in Core's terms — ADR-MCPRE-066 Slice 2.
//!
//! ONE file per crate decides this, and every `wire_code` in the crate is derived from it.
//! `mcp-re-client-core` owns exactly one taxonomy that reaches the wire —
//! [`BindingSpecRefusal`], the rule about which provider lists are a legal contribution to
//! a signed request — and this is where it states which Core verdict each refusal IS.
//!
//! # Why the string table it replaces was a defect
//!
//! `BindingSpecRefusal::wire_code` used to match onto two `&'static str` literals. That
//! made this crate a **second minting authority** for `mcp-re.*` tokens, which is exactly
//! the parallel namespace ADR-MCPRE-066 Slice 2 removed from the carrier and the dispatch
//! taxonomy — and it was invisible: the drift guard's producer list named four files and
//! this was not one of them, so a token renamed in Core would have left two SDKs emitting
//! the old spelling with nothing able to notice.
//!
//! The grouping is unchanged, and it is the security argument rather than a convenience.
//! The narrowing — a generic opaque provider asked to mint a `pdp-decision` binding — is
//! reported as the artifact type not being supported IN THIS FORM, which is what it is and
//! is the same verdict the wrapper classes reach when they refuse earlier. The five
//! shape refusals are all *this spec is not a legal authorization binding*.
//!
//! No wildcard arm. A new [`BindingSpecRefusal`] variant is a compile error here until it
//! says which Core verdict it is.

use mcp_re_core::McpReError;

use crate::binding_spec::BindingSpecRefusal;

impl From<&BindingSpecRefusal> for McpReError {
    fn from(refusal: &BindingSpecRefusal) -> McpReError {
        match refusal {
            // The narrowing, and the form/type disagreement it generalizes: the artifact
            // type is not one this binding form may carry.
            BindingSpecRefusal::OpaqueBindingIsHalfOfADecision
            | BindingSpecRefusal::DecisionFormIsNotThisArtifactType => {
                McpReError::AuthorizationBindingTypeUnsupported
            }
            // Structurally not a legal binding for its form — an unparseable spec list, a
            // material that is not base64url, a decision that is not text, reference
            // fields on a carried document, or two decisions where a request acts under
            // one.
            BindingSpecRefusal::NotSpecJson
            | BindingSpecRefusal::MaterialNotBase64Url
            | BindingSpecRefusal::DecisionNotText
            | BindingSpecRefusal::DecisionCarriesReferenceFields
            | BindingSpecRefusal::MoreThanOneDecision => McpReError::AuthorizationBindingMalformed,
            // The carrier already decided this one; re-spelling it here would hide which
            // layer spoke, and the carrier owns its own exhaustive projection.
            BindingSpecRefusal::Malformed(e) => McpReError::from(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BindingSpecRefusal;
    use mcp_re_core::McpReError;
    use mcp_re_http_profile::HttpProfileError;

    /// The projection is what `wire_code` is derived from, so a Core verdict is what a
    /// refusal states — never a string this crate chose.
    #[test]
    fn every_refusal_names_a_core_verdict() {
        let cases = [
            (
                BindingSpecRefusal::OpaqueBindingIsHalfOfADecision,
                McpReError::AuthorizationBindingTypeUnsupported,
            ),
            (
                BindingSpecRefusal::DecisionFormIsNotThisArtifactType,
                McpReError::AuthorizationBindingTypeUnsupported,
            ),
            (
                BindingSpecRefusal::NotSpecJson,
                McpReError::AuthorizationBindingMalformed,
            ),
            (
                BindingSpecRefusal::MaterialNotBase64Url,
                McpReError::AuthorizationBindingMalformed,
            ),
            (
                BindingSpecRefusal::DecisionNotText,
                McpReError::AuthorizationBindingMalformed,
            ),
            (
                BindingSpecRefusal::DecisionCarriesReferenceFields,
                McpReError::AuthorizationBindingMalformed,
            ),
            (
                BindingSpecRefusal::MoreThanOneDecision,
                McpReError::AuthorizationBindingMalformed,
            ),
        ];
        for (refusal, verdict) in cases {
            assert_eq!(McpReError::from(&refusal), verdict);
            assert_eq!(refusal.wire_code(), verdict.wire_code());
        }
    }

    /// A carrier refusal keeps the carrier's verdict, through the carrier's own projection
    /// rather than through a second opinion formed here.
    #[test]
    fn a_carrier_refusal_keeps_the_carriers_own_verdict() {
        let inner = HttpProfileError::MalformedEvidence("artifact digest_value");
        let refusal = BindingSpecRefusal::Malformed(inner.clone());
        assert_eq!(McpReError::from(&refusal), McpReError::from(&inner));
        assert_eq!(refusal.wire_code(), inner.wire_code());
    }
}
