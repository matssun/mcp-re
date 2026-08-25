// SPDX-License-Identifier: Apache-2.0
//! The SDK-to-core authorization spec: what a language binding may ask this seam to put
//! into one signed request, and what it may not.
//!
//! The language SDKs do not construct [`ArtifactBinding`]s. They send a JSON array of
//! *specs* carrying the artifact MATERIAL, and this module turns them into bindings by
//! digesting that material — so a caller cannot pass off a precomputed digest as a
//! binding to an artifact it does not hold.
//!
//! ## Why the conversion lives here and not in each binding
//!
//! This is the point every construction route passes through: the PyO3 and N-API layers
//! both deserialize their provider list into these types, and the spec JSON is itself a
//! public seam — a guard placed only in the Python or TypeScript wrapper class is
//! cosmetic, because a caller composing the JSON directly walks past it. One
//! implementation here is also what keeps the two languages from drifting apart on a
//! security rule; two copies would only agree until one of them was edited.
//!
//! ## The `pdp-decision` rule (ADR-MCPRE-065)
//!
//! An authorization decision is a PAIR: the authority's signed document inside the
//! evidence block, and the `pdp-decision`/`opaque-digest` binding over those exact bytes.
//! [`RequestSigningInputs::with_authorization_decision`] mints the binding from the
//! document precisely so the two cannot disagree.
//!
//! A generic opaque provider could otherwise mint the binding half on its own, producing
//! a request carrying a `pdp-decision` binding with no document — which a Mode-2 verifier
//! necessarily refuses. So the FORM decides:
//!
//! | spec form | `pdp-decision` |
//! |---|---|
//! | `opaque-bytes` | refused — half of a pair |
//! | `authz-system-reference` | legal: Mode-1 external decision LINKAGE |
//! | `authorization-decision` | legal: the document, whose binding this seam mints |
//!
//! The rule is about the *pair* — the form together with the artifact type — never about
//! the token `pdp-decision` appearing in a spec. Refusing the token would take the
//! reference form with it.
//!
//! [`RequestSigningInputs::with_authorization_decision`]:
//!     crate::request_signing_inputs::RequestSigningInputs::with_authorization_decision

mod refusal;

pub use refusal::BindingSpecRefusal;

use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::BindingType;

/// The binding form a provider asks for (ADR-MCPS-044 §Authorization-binding hook).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingForm {
    /// The digest is over artifact bytes the client holds.
    OpaqueBytes,
    /// The digest is over artifact bytes the client holds, and the record additionally
    /// names the external authorization system that issued them, for cross-audit.
    AuthzSystemReference,
    /// The material is an authorization authority's signed decision document
    /// (ADR-MCPRE-065). Unlike the other two forms this authors no binding of its own:
    /// the document enters the evidence block, and the binding over it is minted by
    /// `with_authorization_decision`, which is what makes the two inseparable.
    AuthorizationDecision,
}

/// One provider-supplied entry, before this seam digests it.
///
/// `material_b64url` is the ARTIFACT ITSELF (base64url, no pad) — never a digest.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct BindingSpec {
    /// The artifact-type registry token this entry is about.
    pub artifact_type: ArtifactType,
    /// Which of the three forms the provider is asking for.
    pub form: BindingForm,
    /// The artifact material, base64url without padding.
    pub material_b64url: String,
    /// Reference form only: the external authorization system's identity.
    #[serde(default)]
    pub authorization_system_id: Option<String>,
    /// Reference form only: the scheme its grant handle is expressed in.
    #[serde(default)]
    pub reference_scheme_id: Option<String>,
    /// Reference form only: the grant handle itself.
    #[serde(default)]
    pub reference_value: Option<String>,
}

/// What one provider list contributes to a signed request.
///
/// The decision is the DOCUMENT only. Its binding is deliberately absent: nothing outside
/// `with_authorization_decision` mints one, which is the whole of the guarantee that a
/// carried decision and its digest describe the same bytes.
#[derive(Debug, Clone, Default)]
pub struct ProvidedAuthorization {
    /// Bindings to append after the built-in, header-derived DPoP binding.
    pub bindings: Vec<ArtifactBinding>,
    /// The compact authorization-decision document, when a provider presented one.
    pub decision: Option<String>,
}

/// Turn a provider list into the bindings and the decision it contributes.
///
/// The material is digested here; `digest_value` is never taken from the caller.
pub fn build_authorization(
    bindings_json: &str,
) -> Result<ProvidedAuthorization, BindingSpecRefusal> {
    let specs: Vec<BindingSpec> =
        serde_json::from_str(bindings_json).map_err(|_| BindingSpecRefusal::NotSpecJson)?;
    let mut out = ProvidedAuthorization::default();
    for spec in specs {
        let material = mcp_re_core::b64url_decode(&spec.material_b64url)
            .map_err(|_| BindingSpecRefusal::MaterialNotBase64Url)?;
        match spec.form {
            BindingForm::AuthorizationDecision => take_decision(&mut out, &spec, material)?,
            _ => out.bindings.push(binding_from(&spec, &material)?),
        }
    }
    Ok(out)
}

/// Accept the one decision document a request may act under.
fn take_decision(
    out: &mut ProvidedAuthorization,
    spec: &BindingSpec,
    material: Vec<u8>,
) -> Result<(), BindingSpecRefusal> {
    if spec.artifact_type != ArtifactType::PdpDecision {
        return Err(BindingSpecRefusal::DecisionFormIsNotThisArtifactType);
    }
    if spec.authorization_system_id.is_some()
        || spec.reference_scheme_id.is_some()
        || spec.reference_value.is_some()
    {
        return Err(BindingSpecRefusal::DecisionCarriesReferenceFields);
    }
    if out.decision.is_some() {
        return Err(BindingSpecRefusal::MoreThanOneDecision);
    }
    let jws = String::from_utf8(material).map_err(|_| BindingSpecRefusal::DecisionNotText)?;
    out.decision = Some(jws);
    Ok(())
}

/// Digest the material into the binding the spec's form describes.
fn binding_from(
    spec: &BindingSpec,
    material: &[u8],
) -> Result<ArtifactBinding, BindingSpecRefusal> {
    if spec.form == BindingForm::OpaqueBytes && spec.artifact_type == ArtifactType::PdpDecision {
        return Err(BindingSpecRefusal::OpaqueBindingIsHalfOfADecision);
    }
    let mut binding = ArtifactBinding::opaque_digest(spec.artifact_type, material);
    if spec.form == BindingForm::AuthzSystemReference {
        binding.binding_type = BindingType::ReferenceDigest;
        binding.authorization_system_id = spec.authorization_system_id.clone();
        binding.reference_scheme_id = spec.reference_scheme_id.clone();
        binding.reference_value = spec.reference_value.clone();
    }
    // Fail closed on a malformed shape: an opaque binding carrying reference fields, or a
    // reference binding missing any of them.
    binding.validate().map_err(BindingSpecRefusal::Malformed)?;
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::build_authorization;
    use super::BindingSpecRefusal;
    use mcp_re_http_profile::ArtifactBinding;
    use mcp_re_http_profile::ArtifactType;
    use mcp_re_http_profile::BindingType;

    const DECISION: &str = "aGVhZGVy.Y2xhaW1z.c2ln";

    /// base64url-no-pad, the encoding the spec carries material in.
    fn b64(raw: &[u8]) -> String {
        mcp_re_core::b64url_encode(raw)
    }

    fn spec(artifact_type: &str, form: &str, material: &[u8]) -> String {
        format!(
            r#"[{{"artifact_type":"{artifact_type}","form":"{form}","material_b64url":"{}"}}]"#,
            b64(material)
        )
    }

    #[test]
    fn the_opaque_form_refuses_pdp_decision_because_that_is_half_of_a_pair() {
        // THE narrowing. A binding with no document is a request the Mode-2 verifier
        // necessarily refuses, so the SDK may not construct one.
        let refusal =
            build_authorization(&spec("pdp-decision", "opaque-bytes", DECISION.as_bytes()))
                .expect_err("half of a decision pair");
        assert_eq!(refusal, BindingSpecRefusal::OpaqueBindingIsHalfOfADecision);
        assert_eq!(
            refusal.wire_code(),
            "mcp-re.authorization_binding_type_unsupported"
        );
    }

    #[test]
    fn the_reference_form_still_accepts_pdp_decision() {
        // The rule is about the (form, artifact_type) PAIR. Mode-1 external linkage is a
        // different, still-legal thing, and a token-keyed refusal would take it too.
        let json = format!(
            r#"[{{"artifact_type":"pdp-decision","form":"authz-system-reference",
                 "material_b64url":"{}","authorization_system_id":"pdp-1",
                 "reference_scheme_id":"urn:example:grant","reference_value":"g-9"}}]"#,
            b64(DECISION.as_bytes())
        );
        let provided = build_authorization(&json).expect("Mode-1 linkage is legal");
        assert!(provided.decision.is_none(), "linkage carries no document");
        assert_eq!(provided.bindings.len(), 1);
        assert_eq!(
            provided.bindings[0].artifact_type,
            ArtifactType::PdpDecision
        );
        assert_eq!(
            provided.bindings[0].binding_type,
            BindingType::ReferenceDigest
        );
    }

    #[test]
    fn the_decision_form_yields_the_document_and_no_binding() {
        // The binding is NOT minted here: only `with_authorization_decision` mints one,
        // which is what makes the carried document and its digest inseparable.
        let provided = build_authorization(&spec(
            "pdp-decision",
            "authorization-decision",
            DECISION.as_bytes(),
        ))
        .expect("legal");
        assert_eq!(provided.decision.as_deref(), Some(DECISION));
        assert!(
            provided.bindings.is_empty(),
            "the seam mints the binding, not the spec"
        );
    }

    #[test]
    fn the_decision_form_is_only_about_a_decision() {
        let refusal = build_authorization(&spec("human-approval", "authorization-decision", b"ok"))
            .expect_err("not a decision");
        assert_eq!(
            refusal,
            BindingSpecRefusal::DecisionFormIsNotThisArtifactType
        );
    }

    #[test]
    fn a_request_acts_under_at_most_one_decision() {
        let json = format!(
            r#"[{{"artifact_type":"pdp-decision","form":"authorization-decision","material_b64url":"{}"}},
                {{"artifact_type":"pdp-decision","form":"authorization-decision","material_b64url":"{}"}}]"#,
            b64(DECISION.as_bytes()),
            b64(b"b3RoZXI.b3RoZXI.b3RoZXI")
        );
        assert_eq!(
            build_authorization(&json).expect_err("two authorities"),
            BindingSpecRefusal::MoreThanOneDecision
        );
    }

    #[test]
    fn a_decision_is_text_or_it_is_not_a_compact_jws() {
        assert_eq!(
            build_authorization(&spec(
                "pdp-decision",
                "authorization-decision",
                &[0xff, 0xfe]
            ))
            .expect_err("not UTF-8"),
            BindingSpecRefusal::DecisionNotText
        );
    }

    #[test]
    fn a_decision_does_not_also_name_an_external_grant_handle() {
        let json = format!(
            r#"[{{"artifact_type":"pdp-decision","form":"authorization-decision",
                 "material_b64url":"{}","authorization_system_id":"pdp-1",
                 "reference_scheme_id":"urn:example:grant","reference_value":"g-9"}}]"#,
            b64(DECISION.as_bytes())
        );
        assert_eq!(
            build_authorization(&json).expect_err("mixed forms"),
            BindingSpecRefusal::DecisionCarriesReferenceFields
        );
    }

    #[test]
    fn other_artifact_types_keep_the_generic_opaque_form() {
        let provided = build_authorization(&spec("human-approval", "opaque-bytes", b"approved"))
            .expect("generic opaque is untouched");
        assert!(provided.decision.is_none());
        assert_eq!(provided.bindings.len(), 1);
        assert_eq!(provided.bindings[0].binding_type, BindingType::OpaqueDigest);
        assert_eq!(
            provided.bindings[0].digest_value,
            ArtifactBinding::opaque_digest(ArtifactType::HumanApproval, b"approved").digest_value,
            "the seam digests the material the caller presented"
        );
    }

    #[test]
    fn a_provider_list_that_is_not_spec_json_is_refused() {
        assert_eq!(
            build_authorization("not json").expect_err("not specs"),
            BindingSpecRefusal::NotSpecJson
        );
    }
}
