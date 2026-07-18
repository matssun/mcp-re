// SPDX-License-Identifier: Apache-2.0
//! Unknown / malformed binding identifiers (#416 rev 2 §13.2).
//!
//! The §13.2 "unknown binding identifier" category: an `artifact_bindings[]`
//! entry naming a type this profile does not define, or whose declared
//! `binding_type` disagrees with the fields it actually carries. Both are
//! evidence that is PRESENT but not something this profile can interpret, so both
//! fail closed as `malformed_envelope` — never as a silently-ignored binding.
//!
//! Silently ignoring an uninterpretable binding would be the dangerous outcome: a
//! request would then be admitted having declared a constraint the verifier never
//! actually checked.

use mcp_re_http_profile::block::ArtifactBinding;
use mcp_re_http_profile::HttpProfileError;

/// An `artifact_type` outside the profile's closed set. The vocabulary is
/// `deny_unknown_fields`-strict and the enum is closed, so a foreign type cannot
/// deserialize into a binding at all.
#[test]
fn unknown_artifact_type_fails_closed() {
    let json = serde_json::json!({
        "artifact_type": "acme-custom-attestation",
        "binding_type": "opaque-digest",
        "digest_alg": "sha256",
        "digest_value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    assert!(
        serde_json::from_value::<ArtifactBinding>(json).is_err(),
        "a binding naming a type this profile does not define must not parse"
    );
}

/// An unknown `binding_type` is equally uninterpretable: the verifier would not
/// know which shape rules to apply, so it cannot accept the binding.
#[test]
fn unknown_binding_type_fails_closed() {
    let json = serde_json::json!({
        "artifact_type": "oauth-dpop",
        "binding_type": "acme-indirect-digest",
        "digest_alg": "sha256",
        "digest_value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    assert!(serde_json::from_value::<ArtifactBinding>(json).is_err());
}

/// A binding that declares the opaque form but carries reference fields: the two
/// halves disagree about what the digest commits to. Fail closed rather than pick
/// an interpretation.
#[test]
fn opaque_binding_carrying_reference_fields_is_malformed() {
    let binding: ArtifactBinding = serde_json::from_value(serde_json::json!({
        "artifact_type": "oauth-rar",
        "binding_type": "opaque-digest",
        "digest_alg": "sha256",
        "digest_value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "authorization_system_id": "https://pdp.example.com",
        "reference_scheme_id": "acme/decision-v1",
        "reference_value": "decision-123",
    }))
    .expect("the shape parses; the disagreement is a validation failure");
    assert_eq!(
        binding.validate().unwrap_err(),
        HttpProfileError::MalformedEvidence("opaque binding carries reference fields"),
    );
    assert_eq!(
        binding.validate().unwrap_err().wire_code(),
        "mcp-re.malformed_envelope"
    );
}

/// The mirror: a reference-form binding missing the reference fields that give it
/// meaning. A dangling reference is not a weaker binding, it is an unusable one.
#[test]
fn reference_binding_missing_its_reference_fields_is_malformed() {
    let binding: ArtifactBinding = serde_json::from_value(serde_json::json!({
        "artifact_type": "pdp-decision",
        "binding_type": "reference-digest",
        "digest_alg": "sha256",
        "digest_value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "authorization_system_id": "https://pdp.example.com",
    }))
    .expect("the shape parses");
    assert_eq!(
        binding.validate().unwrap_err(),
        HttpProfileError::MalformedEvidence("reference binding missing reference fields"),
    );
}
