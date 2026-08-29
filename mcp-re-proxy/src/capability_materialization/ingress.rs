// SPDX-License-Identifier: Apache-2.0
//! The Mode-C attested-ingress verifier (ADR-MCPS-023 §C).

use crate::deployment_request::DeploymentRequest;
use crate::transport::IdentityPolicy;
use mcp_re_core::VerificationKey;

/// Build the ADR-MCPS-023 §C (Mode C) attested-ingress verifier from `config`, or
/// `Ok(None)` when `binding != AttestedIngress`. The validation boundary has already
/// refused a deployment missing the attestor keys, a trusted ingress identity, the
/// audience or the pinned-mTLS acknowledgement (fail closed), and one whose attestor
/// key is not a valid Ed25519 public key — this only reconstructs the verifier, failing
/// closed with a precise error if any invariant were ever violated.
///
/// **Retained, not live.** No validated deployment reaches it:
/// [`undeployable_transport_binding_refusal`] refuses Mode C in every build, because the
/// rebinding of an attestation onto the RFC 9421 request evidence is not yet specified —
/// a deferred capability rather than a rejected posture, on the same terms as
/// [`build_ocsp_checker`]. Its test mints a real v2 assertion and verifies it through the
/// built binding, so the capability stays correct rather than merely compiling. The
/// lb-assertion builder had no such standing — that binding is refused because the LB
/// belongs outside the trusted computing base, which is a ruling and not a gap — and it
/// was deleted.
pub fn build_attested_ingress_binding(
    config: &DeploymentRequest,
) -> Result<Option<crate::transport::ingress::LbAssertionV2Binding>, String> {
    let crate::deployment_request::PeerIdentityEvidenceRequest::AttestedIngress(attested) =
        &config.peer_identity
    else {
        return Ok(None);
    };
    let source = match attested.asserted_identity_kind {
        IdentityPolicy::UriSan => crate::transport::IdentitySource::UriSan,
        IdentityPolicy::DnsSan => crate::transport::IdentitySource::DnsSan,
        IdentityPolicy::CnLegacy => crate::transport::IdentitySource::CommonName,
    };
    // The form always carries an audience — it is a member, not a sibling — but an EMPTY
    // one is still representable, and a verifier built around it would admit assertions
    // minted for any other node that also named none. The absent case is gone; this one is
    // not, so it stays here as well as at the boundary.
    if attested.audience.trim().is_empty() {
        return Err(
            "--ingress-audience names nothing: the audience scopes an assertion to THIS \
             node's route, so an empty one admits assertions minted for another"
                .to_string(),
        );
    }
    let mut binding =
        crate::transport::ingress::LbAssertionV2Binding::new(source, &attested.audience);
    for (key_id, key_b64) in &attested.attestor_keys {
        let key = VerificationKey::from_b64url(key_b64).map_err(|_| {
            format!(
                "invalid --ingress-attestor-key '{key_id}': the body must be a \
                 base64url-no-pad 32-byte Ed25519 public key"
            )
        })?;
        binding.add_key(key_id.clone(), key);
    }
    for ingress_identity in &attested.identities {
        binding.permit_ingress_identity(ingress_identity.clone());
    }
    Ok(Some(binding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;

    /// A complete Mode-C [`DeploymentRequest`], built from the configuration fixture rather
    /// than parsed: the boundary refuses the mode, so no parsed path can produce one, and a
    /// materializer's test has no business depending on the CLI's fixtures.
    fn mode_c_config() -> DeploymentRequest {
        let mut config = crate::config_state::test_support::legal_config();
        config.peer_identity = mode_c_form(
            vec!["spiffe://example.org/ingress-1".to_string()],
            "did:example:server-1".to_string(),
        );
        config
    }

    /// A distinct valid Ed25519 public key for `--ingress-attestor-key`.
    fn attestor_pub_b64() -> String {
        mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32])
            .public_key()
            .to_b64url()
    }
    /// A Mode-C form over the standard fixture attestor. A literal rather than a helper on
    /// the request type: the pinned-channel acknowledgement is the point, and a constructor
    /// that supplied it silently would hide what the form rests on.
    fn mode_c_form(
        identities: Vec<String>,
        audience: String,
    ) -> crate::deployment_request::PeerIdentityEvidenceRequest {
        crate::deployment_request::PeerIdentityEvidenceRequest::AttestedIngress(
            crate::deployment_request::AttestedIngressRequest {
                asserted_identity_kind: IdentityPolicy::UriSan,
                attestor_keys: vec![("attestor-1".to_string(), attestor_pub_b64())],
                identities,
                audience,
                pinned_channel:
                    crate::deployment_request::PinnedChannelAcknowledgement::acknowledged(),
            },
        )
    }

    #[test]
    fn the_retained_mode_c_verifier_still_admits_an_assertion_from_its_configured_attestor() {
        // Mode C is refused for deployment but RETAINED as a capability, so its verifier
        // has to stay correct rather than merely compile. Minting a real assertion and
        // verifying it through the built binding is what proves the builder actually
        // transferred all three configured facts: an implementation that skipped
        // `add_key`, skipped `permit_ingress_identity`, or passed the wrong audience
        // would fail this with `UnknownKeyId`, `UntrustedIngressIdentity`, or
        // `AudienceMismatch` respectively.
        let binding = build_attested_ingress_binding(&mode_c_config())
            .expect("a complete Mode-C config builds its verifier")
            .expect("the verifier is present for the attested-ingress binding");

        let request_hash = mcp_re_core::sha256_hash_id(b"an in-hand request body");
        let now = 1_800_000_000_i64;
        let assertion = crate::transport::ingress::LbAssertionV2 {
            key_id: "attestor-1".to_string(),
            ingress_identity: "spiffe://example.org/ingress-1".to_string(),
            asserted_client_identity: "spiffe://example.org/agent-1".to_string(),
            request_hash: request_hash.clone(),
            audience: "did:example:server-1".to_string(),
            cert_verification_result: crate::transport::ingress::AttestedCertVerification::Verified,
            revocation_result: crate::transport::ingress::AttestedRevocation::Good,
            validation_time: now,
            crl_next_update: now + 86_400,
            expires_at: None,
        };
        let attestor = SigningKey::from_seed_bytes(&[9u8; 32]);
        let wire = assertion.to_wire(&attestor.sign(&assertion.signing_preimage()));

        let verified = binding
            .verify(&wire, &request_hash, now)
            .expect("the configured attestor's assertion must verify");
        assert_eq!(
            verified.client_identity().value(),
            "spiffe://example.org/agent-1"
        );
        assert_eq!(
            verified.client_identity().source(),
            crate::transport::IdentitySource::UriSan,
            "the configured identity source must be the one stamped on the yielded identity"
        );
    }

    #[test]
    fn the_mode_c_verifier_is_built_only_for_the_attested_ingress_binding() {
        let config = crate::config_state::test_support::legal_config();
        assert!(
            build_attested_ingress_binding(&config)
                .expect("a non-Mode-C config is not an error")
                .is_none(),
            "no verifier may be built for a binding other than attested-ingress"
        );
    }

    #[test]
    fn a_mode_c_verifier_missing_its_audience_fails_closed_rather_than_defaulting() {
        // The audience is what scopes an assertion to THIS node. Building a verifier
        // with an empty or defaulted audience would admit assertions minted for another
        // route, so the absent case must be an error and not a fallback.
        let mut config = mode_c_config();
        config.peer_identity = mode_c_form(
            vec!["spiffe://example.org/ingress-1".to_string()],
            String::new(),
        );
        let err = build_attested_ingress_binding(&config)
            .expect_err("a Mode-C verifier without an audience must not be built");
        assert!(
            err.contains("--ingress-audience"),
            "the failure must name the missing audience, got: {err}"
        );
    }

    #[test]
    fn a_mode_c_verifier_rejects_an_unusable_attestor_key_rather_than_dropping_it() {
        // Silently skipping a key that will not decode would build a verifier that
        // trusts fewer attestors than configured and fails closed later at request
        // time, where the cause is far from the configuration that caused it.
        let mut config = mode_c_config();
        let crate::deployment_request::PeerIdentityEvidenceRequest::AttestedIngress(attested) =
            &mut config.peer_identity
        else {
            panic!("the fixture names the attested form");
        };
        attested.attestor_keys = vec![("attestor-1".to_string(), "not-a-key".to_string())];
        let err = build_attested_ingress_binding(&config)
            .expect_err("an undecodable attestor key must not be silently dropped");
        assert!(
            err.contains("attestor-1"),
            "the failure must name the offending key id, got: {err}"
        );
    }
}
