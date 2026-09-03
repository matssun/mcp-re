<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
-->

# Owner view

Each review unit and the claims it is the semantic authority for. A unit with no
theorem is shown too: an unclaimed unit is a question for the specification work,
not an omission to hide.

| unit | class | owns theorems | assumptions |
|---|---|---|---|
| client.delegation_policy_seal | V0 | THM-0060 | 0 |
| client.execution_contract | V0 | THM-0061 | 0 |
| client.local_ingress_authority | V0 | THM-0091 | 0 |
| client.proxy_request_correspondence | V0 | THM-0084 | 0 |
| client.response_acceptance | V0 | THM-0058, THM-0059, THM-0076 | 0 |
| client.trust_manifest_lifecycle | V0 | THM-0057 | 0 |
| conformance.retained_corpus | V0 | _none_ | 0 |
| core.time_rfc3339 | V1 | THM-0002 | 4 |
| http_profile.admission_assertion | V0 | THM-0053 | 0 |
| http_profile.admission_currency | V1 | THM-0003, THM-0004, THM-0005, THM-0006 | 7 |
| http_profile.artifact_typing | V1 | THM-0007 | 6 |
| http_profile.artifact_verification_boundary | V0 | THM-0008 | 0 |
| http_profile.continuation_binding | V1 | THM-0010 | 4 |
| http_profile.continuation_unbypassability | V1 | THM-0009 | 4 |
| http_profile.freshness_window | V1 | THM-0001 | 9 |
| http_profile.keyid | V0 | THM-0055 | 0 |
| http_profile.keyid_selector | V0 | THM-0050 | 1 |
| http_profile.pdp_decision_authentication | V0 | THM-0039 | 0 |
| http_profile.replay_key | V0 | THM-0079 | 0 |
| http_profile.request_envelope | V0 | THM-0083 | 0 |
| http_profile.response_emission_binding | V0 | THM-0065 | 0 |
| http_profile.scitt_receipt_offline | V0 | THM-0041, THM-0072 | 0 |
| http_profile.scitt_retained_correspondence | V0 | THM-0042 | 0 |
| http_profile.scitt_service_pin | V0 | THM-0068 | 0 |
| http_profile.submitted_hop_identity | V0 | _none_ | 0 |
| http_profile.verifier_result_separation | V0 | THM-0047 | 0 |
| http_profile.verifier_results | V0 | THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022 | 3 |
| proxy.audit_delivery | V0 | THM-0070 | 0 |
| proxy.audit_record_coordinates | V0 | THM-0069, THM-0071 | 0 |
| proxy.authenticated_relationship_peer | V0 | THM-0031 | 1 |
| proxy.authorization_posture | V0 | THM-0056 | 0 |
| proxy.certificate_identity | V0 | THM-0024 | 1 |
| proxy.channel_associated_credential | V0 | THM-0028 | 1 |
| proxy.channel_associated_identity | V0 | THM-0029 | 1 |
| proxy.continuation_correlation_store | V0 | THM-0087 | 0 |
| proxy.continuation_installation | V0 | _none_ | 0 |
| proxy.continuation_key_provenance | V0 | _none_ | 0 |
| proxy.continuation_leg_binding | V0 | THM-0093 | 0 |
| proxy.continuation_materialization | V0 | THM-0096 | 0 |
| proxy.credential_currency | V0 | THM-0032 | 1 |
| proxy.credential_key_correspondence | V0 | THM-0026 | 1 |
| proxy.cross_machine_legality | V0 | THM-0049 | 0 |
| proxy.current_authenticated_peer | V0 | THM-0033 | 0 |
| proxy.custody_exposure | V0 | THM-0064 | 0 |
| proxy.delegated_resolver_materialization | V0 | THM-0027 | 1 |
| proxy.delegated_signing_credential | V0 | THM-0062 | 0 |
| proxy.dispatch_commitment | V0 | THM-0045, THM-0051, THM-0052, THM-0074 | 0 |
| proxy.ed25519_public_key | V0 | THM-0025 | 1 |
| proxy.exchange_lifecycle | V0 | THM-0043, THM-0044, THM-0078 | 0 |
| proxy.kms_endpoint_authority | V0 | THM-0089 | 0 |
| proxy.mechanism_verified_credential | V0 | THM-0030 | 1 |
| proxy.online_ocsp_reachability | V0 | THM-0013 | 0 |
| proxy.outbound_destination | V0 | THM-0090 | 0 |
| proxy.outstanding_id_provenance | V0 | _none_ | 0 |
| proxy.pdp_decision_relation | V0 | THM-0040 | 0 |
| proxy.peer_identity_value | V0 | THM-0023 | 0 |
| proxy.refusal_audit_emission | V0 | THM-0085 | 0 |
| proxy.refusal_provenance | V0 | THM-0046 | 0 |
| proxy.refusal_site_totality | V0 | THM-0081 | 0 |
| proxy.replay_admission_gate | V0 | THM-0092 | 2 |
| proxy.replay_materialization | V0 | THM-0086 | 0 |
| proxy.request_peer_binding | V0 | THM-0034 | 0 |
| proxy.response_signing | V0 | THM-0063, THM-0075 | 0 |
| proxy.retention_commitment | V0 | THM-0088 | 0 |
| proxy.runtime_lifecycle | V0 | THM-0012 | 0 |
| proxy.serving_identity_provenance | V0 | THM-0080 | 0 |
| proxy.serving_trust_seam | V0 | THM-0066 | 0 |
| proxy.signing_credential_provenance | V0 | THM-0082 | 0 |
| proxy.signing_role_separation | V0 | THM-0073 | 0 |
| proxy.tls_listener_state | V0 | THM-0048, THM-0054 | 0 |
| proxy.trust_composition_root | V0 | THM-0038, THM-0067, THM-0077 | 0 |
| proxy.trust_configuration_state | V0 | THM-0035, THM-0036 | 0 |
| proxy.trust_plan | V0 | THM-0037 | 0 |
| sdk_python.exchange_path | V0 | THM-0094 | 1 |
| sdk_typescript.exchange_path | V0 | THM-0095 | 1 |
