<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
-->

# Structural blast radius

If this object changes, what must be re-established. Derived from the declared
edges only — it says what WOULD be invalidated, never what IS dirty. For the live
answer, including which component moved (`DIRTY_SELF` vs `DIRTY_ASSUMPTION` vs
`DIRTY_CONTRACT`), run `tools/verification/review-frontier`, which reads the
attestations this view cannot see.

## Review units

| object | a change to | re-establishes theorems | propagates to units |
|---|---|---|---|
| unit://client.delegation_policy_seal | source, contracts or evidence | THM-0060 | _no consumer_ |
| unit://client.execution_contract | source, contracts or evidence | THM-0061 | _no consumer_ |
| unit://client.proxy_request_correspondence | source, contracts or evidence | THM-0084 | _no consumer_ |
| unit://client.response_acceptance | source, contracts or evidence | THM-0058, THM-0059, THM-0076 | _no consumer_ |
| unit://client.trust_manifest_lifecycle | source, contracts or evidence | THM-0057, THM-0058 | _no consumer_ |
| unit://core.time_rfc3339 | source, contracts or evidence | THM-0002 | _no consumer_ |
| unit://http_profile.admission_assertion | source, contracts or evidence | THM-0053 | _no consumer_ |
| unit://http_profile.admission_currency | source, contracts or evidence | THM-0003, THM-0004, THM-0005, THM-0006 | _no consumer_ |
| unit://http_profile.artifact_typing | source, contracts or evidence | THM-0007 | _no consumer_ |
| unit://http_profile.artifact_verification_boundary | source, contracts or evidence | THM-0008, THM-0015 | _no consumer_ |
| unit://http_profile.continuation_binding | source, contracts or evidence | THM-0010 | http_profile.continuation_unbypassability (PROOF_DEPENDENCY) |
| unit://http_profile.continuation_unbypassability | source, contracts or evidence | THM-0009 | _no consumer_ |
| unit://http_profile.freshness_window | source, contracts or evidence | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 | _no consumer_ |
| unit://http_profile.keyid | source, contracts or evidence | THM-0055 | _no consumer_ |
| unit://http_profile.keyid_selector | source, contracts or evidence | THM-0050 | _no consumer_ |
| unit://http_profile.pdp_decision_authentication | source, contracts or evidence | THM-0039 | _no consumer_ |
| unit://http_profile.replay_key | source, contracts or evidence | THM-0079 | _no consumer_ |
| unit://http_profile.request_envelope | source, contracts or evidence | THM-0083 | _no consumer_ |
| unit://http_profile.response_emission_binding | source, contracts or evidence | THM-0065, THM-0075 | _no consumer_ |
| unit://http_profile.scitt_receipt_offline | source, contracts or evidence | THM-0041, THM-0072 | _no consumer_ |
| unit://http_profile.scitt_retained_correspondence | source, contracts or evidence | THM-0042 | _no consumer_ |
| unit://http_profile.scitt_service_pin | source, contracts or evidence | THM-0068, THM-0072 | _no consumer_ |
| unit://http_profile.verifier_result_separation | source, contracts or evidence | THM-0047, THM-0051 | _no consumer_ |
| unit://http_profile.verifier_results | source, contracts or evidence | THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022, THM-0065 | proxy.request_peer_binding (COMPILE_DEPENDENCY) |
| unit://proxy.audit_delivery | source, contracts or evidence | THM-0070 | _no consumer_ |
| unit://proxy.audit_record_coordinates | source, contracts or evidence | THM-0069, THM-0071 | _no consumer_ |
| unit://proxy.authenticated_relationship_peer | source, contracts or evidence | THM-0031 | proxy.current_authenticated_peer (CONTRACT_CONSUMES) |
| unit://proxy.authorization_posture | source, contracts or evidence | THM-0056 | _no consumer_ |
| unit://proxy.certificate_identity | source, contracts or evidence | THM-0024 | proxy.channel_associated_identity (COMPILE_DEPENDENCY) |
| unit://proxy.channel_associated_credential | source, contracts or evidence | THM-0028 | proxy.channel_associated_identity (CONTRACT_CONSUMES), proxy.mechanism_verified_credential (CONTRACT_CONSUMES) |
| unit://proxy.channel_associated_identity | source, contracts or evidence | THM-0029 | proxy.authenticated_relationship_peer (CONTRACT_CONSUMES) |
| unit://proxy.credential_currency | source, contracts or evidence | THM-0032 | proxy.current_authenticated_peer (CONTRACT_CONSUMES) |
| unit://proxy.credential_key_correspondence | source, contracts or evidence | THM-0026 | proxy.delegated_resolver_materialization (CONTRACT_CONSUMES) |
| unit://proxy.cross_machine_legality | source, contracts or evidence | THM-0049, THM-0077 | _no consumer_ |
| unit://proxy.current_authenticated_peer | source, contracts or evidence | THM-0033 | proxy.request_peer_binding (CONTRACT_CONSUMES) |
| unit://proxy.custody_exposure | source, contracts or evidence | THM-0064 | _no consumer_ |
| unit://proxy.delegated_resolver_materialization | source, contracts or evidence | THM-0027 | _no consumer_ |
| unit://proxy.delegated_signing_credential | source, contracts or evidence | THM-0062, THM-0063 | _no consumer_ |
| unit://proxy.dispatch_commitment | source, contracts or evidence | THM-0045, THM-0051, THM-0052, THM-0074 | _no consumer_ |
| unit://proxy.ed25519_public_key | source, contracts or evidence | THM-0025 | proxy.credential_key_correspondence (COMPILE_DEPENDENCY) |
| unit://proxy.exchange_lifecycle | source, contracts or evidence | THM-0043, THM-0044, THM-0074, THM-0078 | _no consumer_ |
| unit://proxy.mechanism_verified_credential | source, contracts or evidence | THM-0030 | proxy.authenticated_relationship_peer (CONTRACT_CONSUMES), proxy.credential_currency (CONTRACT_CONSUMES) |
| unit://proxy.online_ocsp_reachability | source, contracts or evidence | THM-0013 | _no consumer_ |
| unit://proxy.outstanding_id_provenance | source, contracts or evidence | THM-0083 | _no consumer_ |
| unit://proxy.pdp_decision_relation | source, contracts or evidence | THM-0040, THM-0052 | _no consumer_ |
| unit://proxy.peer_identity_value | source, contracts or evidence | THM-0023 | proxy.certificate_identity (COMPILE_DEPENDENCY) |
| unit://proxy.refusal_audit_emission | source, contracts or evidence | THM-0085 | _no consumer_ |
| unit://proxy.refusal_provenance | source, contracts or evidence | THM-0046, THM-0069, THM-0071, THM-0078 | _no consumer_ |
| unit://proxy.refusal_site_totality | source, contracts or evidence | THM-0081 | _no consumer_ |
| unit://proxy.request_peer_binding | source, contracts or evidence | THM-0034 | _no consumer_ |
| unit://proxy.response_signing | source, contracts or evidence | THM-0063, THM-0075 | _no consumer_ |
| unit://proxy.runtime_lifecycle | source, contracts or evidence | THM-0012 | _no consumer_ |
| unit://proxy.serving_identity_provenance | source, contracts or evidence | THM-0080 | _no consumer_ |
| unit://proxy.serving_trust_seam | source, contracts or evidence | THM-0066 | _no consumer_ |
| unit://proxy.signing_credential_provenance | source, contracts or evidence | THM-0082 | _no consumer_ |
| unit://proxy.signing_role_separation | source, contracts or evidence | THM-0073 | _no consumer_ |
| unit://proxy.tls_listener_state | source, contracts or evidence | THM-0048, THM-0054 | proxy.credential_currency (COMPILE_DEPENDENCY) |
| unit://proxy.trust_composition_root | source, contracts or evidence | THM-0038, THM-0067, THM-0077 | _no consumer_ |
| unit://proxy.trust_configuration_state | source, contracts or evidence | THM-0035, THM-0036 | _no consumer_ |
| unit://proxy.trust_plan | source, contracts or evidence | THM-0037, THM-0066 | _no consumer_ |

## Theorems

| object | a change to | invalidates | and every claim above |
|---|---|---|---|
| THM-0001 | statement, consequence, scope or review requirement | specification review | THM-0014, THM-0021, THM-0022 |
| THM-0002 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0003 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0004 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0005 | statement, consequence, scope or review requirement | specification review | THM-0074, THM-0077 |
| THM-0006 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0007 | statement, consequence, scope or review requirement | specification review | THM-0008, THM-0015 |
| THM-0008 | statement, consequence, scope or review requirement | specification review | THM-0015 |
| THM-0009 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0010 | statement, consequence, scope or review requirement | specification review | THM-0009 |
| THM-0012 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0013 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0014 | statement, consequence, scope or review requirement | specification review | THM-0015 |
| THM-0015 | statement, consequence, scope or review requirement | specification review | THM-0051, THM-0074 |
| THM-0016 | statement, consequence, scope or review requirement | specification review | THM-0018, THM-0058 |
| THM-0017 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0018 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0019 | statement, consequence, scope or review requirement | specification review | THM-0058 |
| THM-0020 | statement, consequence, scope or review requirement | specification review | THM-0059 |
| THM-0021 | statement, consequence, scope or review requirement | specification review | THM-0016, THM-0019, THM-0065 |
| THM-0022 | statement, consequence, scope or review requirement | specification review | THM-0017, THM-0020, THM-0059, THM-0065, THM-0075 |
| THM-0023 | statement, consequence, scope or review requirement | specification review | THM-0024 |
| THM-0024 | statement, consequence, scope or review requirement | specification review | THM-0029 |
| THM-0025 | statement, consequence, scope or review requirement | specification review | THM-0026, THM-0073 |
| THM-0026 | statement, consequence, scope or review requirement | specification review | THM-0027 |
| THM-0027 | statement, consequence, scope or review requirement | specification review | THM-0073 |
| THM-0028 | statement, consequence, scope or review requirement | specification review | THM-0029, THM-0030, THM-0032 |
| THM-0029 | statement, consequence, scope or review requirement | specification review | THM-0031 |
| THM-0030 | statement, consequence, scope or review requirement | specification review | THM-0031, THM-0032 |
| THM-0031 | statement, consequence, scope or review requirement | specification review | THM-0033, THM-0034, THM-0080 |
| THM-0032 | statement, consequence, scope or review requirement | specification review | THM-0033 |
| THM-0033 | statement, consequence, scope or review requirement | specification review | THM-0034, THM-0080 |
| THM-0034 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0035 | statement, consequence, scope or review requirement | specification review | THM-0036, THM-0037, THM-0038 |
| THM-0036 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0037 | statement, consequence, scope or review requirement | specification review | THM-0038, THM-0066 |
| THM-0038 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0039 | statement, consequence, scope or review requirement | specification review | THM-0040 |
| THM-0040 | statement, consequence, scope or review requirement | specification review | THM-0045, THM-0052, THM-0074 |
| THM-0041 | statement, consequence, scope or review requirement | specification review | THM-0072 |
| THM-0042 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0043 | statement, consequence, scope or review requirement | specification review | THM-0044, THM-0074, THM-0078, THM-0081 |
| THM-0044 | statement, consequence, scope or review requirement | specification review | THM-0078 |
| THM-0045 | statement, consequence, scope or review requirement | specification review | THM-0052, THM-0074, THM-0078 |
| THM-0046 | statement, consequence, scope or review requirement | specification review | THM-0069, THM-0071, THM-0078, THM-0081, THM-0085 |
| THM-0047 | statement, consequence, scope or review requirement | specification review | THM-0051 |
| THM-0048 | statement, consequence, scope or review requirement | specification review | THM-0054, THM-0077 |
| THM-0049 | statement, consequence, scope or review requirement | specification review | THM-0073, THM-0077 |
| THM-0050 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0051 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0052 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0053 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0054 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0055 | statement, consequence, scope or review requirement | specification review | THM-0050 |
| THM-0056 | statement, consequence, scope or review requirement | specification review | THM-0052 |
| THM-0057 | statement, consequence, scope or review requirement | specification review | THM-0058, THM-0076 |
| THM-0058 | statement, consequence, scope or review requirement | specification review | THM-0076 |
| THM-0059 | statement, consequence, scope or review requirement | specification review | THM-0076 |
| THM-0060 | statement, consequence, scope or review requirement | specification review | THM-0076 |
| THM-0061 | statement, consequence, scope or review requirement | specification review | THM-0076 |
| THM-0062 | statement, consequence, scope or review requirement | specification review | THM-0063, THM-0075, THM-0082 |
| THM-0063 | statement, consequence, scope or review requirement | specification review | THM-0075, THM-0078 |
| THM-0064 | statement, consequence, scope or review requirement | specification review | THM-0077, THM-0082 |
| THM-0065 | statement, consequence, scope or review requirement | specification review | THM-0075 |
| THM-0066 | statement, consequence, scope or review requirement | specification review | THM-0074, THM-0077 |
| THM-0067 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0068 | statement, consequence, scope or review requirement | specification review | THM-0072 |
| THM-0069 | statement, consequence, scope or review requirement | specification review | THM-0071, THM-0078, THM-0085 |
| THM-0070 | statement, consequence, scope or review requirement | specification review | THM-0071 |
| THM-0071 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0072 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0073 | statement, consequence, scope or review requirement | specification review | THM-0077, THM-0082 |
| THM-0074 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0075 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0076 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0077 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0078 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0079 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0080 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0081 | statement, consequence, scope or review requirement | specification review | THM-0071, THM-0078, THM-0085 |
| THM-0082 | statement, consequence, scope or review requirement | specification review | THM-0075 |
| THM-0083 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0084 | statement, consequence, scope or review requirement | specification review | THM-0076 |
| THM-0085 | statement, consequence, scope or review requirement | specification review | THM-0071 |

## Assumptions

| object | a change to | dirties units | and invalidates |
|---|---|---|---|
| ASM-0001 | description, justification, scope or mechanism | core.time_rfc3339 | assumption review |
| ASM-0002 | description, justification, scope or mechanism | core.time_rfc3339 | assumption review |
| ASM-0003 | description, justification, scope or mechanism | core.time_rfc3339 | assumption review |
| ASM-0004 | description, justification, scope or mechanism | core.time_rfc3339 | assumption review |
| ASM-0005 | description, justification, scope or mechanism | http_profile.freshness_window | assumption review |
| ASM-0006 | description, justification, scope or mechanism | http_profile.freshness_window | assumption review |
| ASM-0007 | description, justification, scope or mechanism | http_profile.freshness_window | assumption review |
| ASM-0008 | description, justification, scope or mechanism | http_profile.freshness_window | assumption review |
| ASM-0009 | description, justification, scope or mechanism | http_profile.freshness_window | assumption review |
| ASM-0010 | description, justification, scope or mechanism | http_profile.freshness_window | assumption review |
| ASM-0011 | description, justification, scope or mechanism | http_profile.admission_currency | assumption review |
| ASM-0012 | description, justification, scope or mechanism | http_profile.admission_currency | assumption review |
| ASM-0013 | description, justification, scope or mechanism | http_profile.admission_currency | assumption review |
| ASM-0014 | description, justification, scope or mechanism | http_profile.admission_currency | assumption review |
| ASM-0015 | description, justification, scope or mechanism | _no unit_ | assumption review |
| ASM-0018 | description, justification, scope or mechanism | http_profile.artifact_typing | assumption review |
| ASM-0019 | description, justification, scope or mechanism | http_profile.artifact_typing | assumption review |
| ASM-0020 | description, justification, scope or mechanism | http_profile.artifact_typing | assumption review |
| ASM-0021 | description, justification, scope or mechanism | http_profile.continuation_unbypassability | assumption review |
| ASM-0022 | description, justification, scope or mechanism | _no unit_ | assumption review |
| ASM-0023 | description, justification, scope or mechanism | http_profile.continuation_binding | assumption review |
| ASM-0024 | description, justification, scope or mechanism | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | assumption review |
| ASM-0025 | description, justification, scope or mechanism | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | assumption review |
| ASM-0026 | description, justification, scope or mechanism | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | assumption review |
| ASM-0027 | description, justification, scope or mechanism | http_profile.verifier_results | assumption review |
| ASM-0028 | description, justification, scope or mechanism | http_profile.verifier_results | assumption review |
| ASM-0029 | description, justification, scope or mechanism | http_profile.verifier_results | assumption review |
| ASM-0030 | description, justification, scope or mechanism | proxy.certificate_identity, proxy.credential_currency | assumption review |
| ASM-0031 | description, justification, scope or mechanism | proxy.ed25519_public_key | assumption review |
| ASM-0032 | description, justification, scope or mechanism | proxy.credential_key_correspondence, proxy.delegated_resolver_materialization | assumption review |
| ASM-0033 | description, justification, scope or mechanism | proxy.channel_associated_credential | assumption review |
| ASM-0034 | description, justification, scope or mechanism | proxy.channel_associated_identity | assumption review |
| ASM-0035 | description, justification, scope or mechanism | proxy.mechanism_verified_credential | assumption review |
| ASM-0036 | description, justification, scope or mechanism | proxy.authenticated_relationship_peer | assumption review |
| ASM-0037 | description, justification, scope or mechanism | http_profile.keyid_selector | assumption review |
