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
| client.response_acceptance | V0 | THM-0058, THM-0059 | 0 |
| client.trust_manifest_lifecycle | V0 | THM-0057 | 0 |
| core.time_rfc3339 | V1 | THM-0002 | 4 |
| http_profile.admission_currency | V1 | THM-0003, THM-0004, THM-0005, THM-0006, THM-0053 | 4 |
| http_profile.artifact_typing | V1 | THM-0007 | 3 |
| http_profile.artifact_verification_boundary | V0 | THM-0008 | 0 |
| http_profile.continuation_binding | V1 | THM-0010 | 1 |
| http_profile.continuation_unbypassability | V1 | THM-0009 | 1 |
| http_profile.freshness_window | V1 | THM-0001 | 6 |
| http_profile.keyid | V0 | THM-0050, THM-0055 | 0 |
| http_profile.pdp_decision_authentication | V0 | THM-0039 | 0 |
| http_profile.response_emission_binding | V0 | THM-0065 | 0 |
| http_profile.scitt_receipt_offline | V0 | THM-0041 | 0 |
| http_profile.scitt_retained_correspondence | V0 | THM-0042 | 0 |
| http_profile.verifier_result_separation | V0 | THM-0047 | 0 |
| http_profile.verifier_results | V0 | THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022 | 3 |
| proxy.authenticated_relationship_peer | V0 | THM-0031 | 1 |
| proxy.authorization_posture | V0 | THM-0056 | 0 |
| proxy.certificate_identity | V0 | THM-0024 | 1 |
| proxy.channel_associated_credential | V0 | THM-0028 | 1 |
| proxy.channel_associated_identity | V0 | THM-0029 | 1 |
| proxy.credential_currency | V0 | THM-0032 | 1 |
| proxy.credential_key_correspondence | V0 | THM-0026 | 1 |
| proxy.cross_machine_legality | V0 | THM-0049 | 0 |
| proxy.current_authenticated_peer | V0 | THM-0033 | 0 |
| proxy.custody_exposure | V0 | THM-0064 | 0 |
| proxy.delegated_resolver_materialization | V0 | THM-0027 | 1 |
| proxy.delegated_signing_credential | V0 | THM-0062 | 0 |
| proxy.dispatch_commitment | V0 | THM-0045, THM-0051, THM-0052 | 0 |
| proxy.ed25519_public_key | V0 | THM-0025 | 1 |
| proxy.exchange_lifecycle | V0 | THM-0043, THM-0044 | 0 |
| proxy.mechanism_verified_credential | V0 | THM-0030 | 1 |
| proxy.online_ocsp_reachability | V0 | THM-0013 | 0 |
| proxy.pdp_decision_relation | V0 | THM-0040 | 0 |
| proxy.peer_identity_value | V0 | THM-0023 | 0 |
| proxy.refusal_provenance | V0 | THM-0046 | 0 |
| proxy.request_peer_binding | V0 | THM-0034 | 0 |
| proxy.response_signing | V0 | THM-0063 | 0 |
| proxy.runtime_lifecycle | V0 | THM-0012 | 0 |
| proxy.tls_listener_state | V0 | THM-0048, THM-0054 | 0 |
| proxy.trust_composition_root | V0 | THM-0038 | 0 |
| proxy.trust_configuration_state | V0 | THM-0035, THM-0036 | 0 |
| proxy.trust_plan | V0 | THM-0037 | 0 |
