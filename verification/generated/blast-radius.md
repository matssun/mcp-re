<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
       verification/policy/trust-boundaries.toml
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
| unit://client.accepted_authority | source, contracts or evidence | THM-0091 | _no consumer_ |
| unit://client.accepted_authority_sole_producer | source, contracts or evidence | THM-0091 | _no consumer_ |
| unit://client.anchor_refresh | source, contracts or evidence | THM-0120 | _no consumer_ |
| unit://client.bind_scope | source, contracts or evidence | THM-0091 | _no consumer_ |
| unit://client.bind_scope_sole_producer | source, contracts or evidence | THM-0091 | _no consumer_ |
| unit://client.binding_spec_refusal | source, contracts or evidence | THM-0111 | _no consumer_ |
| unit://client.caller_shape_admission | source, contracts or evidence | THM-0091 | _no consumer_ |
| unit://client.delegated_trust_pairing_seal | source, contracts or evidence | THM-0057 | _no consumer_ |
| unit://client.delegation_policy_seal | source, contracts or evidence | THM-0060 | _no consumer_ |
| unit://client.deployment_config | source, contracts or evidence | THM-0124 | _no consumer_ |
| unit://client.execution_contract | source, contracts or evidence | THM-0061 | _no consumer_ |
| unit://client.local_leg_declaration | source, contracts or evidence | THM-0091 | _no consumer_ |
| unit://client.local_request_surface | source, contracts or evidence | THM-0091 | _no consumer_ |
| unit://client.local_serving_pipeline | source, contracts or evidence | THM-0123 | _no consumer_ |
| unit://client.manifest_floor | source, contracts or evidence | THM-0121 | _no consumer_ |
| unit://client.proxy_reply_disposition | source, contracts or evidence | THM-0061 | _no consumer_ |
| unit://client.proxy_request_correspondence | source, contracts or evidence | THM-0084 | _no consumer_ |
| unit://client.receipt_contract_carriage | source, contracts or evidence | THM-0061 | _no consumer_ |
| unit://client.request_construction | source, contracts or evidence | THM-0125 | _no consumer_ |
| unit://client.response_binding_disposition | source, contracts or evidence | THM-0059, THM-0076 | _no consumer_ |
| unit://client.response_signer_authorization | source, contracts or evidence | THM-0058, THM-0076 | _no consumer_ |
| unit://client.serving_lifetime | source, contracts or evidence | THM-0127 | _no consumer_ |
| unit://client.transport_message_hygiene | source, contracts or evidence | THM-0110 | _no consumer_ |
| unit://client.transport_server_identity | source, contracts or evidence | THM-0109 | _no consumer_ |
| unit://client.trust_manifest_lifecycle | source, contracts or evidence | THM-0057, THM-0058 | _no consumer_ |
| unit://client.verified_outcome | source, contracts or evidence | THM-0126 | _no consumer_ |
| unit://conformance.audit_vocabulary_drift | source, contracts or evidence | THM-0122 | _no consumer_ |
| unit://conformance.carrier_minting_absence | source, contracts or evidence | THM-0111 | _no consumer_ |
| unit://conformance.production_half_definition | source, contracts or evidence | THM-0111 | _no consumer_ |
| unit://conformance.retained_corpus | source, contracts or evidence | THM-0042 | http_profile.scitt_retained_correspondence (PROOF_DEPENDENCY) |
| unit://conformance.scanned_tree_declaration | source, contracts or evidence | THM-0111 | _no consumer_ |
| unit://conformance.verdict_vocabulary_scope | source, contracts or evidence | THM-0111 | _no consumer_ |
| unit://core.audit_vocabulary | source, contracts or evidence | THM-0122 | _no consumer_ |
| unit://core.content_address | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://core.ed25519_primitive | source, contracts or evidence | THM-0014 | _no consumer_ |
| unit://core.replay_seam | source, contracts or evidence | THM-0118 | _no consumer_ |
| unit://core.time_civil_from_days | source, contracts or evidence | THM-0128 | _no consumer_ |
| unit://core.time_rfc3339 | source, contracts or evidence | THM-0002 | _no consumer_ |
| unit://core.trust_resolver_seam | source, contracts or evidence | THM-0119 | _no consumer_ |
| unit://core.verification_taxonomy | source, contracts or evidence | THM-0111 | _no consumer_ |
| unit://host.request_freshness_inputs | source, contracts or evidence | THM-0114 | _no consumer_ |
| unit://http_profile.admission_assertion | source, contracts or evidence | THM-0053 | _no consumer_ |
| unit://http_profile.admission_currency | source, contracts or evidence | THM-0003, THM-0004, THM-0005, THM-0006 | _no consumer_ |
| unit://http_profile.admission_state_provenance | source, contracts or evidence | THM-0129 | _no consumer_ |
| unit://http_profile.artifact_typing | source, contracts or evidence | THM-0007 | _no consumer_ |
| unit://http_profile.artifact_verification_boundary | source, contracts or evidence | THM-0008, THM-0015 | _no consumer_ |
| unit://http_profile.bodyless_acknowledgement | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.bound_response_full_result | source, contracts or evidence | THM-0018 | _no consumer_ |
| unit://http_profile.bound_response_seam_result | source, contracts or evidence | THM-0016 | _no consumer_ |
| unit://http_profile.bound_response_shared_facts | source, contracts or evidence | THM-0021 | _no consumer_ |
| unit://http_profile.carrier_verdict_projection | source, contracts or evidence | THM-0111 | _no consumer_ |
| unit://http_profile.continuation_binding | source, contracts or evidence | THM-0010 | http_profile.continuation_unbypassability (PROOF_DEPENDENCY) |
| unit://http_profile.continuation_unbypassability | source, contracts or evidence | THM-0009 | _no consumer_ |
| unit://http_profile.delegated_bound_result | source, contracts or evidence | THM-0019 | _no consumer_ |
| unit://http_profile.delegated_credential_chain | source, contracts or evidence | THM-0019, THM-0020 | _no consumer_ |
| unit://http_profile.delegated_signing_custody | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.delegated_unbound_result | source, contracts or evidence | THM-0020 | _no consumer_ |
| unit://http_profile.evidence_block_carriage | source, contracts or evidence | THM-0015, THM-0125 | _no consumer_ |
| unit://http_profile.evidence_block_closure | source, contracts or evidence | THM-0015 | _no consumer_ |
| unit://http_profile.fleet_strict_store_class | source, contracts or evidence | THM-0092 | _no consumer_ |
| unit://http_profile.freshness_window | source, contracts or evidence | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 | _no consumer_ |
| unit://http_profile.keyid | source, contracts or evidence | THM-0055 | _no consumer_ |
| unit://http_profile.keyid_selector | source, contracts or evidence | THM-0050 | _no consumer_ |
| unit://http_profile.pdp_decision_authentication | source, contracts or evidence | THM-0039 | _no consumer_ |
| unit://http_profile.replay_key | source, contracts or evidence | THM-0079 | _no consumer_ |
| unit://http_profile.request_envelope | source, contracts or evidence | THM-0083 | _no consumer_ |
| unit://http_profile.request_floor_result | source, contracts or evidence | THM-0014 | proxy.request_peer_binding (COMPILE_DEPENDENCY) |
| unit://http_profile.request_full_result | source, contracts or evidence | THM-0015 | _no consumer_ |
| unit://http_profile.response_emission_binding | source, contracts or evidence | THM-0065, THM-0075 | _no consumer_ |
| unit://http_profile.retained_chain_record | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.scitt_algorithm_agreement | source, contracts or evidence | THM-0041 | _no consumer_ |
| unit://http_profile.scitt_derived_root | source, contracts or evidence | THM-0041 | _no consumer_ |
| unit://http_profile.scitt_inclusion_fold | source, contracts or evidence | THM-0041 | _no consumer_ |
| unit://http_profile.scitt_position_commitment | source, contracts or evidence | THM-0041 | _no consumer_ |
| unit://http_profile.scitt_receipt_shape | source, contracts or evidence | THM-0041 | _no consumer_ |
| unit://http_profile.scitt_retained_correspondence | source, contracts or evidence | THM-0042 | _no consumer_ |
| unit://http_profile.scitt_service_pin | source, contracts or evidence | THM-0068, THM-0072 | _no consumer_ |
| unit://http_profile.scitt_statement_attribution | source, contracts or evidence | THM-0041 | _no consumer_ |
| unit://http_profile.submitted_hop_identity | source, contracts or evidence | THM-0042 | http_profile.scitt_retained_correspondence (PROOF_DEPENDENCY) |
| unit://http_profile.unbound_response_seam_result | source, contracts or evidence | THM-0017 | _no consumer_ |
| unit://http_profile.unbound_response_shared_facts | source, contracts or evidence | THM-0022 | _no consumer_ |
| unit://http_profile.verifier_result_separation | source, contracts or evidence | THM-0047, THM-0051 | _no consumer_ |
| unit://policy.authorization_taxonomy | source, contracts or evidence | THM-0111 | _no consumer_ |
| unit://proxy.admission_configuration_state | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.admission_configuration_state_sole_producer | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.admission_currency_gate | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.admission_record_addressing | source, contracts or evidence | THM-0129 | _no consumer_ |
| unit://proxy.admission_state_source | source, contracts or evidence | THM-0129 | _no consumer_ |
| unit://proxy.async_replay_retention | source, contracts or evidence | THM-0105 | _no consumer_ |
| unit://proxy.audit_authority_coordinates | source, contracts or evidence | THM-0069 | _no consumer_ |
| unit://proxy.audit_delivery | source, contracts or evidence | THM-0070 | _no consumer_ |
| unit://proxy.audit_text_rendering | source, contracts or evidence | THM-0130 | _no consumer_ |
| unit://proxy.audit_vocabulary_import | source, contracts or evidence | THM-0071 | _no consumer_ |
| unit://proxy.authenticated_relationship_peer | source, contracts or evidence | THM-0031 | proxy.current_authenticated_peer (CONTRACT_CONSUMES) |
| unit://proxy.authorization_capability | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.authorization_configuration_state | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.authorization_coordinate_provenance | source, contracts or evidence | THM-0040 | _no consumer_ |
| unit://proxy.authorization_posture | source, contracts or evidence | THM-0056 | _no consumer_ |
| unit://proxy.aws_kms_adapter | source, contracts or evidence | THM-0116 | _no consumer_ |
| unit://proxy.aws_sts_credentials | source, contracts or evidence | THM-0117 | _no consumer_ |
| unit://proxy.aws_web_identity_credential_exchange | source, contracts or evidence | THM-0117 | _no consumer_ |
| unit://proxy.capsule_anchor_registration_leaf | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.certificate_identity | source, contracts or evidence | THM-0024 | proxy.channel_associated_identity (COMPILE_DEPENDENCY) |
| unit://proxy.certificate_identity_authority_boundary | source, contracts or evidence | THM-0024 | _no consumer_ |
| unit://proxy.certificate_identity_refusal_vocabulary | source, contracts or evidence | THM-0024 | _no consumer_ |
| unit://proxy.channel_associated_credential | source, contracts or evidence | THM-0028 | proxy.channel_associated_identity (CONTRACT_CONSUMES), proxy.mechanism_verified_credential (CONTRACT_CONSUMES) |
| unit://proxy.channel_associated_identity | source, contracts or evidence | THM-0029 | proxy.authenticated_relationship_peer (CONTRACT_CONSUMES) |
| unit://proxy.channel_credential_custody_state | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.channel_peer_resolution | source, contracts or evidence | THM-0031 | _no consumer_ |
| unit://proxy.client_certificate_posture | source, contracts or evidence | THM-0054 | proxy.credential_currency (COMPILE_DEPENDENCY) |
| unit://proxy.client_credential_window | source, contracts or evidence | THM-0102 | _no consumer_ |
| unit://proxy.client_credential_window_sole_producer | source, contracts or evidence | THM-0102 | _no consumer_ |
| unit://proxy.client_crl_next_update_gate | source, contracts or evidence | THM-0131 | _no consumer_ |
| unit://proxy.client_revocation_currency | source, contracts or evidence | THM-0131 | _no consumer_ |
| unit://proxy.client_revocation_index_verdict | source, contracts or evidence | THM-0032 | _no consumer_ |
| unit://proxy.client_revocation_snapshot | source, contracts or evidence | THM-0032 | _no consumer_ |
| unit://proxy.continuation_control_subject_boundary | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.continuation_correlation_store | source, contracts or evidence | THM-0087 | _no consumer_ |
| unit://proxy.continuation_installation | source, contracts or evidence | THM-0096 | _no consumer_ |
| unit://proxy.continuation_key_provenance | source, contracts or evidence | THM-0087 | _no consumer_ |
| unit://proxy.continuation_leg_binding | source, contracts or evidence | THM-0093 | _no consumer_ |
| unit://proxy.continuation_materialization | source, contracts or evidence | THM-0096 | _no consumer_ |
| unit://proxy.continuation_materialization_shared | source, contracts or evidence | THM-0096 | _no consumer_ |
| unit://proxy.continuation_materialization_sole_producer | source, contracts or evidence | THM-0096 | _no consumer_ |
| unit://proxy.credential_currency | source, contracts or evidence | THM-0032 | proxy.current_authenticated_peer (CONTRACT_CONSUMES) |
| unit://proxy.credential_currency_evidence_reporting | source, contracts or evidence | THM-0032 | _no consumer_ |
| unit://proxy.credential_key_correspondence | source, contracts or evidence | THM-0026 | proxy.delegated_resolver_materialization (CONTRACT_CONSUMES) |
| unit://proxy.credential_key_correspondence_sole_producer | source, contracts or evidence | THM-0026 | _no consumer_ |
| unit://proxy.cross_machine_legality | source, contracts or evidence | THM-0049, THM-0077 | _no consumer_ |
| unit://proxy.currency_policy_classification | source, contracts or evidence | THM-0032 | _no consumer_ |
| unit://proxy.current_authenticated_peer | source, contracts or evidence | THM-0033 | proxy.request_peer_binding (CONTRACT_CONSUMES) |
| unit://proxy.custody_exposure | source, contracts or evidence | THM-0064 | _no consumer_ |
| unit://proxy.custody_exposure_sole_producer | source, contracts or evidence | THM-0064 | _no consumer_ |
| unit://proxy.delegated_resolver_materialization | source, contracts or evidence | THM-0027 | _no consumer_ |
| unit://proxy.delegated_resolver_materialization_sole_producer | source, contracts or evidence | THM-0027 | _no consumer_ |
| unit://proxy.delegated_signing_configuration_state | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.delegated_signing_credential | source, contracts or evidence | THM-0062, THM-0063 | _no consumer_ |
| unit://proxy.deployment_topology_state | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.dispatch_commitment | source, contracts or evidence | THM-0045, THM-0051, THM-0052, THM-0074 | _no consumer_ |
| unit://proxy.ed25519_public_key | source, contracts or evidence | THM-0025 | proxy.credential_key_correspondence (COMPILE_DEPENDENCY) |
| unit://proxy.ed25519_public_key_sole_producer | source, contracts or evidence | THM-0025 | _no consumer_ |
| unit://proxy.epoch_bound_session_store | source, contracts or evidence | THM-0103 | _no consumer_ |
| unit://proxy.etcd_replay_adapter | source, contracts or evidence | THM-0107 | _no consumer_ |
| unit://proxy.evidence_attestation | source, contracts or evidence | THM-0113 | _no consumer_ |
| unit://proxy.evidence_retention_state | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.exchange_publication | source, contracts or evidence | THM-0101 | _no consumer_ |
| unit://proxy.exchange_relation | source, contracts or evidence | THM-0043, THM-0074, THM-0078 | _no consumer_ |
| unit://proxy.exchange_retry_consequence | source, contracts or evidence | THM-0044 | _no consumer_ |
| unit://proxy.exchange_transition_ownership | source, contracts or evidence | THM-0101 | _no consumer_ |
| unit://proxy.fleet_topology_provenance | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.freshness_window_state | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.gcp_kms_adapter | source, contracts or evidence | THM-0116, THM-0117 | _no consumer_ |
| unit://proxy.gcp_metadata_token_lifetime | source, contracts or evidence | THM-0117 | _no consumer_ |
| unit://proxy.in_flight_limit_basis | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.kms_ed25519_seam | source, contracts or evidence | THM-0108 | _no consumer_ |
| unit://proxy.kms_endpoint_authority | source, contracts or evidence | THM-0089 | _no consumer_ |
| unit://proxy.legality_boundary_totality | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.listener_state_assembly | source, contracts or evidence | THM-0048 | _no consumer_ |
| unit://proxy.mcp_transport_contract_state | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.mechanism_verified_credential | source, contracts or evidence | THM-0030 | proxy.authenticated_relationship_peer (CONTRACT_CONSUMES), proxy.credential_currency (CONTRACT_CONSUMES) |
| unit://proxy.online_ocsp_reachability | source, contracts or evidence | THM-0013 | _no consumer_ |
| unit://proxy.operator_facing_redaction | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.outbound_destination | source, contracts or evidence | THM-0090 | _no consumer_ |
| unit://proxy.outstanding_id_provenance | source, contracts or evidence | THM-0083 | _no consumer_ |
| unit://proxy.pdp_decision_relation | source, contracts or evidence | THM-0040, THM-0052 | _no consumer_ |
| unit://proxy.peer_identity_value | source, contracts or evidence | THM-0023 | proxy.certificate_identity (COMPILE_DEPENDENCY) |
| unit://proxy.peer_identity_value_sole_producer | source, contracts or evidence | THM-0023 | _no consumer_ |
| unit://proxy.per_request_revocation_serving | source, contracts or evidence | THM-0032 | _no consumer_ |
| unit://proxy.pkcs11_adapter | source, contracts or evidence | THM-0116 | _no consumer_ |
| unit://proxy.pre_dispatch_refusal_precedence | source, contracts or evidence | THM-0078 | _no consumer_ |
| unit://proxy.redis_replay_adapter | source, contracts or evidence | THM-0106 | _no consumer_ |
| unit://proxy.refusal_audit_emission | source, contracts or evidence | THM-0085 | _no consumer_ |
| unit://proxy.refusal_provenance | source, contracts or evidence | THM-0046, THM-0069, THM-0071, THM-0078 | _no consumer_ |
| unit://proxy.refusal_site_totality | source, contracts or evidence | THM-0081 | _no consumer_ |
| unit://proxy.remote_signer_call_aws | source, contracts or evidence | THM-0115 | _no consumer_ |
| unit://proxy.remote_signer_call_gcp | source, contracts or evidence | THM-0115 | _no consumer_ |
| unit://proxy.remote_signer_egress_bound | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.replay_admission_gate | source, contracts or evidence | THM-0092 | _no consumer_ |
| unit://proxy.replay_configuration_state | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.replay_materialization | source, contracts or evidence | THM-0086 | _no consumer_ |
| unit://proxy.replay_tier_production_minimum | source, contracts or evidence | THM-0092 | _no consumer_ |
| unit://proxy.request_peer_binding | source, contracts or evidence | THM-0034 | _no consumer_ |
| unit://proxy.response_signing | source, contracts or evidence | THM-0063, THM-0075 | _no consumer_ |
| unit://proxy.retained_record_at_the_store | source, contracts or evidence | THM-0112 | _no consumer_ |
| unit://proxy.retained_record_content | source, contracts or evidence | THM-0112 | _no consumer_ |
| unit://proxy.retention_commitment | source, contracts or evidence | THM-0088 | _no consumer_ |
| unit://proxy.retired_plane_cadence_retraction | source, contracts or evidence | THM-0131 | _no consumer_ |
| unit://proxy.runtime_lifecycle | source, contracts or evidence | THM-0012 | _no consumer_ |
| unit://proxy.runtime_lifecycle_sole_mutator | source, contracts or evidence | THM-0012 | _no consumer_ |
| unit://proxy.scrapi_registration_leaf | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.server_identity_facts | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.serving_capability_posture | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.serving_drain | source, contracts or evidence | THM-0104 | _no consumer_ |
| unit://proxy.serving_identity_provenance | source, contracts or evidence | THM-0080 | _no consumer_ |
| unit://proxy.serving_trust_seam | source, contracts or evidence | THM-0066, THM-0099 | _no consumer_ |
| unit://proxy.signing_credential_provenance | source, contracts or evidence | THM-0082 | _no consumer_ |
| unit://proxy.signing_plane_epoch_read_refusal | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.signing_role_separation | source, contracts or evidence | THM-0073 | _no consumer_ |
| unit://proxy.startup_plan_legality | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.startup_plan_pool_ceiling | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.startup_plan_provenance | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.transport_binding_and_crl_state | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://proxy.transport_binding_application | source, contracts or evidence | THM-0034 | _no consumer_ |
| unit://proxy.trust_cache_entry_addressing | source, contracts or evidence | THM-0097 | _no consumer_ |
| unit://proxy.trust_composition_root | source, contracts or evidence | THM-0038, THM-0067, THM-0077 | _no consumer_ |
| unit://proxy.trust_configuration_state_sole_producer | source, contracts or evidence | THM-0035, THM-0036 | _no consumer_ |
| unit://proxy.trust_document_interpretation | source, contracts or evidence | THM-0098 | _no consumer_ |
| unit://proxy.trust_document_locator | source, contracts or evidence | THM-0036 | _no consumer_ |
| unit://proxy.trust_epoch_source | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.trust_plan | source, contracts or evidence | THM-0037, THM-0066 | _no consumer_ |
| unit://proxy.trust_plan_co_provenance | source, contracts or evidence | THM-0037 | _no consumer_ |
| unit://proxy.trust_posture_declaration | source, contracts or evidence | THM-0100 | _no consumer_ |
| unit://proxy.trust_reload_cadence | source, contracts or evidence | THM-0100 | _no consumer_ |
| unit://proxy.trust_resolution_window | source, contracts or evidence | THM-0097, THM-0098 | _no consumer_ |
| unit://proxy.trust_revocation_classification | source, contracts or evidence | THM-0035 | _no consumer_ |
| unit://proxy.trust_snapshot_swap | source, contracts or evidence | THM-0100 | _no consumer_ |
| unit://proxy.unestablishable_capability_refusal | source, contracts or evidence | THM-0077 | _no consumer_ |
| unit://sdk_python.authorization_binding | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://sdk_python.bounded_read | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://sdk_python.continuation_drive | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.correlation_lifecycle | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.exchange_binding | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.execution_report | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.local_failure_provenance | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.nonce_floor | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.notification_delivery | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.reply_envelope | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.signer_policy | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://sdk_python.trust_anchor_completeness | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_python.verdict_delivery | source, contracts or evidence | THM-0094 | _no consumer_ |
| unit://sdk_typescript.authorization_binding | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://sdk_typescript.bounded_read | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://sdk_typescript.continuation_drive | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.correlation_lifecycle | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.exchange_binding | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.execution_report | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.local_failure_provenance | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.nonce_floor | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.notification_delivery | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.post_close_emission | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.reply_envelope | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.signer_policy | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://sdk_typescript.trust_anchor_completeness | source, contracts or evidence | THM-0095 | _no consumer_ |
| unit://sdk_typescript.verdict_delivery | source, contracts or evidence | THM-0095 | _no consumer_ |

## Theorems

| object | a change to | invalidates | and every claim above |
|---|---|---|---|
| THM-0001 | statement, consequence, scope or review requirement | specification review | THM-0014, THM-0021, THM-0022 |
| THM-0002 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0003 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0004 | statement, consequence, scope or review requirement | specification review | THM-0074, THM-0129 |
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
| THM-0043 | statement, consequence, scope or review requirement | specification review | THM-0044, THM-0074, THM-0078, THM-0081, THM-0101 |
| THM-0044 | statement, consequence, scope or review requirement | specification review | THM-0078 |
| THM-0045 | statement, consequence, scope or review requirement | specification review | THM-0052, THM-0074, THM-0078 |
| THM-0046 | statement, consequence, scope or review requirement | specification review | THM-0069, THM-0071, THM-0078, THM-0081, THM-0085, THM-0111 |
| THM-0047 | statement, consequence, scope or review requirement | specification review | THM-0051 |
| THM-0048 | statement, consequence, scope or review requirement | specification review | THM-0054, THM-0077 |
| THM-0049 | statement, consequence, scope or review requirement | specification review | THM-0073, THM-0077 |
| THM-0050 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0051 | statement, consequence, scope or review requirement | specification review | THM-0074, THM-0087 |
| THM-0052 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0053 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0054 | statement, consequence, scope or review requirement | specification review | THM-0077, THM-0131 |
| THM-0055 | statement, consequence, scope or review requirement | specification review | THM-0050 |
| THM-0056 | statement, consequence, scope or review requirement | specification review | THM-0052 |
| THM-0057 | statement, consequence, scope or review requirement | specification review | THM-0058, THM-0076, THM-0120 |
| THM-0058 | statement, consequence, scope or review requirement | specification review | THM-0076, THM-0094 |
| THM-0059 | statement, consequence, scope or review requirement | specification review | THM-0076, THM-0094 |
| THM-0060 | statement, consequence, scope or review requirement | specification review | THM-0076, THM-0094 |
| THM-0061 | statement, consequence, scope or review requirement | specification review | THM-0076, THM-0094, THM-0126 |
| THM-0062 | statement, consequence, scope or review requirement | specification review | THM-0063, THM-0075, THM-0082 |
| THM-0063 | statement, consequence, scope or review requirement | specification review | THM-0075, THM-0078 |
| THM-0064 | statement, consequence, scope or review requirement | specification review | THM-0077, THM-0082 |
| THM-0065 | statement, consequence, scope or review requirement | specification review | THM-0075 |
| THM-0066 | statement, consequence, scope or review requirement | specification review | THM-0074, THM-0077, THM-0099 |
| THM-0067 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0068 | statement, consequence, scope or review requirement | specification review | THM-0072 |
| THM-0069 | statement, consequence, scope or review requirement | specification review | THM-0071, THM-0078, THM-0085, THM-0130 |
| THM-0070 | statement, consequence, scope or review requirement | specification review | THM-0071 |
| THM-0071 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0072 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0073 | statement, consequence, scope or review requirement | specification review | THM-0077, THM-0082 |
| THM-0074 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0075 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0076 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0077 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0078 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0079 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0080 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0081 | statement, consequence, scope or review requirement | specification review | THM-0071, THM-0078, THM-0085 |
| THM-0082 | statement, consequence, scope or review requirement | specification review | THM-0075 |
| THM-0083 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0084 | statement, consequence, scope or review requirement | specification review | THM-0076 |
| THM-0085 | statement, consequence, scope or review requirement | specification review | THM-0071 |
| THM-0086 | statement, consequence, scope or review requirement | specification review | THM-0077, THM-0092 |
| THM-0087 | statement, consequence, scope or review requirement | specification review | THM-0093 |
| THM-0088 | statement, consequence, scope or review requirement | specification review | THM-0078, THM-0113 |
| THM-0089 | statement, consequence, scope or review requirement | specification review | THM-0077, THM-0090, THM-0116 |
| THM-0090 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0091 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0092 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0093 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0094 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0095 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0096 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0097 | statement, consequence, scope or review requirement | specification review | THM-0074, THM-0099, THM-0100 |
| THM-0098 | statement, consequence, scope or review requirement | specification review | THM-0074, THM-0099 |
| THM-0099 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0100 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0101 | statement, consequence, scope or review requirement | specification review | THM-0074 |
| THM-0102 | statement, consequence, scope or review requirement | specification review | THM-0077 |
| THM-0103 | statement, consequence, scope or review requirement | specification review | THM-0048 |
| THM-0104 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0105 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0106 | statement, consequence, scope or review requirement | specification review | THM-0092 |
| THM-0107 | statement, consequence, scope or review requirement | specification review | THM-0092 |
| THM-0108 | statement, consequence, scope or review requirement | specification review | THM-0116 |
| THM-0109 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0110 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0111 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0112 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0113 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0114 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0115 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0116 | statement, consequence, scope or review requirement | specification review | THM-0082 |
| THM-0117 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0118 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0119 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0120 | statement, consequence, scope or review requirement | specification review | THM-0127 |
| THM-0121 | statement, consequence, scope or review requirement | specification review | THM-0120 |
| THM-0122 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0123 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0124 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0125 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0126 | statement, consequence, scope or review requirement | specification review | THM-0076 |
| THM-0127 | statement, consequence, scope or review requirement | specification review | THM-0076 |
| THM-0128 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0129 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0130 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0131 | statement, consequence, scope or review requirement | specification review | _no dependent_ |

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
| ASM-0027 | description, justification, scope or mechanism | http_profile.bound_response_seam_result, http_profile.bound_response_shared_facts, http_profile.delegated_bound_result, http_profile.delegated_credential_chain, http_profile.delegated_unbound_result, http_profile.request_floor_result, http_profile.unbound_response_seam_result, http_profile.unbound_response_shared_facts | assumption review |
| ASM-0028 | description, justification, scope or mechanism | http_profile.bound_response_full_result, http_profile.bound_response_shared_facts, http_profile.delegated_bound_result, http_profile.request_floor_result, http_profile.request_full_result, http_profile.unbound_response_shared_facts | assumption review |
| ASM-0029 | description, justification, scope or mechanism | http_profile.bound_response_seam_result, http_profile.delegated_credential_chain, http_profile.request_floor_result, http_profile.unbound_response_seam_result | assumption review |
| ASM-0030 | description, justification, scope or mechanism | proxy.certificate_identity | assumption review |
| ASM-0031 | description, justification, scope or mechanism | proxy.ed25519_public_key | assumption review |
| ASM-0032 | description, justification, scope or mechanism | proxy.credential_key_correspondence | assumption review |
| ASM-0033 | description, justification, scope or mechanism | proxy.channel_associated_credential | assumption review |
| ASM-0034 | description, justification, scope or mechanism | proxy.channel_associated_identity | assumption review |
| ASM-0035 | description, justification, scope or mechanism | proxy.mechanism_verified_credential | assumption review |
| ASM-0036 | description, justification, scope or mechanism | proxy.authenticated_relationship_peer | assumption review |
| ASM-0037 | description, justification, scope or mechanism | http_profile.keyid_selector | assumption review |
| ASM-0038 | description, justification, scope or mechanism | proxy.credential_currency | assumption review |
| ASM-0039 | description, justification, scope or mechanism | proxy.delegated_resolver_materialization | assumption review |
| ASM-0040 | description, justification, scope or mechanism | proxy.replay_admission_gate | assumption review |
| ASM-0041 | description, justification, scope or mechanism | proxy.replay_admission_gate | assumption review |
| ASM-0042 | description, justification, scope or mechanism | _no unit_ | assumption review |
| ASM-0043 | description, justification, scope or mechanism | _no unit_ | assumption review |
| ASM-0044 | description, justification, scope or mechanism | proxy.trust_epoch_source | assumption review |
| ASM-0045 | description, justification, scope or mechanism | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | assumption review |
| ASM-0046 | description, justification, scope or mechanism | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | assumption review |
| ASM-0047 | description, justification, scope or mechanism | proxy.continuation_correlation_store | assumption review |
| ASM-0048 | description, justification, scope or mechanism | proxy.continuation_correlation_store | assumption review |
| ASM-0049 | description, justification, scope or mechanism | proxy.epoch_bound_session_store, proxy.listener_state_assembly | assumption review |
