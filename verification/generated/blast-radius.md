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
| unit://core.time_rfc3339 | source, contracts or evidence | THM-0002 | _no consumer_ |
| unit://http_profile.admission_currency | source, contracts or evidence | THM-0003, THM-0004, THM-0005, THM-0006 | _no consumer_ |
| unit://http_profile.artifact_typing | source, contracts or evidence | THM-0007, THM-0008, THM-0015 | _no consumer_ |
| unit://http_profile.continuation_binding | source, contracts or evidence | THM-0010 | http_profile.continuation_unbypassability (PROOF_DEPENDENCY) |
| unit://http_profile.continuation_unbypassability | source, contracts or evidence | THM-0009 | _no consumer_ |
| unit://http_profile.freshness_window | source, contracts or evidence | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 | _no consumer_ |
| unit://http_profile.keyid | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.verifier_result_separation | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.verifier_results | source, contracts or evidence | THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022 | _no consumer_ |
| unit://proxy.certificate_identity | source, contracts or evidence | THM-0024 | proxy.channel_associated_identity (COMPILE_DEPENDENCY) |
| unit://proxy.channel_associated_credential | source, contracts or evidence | THM-0028 | proxy.channel_associated_identity (CONTRACT_CONSUMES) |
| unit://proxy.channel_associated_identity | source, contracts or evidence | THM-0029 | _no consumer_ |
| unit://proxy.credential_key_correspondence | source, contracts or evidence | THM-0026 | proxy.delegated_resolver_materialization (CONTRACT_CONSUMES) |
| unit://proxy.delegated_resolver_materialization | source, contracts or evidence | THM-0027 | _no consumer_ |
| unit://proxy.ed25519_public_key | source, contracts or evidence | THM-0025 | proxy.credential_key_correspondence (COMPILE_DEPENDENCY) |
| unit://proxy.online_ocsp_reachability | source, contracts or evidence | THM-0013 | _no consumer_ |
| unit://proxy.peer_identity_value | source, contracts or evidence | THM-0023 | proxy.certificate_identity (COMPILE_DEPENDENCY) |
| unit://proxy.runtime_lifecycle | source, contracts or evidence | THM-0012 | _no consumer_ |
| unit://proxy.tls_listener_state | source, contracts or evidence | _no theorem_ | _no consumer_ |

## Theorems

| object | a change to | invalidates | and every claim above |
|---|---|---|---|
| THM-0001 | statement, consequence, scope or review requirement | specification review | THM-0014, THM-0021, THM-0022 |
| THM-0002 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0003 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0004 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0005 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0006 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0007 | statement, consequence, scope or review requirement | specification review | THM-0008, THM-0015 |
| THM-0008 | statement, consequence, scope or review requirement | specification review | THM-0015 |
| THM-0009 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0010 | statement, consequence, scope or review requirement | specification review | THM-0009 |
| THM-0012 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0013 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0014 | statement, consequence, scope or review requirement | specification review | THM-0015 |
| THM-0015 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0016 | statement, consequence, scope or review requirement | specification review | THM-0018 |
| THM-0017 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0018 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0019 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0020 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0021 | statement, consequence, scope or review requirement | specification review | THM-0016, THM-0019 |
| THM-0022 | statement, consequence, scope or review requirement | specification review | THM-0017, THM-0020 |
| THM-0023 | statement, consequence, scope or review requirement | specification review | THM-0024 |
| THM-0024 | statement, consequence, scope or review requirement | specification review | THM-0029 |
| THM-0025 | statement, consequence, scope or review requirement | specification review | THM-0026 |
| THM-0026 | statement, consequence, scope or review requirement | specification review | THM-0027 |
| THM-0027 | statement, consequence, scope or review requirement | specification review | _no dependent_ |
| THM-0028 | statement, consequence, scope or review requirement | specification review | THM-0029 |
| THM-0029 | statement, consequence, scope or review requirement | specification review | _no dependent_ |

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
| ASM-0030 | description, justification, scope or mechanism | proxy.certificate_identity | assumption review |
| ASM-0031 | description, justification, scope or mechanism | proxy.ed25519_public_key | assumption review |
| ASM-0032 | description, justification, scope or mechanism | proxy.credential_key_correspondence | assumption review |
| ASM-0033 | description, justification, scope or mechanism | proxy.channel_associated_credential | assumption review |
| ASM-0034 | description, justification, scope or mechanism | proxy.channel_associated_identity | assumption review |
