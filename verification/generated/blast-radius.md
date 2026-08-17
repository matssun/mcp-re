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
| unit://core.time_rfc3339 | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.admission_currency | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.artifact_typing | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.continuation_binding | source, contracts or evidence | _no theorem_ | http_profile.continuation_unbypassability (PROOF_DEPENDENCY) |
| unit://http_profile.continuation_unbypassability | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.freshness_window | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://http_profile.keyid | source, contracts or evidence | _no theorem_ | _no consumer_ |
| unit://proxy.runtime_lifecycle | source, contracts or evidence | _no theorem_ | _no consumer_ |

## Theorems

_None._

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
