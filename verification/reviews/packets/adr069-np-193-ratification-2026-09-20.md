<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-193 — R6 ratification packet: IRSA misconfiguration, refused and named

**Disposition:** R6, referred entire. Three controls, split out of NP-158 under RR-002 C5
when that record's twelve rows were measured and found to span three propositions.

**3 controls**, `mcp-re-proxy`, rust integration test, `aws_kms_keysource` lane, carrier
`mcp-re-proxy/tests/aws_irsa_web_identity_test.rs`:

- `tests/aws_irsa_web_identity_test#a_pod_that_is_not_under_irsa_is_told_which_variable_is_missing`
- `tests/aws_irsa_web_identity_test#an_empty_role_arn_is_refused_rather_than_posted_as_a_blank_role`
- `tests/aws_irsa_web_identity_test#an_sts_rejection_fails_closed_and_names_the_role`

All three are zero-selection without `--features aws_kms_keysource`: the target compiles to
`0 tests, 0 benchmarks` and exits 0.

## Why THM-0117 does not reach two of them — the scope excludes the role in terms

THM-0117, scope, verbatim:

> Nothing here is about what the credential is permitted to do, which role it assumes, or
> whether the assumed role is least-privileged.

`an_empty_role_arn_is_refused_rather_than_posted_as_a_blank_role` is about which role is
assumed and refuses a deployment that names none. `an_sts_rejection_fails_closed_and_names_the_role`
asserts three things — the status is carried, the role is carried, the provider's code is
carried — two of which are the role. Registering either under THM-0117 would assert the
theorem says something it disclaims in a sentence.

## Why THM-0117 does not reach the third — it states no rendering clause

`a_pod_that_is_not_under_irsa_is_told_which_variable_is_missing` drives
`WebIdentityConfig::from_env` with the environment cleared, asserts the refusal names
`AWS_ROLE_ARN`, sets that variable, and asserts the next refusal names
`AWS_WEB_IDENTITY_TOKEN_FILE`. That is a claim about what the operator READS.

THM-0117's statement has no clause about how a refusal renders. Its owner unit's nearest
control, `each_missing_credential_field_is_named`, is about the STS RESPONSE document —
which credential field the provider omitted — and not about which of the pod's environment
variables the deployment failed to set. The carrier differs, the input differs, and the
reader differs.

## The axis, and why it is referred rather than dispositioned

This is the same axis as two propositions this campaign has already referred: NP-123, *every
OFF posture line tells the operator what to do about it*, and NP-145's rendering agreement.
The reasoning recorded there applies unchanged — what a refusal TELLS an operator is an
operator-facing product promise about a transcript, not a decomposition of the security
claim the refusal enforces. The deployment's security posture is identical whether or not
the sentence names a variable.

It is carried as a proposition and not as `not-evidence`. The three are real controls over
production refusals; none of the thirteen families covers operator-facing naming; and this
slice may not mint a fourteenth.

## Kept as ONE proposition

All three assert the same rule at three inputs: a misconfigured IRSA deployment is refused
at the earliest point it can be detected, and the refusal names the thing that is wrong. The
first two refuse at construction from the environment, the third at the first exchange
because STS is the only authority that can decide it. They fail the same way — an opaque
failure at signing time that an operator cannot attribute.

**Severity:** `high`.
