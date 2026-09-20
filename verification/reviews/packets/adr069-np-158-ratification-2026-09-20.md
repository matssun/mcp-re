<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-158 residue — R6 ratification packet: the projected token's provenance

**Disposition:** R2 in part, R6 for the residue. Six of NP-158's twelve controls landed as
`unit://proxy.aws_web_identity_credential_exchange` under THM-0117, falsifier
`M345-proxy-the-refresh-margin-is-dropped-from-the-cache-hit`. Three more became NP-193.
Three rows remain; NP-158's `[[proposition]]` entry and record stay in place, with the title
narrowed to the half that remains.

## The lane, measured first

| selection | tests |
|---|---|
| `cargo test -p mcp-re-proxy --test aws_irsa_web_identity_test -- --list` | **0 tests, 0 benchmarks**, exit **0** |
| `cargo test -p mcp-re-proxy --features aws_kms_keysource --test aws_irsa_web_identity_test -- --list` | **12 tests** |

The file opens `#![cfg(feature = "aws_kms_keysource")]`, so the default lane compiles the
whole target to nothing and reports success. This is the second instance of the shape
`docs/dev/` already records for `tls_load_harness_bench`, and it is why
`proxy.aws_web_identity_credential_exchange` declares
`test_features = ["aws_kms_keysource"]`.

**The declaration was verified to be load-bearing rather than assumed.** With
`test_features` removed from the unit and nothing else changed, `M345` reports:

> MEASUREMENT FAILURE — expected control(s) ['tests/aws_irsa_web_identity_test#a_credential_inside_the_refresh_margin_is_re_exchanged']
> were never reported by the run. The lane cannot say the weakening broke a test it did not
> watch execute; absence is not a red result.

With it restored, the same probe reports that control **FAILED**. The lane is the property.

## What landed, and the clauses that contain it

THM-0117, statement, verbatim:

> A credential acquired from AWS STS or from the GCE/GKE metadata server carries the expiry
> its issuer stated, and that expiry is never extended

> The credential is still reused briefly rather than re-exchanged per call, and that brief
> window is a floor on churn rather than an extension of a stated lifetime.

Contains `the_projected_token_is_exchanged_for_temporary_credentials`,
`a_live_credential_is_cached_rather_than_re_exchanged_per_call` and
`a_credential_inside_the_refresh_margin_is_re_exchanged`.

THM-0117, scope, verbatim:

> WHERE THE TOKEN IS SENT is a conjunct of the AWS unit and not of the metadata one: a
> projected web-identity token handed to a re-pointed STS endpoint is a credential leak, and
> it is refused at construction.

Contains `the_default_sts_endpoint_is_regional` — the construction-time settlement of the
destination — alongside the owner unit's existing
`a_hostile_region_stops_the_default_endpoint_being_built`.

Two land as the composition twins of controls already inside `proxy.aws_sts_credentials`,
THM-0117's own owner unit: `a_malformed_sts_body_fails_closed` beside
`a_response_without_credentials_is_refused`, and
`an_out_of_grammar_session_name_is_refused_at_construction` beside
`session_names_are_validated_against_the_sts_grammar`. Both are the same rule measured
through the wiring in force rather than over the function directly.

**Why a twin over the same path and not an append to `proxy.aws_sts_credentials`.** The
existing unit's proposition is the lifetime algebra over the parser and the cache; the new
one's is that a running exchange against a protocol speaker performs it. Duplicate path-sets
are established here — twenty pairs of units already share one — and the twin keeps the two
propositions separately falsifiable. No `paths` was widened and no description amended.

## The residue

**3 controls**, `mcp-re-proxy`, rust integration test, `aws_kms_keysource` lane, carrier
`mcp-re-proxy/tests/aws_irsa_web_identity_test.rs`:

- `tests/aws_irsa_web_identity_test#the_token_file_is_re_read_on_every_exchange_not_cached_at_construction`
- `tests/aws_irsa_web_identity_test#a_missing_token_file_fails_closed_rather_than_falling_back_to_the_environment`
- `tests/aws_irsa_web_identity_test#an_empty_token_file_is_refused_rather_than_posted`

### Why THM-0117 does not reach them

The statement begins:

> A credential acquired from AWS STS or from the GCE/GKE metadata server

The projected web-identity token is the INPUT to that acquisition. It is not acquired from
STS; it is what is presented to STS. Every clause of the theorem quantifies over the
credential that comes BACK — its stated expiry, its reuse floor, the single flight that
obtains it, the cool-off after a failed attempt to obtain it. None of them says anything
about where the presented token came from, how often it is re-read, or what happens when its
mount is empty.

The one place the scope mentions the projected token is about destination only:

> WHERE THE TOKEN IS SENT is a conjunct of the AWS unit and not of the metadata one: a
> projected web-identity token handed to a re-pointed STS endpoint is a credential leak, and
> it is refused at construction.

Where it is sent, yes. Where it is read from, no. The operational test is clean: delete the
re-read, delete the empty-file refusal, delete the no-fallback rule, and every sentence of
THM-0117 still holds — the credential STS returns still carries its stated expiry, is still
never extended, and is still obtained once between concurrent callers.

### Why the residue matters more than the half that landed

`a_missing_token_file_fails_closed_rather_than_falling_back_to_the_environment` is the
sharpest control in the record. Its assertion is that **nothing was exchanged and nothing
was substituted** — no promotion of whatever `AWS_ACCESS_KEY_ID` the process environment
happens to hold to the credential source for this workload. That is an identity-provenance
claim about which principal the proxy signs as, and no ratified theorem in this tree states
it. `an_empty_token_file_is_refused_rather_than_posted` is the same rule for the mount that
exists but has not been populated, which is the ordinary startup race under IRSA.

### Kept as ONE proposition rather than split

All three are about the same value at the same seam: the file at
`AWS_WEB_IDENTITY_TOKEN_FILE` is the pod's only credential, and it is read at the moment of
use. Re-reading, refusing an absent one and refusing an empty one are the three ways that
single rule is stated, and all three fail the same way — by the exchange proceeding under
something other than the token the mount currently holds.

**Severity:** `critical`.
