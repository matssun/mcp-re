<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-114 residue — R6 ratification packet: what a Cloud KMS token refusal costs

**Disposition:** R2 in part, R6 for the residue. Fifteen of NP-114's twenty-three controls
landed as `unit://proxy.gcp_metadata_token_lifetime` under THM-0117, falsifier
`M344-proxy-the-reuse-floor-extends-a-stated-token-lifetime`. One more became NP-192. Seven
rows remain; NP-114's `[[proposition]]` entry and record stay in place, with the title
narrowed to the half that remains and the severity corrected from `critical` to `high`.

## The lane, measured first, because it decides everything after it

| selection | controls |
|---|---|
| `cargo test -p mcp-re-proxy --lib -- --list` | 1498, of which **0** are `gcp_kms_keysource::` |
| `cargo test -p mcp-re-proxy --features gcp_kms_keysource --lib -- --list` | 1565, of which **39** are `gcp_kms_keysource::` |

All twenty-three of this record's controls are in the second list and none in the first. The
default lane exits **0** having compiled every one of them out of existence, so a battery
declared without `test_features = ["gcp_kms_keysource"]` would be the false green this
repository's standing rule names. THM-0117's own scope says so:

> TWO LANES. The AWS acquirer exists under `aws_kms_keysource` and the metadata acquirer
> under `gcp_kms_keysource`; neither is in the default lane.

The falsifier was demonstrated in that lane, not beside it: `M344` reports
`a_stated_expiry_is_never_extended_by_the_reuse_floor` and
`a_stated_lifetime_is_never_read_as_an_unestablishable_one` **FAILED**, and a control the
lane did not compile cannot be observed failing — `verify-mutations`' adjudicator reports an
absent expectation as a measurement failure rather than a pass.

## What landed, and the clauses that contain it

THM-0117, statement, verbatim:

> A credential acquired from AWS STS or from the GCE/GKE metadata server carries the expiry
> its issuer stated, and that expiry is never extended: neither by the reuse floor that
> keeps an unreadable one from being re-exchanged on every call, nor by a stated value
> beyond the real session ceiling, which is truncated to it.

Contains `a_token_response_yields_the_credential_and_its_lifetime` and
`a_stated_expiry_is_never_extended_by_the_reuse_floor`.

THM-0117, statement, verbatim:

> An expiry that CANNOT be read — absent, unparseable, or a lifetime the issuer did not
> establish — is treated as already expired, never as unlimited.

> The credential is still reused briefly rather than re-exchanged per call, and that brief
> window is a floor on churn rather than an extension of a stated lifetime.

Contains `a_stated_lifetime_is_never_read_as_an_unestablishable_one`,
`stated_expiry_reports_an_unestablishable_lifetime_as_a_fact`,
`an_unreadable_expires_in_is_reused_briefly_rather_than_refetched_every_call` and
`an_unreadable_expires_in_is_reused_when_every_clock_read_differs`.

THM-0117, statement, verbatim:

> Concurrent callers perform ONE exchange between them, a failed exchange is not repeated by
> every waiter, and the cool-off after a failure expires on its own and is cleared by a
> success.

> A clock that steps backwards does not extend it.

Contains `concurrent_callers_perform_one_metadata_fetch_between_them`,
`a_failed_metadata_fetch_is_not_repeated_by_every_waiter`,
`the_failure_cool_off_expires_and_a_success_clears_it`,
`a_backwards_clock_step_does_not_extend_the_failure_cool_off` and — as the boundary of *ONE
exchange between THEM* — `two_token_sources_do_not_share_a_cache_or_a_flight`.

Three land as the metadata twins of controls already inside THM-0117's own owner unit
`proxy.aws_sts_credentials`, which is *existing subordinate authority* rather than a
widening of the claim:

| metadata control | the AWS control already in the battery |
|---|---|
| `an_empty_or_absent_access_token_is_refused` | `an_empty_credential_field_is_refused_rather_than_signed_with` |
| `the_failure_cool_off_must_outlast_the_network_timeout`, `the_unknown_expiry_floor_must_outlast_the_refresh_margin` | `the_sts_windows_must_outlast_what_they_are_measured_against` |
| `a_poisoned_token_lock_still_serves_tokens` | `a_poisoned_credential_lock_still_serves_credentials` |

**Why a twin and not an R1 into `proxy.gcp_kms_adapter`.** That unit declares the same single
path and is already in THM-0117's `supported_by`, so an append would have been mechanically
admissible. It is refused on the proposition: its description is *"The GCP Cloud KMS Ed25519
response signer"* and every clause of it is about the key version, the advertised public key
and the emitted signature. How the bearer credential that authorizes those calls is acquired
and how long it may be reused is a second authority in the same file, and ADR-069 §5 forbids
widening a unit to swallow it. No `paths` was widened and no description amended.

## The residue

**7 controls**, `mcp-re-proxy`, rust unit test, `gcp_kms_keysource` lane, carrier
`mcp-re-proxy/src/gcp_kms_keysource.rs`:

- `lib#gcp_kms_keysource::tests::a_cloud_kms_401_discards_the_token_and_retries_once`
- `lib#gcp_kms_keysource::tests::a_cloud_kms_403_does_not_discard_a_valid_token`
- `lib#gcp_kms_keysource::tests::a_persistent_401_stops_costing_a_refetch_per_call`
- `lib#gcp_kms_keysource::tests::a_401_a_fresh_token_fixes_is_retried_every_time`
- `lib#gcp_kms_keysource::tests::only_a_token_refusal_with_a_token_to_discard_costs_a_second_call`
- `lib#gcp_kms_keysource::tests::invalidating_a_token_another_thread_has_already_replaced_is_a_no_op`
- `lib#gcp_kms_keysource::tests::invalidating_the_metadata_source_forces_the_next_call_to_re_fetch`

### Why THM-0117 does not reach them

THM-0117, scope, verbatim:

> THE LIFETIME, NOT THE CREDENTIAL'S POWER.

> NOT A CLAIM ABOUT THE ISSUER. That the issuer's stated expiry is honest, and that the
> token it returns is the one it minted, are the provider's; what is established is that
> this implementation never reads more lifetime out of an answer than the answer states.

A 401 or a 403 is the CONSUMER's runtime verdict on a credential whose stated lifetime has
not lapsed. Nothing in the statement is about a credential being refused while still inside
its window, about how many calls that refusal may cost, or about which cached value an
eviction is allowed to remove. Reading *"never extended"* to cover *"discarded when
refused"* would be the stretch this campaign exists to refuse: the operational test settles
it, because every clause of THM-0117 still holds under an implementation that never evicts
on a 401 at all.

### Why the availability route is closed in both directions

THM-0117 does admit availability conjuncts, and it names exactly which:

> The single-flight and cool-off conjuncts are availability with a security edge: a failed
> exchange repeated by every waiter is a self-inflicted flood against the credential
> authority, and a cool-off a backwards clock step can extend is a local outage a time
> correction creates.

Two, and these seven are neither. The admission is a closed list, not a licence.

The other direction is closed by review **RR-002**, which forbids creating or widening any
`not-evidence` family whose admission test turns on availability, throughput, concurrency,
latency, a resource ceiling or scheduling. The admission test here would be exactly that —
*how many Cloud KMS calls and metadata round trips a refusal costs under an unauthenticated
peer's flood* — so no family may absorb them. A proposition is the only honest place left,
and that is where they stay.

### A correction to the brief, and it enlarges the residue

The work package said *two* of NP-114's twenty-three clauses are availability, naming *a 403
does not discard a valid token*. Measured against the tree there are seven controls in this
authority. The brief counted clauses of the record's prose statement; the registry holds
controls, and the 401/403 sentence of that statement expands into five controls driving
`UreqGcpClient::with_token_retry` plus two driving `MetadataServerTokenSource::invalidate`.
The two sides are one authority: the source-side eviction exists only because the client
evicts on a refusal, and `invalidating_a_token_another_thread_has_already_replaced_is_a_no_op`
is stated in its own doc comment as the fix for *"N refusals into N serialized metadata
fetches"*.

### Kept as ONE proposition rather than split

All seven answer one question — *what does a token refusal cost, and what does it discard* —
and all seven fail in one of two directions of the same bound: a refusal that discards too
much (the 403 arm, the stale-thread eviction) or one that costs too much (the persistent-401
arm, the no-token-to-discard arm). `a_401_a_fresh_token_fixes_is_retried_every_time` is the
positive control the file's own comment pairs with `a_persistent_401_stops_costing_a_refetch_per_call`.
Splitting them would produce records naming one direction of one bound.

**Severity:** `high`.
