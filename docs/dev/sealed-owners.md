# Sealed owners and the composition root

The rules this implements are in [`CLAUDE.md`](../../CLAUDE.md) — **R-SEAL** and
**R-COMPOSE**. This file records which owners are sealed, what each one projects, and how
to seal the next one.

> **Scope.** This document owns the **current** sealed state: which owners are sealed
> today, what each projects, which are deliberately unsealed and why, and the procedure for
> the next one. The **target** design for each authority domain — intended hierarchy,
> visibility, theorem and test inventory, implementation map — lives in
> [`docs/architecture/components/`](../architecture/components/). Each blueprint's *Known
> deviations* section is the diff between the two. Neither document restates the other's
> tables (ADR-MCPRE-061 §13.1).

## The failure mode being removed

> The invariant is enforced at a construction site, but the constructed value does not own
> the invariant.

Validation existed at every one of these owners. The defect was that correctness depended
on remembering where and how to construct the value — so the system could only say *if you
possess this value, and everyone constructing it remembered the rules, the invariant
probably holds*, where it needs to say *if you possess this value, my invariant holds*.

`ReplayState` stated the gap in its own doc comment:

> *"Outside this crate the only way to obtain a value is `classify_and_validate`, so a
> caller cannot hand itself a `SharedRedis` whose quorum parameters no validator ever
> saw."*

Every consumer of `ReplayState` is **inside** this crate. The seal held against none of
them.

## The mechanism

`#[non_exhaustive]` and `pub(crate)` bind only *other crates*. An owner's consumers —
`app.rs`, `startup_plan.rs`, `cli.rs`, `http_profile_serve.rs`, `tls_plane.rs`,
`serving_capabilities.rs` — all live in `mcp-re-proxy`, the same crate as the owners. The
only lever that works at that distance is **module privacy**:

```rust
pub struct ReplayState { kind: ReplayKind }   // public type, private field
enum ReplayKind { … }                          // private to the owner's module
```

Consumers then reach the state only through named projections on `impl ReplayState`.

## Sealed owners

| owner | module | projections |
|---|---|---|
| `ReplayState` | `config_state/replay.rs` | `materialization_plan()`, `durability_tier()`, `required_feature()` |
| `ReplayPlan` | `config_state/replay.rs` | `store() -> PlannedStore<'_>`, `tier()`, `needs_control_runtime()` |
| `ContinuationControlState` | `config_state/continuation_control.rs` | `continuation_plan()`, `is_shared()` |
| `ContinuationControlPlan` | `config_state/continuation_control.rs` | `shared_store() -> Option<&str>`, `needs_control_runtime()` |
| `AdmissionState` | `config_state/admission.rs` | `enforced() -> Option<EnforcedAdmission<'_>>`, `is_enforced()` |
| `RetentionState` | `config_state/evidence.rs` | `directory() -> Option<&str>`, `is_on()` |
| `McpTransportContractState` | `config_state/mcp_transport_contract.rs` | `enforced_versions() -> Option<&[String]>`, `is_enforced()` |
| `TrustRevocationState` | `config_state/trust_revocation.rs` | `epoch_source() -> Option<EpochSource<'_>>`, `reload_cadence()`, `tier()`, `declared_window_secs()`, `push_channel_is_inert()`, `has_networked_epoch()` |
| `CrlRevocationState` | `config_state/transport.rs` | `client_revocation_plan()`, `paths()`, `reload_cadence_secs()`, `is_enforced()` |
| `ClientRevocationPlan` | `config_state/transport.rs` | `paths()`, `reload_cadence_secs()`, `is_enforced()` |
| `TlsCustodyState` | `config_state/tls_custody.rs` | `exported_key_path()`, `delegated_pkcs11_label()`, `delegated_aws_key_id()`, `delegated_gcp_key_version()`, `is_delegated()` |
| `CustodyState` | `config_state/custody.rs` | `material() -> CustodyMaterial<'_>`, `disk_secret_paths()`, `locators_are_filesystem_paths()`, `is_non_exporting_device()` |
| `FreshnessWindow` | `config_state/freshness.rs` | `verifier_skew_secs()`, `replay_retain_until()`, `verifier_accepts_until()` |
| `TrustDocumentSource` | `config_state/trust_document.rs` | `path()` |
| `ClientCredentialWindow` | `config_state/client_credential_window.rs` | `cert_lifetime()`, `connection_age()`, `exposure_window()` |
| `ShardTopologyRequest` | `config_state/topology.rs` | `shards()`, `workers_per_shard()`, `shards_or_auto()`, `workers_per_shard_or_auto()` |
| `TrustPlan` | `startup_plan.rs` | `revocation()`, `document_path()`, `response_kid()`, `reload()`, `epoch()` |
| `TlsListenerSecurityState` | `tls_listener_state.rs` | `epoch()`, `build_exported_key_config()`, `build_delegated_config()`, `build_delegated_resolver_config()` |

A plan produced by an owner lives **with that owner**, not in `startup_plan.rs`.
`startup_plan` re-exports it. The plan is the owner's projection of its own validated
state, so building it in the planner was the planner restating the owner's semantics.

### `TlsListenerSecurityState` — the projections ARE the operations (MCPRE-137)

Every other owner above projects FACTS. This one mostly projects OPERATIONS, and the
difference is the point.

The invariant is a relation between four things — the trusted client CAs, the
authentication epoch they digest to, the session cache tagged with that epoch, and the
handshake-signature budget — all of which must belong to one listener and survive its
`ServerConfig` rebuilds together. A fact projection (`client_ca()`, `session_store()`) would
hand a caller the terms of the relation back as independently passable arguments, which is
exactly [the split this document forbids](#a-relation-that-is-validated-must-not-be-split-back-into-its-terms).
That is not hypothetical: it is what the code did. A rebuild read

```rust
builder(state.client_ca.clone(), …, &state.resumption)
```

— two arguments carrying one relationship, related by nothing but the call site.

So the build is a **method on the state**. The anchors and the store are never separately
obtainable, and `mcp-re-proxy/src/tls.rs` retains only `pub(crate)` **resumption-free**
assembly (`assemble_exported_key_config`, `assemble_delegated_config`): a config it returns
has no session cache installed at all, and the only thing that installs one is the owner's
private `bind_resumption`.

**What the seal covers, precisely.** `EpochBoundSessionStore` is still publicly
constructible — `tests/integration/tls_epoch_resumption_test.rs` builds one to drive real
rustls handshakes, which is the store's own acceptance evidence and worth keeping. A store
in isolation is not an illegal value. The illegal value was *a serving config whose cache is
unrelated to the anchors its verifier was built from*, and that is what is now
unconstructible: no public path installs a store on a config.

**The operational test.** Delete the pairing check — there is none to delete, which is the
answer. The census (EX-004) found the check was a naming convention: builders whose names
differed by a `_resuming` suffix differed in whether the epoch was a live lever. Both
one-shot builders are gone; there is one way to build, and it goes through the state.

`tools/verification/verify-mutations` probes it: creating a store per build, or deriving the
epoch from anything but the owner's anchors, each turns a declared control red
(`T01`, `T02` in `verification/policy/mutation-probes.toml`).

**What it deliberately does not project.** No epoch setter. Within a listener the anchors
are immutable, so the epoch is a construction-time constant; a mutation seam would advertise
a lifecycle production does not implement. See the module note for the three propositions
this owner keeps apart.

## A composition may combine owned facts; it may not make them replaceable again

`TrustPlan` is the first entry above that is a **composition**, not a classifier's output,
and it is where the rule needed stating. It combines three independently owned facts — the
revocation posture, the trust document, and the shared epoch mechanism — which is exactly
what a composition is for. What it must not do is hand them back out as a public bag,
because then the pairing holds only for as long as every construction site takes all three
from one deployment.

Two things make the combination stick:

- the representation is private and `from_validated(&ValidatedDeployment, …)` is the only
  producer, so both owned facts come from one accepted deployment by construction;
- **`reload` is not a field.** It is derived from the revocation state on demand, because
  that state is the authority on how often the document is re-read. A stored copy is a
  second value that can disagree with the first — and it already had: the fixture in
  `trust_plane`'s tests paired a 30s reload with a state carrying 5s, and asserted the
  wording of an operator-facing line no deployment prints. Sealing surfaced it; deriving
  removed the possibility.

The same shape settled a second question. `ReadOnceAtStartup` is reachable only under
bounded-cache — `Live` and `Push` name a cadence in their Required column — so the test
that asserted the frozen-store wording for all four postures was describing deployments
layer A refuses. It now asserts it where it is reachable.

## A relation that is validated must not be split back into its terms

`ClientCredentialWindow` is the second composition, and it is where asking the R-SEAL
question found a live defect rather than a latent one.

Relation X5 said, in its own refusal text, *"a connection would outlive the credential that
authenticated it"*. It compared `max_connection_age` against the ceiling **constant**, never
against the configured `max_client_cert_lifetime`. So this deployment was accepted:

```text
--max-client-cert-lifetime 600 --max-connection-age-secs 3000
```

Both halves are individually inside the ceiling; together they mean a connection serves
requests for forty minutes after the certificate that authenticated it expired, while the
startup transcript reports `exposure_window=600s`. `TlsPlan` then carried the two values on
as `Option<Duration>` fields under a doc comment stating their relation "was settled at
layer A" — the relation was stated three times and checked nowhere.

The owner holds both durations and enforces the relation at construction, so
`exposure_window()` is a claim the value can make rather than a number picked from two.
Making them non-optional also deleted two tests: the `unbounded` and `none` rendering arms
were only reachable for a configuration the boundary refuses, so the tests asserting their
wording were describing a transcript no proxy prints.

## Borrowed views

Where a consumer must still branch — materialization has to pick a backend client —
the owner hands out a **borrowed view**: `PlannedStore<'a>`, `CustodyMaterial<'a>`,
`EnforcedAdmission<'a>`, `EpochSource<'a>`.

A view is matchable, so selecting a backend still reads naturally, and borrowed, so it is a
way to READ a state and never a way to assemble one. Holding a `CustodyMaterial` does not
let you build a `CustodyState`.

## What sealing found

- `ReplayPlan::Redis { url, tier: Linearizable }` was an ordinary expression in any module.
  The startup audit line would have advertised a durability guarantee no store implements.
- `AdmissionState`'s two enforcing variants carried identical fields, and the gate was
  built by destructuring both — so the enforcement level and the authority key it enforces
  under were paired only by the caller doing it correctly.
- `replay_plane`'s tests materialized `ReplayPlan::Redis { tier: SingleStoreFailClosed }`,
  a tier `classify` refuses. The "backend not compiled in" refusal was being proven against
  a plan no configuration can reach.
- `McpTransportContractState::Enforced { versions: vec![] }` was constructible;
  `is_enforced()` called it true and the request path had nothing to check against.
- `key_files_read_from_disk` in `app.rs` reconstructed a security answer — which secrets
  land on local disk, for a permissions floor — out of two owners' representations.

## Owners that are not sealed, and why that is the right answer

Two of this campaign's owners have public representations, deliberately.

`KeyFileAccessPolicy` and `DeploymentTopology` are two-variant enums where **both variants
are legal deployments**. There is no illegal inhabitant to exclude, so `X { kind: Kind }`
would add ceremony and no theorem. What they own is not a constructible invariant but a
RULE: `policy.violation(mode, gid, process_gids)` answers whether a file posture is refused,
where the consumer used to receive a `bool` and re-derive three conditions around it. The
question a value like this answers is *whose rule is this?*, not *which inhabitants exist?*

`ShardTopologyRequest` IS sealed, and the difference is instructive: `0` there is not a
count but a deferral, so a public `usize` is a value every reader has to remember to
interpret — and the composition root was the reader remembering it.

## Where sealing buys nothing

Privacy is only worth adding when **the owner is the sole legitimate producer**. Where a
trait or closure seam lets code outside the module produce the value, a private field
forces a public constructor, and `X::new(a, b, c)` is exactly as permissive as `X { a, b,
c }` — the same arguments, the same absence of checking, one more line of ceremony.

`ResolvedActor` (`mcp-re-http-profile/src/block.rs`) is the example. It looks like a
verdict — *the trust layer authorized this actor for this slot* — but the trust seam is a
resolver supplied by the caller, so every in-process and test resolver is a legitimate
producer. The invariant genuinely does not belong to the type; it belongs to the seam's
contract. Sealing it would relocate the ceremony without moving the authority, which is
the same mistake as the wide composition object.

The question to ask before sealing: **if this value is illegal, whose bug is it?** If the
answer is "the owner's classifier", seal. If it is "whoever implemented the seam", the
invariant is a contract on the seam and privacy is theatre.

### A proved postcondition outranks a seal

`VerifiedAdmission` (`mcp-re-http-profile/src/admission.rs`) is the strongest-looking
target in the tree: it is the VERDICT of the admission check, and all five fields are
`pub`, so `VerifiedAdmission { status: Admitted, .. }` is an ordinary expression in any
crate that depends on this one. **It must stay that way.** Measured, not assumed — the seal
was written, and `verify-verus` reported:

```
error: external_type_specification: private fields not supported for transparent
       datatypes (try 'external_body' instead?)
   --> mcp-re-http-profile/src/verus_std_specs.rs:100
```

`pub(crate)` does not satisfy it either; Verus requires the fields to be `pub`. The only
way to seal the type is `external_body`, which makes the datatype OPAQUE — and this unit's
postconditions are stated over exactly those fields:

```
&&& v.admission_id@ == binding.admission_id@
&&& v.admitted_actor@ == presenter_actor_id@
&&& !v.degraded ==> (… binding.generation == state.generation …)
```

Opaque fields make those conjuncts unstatable, so sealing would cost THM-0003, THM-0004,
THM-0005 and THM-0006 the ability to say anything about the verdict's contents.

The trade resolves on evidence strength, not on tidiness. A seal says *this value cannot be
assembled by hand*. The proof says *every value this function returns satisfies these
properties, over all executions* — including that the admitted actor IS the presenter,
which is the conjunct that catches a refactor dropping the presenter check. The proof is
the stronger claim and it subsumes what the seal would defend against on the path that
actually runs. What the seal would still add — that no one FABRICATES a verdict instead of
obtaining one — is a real but different property, and it belongs to review-unit membership
in the assurance graph rather than to field privacy.

With the seal reverted, `verify-verus` reports PASS over 6 units. **Do not re-seal this type
without a plan for the four theorems.**

### The same trade, measured a second time

`CryptographicFloorVerifiedRequest` and `VerifiedMcpRequest`
(`mcp-re-http-profile/src/verified_request.rs`) were written with `pub(crate)` fields and a
crate-boundary seal — every consumer of these products lives in another crate, so unlike
the proxy's owners the boundary would have been real. `verify-verus` returned the same
error, twice, and then a second one when only the outer type was opened:

```
error: cannot use function `…VerifiedMcpRequest::profile_id` which is ignored because it
       is either declared outside the verus! macro or it is marked as `external`.
```

Verus cannot call the accessors from verified code either, so the verified body must read
fields — which requires BOTH products transparent, not just the one the postcondition
mentions. Both are now `pub`, and `prepare_http_dispatch` reads `verified.floor.nonce`
rather than `verified.nonce()` for that reason.

What the split still buys is not a seal and does not depend on one: the floor and full
propositions are different TYPES, so a consumer requiring the full one cannot be handed the
floor one. That is enforced by the compiler on every path, which is more than the runtime
`audience_hash` check it replaced ever gave.

The proof got stronger in the exchange. THM-0009's postcondition used to read

```
verified.request_block matches Some(block) ==> (block.continuation is Some ==> …)
```

— vacuously true for any product whose block was absent, which is exactly a floor-verified
request. The parameter type now excludes those, so the obligation is stated
unconditionally. `verify-verus` reports PASS over 6 units with the same 15 verified
obligations in `mcp-re-http-profile` as before, so the strengthening is not paid for by a
weaker proof somewhere else.

## Sealing the next owner

1. Make the representation private: `pub struct X { kind: XKind }`, `enum XKind` private.
2. `cargo check -p <crate> --all-targets`. **The error list is the consumer set.** It is
   the measurement; greps and audit findings are not.
3. For each error ask *what does this consumer actually need to know?* The answer is
   normally much narrower than the fields it was destructuring. Name that projection.
4. Where the consumer must branch, give it a borrowed view rather than the representation.
5. Tests that built the state as a literal go through the owner's classifier — see
   `config_state::test_support`. A literal can express combinations the classifier refuses;
   a fixture built through it cannot.
6. State the theorem the seal makes available: not *this constructor checks X* but *every
   inhabitant satisfies X*.

Never work around a compile failure with `#[non_exhaustive]`, a runtime re-check, or a doc
note. The failure is the boundary detector; those consume the signal.

## Property 1 needs no separate witness here

*Illegal state cannot be publicly constructed* is the first completion property, and the
obvious way to evidence it is a compile-fail test. **For these owners that would prove the
wrong thing.**

A `trybuild` case, and equally a ```compile_fail doctest, compiles a standalone file as a
SEPARATE crate. It can only witness the crate boundary — that a downstream crate cannot
construct the value. The consumers that mattered here are all *inside* `mcp-re-proxy`, and
the crate boundary already held against them before any of this work: that is exactly what
`ReplayState`'s "outside this crate" doc comment claimed, while the seal held against none
of its actual callers.

The in-crate seal is instead enforced **continuously, by every build**. With the
representation private to the owner's module, the violating expression cannot be written
anywhere in the crate and still compile — there is no file that could hold the negative
case, because such a file would not build. `cargo check -p mcp-re-proxy --all-targets`
passing IS the witness, and it is a stronger one than a single pinned case: it re-proves
the property over the whole crate on every run rather than over one example.

What a compile-fail lane would still be worth: pinning the *crate*-boundary claims for
types re-exported to SDK or integration consumers. That is a narrower property than the one
this campaign was about, and it is not a prerequisite for any owner above.

## Open

Nothing structural. The remaining owners (`ChannelBindingState`, `DelegatedSigningFacts`,
`ServerIdentityFacts`, `AuditState`, `VerifiedContextState`) carry no representation a
consumer reads: measured at 0 external destructuring sites each, and the fieldless ones
have no illegal inhabitant to exclude.
