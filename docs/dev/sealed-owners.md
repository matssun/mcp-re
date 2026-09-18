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
| `ChannelCredentialCustodyState` | `config_state/channel_credential_custody.rs` | `exposure()`, `material()` |
| `CustodyState` | `config_state/custody.rs` | `material() -> CustodyMaterial<'_>`, `disk_secret_paths()`, `locators_are_filesystem_paths()`, `is_non_exporting_device()` |
| `FreshnessWindow` | `config_state/freshness.rs` | `verifier_skew_secs()`, `replay_retain_until()`, `verifier_accepts_until()` |
| `TrustDocumentSource` | `config_state/trust_document.rs` | `path()` |
| `ClientCredentialWindow` | `config_state/client_credential_window.rs` | `cert_lifetime()`, `connection_age()`, `exposure_window()` |
| `ShardTopologyRequest` | `config_state/topology.rs` | `shards()`, `workers_per_shard()`, `shards_or_auto()`, `workers_per_shard_or_auto()` |
| `TrustPlan` | `trust_plan.rs` | `revocation()`, `document_path()`, `response_kid()`, `reload()`, `epoch()` |
| `TlsListenerSecurityState` | `tls_listener_state/` (a module TREE) | `epoch()`, `build_exported_key_config()`, `build_delegated_config()`, `build_delegated_resolver_config()` |
| `PeerIdentityValue` | `communication_assurance/peer_identity_value.rs` | `as_str()` |
| `CertificatePeerIdentityEvidence` | `communication_assurance/certificate_peer_identity_evidence.rs` | `value()`, `source()` |
| `Ed25519PublicKeyValue` | `communication_assurance/ed25519_public_key.rs` | `raw_point()`, `spki_der_for_point()` (associated) |
| `CredentialPublicKeyEvidence` | `communication_assurance/credential_public_key_evidence.rs` | `key()` |
| `CryptographicSigningKeyEvidence` | `communication_assurance/signing_key_evidence.rs` | `key()` |
| `CredentialKeyCorrespondenceFacts` | `communication_assurance/credential_key_correspondence.rs` | `corresponding_key()` |
| `DelegatedCertResolver` | `delegated_tls/resolver.rs` | `budget()`, `materialize()` (the only constructor) |
| `P256Point` | http-profile `scitt.rs` | `verifying_key()` — the representation IS the decoded key |
| `ScittServiceTrustPin` | http-profile `scitt.rs` | `verification_key()`, `kid()`, `service_identifier()`, `leaf_profile()`, `position_profile()`, `resolve()` |
| `EvidenceCommitment` | http-profile `scitt.rs` | `corresponds_to()`, `is_complete_record()`, `commits_to_verified_evidence()`, `identifies_a_submission()`, `chain_label()` |

A plan produced by an owner lives **with that owner**, not in `startup_plan.rs`.
`startup_plan` re-exports it. The plan is the owner's projection of its own validated
state, so building it in the planner was the planner restating the owner's semantics.

`TrustPlan` was the last entry still contradicting that rule, and MCPRE-148 moved it to
`trust_plan.rs` beside the rest of the trust subtree. Two details of the move are worth
keeping:

- **`TrustEpochPlan` deliberately did NOT move.** It is shared with `SigningPlan`, so
  relocating it into a trust-only module would make trust the authority over a fact
  signing also consumes — the CF-09 defect this tree already closed. It stays in
  `startup_plan` as the shared composition input, and `TrustPlan` takes it as an argument.
- **The move made the seal bite.** A `startup_plan` test was reading `trust.epoch` and
  `trust.response_kid` directly; once the fields were private to the owner's module that
  stopped compiling, and the test now relates the two plans through `epoch()` and
  `response_kid()`. The compile error was the boundary detector working.

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

So the build is a **method on the state**, and — the part the first attempt got wrong — the
seal is the module TREE, not one file:

```text
tls_listener_state            the only construction authority (pub)
  ├── assembly                what the serving config IS
  ├── auth_epoch              the epoch VALUE is pub; the store and the mutable
  │                           wrapper are pub(super)
  ├── client_verifier         what a valid client certificate is
  ├── resumption_binding      whether a stored session is still a shortcut
  └── resumption_acceptance   the real-handshake controls, inside the boundary
```

The first version left `assemble_*` and `epoch_bound_resumption` `pub(crate)` in `tls.rs`
and `tls_auth_epoch` a `pub` sibling module, then claimed the pairing was unconstructible.
It was not: any module in the crate could assemble a verifier over anchors A, build a store
over epoch B, and pair them. **`pub(crate)` seals against nobody when every consumer lives
in the crate** — the rule this document already states, applied to itself. The subordinates
moved INTO the owner rather than being described as subordinate.

**What the seal covers, precisely.** No path outside the tree can build a store, install
one, or assemble a config to install it on. The residual limit is foreign:
`rustls::ServerConfig::session_storage` is a public field of a type this project does not
own, so code holding a config can overwrite it. What is unconstructible is BUILDING a
mispaired config — and construction is where the owner is the sole legitimate producer,
which is the test this document sets for whether privacy is worth adding.

**The acceptance test moved rather than the interface widening.** The real-handshake
ADR-055 controls used to be an integration test reaching the store through the crate's
public surface, which would have forced the subordinates to stay `pub`. That is §8
question 8 — a production interface widened by a test — so the TEST moved inside the
boundary, to `tls_listener_state/resumption_acceptance.rs`.

**The operational test.** Delete the pairing check — there is none to delete, which is the
answer. The census (EX-004) found the check was a naming convention: builders whose names
differed by a `_resuming` suffix differed in whether the epoch was a live lever. Both
one-shot builders are gone; there is one way to build, and it goes through the state.

`tools/verification/verify-mutations` probes all four conjuncts, each turning a declared
control red (`T01`–`T04` in `verification/policy/mutation-probes.toml`): a session store
created per build, an epoch derived from anything but the owner's anchors, an enabled
stateless ticketer that would resume outside the store entirely, and a signing budget
created per delegated rebuild. The fourth exists because the budget was named among the
things "established together" while nothing asked what breaks if a rebuild recreates it —
a conjunct asserted in prose on a V0 unit.

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
startup transcript reports `exposure_window=600s`. `ChannelEstablishmentPlan` then carried the two values on
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

- `PeerIdentityValue` (ADR-MCPRE-063 Slice 1) is the first owner here whose invariant was
  previously held by *two* validating call sites that agreed. `extract_identity` and the
  trusted-ingress header path both called `validate_asserted_identity_value`, correctly, at
  every site — and correctness depended on the next provenance remembering to. Deleting
  either call brought an invalid identity into existence; deleting the check inside the
  owner now cannot, because there is no other way to obtain the type. This is the R-SEAL
  quantifier difference in its purest form: two `for this call site` facts became one
  `for every inhabitant` fact, and no behaviour changed.
- `DelegatedCertResolver` (Slice 3) is the first sealed owner here that is a CONCRETE
  RUNTIME VALUE rather than a fact. What its private field holds is a construction witness
  — `CredentialKeyCorrespondenceFacts`, never read and never projected — and what that buys
  is that possession of the resolver proves its credential and signer corresponded. The
  assembling constructor is private and demands the witness, so the usual weakening ("skip
  the check and construct anyway") does not compile. The category worth noticing: where a
  seal makes invalid construction unrepresentable, the evidence is the visibility boundary
  plus compilation of the consumer closure — not a mutation probe, and certainly not a
  bypass seam added so a probe could exist. Mutation moves to the supplying invariant.
- `CredentialKeyCorrespondenceFacts` (Slice 2) shows what a sealed RELATION result looks
  like. It projects ONE key, not the credential's and the signer's separately — after
  correspondence holds there is only one key, and offering two accessors would invite a
  consumer to compare them again, re-deriving the fact the value already carries. The
  refusal is likewise a unit struct carrying no key material: naming the expected key in an
  error invites exactly the comparison the authority exists to own.
- `CertificatePeerIdentityEvidence` seals PROVENANCE, not the value. Its `source` field was
  a public field on `TransportIdentity`, so any module could pair an identity read from one
  certificate field with a source naming another. Nothing downstream could detect it: this
  field is the only record of where an identity came from. The mutation probe for it
  (`M27`) turns two controls red — which is what a field that was previously unprotected
  looks like once it has an owner.

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

#### The same measurement a second time — `ResolvedTransparencyService` (MCPRE-155)

EX-004 question 11 named it: its own doc says the key and the profiles *"travel together"*
while all three fields were `pub`, so a caller could pair a pinned key with a leaf profile
nobody pinned. The seal was attempted and the answer came out the same way as
`ResolvedActor`'s. `verify_receipt_offline` takes the service through a
`Fn(&str) -> Option<ResolvedTransparencyService>` seam, and there is a real second producer
with no pin behind it — the in-process `PrototypeTransparencyService`, which the conformance
corpora are built from.

What was done instead, and what it is worth: the fields are private and there are two NAMED
producers, `pinned` (private, reached only through `ScittServiceTrustPin::resolve`) and
`stated`, whose name is its contract — *the caller is asserting these; no operator pinned
them*. That buys legibility at every call site, not unconstructibility, and the record says
so rather than claiming a seal. It is the third measurement of this rule and the first where
the seam's second producer is a shipped type rather than a test.

#### Where the seal DID hold, in the same file

Three of EX-004's four question-11 types were sealable and are sealed:

- **`P256Point`** (new). `CoseVerificationKey::EcdsaP256 { x, y }` let a struct literal name
  two 32-octet numbers that are not a point on the curve, while the variant's name said
  otherwise; `from_ec2_p256` checked and then threw the parsed key away, so every
  verification re-decoded. The representation is now the DECODED `VerifyingKey`, the decode
  is the proof, and the §11 operational test passes: delete the check and an invalid value
  is still unconstructible, because the check *is* the constructor.
- **`ScittServiceTrustPin`**. The illegal state was the `(algorithm, public_key)` PAIR — an
  `EdDSA` pin carrying an `ES256` `y`. It was constructible and refused only if somebody
  called `verification_key`. Deserialization now goes through a private `PinDocument` and
  `TryFrom`, so the pair is checked on the way in and `verification_key` is infallible. The
  seal is on the pin, not on `PinnedPublicKey`: a key is not illegal, a mislabelled pairing
  is.
- **`EvidenceCommitment`**. Two producers, both named — `from_reconstruction` (derived from
  one `ChainReconstruction`, so the label and the handles cannot be chosen separately) and
  `Deserialize` (a received CLAIM, trusted only after the issuer's `COSE_Sign1` verifies).
  The third way — assembling one field by field, so a `complete` label could carry an
  unrelated call's handles — is gone.

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

## Property 1 needs a witness, and this document was wrong about what supplies it

**Corrected 2026-09-17 under ADR-MCPRE-068 §12.1, ratified by the owner.** What follows
first is the claim this section used to make, because the correction is only legible beside
it.

*Illegal state cannot be publicly constructed* is the first completion property. This
document argued that no separate witness was needed: a `trybuild` case, and equally a
```compile_fail doctest, compiles a standalone file as a SEPARATE crate, so it can only
witness the crate boundary — that a downstream crate cannot construct the value. The
consumers that mattered here are all *inside* `mcp-re-proxy`, and the crate boundary already
held against them before any of this work: that is exactly what `ReplayState`'s "outside
this crate" doc comment claimed, while the seal held against none of its actual callers.
That part is right, and it is why the in-crate case needs its own mechanism.

The conclusion drawn from it is not. This document went on to say that with the
representation private, *"there is no file that could hold the negative case, because such a
file would not build"*, and therefore that `cargo check -p mcp-re-proxy --all-targets`
passing **is** the witness — a stronger one than a single pinned case, re-proved over the
whole crate on every run.

**It is not a witness at all.** It proves the current tree contains no illegal construction;
it cannot go red when the boundary is deleted. Make the owner's field `pub(crate)`, or add a
public constructor taking the same arguments unchecked, and the build still passes every
time — because nothing in the tree ever attempts the construction. **An absence of
counterexamples in a corpus nobody wrote a counterexample into is not a refusal.** A control
whose green cannot be turned red by deleting the property it claims to protect is the
repository's recurring failure class, and this was an instance of it.

The premise about the missing file is what makes the real mechanism necessary rather than
optional: the negative case cannot live in this crate, so it lives in a **scratch copy**.
ADR-MCPRE-068 Phase 0B builds that lane, `structural://`, with two probe kinds —
`crate-boundary-compile-fail` over the existing `compile_fail` doctest corpus, and
`in-crate-source-injection`, which copies the crate, injects the hostile construction at a
declared insertion module, and requires a specific rustc error code whose primary span is on
the probe's marker line.

**What a structural witness must account for**, per the same ratification, because a seal is
established only for the exact invariant whose construction boundary is closed, and private
fields alone are insufficient:

- **module-tree visibility** — `pub(crate)`, `pub(super)`, and any sibling module inside the
  owner's own module tree;
- **alternate constructors** — a second `new_*`, a `From`, a `Default`, or a builder taking
  the same arguments unchecked;
- **generated / deserialization routes** — a derived `Deserialize` or any generated impl that
  fills fields positionally;
- **test-only construction** — a `#[cfg(test)]` constructor or test-gated `pub` field is a
  producer: it does not run in production, and it does prove the boundary is not closed.

A probe attacking one of these leaves the others unwitnessed, so the invariant a unit claims
and the boundary its probe attacks must be the same boundary.

The crate-boundary case remains worth pinning for types re-exported to SDK or integration
consumers. It is a narrower property than the in-crate seal, and the two are separate
witnesses for separate propositions rather than one standing in for the other.

### The first owner to carry the witness: `ClientCredentialWindow`

**Landed 2026-09-17, ADR-MCPRE-068 Phase 0D-3.** Being a sealed owner was one line in the
table above and evidence for nothing. It is now two registry propositions, because the
seal is two facts and only one of them had a falsifier:

| proposition | unit | class | falsifier |
|---|---|---|---|
| `new` refuses a pair where the connection could outlive the credential, or the lifetime passes the ceiling | `proxy.client_credential_window` | `tested` | M113–M115 — weaken a construction-time predicate, expect a named test red |
| `new` is the **only** producer, so the refusal cannot be routed around | `proxy.client_credential_window_sole_producer` | `structural` | S04 — inject a sibling module that assembles the value from field literals, require `E0451` on the marker line |

The second is the one this section's old claim was about, and the reason it needed its own
unit is the reason the old claim failed: **the eight tests in the first row stay green when
the boundary opens.** That is measured, not argued. Changing `cert_lifetime` and
`connection_age` from bare-private to `pub(crate)` and running both lanes over the opened
tree:

```text
cargo test -p mcp-re-proxy --lib -- config_state::client_credential_window \
                                    config_state::credential_currency_bound
    test result: ok. 8 passed; 0 failed

verify-structural --probe S04
    FAIL S04: the hostile construction COMPILED. … is NOT closed by the representation:
    the compiler admits the illegal inhabitant, so possession of the value is not proof
    of the invariant.
```

Every behavioural control the owner has is green against a boundary that no longer holds,
because none of them attempts the construction the change newly admits. Only a hostile
construction can report it, and only from outside the tree that refuses to hold it.

S04's `[probe.producer_paths]` table answers all four routes above for this owner —
module-tree visibility, alternate constructors, generated/deserialization, test-only
construction — so the unit's claim is worded to the boundary the probe attacks and no
wider. It says nothing about which pairs are legal; that is the other row.

### The second: `DelegatedCertResolver`

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-4.** This owner is the clearer case, because the
sole-producer claim was already written down — in a registry comment (*"it claims something
that authority cannot — that no other construction path exists"*) and in THM-0027's scope,
which discharges it by naming the routes: `build_delegated_resolver_config` is private, its
one caller goes through `materialize`, the signing key's constructor is reachable only inside
`crate::delegated_tls`. That enumeration is correct and it quantifies over the callers that
exist, not over the type.

| proposition | unit | class | falsifier |
|---|---|---|---|
| `materialize` establishes correspondence over `cert_chain` and `signer` themselves and refuses otherwise, carrying the listener budget through the construction | `proxy.delegated_resolver_materialization` | `tested` | M36, M37 |
| `materialize` is the **only** producer, so the `_correspondence` witness cannot be supplied beside operands nobody compared | `proxy.delegated_resolver_materialization_sole_producer` | `structural` | S06 — `E0451` from a sibling module inside `delegated_tls` |

Measured the same way, and the same result: with all three fields opened to `pub(crate)`,

```text
cargo test -p mcp-re-proxy --lib -- delegated_tls::resolver::
    test result: ok. 6 passed; 0 failed

verify-structural --probe S06
    FAIL S06: the hostile construction COMPILED.
```

**S06 attacks the parent, and that is the sharp place rather than an incidental one.** Rust
privacy reaches a module's descendants, not its ancestors, so `delegated_tls` — which
declares `mod resolver;` and re-exports the type with `pub use` — is exactly the module a
reader would assume can see inside the resolver, and cannot.

**One measurement worth keeping: the probe measures CONSTRUCTIBILITY, not field privacy.**
Opening `certified` alone left S06 green, and correctly so — a literal naming three fields is
still refused while any one of them is private, so the boundary was still closed against
construction. A probe written per field would have gone red there and reported a breach that
had not happened.

### The third: `Ed25519PublicKeyValue`, where the seal is not a refusal

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-5.** The first two splits made a *refusal*
unavoidable. There is no refusal to make unavoidable here, and saying why is the point.

Every `[u8; 32]` is a legal Ed25519 point, so this owner's second constructor, `for_point`,
is **total** — it cannot fail. That is not a hole in the seal. The invariant is the canonical
RFC 8410 **encoding**, not a predicate over the bytes, so `for_point` admits no inhabitant
`interpret_rfc8410_spki` would reject; its totality is `the_two_directions_are_inverse` read
as a constructor. A probe asserting *"there is one way in"* would state something false.

What is true is the other half of the same fact: **both ways in are the owner's.** Open the
field and a sibling module writes thirty-two bytes directly — still a legal point, and no
longer a value whose provenance this owner can speak for, which is exactly what the
correspondence relation compares and what `spki_der_for_point` round-trips.

| proposition | unit | class | falsifier |
|---|---|---|---|
| which bytes are a key, and what each refusal says | `proxy.ed25519_public_key` | `tested` | M32, M35 |
| only this owner can place bytes in the representation | `proxy.ed25519_public_key_sole_producer` | `structural` | S07 — `E0451` on the field |

```text
cargo test -p mcp-re-proxy --lib -- communication_assurance::ed25519_public_key::
    test result: ok. 7 passed; 0 failed        # with raw_point opened to pub(crate)

verify-structural --probe S07
    FAIL S07: the hostile construction COMPILED.
```

So the claim is worded to the **boundary**, not to a constructor count, and S07's hostile
value is a perfectly legal key. The probe attacks where the bytes may be *placed*, which is
the only thing that can be false here.

### The fourth: `PeerIdentityValue`, where the theorem statement said it

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-6.** The quantifier was written down three times
before anything attacked it:

- the struct's doc comment — *"there is no public constructor other than `interpret`, which
  is fallible. Every inhabitant therefore satisfies the invariant"*;
- the unit's description — *"every inhabitant is non-empty after trimming, length-bounded,
  and free of control characters"*;
- **THM-0023's statement** — *"the type's representation is private and its only constructor
  is fallible, so this is a property of the type rather than of any call site: no sequence of
  operations available to a caller produces an inhabitant that violates it."*

All three quantify over the **type**, which is the right thing to want — it is exactly
R-SEAL's distinction between *this constructor checks X* and *every inhabitant satisfies X*,
and only the second is a theorem. The five tests quantify over `interpret`. They are correct,
M29 falsifies one of them, and none of them can reach the sentence, because the inhabitants
it ranges over are the ones nobody wrote.

| proposition | unit | class | falsifier |
|---|---|---|---|
| what `interpret` accepts and refuses: trim before judging, `Empty`, inclusive length bound, every control-character shape, first-failing-rule precedence | `proxy.peer_identity_value` | `tested` | M29 |
| every inhabitant is a string `interpret` accepted | `proxy.peer_identity_value_sole_producer` | `structural` | S08 — `E0451` on the field |

```text
cargo test -p mcp-re-proxy --lib -- communication_assurance::peer_identity_value::
    test result: ok. 5 passed; 0 failed        # with value opened to pub(crate)

verify-structural --probe S08
    FAIL S08: the hostile construction COMPILED.
```

S08's hostile value is illegal on all three of the owner's rules at once. `interpret` refuses
it; the probe asks whether refusing it is avoidable.

### The fifth: credential/key correspondence, where one proposition needs three boundaries

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-7.** The first four splits sealed one value each.
This owner's claim spans three, and the claim is worded as that conjunction rather than as a
property of one type — because a probe attacking one would leave the other two unwitnessed.

What correspondence is *for* is a relation between two **parties**, not between two values.
`CredentialPublicKeyEvidence` and `CryptographicSigningKeyEvidence` hold the same field — one
`Ed25519PublicKeyValue` — and exist as two types precisely so that, in the owner's own words,
*"a caller cannot pair one party's key with another party's provenance"*. That separation is
worth exactly what the two construction boundaries are worth.

| probe | what a forgery would buy | |
|---|---|---|
| S10 | a credential key nobody read out of a credential | `E0451` |
| S11 | a signer key no signer exported | `E0451` |
| S09 | the fact value itself — which is also `DelegatedCertResolver`'s `_correspondence` witness (S06). A forgeable fact leaves S06's boundary closed around a token that proves nothing | `E0451` |

The owner already gives the argument in prose: `correspond` is private because *"a published
relation would let a caller pair two keys it fabricated"*. The three probes are what refuse
the fabrication rather than deprecate it.

```text
cargo test -p mcp-re-proxy --lib -- …credential_key_correspondence:: …credential_public_key_evidence:: \
                                    …signing_key_evidence:: tls::delegated_credential_key_correspondence_tests::
    test result: ok. 22 passed; 0 failed       # with all three fields opened to pub(crate)

verify-structural --probe S09 --probe S10 --probe S11
    FAIL: 3 of 3 probe(s) did not witness a closed construction boundary
```

Twenty-two tests, including the eleven cross-machine ones in `tls.rs`, green against three
boundaries that no longer hold.

### The sixth: `CertificatePeerIdentityEvidence`, where the boundary is not one file

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-8.** Every split so far produced a unit named
`…_sole_producer`. This one does not, and the reason is the owner's own argument:

> the seal is stated at the boundary it actually holds at: `pub(super)` means no code outside
> the authority can pair a value with a source, which is the property that matters. Narrowing
> it further — so that literally one file could call the constructor — would need a token or
> typestate device, and inventing one to tighten a boundary that is already the authority's
> own is ceremony, not a theorem.

That reasoning is accepted here, and the consequence is that **the claim is worded to the set
of modules the visibility admits**, not to a file. The standing rule is to name that set and
check what the claim needs: here the set is `communication_assurance` and its descendants,
the semantic content is provenance *inside* that authority, and the two match. So the unit is
`proxy.certificate_identity_authority_boundary`, and the probes are injected at the **crate
root** — a sibling of the authority. A probe injected inside the authority would compile, and
compiling would be correct.

**Two producer paths, two probes,** because a `pub(super)` constructor closes nothing if the
representation is reachable:

| probe | route | refusal |
|---|---|---|
| S12 | `CertificatePeerIdentityEvidence::new` from outside the authority | `E0624` |
| S13 | the struct literal — the fields are *narrower* than the constructor, bare-private to the defining module, so this is refused even inside the authority | `E0451` |

```text
cargo test -p mcp-re-proxy --lib -- communication_assurance::certificate
    test result: ok. 26 passed; 0 failed       # with new made pub and both fields made pub

verify-structural --probe S12 --probe S13
    FAIL: 2 of 2 probe(s) did not witness a closed construction boundary
```

**The lane also caught an error in the probe I wrote**, and that is worth recording. S13's
first draft named a `CertificateIdentitySource` variant that does not exist, and the lane
reported `expected E0451 … saw ['E0599']` — *a refusal the probe cannot attribute is not
evidence about the invariant* — rather than counting a compile failure as a closed boundary.
S12 had the same typo and passed, because rustc resolves call visibility before the enum
path; so the distinction between "refused by the boundary" and "refused by something" is not
academic, and the weak form of this check would have accepted a typo as a seal.

### The seventh: `TrustPlan`, where the seal is co-provenance

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-9.** A third kind of structural claim, after
*refusal made unavoidable* and *the authority that may pair*. Here the constructor refuses
nothing at all — `from_validated` is **total** — and the entire security content of its
signature is its single `&ValidatedDeployment` parameter. The owner says so:

> the one producer, and it takes a `ValidatedDeployment` — so both owned facts come from one
> deployment, and no caller can supply them separately.

That sentence is about **who may pair the fields**, not about whether any one of them is
legal; the legality of each part belongs to its own owner. No behavioural test can reach it,
because in the hostile construction every field could be a perfectly good value — what would
be false is that they describe the same deployment. A struct literal restores exactly the
hand-pairing the parameter removes, which is why S14 is a literal rather than a bad argument.

| proposition | unit | class | falsifier |
|---|---|---|---|
| what the plan projects, and that reload is derived rather than stored | `proxy.trust_plan` | `tested` | M66 |
| the posture and the locator describe one deployment | `proxy.trust_plan_co_provenance` | `structural` | S14 — `E0451` |

```text
cargo test -p mcp-re-proxy --lib -- trust_plan::tests
    test result: ok. 4 passed; 0 failed        # with all four fields opened to pub(crate)

verify-structural --probe S14
    FAIL S14: the hostile construction COMPILED.
```

**Three shapes of structural claim now have units,** and they are worth telling apart when
writing the next one:

| shape | what the probe shows | example |
|---|---|---|
| a refusal made unavoidable | the check cannot be routed around | S04, S06, S08 |
| provenance closed | the value's bytes or pairing are the owner's | S07, S09–S11, S12/S13 |
| co-provenance | separately legal parts cannot be combined by a caller | S14 |

### The eighth: the trust-configuration pair, and a probe that must not measure the wrong privacy

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-10.** Two owners, one proposition — which trust
configuration a deployment is *in*.

| probe | owner | what a forgery would buy |
|---|---|---|
| S15 | `TrustRevocationState` | a posture whose declared witnesses nobody decided |
| S16 | `TrustDocumentSource` | an empty locator reaching the code that opens it |

**S16's hostile value is the exact inhabitant `new` excludes** — `(!path.trim().is_empty()).then_some(…)`
— so the construction is not merely unauthorized, it is the one value the owner's whole check
exists to reject, and that check is a deletable statement unless this boundary holds. The
owner's doc comment states the property: *"construction itself validates, so a
`TrustDocumentSource` means the same thing whichever crate built it."* That sentence is about
every crate, which is a claim over the type; the battery ranges over `new`.

**S15 is the case where two layers of privacy meet, and only one is the claim.**
`TrustRevocationState`'s `kind` is bare-private *and* its type `RevocationKind` is a private
enum, so a sibling can reach neither the field nor a variant to put in it. The probe supplies
`todo!()` rather than naming a variant, deliberately: writing `RevocationKind::BoundedCache { … }`
would be refused by `E0603` for the **type's** privacy, and the lane would then report a
refusal about a boundary this unit does not claim. The field's privacy is the claim, so the
field's privacy is what the probe attacks; the enum's privacy is recorded as a second producer
path rather than conflated with it.

```text
cargo test -p mcp-re-proxy --lib -- config_state::trust_revocation config_state::trust_document
    test result: ok. 15 passed; 0 failed       # with both fields opened to pub(crate)

verify-structural --probe S15 --probe S16
    FAIL: 2 of 2 probe(s) did not witness a closed construction boundary
```

Both supporting theorems gain the unit, since each rests on the classifier's decision being
the only way into a posture.

### The ninth: `CustodyState`, where the owner names the consequence itself

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-11.** This owner's comment above its private
`CustodyKind` is the clearest statement of the whole campaign's thesis found in the tree:

> every consumer lives in this crate, so `pub` variants would let any of them assemble a
> custody state whose material no validator saw — a PKCS#11 token with an arbitrary PIN file,
> or a KMS key in a region the deployment never named.

That is an argument about **who may construct**, and its conclusion is the exposure fact the
theorem rests on: `exposure()` reads the kind and answers whether the signing private key is
readable by this process. A forged kind is a deployment reporting a non-exporting posture
while holding a seed file — and nothing in the battery can range over it.

| proposition | unit | class | falsifier |
|---|---|---|---|
| which selection resolves to which of the five states, and what `exposure()` answers | `proxy.custody_exposure` | `tested` | *(none registered — a pre-existing N1 gap, unchanged by this split)* |
| no consumer can assert a posture the classifier did not reach | `proxy.custody_exposure_sole_producer` | `structural` | S17 — `E0451` |

```text
cargo test -p mcp-re-proxy --lib -- config_state::custody
    test result: ok. 13 passed; 0 failed       # with kind opened to pub(crate)

verify-structural --probe S17
    FAIL S17: the hostile construction COMPILED.
```

Two layers of privacy again, as with S15: the field is bare-private *and* `CustodyKind` is a
private enum. S17 attacks the field — the boundary this unit claims — and supplies `todo!()`
rather than naming a variant, because naming one would be refused by `E0603` for the type.

**Worth stating plainly:** the `tested` half of this owner carries no `mutation://` evidence,
and this split does not change that. It is a pre-existing falsifier gap the census already
counts, and Phase 0E's N1 activation is where it becomes an obligation rather than a note.

### The tenth: the continuation pair, where sealing the state does not seal the plan

**Landed 2026-09-18, ADR-MCPRE-068 Phase 0D-12.** Two values on one path, and the second is
the reason this unit carries two probes.

`ContinuationControlState` is the classified posture (S18). `ContinuationControlPlan` is what
consumers actually **read** to decide whether a shared store must be established, and it is a
value in its own right, handed onward. Its `store: None` means *"flows resolve on the replica
that opened them"* — legal for some deployment and wrong for one that selected a shared
store. A caller able to write that field could assert single-replica resolution **without
touching the state the plan is supposed to project**, so a probe against the state alone
would leave the route unwitnessed.

| probe | value | what a forgery would buy |
|---|---|---|
| S18 | `ContinuationControlState` | a posture the classifier never reached |
| S19 | `ContinuationControlPlan` | single-replica resolution asserted for a shared-store deployment, with the state still saying otherwise |

```text
cargo test -p mcp-re-proxy --lib -- config_state::continuation_control \
                                    serving_capabilities::continuation startup_posture
    test result: ok. 15 passed; 0 failed       # with both fields opened to pub(crate)

verify-structural --probe S18 --probe S19
    FAIL: 2 of 2 probe(s) did not witness a closed construction boundary
```

**The lane refused a broken probe for the second time in this campaign**, and differently:
S19's first draft imported `ContinuationControlPlan` from `config_state`, which does not
re-export it, and the lane reported `saw ['E0432']` — an unresolved import is not a seal.
Between this and S13's `E0599`, the declared-error-code rule has now caught two probe defects
that the weak *"does not compile"* form would have recorded as evidence.

The remaining unit-backed sealed owners follow the same split, one owner per change.

## Open

Nothing structural. The remaining owners (`ChannelBindingState`, `DelegatedSigningFacts`,
`ServerIdentityFacts`, `AuditState`, `VerifiedContextState`) carry no representation a
consumer reads: measured at 0 external destructuring sites each, and the fieldless ones
have no illegal inhabitant to exclude.
