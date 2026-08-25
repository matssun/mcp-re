<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-066 — Audit composition: two authorities, one record

**Status:** **ACCEPTED** 2026-08-25 — refined B, after two grill rounds. Not yet implemented;
implementation order is §9.
**Discussion:** [#638](https://github.com/matssun/mcp-re/discussions/638).
**Characterization:** issue #637.
**Predecessor:** ADR-MCPRE-065 (discussion #629), whose §10 deferred exactly this question
until a semantic authorization product existed. It now does — #632, #634, #636.
**Constrains:** ADR-MCPS-035 (audit vocabulary), whose normative text lives in
[`docs/spec/security-boundary.md`](../spec/security-boundary.md) §9.

This ADR decides an **algebra**, not a token. Nothing here widens a frozen vocabulary, and no
implementation follows until it is grilled and accepted.

## 1. The ruling this ADR starts from

> **Question 2 is decided: there are two independently describable authorities.**
> `McpReError` owns Core/request-verification rejection semantics. `PolicyError` owns
> authorization-mechanism refusal semantics. They must not be flattened into one
> `AuditEvent.reason`, copied into each other's taxonomies, or made interchangeable merely
> because both render `mcp-re.*` tokens.

That is an owner ruling on ADR-MCPRE-061 §8 question 2, and it is the premise of everything
below rather than a conclusion to be re-argued.

Two designs are eliminated by it before any work starts:

- **Do not add the `PolicyError` variants to `McpReError`.** That makes one taxonomy own two
  authorities' semantics, and the merge becomes permanent and invisible.
- **Do not bless `PolicyError::wire_code()` as a second legal producer of `reason`.** That
  institutionalizes precisely the defect #637 found, and names it a feature.

Either would take an accident and ratify it.

### 1.1 The second ruling: the success side is not decoration

> **`NoPolicyConfigured` and `Authorized` must remain observably distinct.**

ADR-MCPRE-065 built three postures rather than two specifically so that *nobody asked* could
never be read as *asked and satisfied*. `posture.rs` preserves that in the type. The audit
projection destroys it: `release()` discards the posture, and `mcp-re.request.accepted` is
byte-identical on an unauthorized proxy and on a PDP-enforcing one.

A distinction preserved in a type and erased in the record is preserved only for as long as
nobody looks at the record. This is not optional telemetry.

### 1.2 Scope rulings

Taken 2026-08-25, before the grill, so the grill had something falsifiable to attack.

**R1 — the two-jobs finding is a law here; the repository-wide repair is not.** ADR-066 states
that lifecycle outcome and authority attribution are separate dimensions with different
cardinalities. Candidate B may satisfy that *locally for authorization* by co-locating two
typed dimensions in one serialized record. Generalizing the separation across admission,
retention, and transport is successor work. **C is therefore not rejected — it is the likely
later generalization of this law.**

**R2 — `Authorized` carries the action coordinate.** Authority + version + evidence digest
answers *who decided, under which policy, on what evidence*; it does not answer *what was
authorized*. Carry only the already-established semantic authorization coordinate —
operation/target as evaluated — never raw params or reconstructed request material. That is
what keeps R-COMPOSE satisfied instead of turning the audit record into a second request
representation.

**R3 — `NoPolicyConfigured` is explicit; absence never means it.** For newly emitted request
records the facet is always present as one of `NotConfigured | Authorized | Refused`. An absent
facet can then mean only *legacy or unknown record*. This is the same `Off == Allow` ambiguity
ADR-065 eliminated in the type, refused again at the record.

**R4 — `PdpRelationRefusal` does not enter the normative facet.** That would make a
mechanism-specific internal algebra part of the general audit contract and widen the
observable vocabulary past `PolicyError`. The two conflations `pdp/refusal.rs` documents are
unfortunate, but **ADR-066 does not repair ADR-MCPS-013 through the back door.** If finer PDP
diagnostics are ever wanted, that is a separate restricted, non-normative diagnostic product.

**R5 — authorization is request-side.** It is not duplicated onto `response.signed`. A
response record does not represent another authorization decision. Under B this is not a note
but a type requirement: the facet belongs to a *request* audit record, not indiscriminately to
every `AuditRecord`.

## 2. What is actually there today

Measured in #637; summarized here only as far as the algebra needs.

```rust
pub struct AuditEvent {
    pub event_type: &'static str,           // 7 fixed tokens, 3 categories
    pub decision: Decision,                 // Accepted | Signed | Rejected
    pub reason: Option<&'static str>,       // rejection only
    pub reason_label: Option<&'static str>, // non-normative
}
pub struct AuditRecord { event, actor_id: Option<String>, status: u16, at_unix: i64 }
```

Every stage — envelope, transport binding, admission, replay, retention, authorization —
funnels into the same two rejection event types and differs only in one string. Which
authority terminated the exchange is not represented anywhere.

And the current shape is this:

```text
McpReError  --+
              +-- wire_code() --> &'static str --> AuditEvent.reason
PolicyError --+
```

The join is a `&'static str`. Nothing at that point knows which authority produced it, and
nothing downstream can recover it.

### 2.1 A doc claim that outran its evidence

`audit.rs`, on `request_rejected_code`:

> `reason` MUST be a member of the frozen `McpReError::wire_code()` taxonomy; there is no
> parallel sub-name. **That containment is not a convention here** — the conformance guard
> asserts every `HttpProfileError::wire_code()` token is a frozen wire code, so the real
> producer's whole reason set is checked.

"The real producer" was true when written and is now false: there are four producers, and the
guard reads the files of three (plus `audit.rs` itself), declared as data in
`mcp-re-conformance/BUILD.bazel`. The claim is not merely stale — it is the reason nobody
looked. A guard whose input set is hand-maintained will describe yesterday's architecture on
exactly the day the architecture changes.

## 3. Invariants this design must satisfy

Owner-set. A proposal that violates one of these is not a candidate.

| # | invariant |
|---|---|
| 1 | Core's existing rejection vocabulary remains **Core-owned**. |
| 2 | Policy refusal remains **Policy-owned**. |
| 3 | Audit represents authorization as a **distinct semantic product/category/facet**, not a token smuggled through Core's `reason`. |
| 4 | Audit distinguishes at least `NoPolicyConfigured`, `Authorized`, `Refused`. |
| 5 | Successful authorization evidence is **projected from the existing `AuthorizedRequestFacts`**; nothing is re-derived at the audit site (R-COMPOSE). |
| 6 | Where available, attribution — authority, version, decision-evidence identity — survives well enough to answer *who authorized what, under which authority, on what evidence*. |
| 7 | No design may require exposing the whole policy artifact or leaking sensitive policy content. |
| 8 | `request_rejected_code(&'static str)` ceases to be an untyped vocabulary escape hatch; the compiler should make the authority distinction harder to violate. |
| 9 | The producer graph is made **irrelevant by construction**: audit rejection accepts a typed Core verdict, so a foreign taxonomy is a type error rather than something a scanner must discover. See §5. |
| 10 | **No production authorization evaluator is wired until this is resolved.** The violation is latent only because none is; wiring one makes it live. |

Invariant 10 is a standing constraint on other work, not a task in this ADR. It is consistent
with [`docs/AGENT_INSTRUCTIONS.md`](../AGENT_INSTRUCTIONS.md) §9: `--authz reference` is a
refusal gated on a decision, and this is now one of the decisions it is gated on.

## 4. Decide the algebra before minting the token

The tempting first move is to mint `mcp-re.authorization_refused` in Core and route
authorization refusals through it. That is *a* design, and this ADR explicitly does not adopt
it yet, because #637 exposed a prior question:

> **`request.rejected` is currently doing two jobs.**
> It is (a) request-lifecycle accounting — this exchange terminated without being served —
> and (b) attribution of the authority that caused the termination.

Those two jobs have different cardinalities. Lifecycle is one fact per exchange. Attribution
is one fact *per authority that had something to say*, and an exchange can be terminated by
one authority while several others already returned findings. Collapsing them is what forced
attribution into a single `&'static str` in the first place, and minting a Core token for
authorization would re-collapse them at a new address.

So the shape to decide first is the **relation between a lifecycle record and an authority's
product**, and only then what tokens each needs.

### 4.1 The target shape

```text
Core verification evidence ------+
                                 |
Admission evidence --------------+--> composed audit record / evidence
                                 |
Authorization evidence ----------+
        |
        +-- NotConfigured
        |
        +-- Authorized
        |      authority
        |      version
        |      action
        |      evidence identity
        |
        +-- Refused
               PolicyError
               authority / evidence where applicable
```

Each contributor keeps its own vocabulary and its own owner. The record composes their
products; it does not translate them into one another.

### 4.2 Candidate compositions

Three shapes satisfy the ruling. This ADR presents them for the grill and states a lean; it
does not close the question.

**A — a fourth audit category.** Authorization becomes its own `event_type` category beside
success, rejection, and key lifecycle, carrying a typed authorization outcome. The precedent
is real and recent: `KEY_LIFECYCLE_EVENT_TYPES` was added as a third category under
ADR-MCPRE-052 §7, so a new category with an authorizing ADR is an established move rather
than an invention.
*Cost:* two records per authorized exchange, and consumers must join them.

**B — a typed facet on the existing record.** `AuditRecord` gains an
`authorization: AuthorizationFacet` whose variants are the three postures, projected from
`AuthorizedRequestFacts`. Core's `event_type`/`reason` are untouched and stay Core-owned;
`PolicyError` appears only inside the facet, in its own type, never as `reason`.
*Cost:* the record grows a field every exchange carries, most of them `NotConfigured`.

**C — separate lifecycle and attribution records.** The deepest reading of §4: `request.rejected`
keeps only lifecycle, and every authority that reached a verdict emits its own attributed
product.
*Cost:* the largest change, and it touches every existing stage rather than only
authorization.

**Preferred hypothesis: refined B — not the accepted answer.** A is the fallback if refined B
cannot be established; C stays recorded as R1's later generalization and is not dragged into
this slice.

### 4.3 Refined B — co-location is not conflation

Plain B is under-specified in a way that would quietly destroy the algebra it exists to
preserve. `AuditRecord` also represents `response.signed`, response rejection, and key
lifecycle. A facet on *every* record forces either an `Option` or a `NotApplicable` state, and
both re-introduce an absence with two meanings — the exact defect R3 refuses.

So B means a record kind, not a wider struct:

```text
AuditRecord
    |
    +-- RequestRecord
    |      lifecycle
    |      authorization:  NotConfigured | Authorized(..) | Refused(..)
    |
    +-- ResponseRecord
    |      lifecycle
    |
    +-- KeyLifecycleRecord
           ...
```

Not those exact Rust types — that is the algebra an implementation must preserve.

And `Refused` cannot collapse to `Refused(PolicyError)`, because ADR-065 already has two
refusal paths and only one of them reaches a policy at all:

```text
AuthorizationRefusal
    +-- ActionNotVerifiable(..)      no policy verdict was ever reached
    +-- PolicyRefused(PolicyError)   a policy returned a verdict
```

So:

```text
AuthorizationFacet
    +-- NotConfigured
    +-- Authorized(AuthorizationAttribution)
    +-- Refused
           +-- BeforePolicy
           +-- ByPolicy(PolicyRefusalAttribution)
```

`BeforePolicy` imports **no vocabulary**. The request defect it accompanies is already
expressed by the Core-owned lifecycle reason; the facet adds exactly one fact — *no policy
verdict was reached* — which is why it does not duplicate `McpReError` inside the
authorization authority.

The point of the whole shape: **co-location is not conflation.** Lifecycle and authorization
remain separately typed coordinates that happen to serialize into one record. That keeps B's
practical advantages — no join for a consumer, and no change to what `request.rejected` means
today — without denying §4's finding.

### 4.4 What each candidate must answer

- Which type does a consumer hold that makes an authorization fact unavailable-by-construction
  when no policy was configured? (Invariant 4 is not satisfied by an `Option` that reads as
  absent for two different reasons — see the one-`Verified…`-type rule.)
- Where does `AuthorizedRequestFacts` become the facet, and does that path destructure it or
  ask it for a named projection? (R-COMPOSE. Today `release()` drops it entirely; the fix is
  a projection, not a wider struct handed to the composition root.)
- What is the decision-evidence *identity*, exactly? The natural candidate is the digest
  already bound by `BoundDecisionEvidence`, which answers "on what evidence" without carrying
  a byte of the artifact — satisfying invariant 7 by construction rather than by redaction.
  Note the retained-evidence store is content-addressed, so a digest is already the repo's
  idiom for naming an artifact without holding it.
- What replaces `request_rejected_code(&'static str)`? (Invariant 8. A constructor taking a
  typed Core verdict, with the authorization path unable to reach it at all, is the shape that
  makes the authority distinction a compile error rather than a review note.)

## 5. Make the producer graph irrelevant, not discoverable

The blueprint's first form of invariant 9 asked for a guard that follows the call graph. That
is the wrong end state, and this section replaces it.

Today the guard *must* discover producers because the sink accepts a string:

```text
request_rejected_code(&'static str)      <- anyone who can make a string is a producer
```

The accepted design should instead reach:

```text
Audit request rejection
        accepts
        v
typed Core rejection
        ^
only explicit typed conversions
```

Then this is not a rule anybody enforces — it does not typecheck:

```text
PolicyError -> &'static str -> AuditEvent.reason
```

`PolicyError` simply has the wrong type. HTTP-profile and dispatch errors that legitimately
represent Core taxonomy outcomes make an **explicit exhaustive typed projection** into the
Core rejection type instead of laundering themselves through strings.

At that point the compiler is the producer-graph guard, and the conformance test becomes
defence in depth — it checks the frozen enums and the projections, and may forbid an
authority-crossing conversion outright. It no longer has to guess which source file might one
day reach a string-taking function. A scanner over a hand-maintained file list was always
going to agree with the architecture right up until the moment it changed.

Adding `mcp-re-policy/src/error.rs` to the current guard's inputs still turns it red, and that
red is still the algebra decision — so the guard change lands with the design either way. The
difference is what it lands as.

## 6. Grill round 1 — five propositions, measured

Refined B is a hypothesis, so it was attacked rather than admired. Each proposition below was
tested against the code, not reasoned about abstractly. **Four survive; one fails as currently
written, and its failure is the most useful result in this record.**

### P1 — request/response applicability without an ambiguous `Option`? **SURVIVES**

Three `AuditSink` implementors exist, all in-crate (`StderrAuditSink`, `NoAuditSink`,
`CollectingAuditSink`); no external implementor constrains the shape.

More importantly, `event_type` **already** discriminates request records from response records.
The record-kind split is therefore a re-expression of a distinction the data carries today, not
a new one being invented — which is why it needs no `Option` and no `NotApplicable`.

### P2 — `BeforePolicy` vs `ByPolicy` without merging vocabularies? **SURVIVES**

More cleanly than expected. `AuthorizationRefusal::wire_code()` already renders
`ActionNotVerifiable` onto **Core** tokens — `digest_mismatch` and `malformed_envelope` — under
a comment stating this slice "is not entitled to restate in a vocabulary ADR-MCPS-035 freezes."

So the Core-owned lifecycle reason already carries the `BeforePolicy` defect correctly, today,
by prior deliberate design. `BeforePolicy` adds one fact and imports no vocabulary.

### P3 — project the action coordinate without re-derivation? **SURVIVES ON SUCCESS, FAILS ON REFUSAL**

*Success path — survives, with no carrying required.* The posture is bound at
`http_profile_serve.rs:1459`; `release()` consumes it at :1570; `request_accepted()` is emitted
at **:1535 — between them**. The sealed product is alive at the audit site, so the facet is a
borrowing projection taken right there. No wider struct, no threading through
`ReadyForDispatch`.

*Refusal path — fails as currently written:*

```rust
// authorization_stage
.map_err(|refusal| Refusal::before_admission(refusal.wire_code(), 403))
```

The typed `AuthorizationRefusal` is destroyed **at the stage boundary**. `Refusal` is
`{ wire_code: &'static str, status, posture }`, so only a pre-rendered string survives, and
`BeforePolicy` vs `ByPolicy` is unrecoverable downstream. **Refined B requires `Refusal` to
stop pre-rendering and carry a typed verdict.**

### P4 — old-record absence distinguishable from explicit `NotConfigured`? **SURVIVES, conditionally**

`StderrAuditSink` formats every field unconditionally, rendering `None` as `-`
(`reason=record.event.reason.unwrap_or("-")`). So a new request record always carries the key,
and a missing `authorization=` key can only mean an older build — provided one condition:

> **`-` is reserved for *not established*. `NotConfigured` must render as its own token and
> must never render as `-`.**

The other absence — a response record legitimately having no facet — is already disambiguated
by `event_type` (P1). Both meanings of "no facet here" stay separable.

### P5 — eliminate the raw-string producer by typing? **SURVIVES, and is smaller than feared**

`HttpProfileError::wire_code()` is a **total** match over its variants into Core tokens.
`ProxyDispatchError::wire_code()` delegates to it plus one token of its own,
`mcp-re.replay_cache_unavailable`, which **is** in the Core taxonomy
(`McpReError::ReplayCacheUnavailable`).

The exhaustive typed projection §5 asks for therefore already exists semantically — it is
merely spelled as strings. And the conformance guard's current assertion (every
`HttpProfileError::wire_code()` token is a frozen Core code) is exactly the **proof of totality**
that makes converting it safe rather than speculative.

### The synthesis: P3's failure and P5 are one defect

Both are `wire_code()`-to-`&'static str` at a stage boundary. That single move destroys the
authority distinction (P5) *and* destroys the authorization facet (P3-refusal). They are not
two problems that happen to rhyme.

The consequence for sequencing is concrete: **§5's typed-projection work is a precondition for
refined B being implementable at all**, not an independent hardening item that could follow it.
An implementation that added the facet while `Refusal` still pre-rendered would produce a
record able to say `Refused` but never able to say *by whom* — the same silent flattening this
ADR exists to stop, one layer further in.

### Verdict of round 1

Refined B survives with one required precondition (typed `Refusal`) and one serialization
constraint (P4's reserved `-`). A remains the fallback if the record-kind split proves more
disruptive than measured. C remains R1's recorded generalization.

**Not yet accepted.** Round 1 attacked the algebra; it did not attack the deployment
consequences, the cost to existing consumers of the stderr format, or the migration for
records already written.

## 7. Grill round 2 — deployment, consumers, migration

Round 1 attacked the algebra. Round 2 attacks refined B specifically, on the three fronts
round 1 explicitly did not reach. Measured, not reasoned.

### R2-P1 — is R3 meaningful in a shipped deployment? **YES**

`deploy/helm/mcp-re-proxy/values.yaml` ships `auditSink: stderr` and the chart passes
`--audit-sink` through. So the facet is observable in a default production deployment, and R3
is a real property rather than a property of a test harness.

`--audit-sink none` produces **no record at all**, which is a third absence — and all three
stay separable:

| absence | means | discriminated by |
|---|---|---|
| no record | the deployment chose `--audit-sink none` | nothing was emitted |
| no facet on an emitted record | it is a response/key-lifecycle record | `event_type` |
| no facet field on a request record | record predates ADR-066 | field presence (R3) |

A deployment that turns the sink off has made authorization posture unobservable *by
decision*. That is not the `Off == Allow` ambiguity — nothing claims anything.

### R2-P2 — is there a committed serialization contract to break? **NO**

The only emitting sink formats a flat line:

```text
mcp-re-proxy: audit seq=… event=… decision=… reason=… actor=… status=… at=…
```

There is **no JSON audit record anywhere in the product**. `security-boundary.md` §9 shows
`{ "event_type": …, "reason": … }`, but that example illustrates the *vocabulary*, not a wire
format — and §9 opens by stating this is "**not** a SIEM schema".

So refined B's record-kind split changes an in-crate Rust type and one stderr line. It does not
break a published schema, because there is not one.

**A divergence this exposes, and a constraint it creates.** §9's JSON example and the emitted
key=value line already differ in shape. That is tolerable while the example is read as
vocabulary. It would stop being tolerable if ADR-066 were read as adding a *serialization*
contract, so this record states explicitly: **ADR-066 introduces no audit serialization
contract.** It decides which facts exist and who owns them. How a sink renders them stays the
sink's, and any future serialization contract needs its own record.

### R2-P3 — what does the change cost existing consumers? **Measurably little**

- **No external `AuditSink` implementor exists.** Three, all in-crate: `StderrAuditSink`,
  `NoAuditSink`, `CollectingAuditSink`.
- **The line format is pinned by exactly one test, and only its prefix** — `app.rs:1439,1450`
  assert `stderr.contains("audit seq=0 ")` and a `format!("audit seq={} ", BATCH - 1)`. Adding
  a field does not break it.
- **`CollectingAuditSink::records()` is consumed by two e2e test functions**
  (`delegated_client_server_e2e_test.rs:711,743`), asserting on `record.event.event_type` and
  neighbours. Those become pattern matches on a record kind. Contained.
- For a line-oriented log consumer, an added `key=value` field is additive.

### R2-P4 — what has to migrate? **Nothing inside the artifact**

The product **never persists an audit record.** There is no file sink, no object-store sink, no
Redis sink — `StderrAuditSink` writes to stderr, `NoAuditSink` discards, `CollectingAuditSink`
is a test double. Records already written live in an operator's log pipeline, outside the
artifact entirely.

This resolves round 1's open question 5. R3's "an absent facet means a legacy record" is a
statement about **operator-side historical logs**, not a migration this repository performs.
There is no stored corpus to rewrite, version, or dual-write.

### Verdict of round 2

**Refined B survives.** No disqualifying deployment, consumer, or migration consequence was
found, and two objections dissolved on measurement: there is no serialization contract to
break, and there is no stored record corpus to migrate.

## 8. Design selection

**Design selection after grill rounds 1 and 2: refined B.**

- **A** remains the fallback, and is now only reachable if implementation discovers something
  neither round found.
- **C** remains the successor generalization of the lifecycle-versus-attribution law (R1). It
  is not an alternative to B; it is what B's law grows into across the other stages.

A/B/C stop being equally open alternatives at this point.

## 9. Implementation order

Frozen. Each slice has an independent correctness criterion, so a failure is attributable.

```text
Slice 0   typed Refusal — preserve authority provenance across the stage boundary
          NO audit schema change · NO vocabulary widening
          MERGED b9246fe (#643, issue #642)
              v
Slice 1   the authorization audit facet
          NotConfigured | Authorized | Refused, projected from the live sealed product
              v
Slice 2   close the remaining untyped audit escape hatches; containment becomes structural
          INCLUDING the deferred HttpProfileError -> McpReError projection and the
          wire_code derivation that makes room for it
              v
          only afterwards may wiring a production evaluator be considered
```

**Slices 1 and 2 do not share a PR.** Ruled after Slice 0, on evidence Slice 0 produced.
Slice 2 has an internal dependency chain of its own — structural containment, the deferred
projection, and deriving `wire_code` from it rather than duplicating it beside it, where the
derivation is what creates the room under `mcp-re-http-profile/src/error.rs`'s pinned
baseline. Slice 1 depends on none of that. They are adjacent; they are not one atomic
change. Slice 1 changes what authorization facts exist; Slice 2 changes how facts and
failures are structurally contained and projected.

After Slice 2 is complete and measured, **stop again.** An evaluator is a subsequent
implementation decision, not an automatic next step: this ADR establishes the model and the
containment first.

### 9.1 Slice 0 contract — semantically neutral

Slice 0's job is **only to stop destroying the information** the next slice needs. It preserves
what the stages already decided; it does not decide how audit represents those facts. That is
what gives it a correctness criterion independent of B, and what keeps it valid even if a later
round modifies B.

```text
stage-specific typed refusal          stage-specific typed refusal
          v                                     v
   typed refusal cause          NOT        wire_code()
          v                                     v
final serving/audit boundary            &'static str -> Refusal
```

**It must not:** add the authorization facet · mint or widen any vocabulary · add `PolicyError`
to Core · make `PolicyError` a legal Core audit reason · wire a production evaluator · change
`request.accepted`/`request.rejected` semantics · attempt candidate C.

**The cause must stay closed over owners.** Replacing `wire_code: &'static str` with
`error: McpReError` would move the authority collapse one level earlier rather than remove it.
The representation must be able to say:

```text
RefusalCause
    Core(..)
    Authorization(AuthorizationRefusal)
```

An exhaustive projection `HttpProfileError -> Core` is legitimate, because that relationship is
already a ratified invariant — every HTTP-profile `wire_code()` is deliberately a Core token,
and the conformance guard asserts it. But **`PolicyError -> McpReError` must remain
impossible**: the authorization branch has to arrive at the audit-composition boundary still
recognizably authorization provenance. That is the entire value of Slice 0.

Only the final presentation boundary renders a public code.

### 9.3 Slice 1 contract — the facet, and only the facet

Slice 1 spends what Slice 0 preserved. It adds the authorization coordinate to the record
and nothing else.

```text
AuthorizationFacet
    NotConfigured
    Authorized(authority · version · action · evidence handle)
    Refused
        BeforePolicy
        ByPolicy(PolicyError)
```

**It must not:** pull forward structural containment · project `HttpProfileError` onto
`McpReError` · derive `wire_code` · expand the audit drift guard's inputs · wire a production
evaluator · widen any Core vocabulary.

What it therefore leaves standing, named in the code rather than left to be discovered: an
authorization refusal's `wire_code()` still reaches Core's `reason` through
`request_rejected_code`. Slice 1 adds the second coordinate; it does not close the first,
and it does not claim to. That is invariant 8/9 and it is Slice 2's.

**The record kind is two arms, not three.** §4.3 draws `KeyLifecycleRecord` beside the other
two, and it is not implemented, because it never used this type: the ADR-MCPRE-052 §7
lifecycle events are emitted by the custody layer as bare `AuditEvent`s on its own path. An
arm nothing constructs would model a producer that does not exist.

**The projection is one call per owner.** `AuthorizationPosture::audit_facet`,
`AuthorizedRequestFacts::audit_attribution`, `AuthorizationRefusal::audit_facet`,
`RefusalCause::authorization_facet`. §4.4 asks whether the path destructures the sealed
product or asks it for a named projection; the answer is one named projection, written in
the owner's own module where it reads the private representation, so the composition root
holds a single call rather than four accessor reads it then assembles (R-COMPOSE).

**What Slice 1 does not carry.** No decision-evidence identity: §4.4 names the
`BoundDecisionEvidence` digest, and no mechanism states it. `GrantAttribution` returns
authority and version; deriving a decision digest at the audit site would re-derive
(invariant 5) and would arrive as an `Option` whose `None` means both *no decision was
presented* and *no decision profile is running* — the shape `grant.rs` already refused for
expiry. It arrives with the first production mechanism, typed by what that mechanism can
establish. Until then the record answers *which exchange* with the request evidence handle
every other authority on this path attributes by.

### 9.2 Slice 0's two poison pills

Mechanical, so the invariant is established before B depends on it:

1. **Replace the typed authorization refusal at the stage boundary with its `wire_code()`
   string again — the suite must fail.**
2. **Attempt to construct a Core audit reason directly from a `PolicyError` — compilation or a
   structural gate must fail.**

A poison pill that does not fail is a control that measures nothing.

## 10. Open questions still standing

Two of round 1's five are now closed:

- **Q4 — packaging of the typed `Refusal` change.** RESOLVED: its own preparatory slice
  (§9.1). Round 1 showed it is an independent information-preservation defect, not a detail of
  the facet.
- **Q5 — migration of already-written records.** RESOLVED by R2-P4: the product persists no
  audit record, so there is no stored corpus to migrate.

Resolved by Slice 1:

- **Q1 — operation *and* target?** Both, and the target keeps its own three states. The
  facet carries the whole `VerifiedAuthorizationAction` rather than a narrower projection,
  because that type is already the evaluated coordinate — narrowing it at the record would
  be a second representation of a fact an owner decided. The one place a narrowing was
  tempting is the diagnostic line, where `AuthorizationTarget::named()` answers `None` for
  both *names no target* and *names one and the body carried none*; the record renders the
  three states apart, since a reader holding only the record could not recover the
  difference.
- **Q3 — the response side of a refused request.** Nothing changes there.
  `response.rejected` is not emitted for a request-side refusal at all — the refusal posture
  decides which of the two events is correct — and where a response record *is* emitted, R5
  is now structural: the type carries no authorization coordinate to duplicate.
- **Q4 — one PR or two?** Two. See §9.

Still open, and neither blocks Slice 1:

1. Should a request record carry an explicit schema version rather than relying on
   field-presence as R3's discriminator? Field-presence works and R2-P4 makes it cheap, but it
   is an inference where a version would be a statement.
2. Does the diagnostic `key=value` rendering want a structured (JSON) audit sink before the
   facet has more than one consumer? The vocabulary is stable either way; this is about the
   sink, not the algebra.

## 11. Explicitly not in this ADR

- **Verified-context widening.** Stays after audit, and only if a real inner-plane consumer
  needs authorization facts. A committed wire representation does not change because a fact
  now exists.
- **The repository-wide lifecycle/attribution split (candidate C).** R1 keeps it recorded as
  this law's later generalization; doing it here would make one change carry two arguments.
- **Reopening ADR-MCPRE-065.** The boundary, the mechanism, and the producer are accepted and
  merged. This ADR observes their product; it does not revisit it.
- **Any implementation.** No vocabulary is widened, no token minted, and no guard input added
  until this is grilled and accepted.
