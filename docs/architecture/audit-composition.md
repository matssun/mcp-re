<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-066 — Audit composition: two authorities, one record

**Status:** PROPOSED — not accepted, not implemented.
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
| 9 | The drift guard covers the **actual producer graph**, not a hand-maintained list. |
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

**Lean: B, with A as the fallback if the facet cannot be kept from growing.** B satisfies
invariant 5 most directly — a facet is a projection of a value that already exists — and it is
the only one of the three that does not change what an existing consumer of `request.rejected`
sees. C is the most honest about §4's finding and should not be dismissed; it is deferred
because doing it *with* the authorization work would make one change carry two arguments.

### 4.3 What each candidate must answer

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

## 5. The guard must follow the producer graph

Invariant 9 is separable from the vocabulary question in principle and not in practice.

Adding `mcp-re-policy/src/error.rs` to the guard's declared inputs makes the gate go **red** —
correctly, because twelve of its thirteen tokens are outside the frozen taxonomy. What to do
about that red *is* the algebra decision above. So the guard change lands with the design, not
before it.

But the deeper defect outlives whichever candidate wins: the guard's producer set is a
hand-maintained list in a BUILD file, and the thing it must track — *who can reach
`AuditEvent.reason`* — is a property of the call graph. A list agrees with the graph until
someone adds a producer, which is the only moment the guard was ever needed. The accepted
design must state how the guard learns about a fourth producer without a human remembering to
tell it, and a proposal that answers "we add it to the list" has answered the wrong question.

This is the same failure the repo has already recorded twice: a threshold that parameterised a
lint nobody switched on, and a `tests/` glob that silently exempted a crate for a whole
campaign while printing OK. **A gate's exemption is part of its measurement.**

## 6. Open questions for the grill

1. Is `request.rejected` doing two jobs (§4), and if so, is fixing that in scope here or a
   successor ADR? The lean defers it; the lean may be wrong.
2. Does an `Authorized` record need the action coordinate, or is the authority + version +
   evidence identity sufficient to answer *who authorized what*? Carrying the operation and
   target is more useful and is also more of the request restated in a second place.
3. Should `NoPolicyConfigured` be recorded at all, or is its correct representation the
   *absence* of an authorization facet? The ruling says observably distinct; absence is
   distinguishable from `Authorized` only if a consumer can tell it from a record written by
   an older build.
4. Two conflations `pdp/refusal.rs` documents — untrusted-issuer ≡ bad-signature, and
   explicit-deny ≡ action-mismatch — are forced by `PolicyError`'s granularity. Does an
   authorization facet carrying the typed `PdpRelationRefusal` resolve them, and is
   distinguishing them in an audit record desirable or an information leak to an attacker who
   can read it?
5. Does the response side need the same treatment, or is authorization request-only by
   construction?

## 7. Explicitly not in this ADR

- **Verified-context widening.** Stays after audit, and only if a real inner-plane consumer
  needs authorization facts. A committed wire representation does not change because a fact
  now exists.
- **Reopening ADR-MCPRE-065.** The boundary, the mechanism, and the producer are accepted and
  merged. This ADR observes their product; it does not revisit it.
- **Any implementation.** No vocabulary is widened, no token minted, and no guard input added
  until this is grilled and accepted.
