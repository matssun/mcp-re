<!-- SPDX-License-Identifier: Apache-2.0 -->

# The MCP-RE canonical formal security model

ADR-MCPRE-059 §10. This file is the single place where MCP-RE's foundational security
relations are named. A module author consumes these definitions; they do not invent a
local near-synonym.

The reason is not tidiness. Two subtly different definitions of "authorized" in two
proofs produce two theorems that look like they compose and do not, and nothing in either
proof's output says so.

---

## Ontological agnosticism is normative

The core model does not assume that an authority-bearing entity is a human, a software
agent, an organization, a workload, a robot, or anything else currently familiar. Roles,
authority, evidence, constraints, and relations are modeled independently of entity kind.

This is a requirement, not a stylistic preference (§10, Operational Rule 15). A concrete
protocol profile may narrow it — MCP-RE's own profile certainly does. The core must not.
A model that bakes in "the delegator is a person" acquires a false theorem the moment the
delegator is a workload identity, and the falseness is invisible because the proof still
passes.

---

## Concepts

| Concept | Meaning | What it is NOT |
|---|---|---|
| `Entity` | Something that can occupy a role. Kind-agnostic. | Not a user, not a principal-with-a-password |
| `Authority` | The permission to cause a class of effects, held by an entity. | Not an identity; an entity may hold none |
| `Evidence` | An artifact offered in support of a claim. | Not proof that the claim is true |
| `Action` | An effect an entity may attempt. | |
| `Resource` | What an action is directed at. | |
| `Constraint` | A condition that narrows when authority applies. | Never a condition that widens it |
| `Delegation` | The transfer of a subset of authority from one entity to another under constraints. | Not a copy; not a grant of new authority |
| `Decision` | The admission or refusal of an attempted action. | |
| `State` | A configuration of a modeled system at a point in its lifecycle. | |
| `Transition` | A change of state caused by an event. | Not every event causes one |

## Relations

```text
authorizes(authority, action, resource)
valid_delegation(parent, child, constraints)
admissible_transition(pre_state, event, post_state)
evidence_supports(evidence, claim)
```

These are the four foundational relations. Anything a proof needs that is not expressible
in terms of them is a signal that the model needs extending here — deliberately, in one
place — rather than that a local definition should be written.

---

## Candidate long-lived theorems

These are the statements worth owning independently of any implementation. A theorem here
is the security asset; the Rust function that currently implements it is allowed to change
underneath it (§10).

They are candidates, not commitments. Each is adopted only when it matches actual MCP-RE
semantics — writing down a theorem the system does not implement produces a proof
obligation that will be discharged by weakening it.

1. **Delegation cannot amplify authority.** For any `valid_delegation(parent, child, c)`,
   the authority held by `child` under `c` is a subset of the authority held by `parent`.
2. **Constraints narrow monotonically.** Adding a constraint to a delegation never admits
   an action that was previously refused.
3. **No chain manufactures a root.** No sequence of delegations produces an authority
   whose origin is not a trust anchor.
4. **Revocation and freshness bound admissibility.** After a revocation or freshness
   boundary, no future decision admits an action on the revoked or stale basis.
5. **Transitions are legal.** A transition occurs only from a state for which that event
   is admissible; an inadmissible event leaves the state unchanged.
6. **Decisions imply their predicate.** An execution decision implies the required
   authority and evidence predicate held at the moment of the decision.

Theorem 5 is the one the Verus pilot candidate speaks to directly.

---

## Layering — and the mistake it prevents

ADR-MCPRE-059 distinguishes three layers, and conflating them is the failure mode that
makes formal verification worthless while looking successful.

**Layer A — normative security concept.** Prose. Long-lived.

> An execution decision is admissible only if the relevant authority permits the requested
> action on the requested resource under the applicable constraints and evidence.

**Layer B — mathematical specification.** `permitted(authority, action, resource,
constraints, evidence)`. Outlives any particular implementation.

**Layer C — executable refinement.** A Rust function, proven to implement B.

> The project MUST avoid defining security truth solely by mirroring the current Rust
> control flow into mathematical syntax.

A formal transcription of an implementation proves that the transcription matches itself.
It will pass. It will also pass when the implementation is wrong, because the specification
was derived from the implementation and inherited its error. Layer B has to be written from
Layer A — from what the system is supposed to guarantee — and only then compared against
Layer C.

The practical test: if the specification changes every time the implementation is
refactored, it is not a specification.

---

## Reusable predicate vocabulary

Verus predicates live in `verification/verus/predicates/` and are consumed rather than
redefined. Expected shapes, to be written when the first proof needs them:

```text
valid_identity(...)
fresh_evidence(...)
authorized(...)
authority_not_amplified(...)
state_invariant(...)
transition_allowed(...)
bound_to_request(...)
```

Adding one is a security-sensitive change (§11): a predicate is where a proof's meaning
lives, and weakening one silently weakens every theorem that consumes it.
