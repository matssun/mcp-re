<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 decomposition packet — THM-0012, the runtime lifecycle record

**ADR-MCPRE-068 Phase 1.** The fourth undecomposed root, and the one ADR-MCPRE-068 §2's
measurement could not see: its table found the three roots whose *entire transitive closure
reaches no falsifier*, and THM-0012's sole unit HAS one — so it was counted as covered while
being exactly as undecomposed as THM-0091.

**Undecomposed is structural, not small, and it is also not the same property as
unfalsified.** The two measurements answer different questions and §2 recorded only one of
them.

---

## 1. The root consequence

| | |
|---|---|
| **root theorem** | THM-0012 |
| **declared root severity** | `medium` |
| **worst credible failure consequence** | an audit record shows a clean drained shutdown for a runtime that never bound a listener |
| **externally visible security failure** | the two terminal states stop being distinguishable in the record, so "this deployment served and drained" and "this deployment never started" read the same to whoever reads the record afterwards |

---

## 2. Falsifying the root statement

### F1 — the statement's second clause had no evidence, and it is the bridge

> Every state has a unique predecessor under the transition relation **and apply is the only
> mutator**, leaving the state unchanged on an illegal event. So a recorded terminal
> `Stopped` implies every event of the path … was applied, in order.

The first clause is a property of the relation and the battery establishes it — eight
controls over eleven states and ten events, with `the_relation_has_exactly_ten_legal_transitions`
pinning closure. The second clause is a property of the **type**, and nothing established it.

It is not decoration. A relation with a unique predecessor says nothing about a *recorded*
state if something other than `apply` could have written it: the conclusion is about what a
record implies, and that implication runs through the seal. A battery exercises the mutators
that exist; a seal quantifies over the ones that do not.

**This root needed NO claim correction.** Unlike THM-0094 and THM-0095, the statement was
already right; what was missing was evidence for a sentence it had asserted since
ratification. That is the cleanest case in this Phase-1 group, and it is the case the seal
census (`seals-stated-as-tested-2026-09-18.md`) was built to find — and initially missed,
because `apply is the only\nmutator` is hard-wrapped in the registry.

### F2 — the scope already answers two of the twelve questions, correctly

Recorded here because an audit that only reports defects misrepresents the tree:

- **Question 11, produced-but-not-consumed.** *`RuntimeState::admits_requests` is a
  DESCRIPTIVE value, not a control: no production path consumes it.* The scope classifies it
  as a witness and explains what actually confines requests to the serving interval —
  resource ownership, because the listener exists only inside the `serve_fleet` call. That is
  the disposition `produced-but-not-consumed` asks for, written before anything asked.
- **Question 9, unreachable branches.** *`FailedToStart` is currently unreachable from
  `Materialized`, so a serve that never bound is recorded as `Materialized` — the record is
  silent about the failure rather than wrong about it.* An unreachable branch recorded with
  its consequence rather than defended.

### F3 — what the falsification did not find

`depends_on = []` is correct: the relation reads nothing but its own state and event. The
scope's own boundary — *establishes what the RECORD can say; it does not establish that any
request was refused* — is exact, and the evidence-class sentence at the end of it (*Evidence
is `test://` only: the uniqueness-of-path argument is a match a reviewer reads, not a proof a
prover checked*) is an honest statement of the class that ADR-MCPRE-068 now gives a name to.

---

## 3. The decomposition

```
THM-0012  the lifecycle record cannot claim a shutdown that did not happen    medium
│
└── supported_by
    proxy.runtime_lifecycle                 tested      medium   8 controls, 1 probe
    proxy.runtime_lifecycle_sole_mutator    STRUCTURAL  medium   S24, S25
```

Two leaves, because the statement has two clauses and they are established by different kinds
of thing. `depends_on = []`, unchanged.

**Two probes, because there are two producer routes and they earn different refusals.**

| probe | hostile construction | refusal |
|---|---|---|
| **S24** | `RuntimeLifecycle { state: RuntimeState::Stopped }` — a lifecycle that starts at the conclusion | `E0451`, the field is private |
| **S25** | `lifecycle.state = RuntimeState::Stopped` — a holder writing the field | `E0616`, the field is private |

The hostile value in both is `Stopped`, which is exactly what the conclusion is about. S25 is
the one the statement names in so many words, and the distinction from S24 is not academic: a
holder that could assign the field would make `apply`'s refusal of an illegal event a
formality — the caller routes around it and the record still reads as a legal path.

Accepting either error code for either construction would report a refusal the probe did not
attribute, which is the rule the structural lane enforces and the reason both codes are
declared.

---

## 4. Evidence classes

`tested` for the relation, `structural` for the seal, and neither is available for the other.
No `proved` leaf: the uniqueness-of-path argument over an eleven-state relation is a finite
case analysis a battery already performs exhaustively
(`every_state_event_pair_is_either_explicitly_legal_or_rejected`), and a prover would add
nothing a reviewer cannot check. No `measured` leaf: nothing here is scoped to a corpus.

---

## 5. Premises

None. `depends_on = []` and no `[[assumption]]` is created or needed — the relation is closed
over its own vocabulary.

---

## 6. ADR-MCPRE-069 dispositions

`mcp-re-proxy/src/runtime_state.rs` holds eight test functions and all eight are registered.
Nothing to disposition — the only root in this Phase-1 group with a clean census, and worth
recording as such: a one-file unit whose battery names every control in it is what the rest
of the estate is being measured against.

---

## 7. Adequacy and the Phase-1 falsifier

| removed | the root's consequence then reachable by |
|---|---|
| `proxy.runtime_lifecycle` | an illegal event advances the state, so a recorded path was never legal |
| `proxy.runtime_lifecycle_sole_mutator` | a record is written directly at `Stopped`, and the relation's properties say nothing about how it got there |

Two NOs. The inverse question returns nothing: both clauses are load-bearing for the one
conclusion, which is what makes this a two-leaf root rather than a seven-leaf one.

**What they deliberately do NOT establish**: that any request was refused; that a serve that
never bound is recorded as a FAILURE rather than silently as `Materialized`; that
`admits_requests` governs anything. All three are in the scope, and F2 records that they were
there before this audit.

---

## 8. Phase-2 obligations

| id | obligation | severity |
|---|---|---|
| **P2-L1** | `FailedToStart` is unreachable from `Materialized`, so a serve that never bound is recorded as `Materialized`. The scope calls the record *silent about the failure rather than wrong about it*, which is true and is a weaker property than the claim's title suggests. Whether the relation should admit that edge is a product question, not an assurance one | medium |
