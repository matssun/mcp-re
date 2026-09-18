<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 finding — ten propositions over one undifferentiated unit

**ADR-MCPRE-068 Phase 1**, the audit half. Where the first three packets decomposed roots
that had no decomposition at all, this one records what the audit of the *decomposed* roots
found first, and it is the largest single defect in the estate:

> **`http_profile.verifier_results` is ONE class-V0 unit over 56 source files and 73
> controls, and TEN theorems name it in `supported_by` — nine of them titled after one of
> the nine public operations `Verifier` exposes. The theorem layer did the decomposition.
> The unit layer never followed.**

It is in the closure of **three** critical roots — THM-0074, THM-0075 and THM-0076 — so this
is not one root's finding. It is written once and referenced from all three.

---

## 1. What was measured

From `verification/policy/*.toml` on the current tree.

| | |
|---|---|
| unit | `http_profile.verifier_results`, class V0, `tested`, `critical` |
| declared `paths` | **56** — the whole of `mcp-re-http-profile/src`, plus `mcp-re-core`'s `crypto.rs`, `error.rs` and `encoding.rs` |
| declared `tested_symbols` | **73** |
| registered `mutation://` probes | **30** |
| theorems naming it in `supported_by` | **10** |

Its own `description` states the count: *"The **seven** public verifier operations and the
products they return … what a SUCCESSFUL return of each establishes."* ADR-MCPRE-061
question 2 — *how many independently describable authorities exist inside it?* — is answered
in the unit's own text, and the answer is not one.

### 1.1 The ten theorems, and the operations they are named after

| theorem | severity | `Verifier` operation |
|---|---|---|
| THM-0014 | critical | `verify_request_floor` |
| THM-0015 | critical | `verify_request` |
| THM-0016 | critical | `verify_bound_response_floor` |
| THM-0017 | high | `verify_unbound_response_floor` |
| THM-0018 | critical | `verify_bound_response` |
| THM-0019 | critical | `verify_delegated_bound_response` |
| THM-0020 | high | `verify_delegated_unbound_response` |
| THM-0021 | critical | the facts bound and unbound response verification share |
| THM-0022 | high | the same, on the unbound side |
| THM-0065 | critical | an emitted bound response signature binds the request it answers |

Nine theorems, nine `pub fn`s, one unit. The tenth (THM-0065) is about emission rather than
verification and belongs elsewhere again.

### 1.2 The probes already partition by theorem — the evidence knows the answer

Every one of the 30 probes carries a `theorem` field, and they group cleanly:

```
THM-0014  4   THM-0015  4   THM-0016  1   THM-0018  4
THM-0019  6   THM-0020  4   THM-0021  2   THM-0022  5
```

So the falsifiers are already organised along exactly the boundary the unit does not have.
Splitting the unit is largely a **re-partition of existing evidence**, not the production of
new evidence — which is why this is a Phase-1 finding with a mechanical Phase-2 discharge
rather than a research problem.

---

## 2. The three defects this shape causes, each measured

### D1 — two theorems are attacked by nothing, and N1 cannot see it

`THM-0017` and `THM-0065` have **zero** probes among the unit's thirty. They are `high` and
`critical` respectively, they are `supported_by` this unit, and the unit declares
`mutation://http_profile/verifier/result_propositions` — so N1 reads them as satisfied.

**N1 accounts per UNIT, and a unit is the falsifier boundary for every theorem that names
it.** Ten theorems inherit one unit's probe status, and two of them are established by a
battery no probe attacks. This is ADR-MCPRE-068's own defect — *a falsifier that attacks an
adjacent proposition* — one layer up, where the adjacency is between theorems rather than
between checks.

It is not a bug in N1's implementation. N1 is a rule about propositions, and the registry's
proposition-bearing object at that layer is the unit; when ten claims share one unit, the
rule has one answer for ten questions. **The fix is the split, not a change to N1.**

### D2 — a change anywhere in 56 files dirties all ten claims

`_fingerprint.fingerprint_unit` digests the declared paths. An edit to
`mcp-re-http-profile/src/body/decimal_token.rs` invalidates the standing evidence for
*A successful delegated unbound response verification establishes a chain and never a
binding*, which does not read that file. The converse is the part that matters: a reviewer
cannot tell, from the graph, which of the ten claims an edit actually touches — so
re-attestation is all-or-nothing and the blast-radius view over-reports by construction.

### D3 — 38 of 73 controls are named by no probe, and 18 of them are a different authority

The unnamed residue is not noise. Eighteen of the thirty-eight are
`lib#delegation::tests::*` — a coherent battery over `delegation/verify.rs`: credential
validity, algorithm and type, root signature, issuer trust, expiry and skew, audience,
profile, key use, trust epoch, rollout window, revocation by three identifiers, `cnf` binding
and segment count.

That is a **proposition about the credential chain**, not about "what a successful verifier
operation establishes". It has no unit of its own and is carried as supporting evidence for
whichever of the ten theorems happens to be read.

---

## 3. The proposed decomposition

Ten units where there is one, each taking the paths its proposition reads, the controls that
establish it, and the probes already tagged with its theorem.

```
http_profile.request_floor_result          THM-0014   4 probes   critical
http_profile.request_full_result           THM-0015   4 probes   critical
http_profile.bound_response_floor_result   THM-0016   1 probe    critical
http_profile.unbound_response_floor_result THM-0017   0 probes   high      ← D1
http_profile.bound_response_full_result    THM-0018   4 probes   critical
http_profile.delegated_bound_result        THM-0019   6 probes   critical
http_profile.delegated_unbound_result      THM-0020   4 probes   high
http_profile.response_shared_bound_facts   THM-0021   2 probes   critical
http_profile.response_shared_unbound_facts THM-0022   5 probes   high
http_profile.delegated_credential_chain    (new)      —          critical  ← D3
```

`THM-0065` stays with `http_profile.response_emission_binding`, which already owns emission
and is THM-0075's direct support; the audit's second finding is that THM-0065 names
`verifier_results` at all, and the edge should be dropped rather than re-pointed.

**Three obligations fall out, and each is a Phase-2 item rather than a Phase-1 one:**

| id | obligation | severity |
|---|---|---|
| **P2-V1** | `http_profile.unbound_response_floor_result` needs its first falsifier. THM-0017 is `high`, is in THM-0075's closure, and nothing attacks it today — the split makes that visible instead of inheriting a neighbour's probes | high |
| **P2-V2** | `http_profile.delegated_credential_chain` needs the theorem that states what its eighteen controls establish. That is a `new-proposition` under ADR-MCPRE-069 §5: identification is this layer's, ratification is the product's | high |
| **P2-V3** | the path partition itself. Shared files (`sigbase.rs`, `digest.rs`, `block.rs`, `error.rs`, `crypto.rs`) legitimately appear in several units; the work is deciding, per operation, which of the 56 its proposition actually reads. Overlap is allowed and expected — the eleven Phase-0D splits all share paths with their tested halves | medium |

---

## 4. Why this is stated and not taken here

The split touches three critical roots' closures at once, re-partitions 73 controls and 30
probes, and changes the fingerprint of every unit involved — which invalidates the standing
attestation for ten claims simultaneously. That is a change whose review needs the ordering
this campaign has been following: **state the graph, then discharge it.** It is the first
item of Phase 2's dependency order and the largest.

What the audit establishes now is that the boundary is wrong, where it should be, and that
the evidence to draw it already exists and is already labelled.

---

## 5. What the audit of these three roots did NOT find

- **The root statements are sound.** Unlike THM-0094 and THM-0095, none of THM-0074,
  THM-0075 or THM-0076 asserts something the production path does not do. THM-0074's
  quantifier — *every pre-dispatch security obligation selected by the validated deployment*
  — is the right shape, and its 25 premises are real edges rather than decoration.
- **`depends_on` is populated and honest** on all three, with 49, 14 and 17 theorems in their
  closures respectively.
- **The severity derivation is doing work**: 39 propositions owe more than their own label
  because a dependent declares more, which is N3 behaving as ratified.
