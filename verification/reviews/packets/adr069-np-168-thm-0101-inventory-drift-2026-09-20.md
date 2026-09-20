<!-- SPDX-License-Identifier: Apache-2.0 -->
# NP-168 landed, and THM-0101's inventory sentence is stale — a finding this slice may not fix

**ADR-MCPRE-069 S-09/CO-S1.** NP-168's single control is now registered evidence under THM-0101
in `proxy.exchange_transition_ownership`. While establishing the containment, a drift between the
ratified statement and the implementation was measured. It is recorded here because a finding
against ratified text must be tracked rather than remembered, and because fixing it means editing
a `theorem_claim` component, which is an ADR-MCPRE-059 §28 event and outside this slice.

---

## 1. What landed

`tests/integration#exchange_transition_ownership_test::no_terminal_the_owner_publishes_is_advanced_by_the_serving_path_again`
joins the five siblings already in the unit. Measured: the file holds **six** controls
(`cargo test -p mcp-re-proxy --test integration -- --list`, 145 tests), five registered, one not —
the plan said three siblings were registered, and three is wrong.

Containment is THM-0101's disjointness conjunct, quoted verbatim and match-verified:

> The two sets are disjoint: no event a stage establishes is also advanced by the serving path, so
> no stage's fact is stated twice or remembered beside the carrier.

`EvidenceRetained`, `TerminalResponseServed` and `OpenLegResponseServed` are driven from
`ServedSuccess::tail()` in `exchange_state.rs` — the owner, outside `http_profile_serve/`. The
control scans the production half of the serving path and asserts none of the three appears in an
`.advance(`. That is the disjointness conjunct's other direction, for the three transitions that
changed sides.

## 2. THE KILL SET, WHICH IS THE POINT OF THIS REGISTRATION

`proxy.exchange_transition_ownership` already carries three probes, and two of them anchor in the
very file the control reads. **Neither kills it.**

* **M110** DELETES `progress.advance(ExchangeEvent::ContinuationNotRequired)`. A deletion adds no
  `advance`, so `RELOCATED_TO_THE_OWNER ∩ advanced` stays empty and the control stays green.
* **M111** adds `progress.advance(ExchangeEvent::ResponseObserved)`. `ResponseObserved` is in
  neither `ASSEMBLY_OWNED` nor `RELOCATED_TO_THE_OWNER`, so again green.

An anchor matching a file the control also reads is not a kill set. **M343** was written for it and
demonstrated red:

```
M343-proxy-a-published-terminal-is-advanced-by-the-serving-path-again  THM-0101
  red: …::no_terminal_the_owner_publishes_is_advanced_by_the_serving_path_again,
       …::the_serving_path_states_only_the_assembly_s_own_transitions
VERDICT: PASS
```

## 3. THE FINDING: the inventory sentence names six, the code states three

THM-0101's statement says:

> An ASSEMBLY-OWNED event is stated by a direct `advance` in the serving path, and the set of events
> stated that way is exactly the six inventoried with the reason no stage's success could carry
> each: `BackendDispatched`, `ContinuationRetired`, `ContinuationNotRequired`, `EvidenceRetained`,
> `TerminalResponseServed`, `OpenLegResponseServed`.

In the tree, `ASSEMBLY_OWNED` holds **three** — `ContinuationRetired`, `BackendDispatched`,
`ContinuationNotRequired` — and `RELOCATED_TO_THE_OWNER` holds the other three, whose whole purpose
is that the serving path does NOT advance them. The unit's own `description` repeats the stale
number: *"the assembly states exactly six named events by direct advance"*.

**The drift is pre-existing and already witnessed.** `the_serving_path_states_only_the_assembly_s_own_transitions`
asserts `declared == actual` with `declared` = the three, and it has been registered under
THM-0101 since before this slice. So the registry already contained a control the inventory
sentence contradicts; NP-168's row does not create the contradiction, it makes it two controls
instead of one.

**Why it is not fixed here.** `statement` is a `theorem_claim` component and participates in
`_fingerprint.fingerprint_theorem`. Editing it moves THM-0101's review fingerprint and is a
ratification event, which the four-clause subsumption test forbids this slice from taking. The
same applies to the unit `description`, which this slice is separately forbidden to amend.

**What the fix is, when someone has the authority.** Restate the inventory as three
assembly-advanced events plus three published from `ServedSuccess::tail()`, keeping the claim that
the six together are the whole residue. Nothing about the security content changes; only the
sentence describing where each of the six is stated.

## 4. What was NOT done

No theorem fingerprint field edited; no unit `description` amended; no `paths` widened; no probe
class substituted. Units without a theorem: 20 before, 20 after.
