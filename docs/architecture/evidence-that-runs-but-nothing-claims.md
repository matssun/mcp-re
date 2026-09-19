<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-069 — Evidence that runs but nothing claims

**Status:** ✅ **COMPLETE** 2026-09-19. ACCEPTED 2026-09-17, subordinate to ADR-MCPRE-068.
A fresh census over the current tree derives `unclaimed + undispositioned = 0`: every
executable control in the repository is claimed by the proposition it establishes,
reattributed to the one it actually supports, identified as evidence for a proposition the
graph does not hold, or dispositioned as not assurance evidence with a durable reason. §10
is the closure report.
**Discussion:** [#968](https://github.com/matssun/mcp-re/discussions/968).
**Parent:** ADR-MCPRE-068 — *Evidence classes*
([discussion #967](https://github.com/matssun/mcp-re/discussions/967),
[`assurance-evidence-classes.md`](assurance-evidence-classes.md)). This record
is **subordinate** to it and was §8 of its revision 1. It is separated because it is a
different defect with a different deliverable, not because 068 grew too long.
**Ratification, 2026-09-17**, in the owner's words: *"Accept 069 as subordinate to 068 for
the separate Gap-D authority, rather than folding that concern back into the evidence-class
ADR. Maintain two-way cross-reference and no duplicated normative authority."* §7 is where
that boundary is kept, and §8 records what the ratification settles there.
**Predecessor:** ADR-MCPRE-059 (discussion #527, rev. 2 = the theorem registry). Nothing here
changes 059's model; this record uses it to ask a question 059 never asks.
**Assurance TCB — but with one exit that is not.** Three of this record's four dispositions
are registry bookkeeping. The fourth writes theorems, and a theorem is a product claim. §5
is where that boundary is drawn, and it is the reason this is a separate record.

---

## 1. The defect

> **A control can run, pass, and be evidence for nothing.** The verification lane selects a
> unit's `tested_symbols` with `--exact`. A test function that is not in that list executes
> on every CI run and participates in no claim: delete it and no unit's declared evidence
> changes, no ReviewFingerprint moves, and nothing goes red.

This is the **mirror image** of the defect ADR-068 exists to fix. There, evidence is
*claimed but not demonstrated* — a unit asserts a proposition and nothing shows the
proposition could fail. Here, evidence is *demonstrated but not claimed* — a control
demonstrates something real and no proposition is stated for it to be evidence of.

The two do not share a remedy. 068's remedy is an ontology: name the kind of thing that
supports a claim, and require the kind to be adequate to what the claim promises. This
record's remedy is a **census with a per-symbol disposition**, and one of its dispositions
creates propositions the registry does not currently hold.

---

## 2. What was measured

Measured by `tools/verification/evidence-class-census` over every `#[test]` / `#[tokio::test]`
function defined in a file some unit lists in `paths`, counting a function as unregistered
only when it appears in **no** unit's `tested_symbols`:

| | count |
|---|---|
| test functions inside declared unit paths | 2168 |
| of those, in no unit's declared battery | **626** |
| units with at least one such function in their own paths | 54 of 127 |

**The count is not the deliverable and must not be read as a worklist.** A file can sit in
several units' `paths`, and a test of a local helper is legitimately not a security claim's
evidence. Curation here is careful and reasoned where it has been done —
`proxy.continuation_correlation_store` annotates each registered symbol with the conjunct it
establishes, and that is the standard, not the exception.

### 2.1 The measurement is incomplete in a way that matters

The figure counts only `#[test]` and `#[tokio::test]`. It is therefore **structurally blind
to `compile_fail` doctests**, which are controls of exactly the same kind: they run in the
doc lane, they pass, and an unregistered one is evidence for nothing.

There are unregistered ones. `mcp-re-client-core/src/delegated_trust/mod.rs:52` and `:63`
each hold a hostile construction that must not compile — one proving `TrustedIssuerSet` no
longer hands out a resolver on its own, the other that the raw lifecycle lookup is no longer
public — and no unit names either. Under ADR-068 §4.1 those are `structural` controls, and
under this record they are unclaimed evidence. **This record's census must cover doctests,
and 068's did not.** That is recorded as a correction rather than a footnote, because a
census that cannot see a whole control kind will report a clean sweep over the wrong
population.

---

### 2.2 The current-tree census, and why 626 is not the worklist

**The figure above is historical and must not be used as a worklist.** It counted only
`#[test]` and `#[tokio::test]` inside declared unit paths, it predates ADR-068's
reclassifications, and by §2.1's own admission it could not see doctests at all — nor
Python, nor TypeScript, nor a gate. A campaign run against it would be a campaign against a
population that does not exist.

So the estate is measured from zero, by `tools/verification/control-census`, over every
control kind the repository's execution machinery actually supports. Measured over
`8a31332c`, the tree ADR-MCPRE-068 closed on — the instrument's own two new carriers
excluded, so the baseline describes the estate the campaign found rather than the estate
plus the thing that measured it:

| kind | lane | total | claimed | unclaimed |
|---|---|---:|---:|---:|
| `rust-test` | cargo | 3167 | 1534 | 1633 |
| `rust-doctest` | cargo | 5 | 0 | **5** |
| `pytest` | python | 809 | 88 | 721 |
| `vitest` | typescript | 184 | 161 | 23 |
| `structural` | structural lane | 25 | 25 | 0 |
| `mutation` | mutation lane | 304 | 304 | 0 |
| `measurement` | measured lane | 1 | 1 | 0 |
| `gate` | gate lane | 63 | 4 | **59** |
| **total** | | **4558** | **2117** | **2441** |

Three things in that table are the reason it was worth measuring rather than extrapolating.
**Every doctest in the repository is unclaimed** — §2.1 predicted two and there are five,
and four of the five are `compile_fail` hostile constructions, which under ADR-068 §4.1 are
`structural` controls and not behavioural evidence. **Four gates of sixty-three are claimed** — the ones ADR-068 Phase 1
registered through `gate_controls` — and the question ADR-069 asks about the other
fifty-nine is not "which unit forgot" but, gate by gate, whether it is the production
carrier of a proposition at all. And the
Python figure is an order of magnitude larger than the Rust ratio would suggest, because
the assurance platform's own self-tests are pytest controls.

### 2.3 What "claimed" means here, and the three ways this measurement could have lied

A control is **claimed** when some unit's declared evidence SELECTS it — the
`tested_symbols` entry resolves to this control in this unit's project — or, for a
registry-carried control, when a probe or measurement names a unit. **Not** when it sits in
a file a unit lists in `paths`. That distinction is the measurement: §3's worked instance
is precisely a file whose controls are two-thirds unregistered inside a unit that lists it.

The instrument therefore carries its own false-green catalogue
(`tools/verification/test_controls.py`), because a census reporting zero over the wrong
population is worse than no census:

- **a control kind going dark.** One NAMED control per ecosystem must be discovered — a lib
  test, an integration test, a binary-target test, a `compile_fail` doctest, an SDK pytest,
  a repository-tooling pytest, a vitest case, a structural probe, a mutation probe and a
  gate. A count would survive losing a whole discovery path as long as something else grew;
  a named identity does not.
- **a join that cannot see a registration.** Every `tested_symbols` selector must resolve to
  a control. Zero stale selectors is evidence in both directions at once: the lane selects
  with `--exact`, so a stale one would fail the lane, and an enumerator that had lost a
  control kind would report every selector of that kind as stale.
- **a measurement insensitive to its input.** Removing one registration must make its
  control read as unclaimed, and removing one control must make its selector stale.

**One census correction, found by reading the campaign's own prior authority rather than by
a search.** A gate is claimed through `gate_controls`, not through `tested_symbols` — ADR-068
Phase 1 built that lane, and four gates are the registered production carriers of theorems a
type could not establish, three of them `critical`. A census reading only `tested_symbols`
reported all four as unclaimed, which would have invited a `not-evidence` reason to be
written about the carrier of a critical claim. The join reads both, and a `gate_controls`
entry naming no gate is stale exactly as a `tested_symbols` entry naming no control is.

A parametrised family is ONE control identified by the TEMPLATE the source declares, and the
registry's per-case selectors are matched back to it. Expanding the family here would mean
reimplementing pytest's and vitest's id algebras — which depend on values the census never
sees — and getting that wrong in the silent direction would present a well-curated battery
as unclaimed, and invite a `not-evidence` reason to be written about somebody's declared
evidence.

## 3. The worked instance

`mcp-re-proxy/src/continuation_store/mod.rs` holds seven test functions. Two are registered
under `proxy.continuation_correlation_store`
(`one_actors_entry_is_not_reachable_by_another`,
`peek_does_not_consume_and_consume_is_one_shot`). The other five were written for R11-348:

```
the_first_open_leg_stores
a_second_open_on_a_live_key_is_refused_and_changes_nothing
concurrent_creators_yield_exactly_one_stored
an_expired_key_may_be_established_again
a_backing_failure_is_unavailable_and_never_a_collision
```

Every one passes in CI. **None of the five is in any unit's `tested_symbols`.** Read
together they establish single-writer establishment semantics — first-writer-wins under
concurrency, a live key refusing a second open without side effects, expiry reopening the
key, and a backing failure reading as unavailable rather than as a collision.

That is a real security proposition. It is also a proposition **no unit claims and no
theorem names**. The honest reading is not that a list drifted: these controls answer a
question the graph has never been told to ask.

This is why the record exists, and why it cannot be folded back into 068's Phase 0D. Acting
on this instance means writing a theorem, and ADR-068 §13 says in terms that it decides no
product claim.

---

## 4. The dispositions

**Decision D1.** The census reports, per unit, every control in that unit's own declared
paths that no unit registers. Each one is dispositioned as exactly one of:

| disposition | meaning | what lands |
|---|---|---|
| `register` | it is this unit's evidence | the symbol joins that unit's `tested_symbols` |
| `reattribute` | it is another unit's evidence | the symbol joins the other unit's battery |
| `new-proposition` | it establishes something no unit claims | §5 |
| `not-evidence` | it is a local helper's control, not a security claim's | a recorded reason, and the symbol stays unregistered |

**The dispositions are the deliverable, not the count.** A phase that reports "626 → 0" while
having reached it by any mixture of the four has said nothing about whether the registry got
more honest.

**Decision D2 — no auto-registration, ever.** Bulk-adding 626 symbols to the batteries
nearest them would inflate every unit's apparent evidence without a single new proposition
being stated, and would destroy exactly the per-symbol reasoning that makes the existing
lists worth reading. This is the same refusal ADR-068 §1 makes about falsifiers: *do not
solve the count.*

**Decision D3 — `not-evidence` carries a reason, and the reason is checked for shape, not
for truth.** A disposition with no recorded reason is not a disposition; it is the symbol
still being unregistered, with a word next to it. The gate requires the field. No gate can
decide whether "a local helper's control" is true of a given function, and pretending
otherwise would be a gate satisfying itself.

**Decision D4 — a registered symbol's disposition is not re-litigated.** Once a control is in
a unit's `tested_symbols` it is that unit's declared evidence and moves that unit's
fingerprint; it leaves the census by construction. The census measures the unregistered
residue and nothing else.

---

## 5. `new-proposition` is where this record stops being bookkeeping

Three dispositions move symbols between lists. The fourth says *a proposition is missing*,
and discharging it means writing a `[[theorem]]`, a `[[unit]]`, or both — which is a product
claim, ratified under ADR-MCPRE-059 §28 like any other, at the altitude the ratification
assigns it.

So `new-proposition` is a **two-step** disposition and the steps have different owners:

1. **Identify** — this record's census records that a named set of controls establishes a
   proposition the graph does not hold, and states the proposition in prose. Assurance TCB.
2. **Ratify** — the proposition becomes a registered claim by the ordinary theorem-
   architecture route, or it does not. Product. **Not this record's to grant.**

A `new-proposition` disposition sitting at step 1 is **visible unresolved assurance debt**, in
the same sense ADR-068 N2 gives an owner-approved `review-obligation`: it is a recorded fact
that the graph is incomplete, and it is not equivalent to completed assurance. It is reported
in the release view until it is ratified or withdrawn.

**What this record must not do is quietly widen an existing unit to swallow the proposition.**
Adding the five continuation-store controls to `proxy.continuation_correlation_store` would
make that unit's battery cover single-writer establishment semantics while its declared
proposition still says nothing about them — a unit's evidence claiming more than the unit
claims. That is `register` misapplied, and it is strictly worse than leaving the five
unregistered, because it makes the graph look complete where it is not.

---

## 6. What this record does NOT decide

- **It does not decide any of the 626.** It supplies the four dispositions and the rules for
  applying them.
- **It does not ratify any new theorem.** §5, step 2.
- **It does not change the evidence-class ontology.** Every control in scope here is
  `tested` — or, after §2.1, `structural` — and its class is not in doubt. That is ADR-068's
  subject, not this one's.
- **It does not change the lane's `--exact` selection.** Exact selection is what makes an
  unregistered control detectable at all; loosening it would delete the measurement.

---

## 7. Relationship to ADR-MCPRE-068

**069 does not block 068's phase plan, and 068 does not block 069.** The 626 are discoverable
and dispositionable against the registry as it stands today, with no schema change. 068's
Phase 0D classifies units; it does not absorb the disposition campaign.

There is one ordering fact rather than a dependency: a `new-proposition` ratified under §5
lands as a unit, and a unit landing after 068's Phase 0A must carry an `evidence_class` and a
`direct_consequence_severity` like any other. That is 068's schema doing its job, not a
sequencing constraint on this record.

**The one thing 069 owes 068** is §2.1's correction: the doctest blind spot means 068's §8
figure describes a smaller population than the defect covers, and 068 records that.

**And the boundary the ratification requires is a two-way reference with no duplicated
normative authority.** Concretely: the evidence-class ontology, the severity model, the
adequacy rules, the two ratchets and the debt registry are 068's and are not restated here;
the four dispositions, the census of unclaimed controls and the `new-proposition` route are
this record's and 068 names them rather than describing them (068 §8). Where a fact belongs
to both — a `new-proposition` that lands as a unit carries an `evidence_class` and a
`direct_consequence_severity` — the rule is 068's and the obligation to satisfy it is this
record's, which is the same shape as every other unit landing after Phase 0A.

---

## 8. Open questions, and what the ratification settles

The ratification accepted this record's authority and its separation; it did not answer the
three questions below, and it did answer one thing they were circling.

**Settled — a disposition record is not assurance debt's registry.** ADR-068's ratification
narrowed `config/assurance-obligation-debt.toml` to a migration ratchet for pre-existing
**unmet ADR-068 assurance obligations**, and forbade duplicating `assumptions.toml`. A
`new-proposition` sitting at step 1 is therefore recorded by this record's own census output
and reported in the release view, as §5 says — never as a row in 068's debt registry and
never as a premise record. It is a different fact: not *an obligation we owe and have not
discharged*, but *a control we run whose proposition is unstated*.

The three below were open at ratification. Phase 069-A answered all three from the
architecture that exists, which is what §8 asked for; each answer is recorded with the
mechanism that carries it.

1. **Is `not-evidence` load-bearing enough to need a review record? — YES, and the
   mechanism already existed.** D3 requires a reason and checks its shape; without somewhere
   durable to look the reason up, a large `not-evidence` population and a campaign that gave
   up are the same artefact, which is exactly what the question was circling. The answer is
   ADR-MCPRE-061 §14's mechanism — a named record in a committed document, cited by a field,
   with the gate failing when the cited record is absent — applied to a register of this
   record's own:
   [`control-dispositions.md`](control-dispositions.md), cited by `reason_family`.
   **A separate register rather than a shared one**, because the authorities are separate:
   061 adjudicates a unit that is too large, 069 adjudicates a control no proposition claims,
   and one register per authority is what keeps a record citable by exactly one gate. It is
   NOT a second generic debt authority: nothing is excused by a record here, a
   `not-evidence` control is still enumerated and still listed under its family, and what
   the record buys is that the reason is written once and reviewed once rather than retyped,
   slightly differently, several hundred times.
   The reason is recorded at FAMILY granularity, which is also what makes a `not-evidence`
   population readable: `n` rows citing `k` families says something a reader can check, and
   `n` free-text sentences says nothing.
2. **Does the census belong in the same tool as 068's? — TWO tools, one walk.**
   `tools/verification/_controls.py` measures what EXISTS and `_census.py` joins it to what
   is CLAIMED; 068's `evidence-class-census` continues to measure the registry's own shape.
   They are separate entry points because they answer to separate records and state separate
   verdicts, and sharing an entry point would put 069's campaign pressure on 068's report.
   They do not duplicate the walk: 069's enumeration is the only thing that reads the tree
   for controls, and 068's census reads the registry.
   The one thing that had to move is 068's own `unregistered_controls` figure, which counted
   a file once per unit whose `paths` name it and so double-counted; it is superseded by
   §2.2 and is a report, not a gate.
3. **What is the unit of a `new-proposition` disposition? — THE PROPOSITION.** §3's worked
   instance is five controls establishing one statement, and recording five separate
   dispositions would lose the only thing that makes them worth ratifying together. So
   `control-dispositions.toml` carries `[[proposition]]` records — statement, production
   carrier, likely owner, consequence, root relationship, status — and a `new-proposition`
   row on a control names the proposition it belongs to. One-control-to-one-proposition
   remains possible and is simply the degenerate case; what is refused is a campaign in
   which the cluster is not stated anywhere.

## 9. How the campaign is held

Three mechanisms, and they refuse different things.

**`tools/verification/control-census --gate`** refuses what is wrong INSIDE the tree: a
selector naming no control, a disposition about a control that is claimed or has ceased to
exist (D4), a `not-evidence` row with no reason family, a family with no record, a
`new-proposition` row naming no proposition. It does **not** refuse a large unclaimed
population — during the campaign that population is the work, and a gate that failed on it
would be pressure to bulk-register, which D2 forbids in terms.

**`scripts/control_census_gate.py`** holds the undispositioned population against a per-file
baseline in `config/control-census-debt.toml`: a registered file may not grow, an
unregistered file may carry none, and an entry whose count reaches zero is removed. So the
campaign pays yesterday's debt while a new control must be claimed or dispositioned in the
commit that introduces it. The register is per FILE rather than per control because per
control it would be 2,458 rows of bookkeeping duplicating the census, kept in step by hand.

**`--closure`** states the closure criterion itself and is the release-time question, not the
merge-time one. It carries two clauses: the residue is zero, and the recorded proposition
population is zero — §5 step 1 identifies a proposition and step 2 ratifies it, so a tree
holding `[[proposition]]` entries nobody has taken through step 2 has not closed, however
empty its residue. The merge path runs `--gate` and the per-file ratchet; running `--closure`
there would hold the merge path red for the length of the step-2 campaign, which is a verdict
nobody can act on.

---

## 10. The closure report

Derived from the tree at the campaign's close, by
`tools/verification/control-census --json` and `--closure`.

### The population

| kind | lane | total | claimed | unclaimed |
|---|---|---:|---:|---:|
| `rust-test` | cargo | 3167 | 1571 | 1596 |
| `rust-doctest` | cargo | 5 | 0 | 5 |
| `pytest` | python | 825 | 117 | 708 |
| `vitest` | typescript | 184 | 161 | 23 |
| `structural` | structural lane | 25 | 25 | 0 |
| `mutation` | mutation lane | 304 | 304 | 0 |
| `measurement` | measured lane | 1 | 1 | 0 |
| `gate` | gate lane | 64 | 4 | 60 |
| **total** | | **4575** | **2183** | **2392** |

Every ecosystem the repository supports is covered, and each is covered by a NAMED control
in `test_controls.py` rather than by a count: a lib test, an integration test, a
binary-target test, a `compile_fail` doctest, an SDK pytest, a repository-tooling pytest, a
vitest case, a structural probe, a mutation probe, a gate, a gate a unit CLAIMS, and a
control a measurement's own argv selects.

### The dispositions

| disposition | controls |
|---|---:|
| `register` / `reattribute` — landed in `verification.toml` | **63 selectors across 12 units** |
| `new-proposition` | **1641 controls across 169 propositions** |
| `not-evidence` | **751 controls across 13 reason families** |
| **undispositioned** | **0** |
| stale selectors | **0** |

### `not-evidence`, by family

| family | controls | what it covers |
|---|---:|---|
| ND-001 | 598 | the assurance platform's own self-tests |
| ND-002 | 47 | the SLO harness's own self-tests, including the Rust load harness |
| ND-011 | 38 | `ocsp.rs` — a carrier the legality model admits no deployment to reach |
| ND-008 | 17 | drivers, runners, reports and demos: not controls |
| ND-003 | 16 | assurance-process ratchets and registries |
| ND-004 | 11 | build-system, toolchain and runner wiring |
| ND-012 | 5 | fixture and report generators |
| ND-013 | 5 | demo fixture material |
| ND-005 | 4 | mirrored and documented values |
| ND-009 | 3 | data-structure API robustness |
| ND-010 | 3 | `compile_fail` doctests superseded by a structural probe |
| ND-006 | 2 | repository and build-infrastructure security controls |
| ND-007 | 2 | architecture shape rules |

**A large `not-evidence` population is not success, and this one is not what it looks
like.** 645 of the 751 — ND-001 and ND-002 — are the assurance platform's and the SLO
harness's own self-tests, dispositioned on ADR-MCPRE-068's own boundary statement: the
assurance TCB sits outside the product theorem roots and no entry there becomes a `THM-`.
A further 38 are one carrier a registered unit says is unreachable. The residue that is
`not-evidence` for an ordinary reason is 68 controls in eleven families, each with a record
in [`control-dispositions.md`](control-dispositions.md) stating what would move a control
OUT of it.

### `new-proposition` — 169, all at step 1

None is ratified. Each is recorded with its controls, its production carrier, the statement
in prose, what is false if it fails, the unit that would hold it, and its root relationship.
They are visible unresolved assurance debt and the release view reports them as such.

The largest clusters, by what they turn out to be:

| what | propositions | controls |
|---|---:|---:|
| the proxy's integration lanes — the compositions | 20 | 322 |
| the proxy's subtree modules, one authority each | 20 | 229 |
| the HTTP profile, including the signature-base layer | 19 | 219 |
| the argv boundary — `cli.rs` and its eighteen per-axis adapters | 13 | 201 |
| the conformance claim surface | 8 | 92 |
| the two shipped SDKs | 12 | 96 |
| the layer-A legality boundary — eleven unowned classifiers | 13 | 85 |
| the external transparency auditor | 5 | 58 |
| the gate lane | 8 | 9 |

### What the campaign found that a count would not have

**Six registrations that are mechanically impossible.** Five come from one fact now stated:
*a unit's battery can only select controls inside the source it measures, in the project it
measures it in.* `verify --manifests` refuses a `lib#` selector whose module the unit's
`paths` do not cover, and a unit's lane runs in one project. Where a proposition's controls
sit outside that, the honest disposition is the twin proposition, not a widened path.
NP-045, NP-048, NP-061, NP-062 and NP-078 are those five, and NP-062 is the sharpest:
**two** units state the proposition and neither owns the carrier.

The sixth is a different kind and was found by RUNNING a registration this campaign had
already written. **A unit's `test_features` are one set for the whole battery, so an
anti-vacuity control whose purpose is to FALSIFY the property cannot live in the same battery
as the property.** `client.transport_server_identity` claims that an untrusted or
wrong-identity server certificate is rejected; `fault_injection_test.rs` proves those
rejections are the verifier's work by breaking the verifier — and it compiles only under
`fault_accept_any_server`, which is off by default. Registered, then run: `0 passed; 0
filtered out`. Withdrawn, and recorded as NP-169 with the shape a ratification would have to
take.

**Three asymmetries between the two SDK system roots.** `sdk_typescript.post_close_emission`
exists and `sdk_python` has no twin (NP-014); `sdk_typescript.signer_policy` says a device
that cannot sign emits no unsigned evidence and the Python statement stops short (NP-015);
`sdk_typescript.authorization_binding` says the core digests the real artifact and no caller
supplies a digest, and the Python twin says everything after the semicolon and nothing
before it (NP-020 … NP-024, twenty-two controls). Two roots promising different things is
not a bookkeeping gap.

**Ten controls that run in no lane** (NP-009), measured in both halves and for two different
causes: a `describe.runIf` guarded on a proxy binary the vitest job never builds, and an
`importorskip("httpx")` against a lock that resolves `httpx2`. They are THM-0094's and
THM-0095's headline demonstration.

**A carrier the estate says is unreachable, with 38 careful controls over it** (ND-011), and
an exit condition that is mechanical rather than remembered.

**A layer inside fourteen fingerprints that nobody answers for**: `block.rs`, `body/` and
`sigbase.rs` are measured by ten to fourteen `http_profile` units each and claimed by none.

**`measured` has no slot for apparatus CORRECTNESS** (NP-036, NP-083). ADR-MCPRE-068 §4.1
gives a measured unit one apparatus control — the demonstration that its number can MOVE —
and a scanner that is wrong in a fixed way still moves.

### Three census corrections, each found by reading prior authority

1. **`gate_controls` is a claim.** ADR-068 Phase 1 registered four gates as the production
   carriers of theorems a type could not establish, three of them `critical`. The first join
   read only `tested_symbols` and reported all four as unclaimed.
2. **A measurement's own argv is a claim.** A `measured` unit declares no battery, and
   MSR-0001's protocol and control select three controls by name. Reading only
   `tested_symbols` would have written a `not-evidence` reason about a measurement's own
   apparatus.
3. **`describe.runIf(expr)("title", …)` nests its cases.** The scanner missed it, so the
   live end-to-end cases were enumerated WITHOUT their suite prefix — worse than losing
   them, because the identity then joins to nothing.

Each is now a named control in `test_controls.py`.

### What closure does NOT mean

- **No proposition is ratified.** 169 sit at ADR-069 §5 step 1. Ratifying one is a product
  claim under ADR-MCPRE-059 §28 and is not this record's to grant.
- **No `not-evidence` reason is certified true.** D3 checks the reason's SHAPE. What the
  campaign adds is that every reason is written once, in a durable record, with an explicit
  statement of what would move a control out of it.
- **The census is not self-validating.** It is worth exactly what `test_controls.py`
  establishes, which is what that file exists to state and what `--selftest` runs on every
  gate.
