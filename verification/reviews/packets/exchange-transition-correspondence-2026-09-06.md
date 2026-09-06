# Exchange work/event correspondence — #583 / MCPRE-147, 2026-09-06

Backlog item 4 of the v0.17 AFK mandate. #583 asks for two deliverables: (1) a theorem
stating that emitted transitions correspond to work performed, with the five (measured:
six) assembly-owned transitions excluded by name in its scope; (2) the §5 refusal-coverage
inventory. #583 is HITL: what follows is the AFK half — inventory, theorem, evidence,
negative controls — and the issue stays open for the owner's specification review.

Baseline: `assurance/serving-interval-confinement` head `18fe41c1` (#819: THM-0100) on main
`ee18cb21` (#818: THM-0099). Slice branch `assurance/exchange-transition-correspondence`.

## 1. Deliverable 2 was already done — by THM-0081

The refusal-coverage question ("which production refusals occur before machine
construction?") has a measured answer since THM-0081 (owner `proxy.refusal_site_totality`):
`ExchangeProgress::new()` is the first statement of `handle`, so every refusal in the
handler is exchange-owned, and the answers given outside the exchange are exactly the
transport frame's four (channel/routing refusal, malformed message, oversized body, shed),
each minted in the frame's own files and reached ahead of the handler; the one
post-exchange framing fallback advertises no retry. `scripts/refusal_provenance_gate.py`
clause 12 widens the mint count to the whole workspace. The lifecycle doc §11(3) still
lists this as open and is corrected in this slice by reference, not restated.

## 2. Deliverable 1 — what existed, and what was missing

| fact | state before this slice |
|---|---|
| `Established<T>` carries a stage's product with the event it justifies; `establish()` advances then releases the value | structural, in `exchange_state.rs` |
| `#[must_use]` on the carrier | structural |
| no stage event is also advanced by the serving path; the assembly advances exactly six named events, each justified; a reintroduced or deleted advance is detected | measured by `exchange_transition_ownership_test` (4 tests) — **registered in no unit** |
| the carrier has no reader other than `establish` (private fields, one method) | true, **unmeasured**: a field widened to `pub(crate)` compiled and left every control green |
| a theorem stating any of it | **none** |

The six assembly-owned transitions (the doc says five; the control inventories six —
`TerminalResponseServed` and `OpenLegResponseServed` are two): `BackendDispatched`,
`ContinuationRetired`, `ContinuationNotRequired`, `EvidenceRetained`,
`TerminalResponseServed`, `OpenLegResponseServed`.

**The deleted-`advance` obligation** #583 names as "no evidence exists" is closed by the
stale half of the inventory control (`the_serving_path_states_only_the_assembly_s_own_transitions`
asserts that every listed event is still advanced), probed by M110.

## 3. Construction sites of `Established` (source-measured, listed once)

Every `Established::new(` in the production half of the serving path sits in the function
whose work produced the value: `forward_body_stage`, `prepare`, `observe_reply`,
`observe_acknowledgement`, `replay_admission_stage`, `answerable_stage`, `commit`,
`verify`, `transport_binding_stage` (both arms), `admission_stage`, `read_reply` (two
carriers wrapping `ValidatedReply::of(..)?` and `classify()?`), `sign_reply`. None is built
from a value obtained elsewhere. This is a reading, not a control: the carrier is
crate-constructible and the theorem's scope says so.

## 4. The theorem

THM-0101, "An emitted exchange transition corresponds to the work that justifies it,
except the six the assembly owns". Owner `unit://proxy.exchange_transition_ownership`
(new: paths `http_profile_serve/**/*.rs` + `exchange_state.rs`, overlapping
`proxy.refusal_site_totality` and `proxy.exchange_lifecycle` on purpose), supported also by
`proxy.exchange_lifecycle` for the carrier's structure, `depends_on = [THM-0043]`, no
assumption, composed at THM-0074.

| conjunct | control | probe |
|---|---|---|
| no stage event is also advanced by the assembly | `no_transition_a_stage_establishes_is_also_advanced_by_the_serving_path` | M111 (advance reintroduced beside `observe_reply`) |
| the assembly's advance set is exactly the six, both directions | `the_serving_path_states_only_the_assembly_s_own_transitions` | M110 (`ContinuationNotRequired` advance deleted) |
| each of the six states why no stage carries it | `every_assembly_owned_transition_states_why_no_stage_carries_it` | — |
| the matcher sees multi-line and post-test-module advances | `the_rule_would_catch_a_reintroduced_advance` | — (self-test) |
| the carrier has no reader but `establish`, keeps `#[must_use]`, has one method | `the_carrier_has_no_reader_but_establish` (NEW) | M112 (`value` widened to `pub(crate)`) |
| legality of every advance | THM-0043 | M-probes of `proxy.exchange_lifecycle` |

## 5. Non-claims

The six assembly-owned transitions' correspondence to the right moment is the assembly's
own statement, read by hand; the theorem says only that they are the whole residue and
that removing one is detected. Nothing about a stage's work being correct, the relation's
completeness (THM-0043) or a refusal's disposition (THM-0081). Source-text evidence:
deleting the battery leaves a reintroduced `advance` compiling.

## 6. Establishment and the issue

Probes M110–M112 red-verified on this tree. Merge condition as for #817–#819. #583's
acceptance boxes 1, 2, 3 and 4 are addressed here; box 5 (drain/lifecycle evidence cited
from the Bazel lane) does not arise — no drain result is cited; boxes 6 and 7 are the
ordinary CI and the pre-handover gate. The issue is left open for the owner's
specification review of THM-0101, which is what makes it HITL.
