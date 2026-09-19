<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-069 NP-061 — the argv routing controls, prepared for ratification

NP-061 has been split by its carriers and the classifier clause has landed. This packet is
the remainder: two controls over `mcp-re-proxy/src/cli/runtime_flags.rs` that no ratified
theorem contains, prepared as the R6 owner decision they are.

## 1. What discharged, and what this packet is about

| controls | carrier | disposition |
|---|---|---|
| 1 | `config_state/continuation_control.rs` | claimed by `[[unit]]` `proxy.continuation_control_subject_boundary`, under THM-0077, falsifier `M319` red |
| 2 | `cli/runtime_flags.rs` | **this packet** |

The two are `lib#cli::runtime_flags::tests::every_claimed_flag_routes_to_the_authority_that_owns_it`
and `lib#cli::runtime_flags::tests::the_composed_runtime_carries_the_ceiling_the_admission_authority_read`.

## 2. They are not the same proposition as the clause that landed

NP-061's statement is *the continuation-control machine does not read the replay tier* — a
SUBJECT-BOUNDARY fact about one classifier, and the landed unit states exactly it. The two
argv controls state a ROUTING fact about the command line: that each runtime flag reaches the
authority that owns it, and that the composed runtime carries the ceiling the admission
authority read. Those are claims about the adapter between argv and the owners, not about
what an owner may read, and grouping them under one unit would give one unit two
independently describable authorities — ADR-MCPRE-061 §8 question 2, whose answer would need
an "and".

They are also not a decomposition of THM-0077, whose statement quantifies over the runtime
and over materialization and serving:

> Every security capability held by the serving runtime is derived from validated semantic
> owner state. Illegal, unsupported or internally contradictory deployment postures cannot
> be silently reinterpreted into a weaker posture during materialization or serving.

What argv routes where is one layer above that, and a programmatic `DeploymentRequest` never
meets it.

## 3. The mechanical half, measured

`mcp-re-proxy/src/cli/runtime_flags.rs` is in no unit's `paths`, so R1 is unavailable:
`tools/verification/_manifest.py::_validate_in_crate_selectors` refuses a `lib#` selector
whose module path has no prefix among the unit's `paths`. Widening the landed unit's `paths`
to reach it is what ADR-069 §5 forbids.

## 4. The decision asked for

The argv boundary's theorem — the same decision NP-055's and NP-059's packets ask for. These
two controls are the sharpest statement of what it would have to say: *every claimed flag
routes to the authority that owns it* is one of the two candidate propositions NP-055's
packet names, and it is registered here as a control with no claim above it. This packet
presumes nothing about which candidate is chosen.

## 5. Terminal state until then

ADR-069 §5 step 1 — visible unresolved assurance debt. The `[[proposition]]` NP-061 entry,
its two remaining `[[disposition]]` rows and its record at
`docs/architecture/control-dispositions.md#np-061` all stay in the tree and state exactly
this. Nothing was registered to make the count fall.
