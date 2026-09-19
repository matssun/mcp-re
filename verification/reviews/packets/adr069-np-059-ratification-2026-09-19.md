<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-069 NP-059 — the argv half of the topology, prepared for ratification

NP-059 has been split by its carriers and the classifier half has landed. This packet is the
other half: one control over `mcp-re-proxy/src/cli/runtime_flags.rs` that no ratified theorem
contains, prepared as the R6 owner decision it is.

## 1. What discharged, and what this packet is about

| controls | carrier | disposition |
|---|---|---|
| 4 | `config_state/topology.rs` | claimed by `[[unit]]` `proxy.deployment_topology_state`, under THM-0077, falsifier `M318` red |
| 1 | `cli/runtime_flags.rs` | **this packet** |

The one is
`lib#cli::runtime_flags::tests::the_topology_counts_admit_zero_as_the_auto_posture`.

## 2. Why it is not a decomposition of THM-0077

THM-0077's statement, quoted in full because the containment question is decided on its
words:

> Every security capability held by the serving runtime is derived from validated semantic
> owner state. Illegal, unsupported or internally contradictory deployment postures cannot
> be silently reinterpreted into a weaker posture during materialization or serving.

`proxy.deployment_topology_state` is inside that: it is the owner state, and the landed unit
says that `0` is a DEFERRAL rather than a count and that the two topology axes do not
constrain each other. The argv control says something one layer above — that a command line
writing `--cores 0` PARSES, and reaches the classifier as the auto posture rather than being
refused as a zero. That is a fact about what the input boundary admits, and a
`DeploymentRequest` built in code never meets it. The classifier's proposition therefore does
not reach it, and reading it as a decomposition would fail subsumption clause 2.

The theorem's scope narrows rather than widens —

> SECURITY POSTURE, not liveness and not permanent runtime availability.

— and no other theorem in the registry names a unit whose `paths` reach `cli/`.

## 3. The mechanical half, measured

`mcp-re-proxy/src/cli.rs` and `mcp-re-proxy/src/cli/**` are in **no** unit's `paths`, so R1 is
unavailable: `tools/verification/_manifest.py::_validate_in_crate_selectors` refuses a `lib#`
selector whose module path has no prefix among the unit's `paths`. Widening
`proxy.deployment_topology_state`'s `paths` to reach `cli/runtime_flags.rs` is refused twice
over — ADR-069 §5 forbids widening a battery past what the unit claims, and the unit would
then answer for two independently describable authorities (ADR-MCPRE-061 §8 question 2,
whose answer would need an "and").

## 4. The decision asked for

The same one NP-055's packet asks for, and this fragment is evidence for its shape rather
than a separate question: **the argv boundary is an authority and needs a theorem of its
own.** Deciding it one fragment at a time would produce the flat authority ADR-MCPRE-061
warns about. This packet presumes nothing about that theorem's proposition, severity,
dependence on THM-0077, or whether the `cli/` family splits by flag group.

## 5. Terminal state until then

ADR-069 §5 step 1 — visible unresolved assurance debt. The `[[proposition]]` NP-059 entry,
its one remaining `[[disposition]]` row and its record at
`docs/architecture/control-dispositions.md#np-059` all stay in the tree and state exactly
this. Nothing was registered to make the count fall.
