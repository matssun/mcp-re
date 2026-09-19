<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-069 NP-055 — the argv half of the server identity, prepared for ratification

NP-055 has been split by its carriers and half of it has landed. This packet is the other
half: two controls over `mcp-re-proxy/src/cli/identity_flags.rs` that no ratified theorem
contains, prepared as the R6 owner decision they are.

## 1. What discharged, and what this packet is about

| controls | carrier | disposition |
|---|---|---|
| 5 | `config_state/server_identity.rs` | claimed by `[[unit]]` `proxy.server_identity_facts`, under THM-0077, falsifier `M310` red |
| 2 | `cli/identity_flags.rs` | **this packet** |

The two are `lib#cli::identity_flags::tests::a_complete_set_is_accepted` and
`lib#cli::identity_flags::tests::every_coordinate_is_required_and_named_when_absent`.

## 2. Why they are not a decomposition of THM-0077

THM-0077's statement is quoted in full, because the containment question is decided on its
words:

> Every security capability held by the serving runtime is derived from validated semantic
> owner state. Illegal, unsupported or internally contradictory deployment postures cannot
> be silently reinterpreted into a weaker posture during materialization or serving.

Both sentences quantify over what the RUNTIME holds and what MATERIALIZATION and SERVING do
with it. `proxy.server_identity_facts` is inside that: it is the owner state, and the theorem
promises the runtime's identity is derived from it. What argv admits is one layer above —
whether a command line that omits `--trust-domain` is answered at parse time, and with which
message. A deployment can reach the classifier without meeting a parser at all; that is the
bypass `ValidatedDeployment` exists to close, and it is exactly why the classifier's
proposition does not reach argv.

Reading the argv controls as a decomposition of THM-0077 would therefore fail subsumption
clause 2: the theorem's claim does not contain them, and neither does its scope, which
narrows rather than widens —

> SECURITY POSTURE, not liveness and not permanent runtime availability.

Nor does any other theorem in the registry. THM-0089 mentions the command line —

> consumed by the command line, the validation boundary, and the AWS-KMS…key sources alike

— but its claim is about the KMS endpoint decision, not about what argv admits, and it names
no unit whose `paths` reach `cli/`.

## 3. The mechanical half, measured

`mcp-re-proxy/src/cli.rs` and `mcp-re-proxy/src/cli/**` are in **no** unit's `paths`, so R1 is
unavailable: `tools/verification/_manifest.py::_validate_in_crate_selectors` refuses a `lib#`
selector whose module path has no prefix among the unit's `paths` —

> tested_symbol … executes code in `<pkg>/src`, but no prefix of its module path is among this
> unit's `paths`. An in-crate test whose source the unit does not measure can be rewritten
> under the same name without moving the fingerprint. Declare the module's file.

And widening `proxy.server_identity_facts`'s `paths` to reach `cli/identity_flags.rs` is
refused twice over: ADR-069 §5 forbids widening a battery past what the unit claims, and the
unit would then answer for two independently describable authorities — ADR-MCPRE-061 §8
question 2, whose answer would need an "and".

## 4. The decision asked for

**The argv boundary is an authority and needs a theorem of its own.** It is not a
single-proposition gap: the same census routes thirteen further `new-proposition` records
(NP-025…NP-035, NP-071, NP-072) and two further fragments (NP-059, NP-061) to the same
carrier, ~190 controls in all. Deciding it one fragment at a time would produce the flat
authority ADR-MCPRE-061 warns about.

What a ratified theorem over `cli.rs` + `cli/**` would have to say, and what this packet does
NOT presume:

- whether the command line's proposition is *every claimed flag routes to the authority that
  owns it* (a routing fact) or *the boundary admits no request an owner would refuse* (a
  legality fact) — the two have different falsifiers;
- its `direct_consequence_severity`, and whether it is a root or depends on THM-0077;
- whether one theorem covers the whole `cli/` family or the family splits by flag group.

## 5. Terminal state until then

ADR-069 §5 step 1 — visible unresolved assurance debt, which §10 says in terms is what
closure leaves behind. The `[[proposition]]` NP-055 entry, its two remaining
`[[disposition]]` rows and its record at
`docs/architecture/control-dispositions.md#np-055` all stay in the tree and state exactly
this. Nothing was registered to make the count fall.
