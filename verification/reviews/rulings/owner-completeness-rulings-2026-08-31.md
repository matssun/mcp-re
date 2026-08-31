<!-- SPDX-License-Identifier: Apache-2.0 -->

# Owner completeness rulings — 2026-08-31

```
STATUS:  OWNER DECISION RECORD
         NORMATIVE for what work exists and where it belongs
         NOT itself the claim boundary, the root graph, or a theorem
```

**Ruled by** mats@sundvall.name, 2026-08-31.
**Over** [`../packets/system-assurance-completeness-audit-2026-08-31.md`](../packets/system-assurance-completeness-audit-2026-08-31.md), re-derived against `main @ 8551061c`.

## What layer this is

The audit is a measurement. This record is the decision taken over it. Neither is the
authoritative state.

```
Layer 1   raw audit evidence          packets/system-assurance-completeness-audit-2026-08-31.md
          + r9-dispositions.json      kept permanently, NON-NORMATIVE, never edited into truth

Layer 2   owner decision record       THIS FILE
          what is in scope, what is bounded out, what may not be inferred

Layer 3   authoritative state         theorems.toml · verification.toml · assumptions.toml
          ADR-MCPRE-059 · the current security-claim boundary
          changed only by encoding a Layer-2 decision
```

The failure this separation exists to prevent is Layer 1 becoming Layer 3 — a measurement
promoted to an architecture because it was written down carefully. The audit was accepted
as a finished measurement, not as a work plan.

## The eight completeness questions

The question in each case was whether the declared root graph is a complete representation
of the **current** claim surface, not whether more theorems could exist.

**1 — Replay/continuation store durability: IN SCOPE. No new root.**
MCP-RE advertises durability tiers; their behaviour is therefore part of the security claim
and cannot be shifted onto the operator. The selected-tier/materialization proposition sits
beneath **R4** (posture). The fail-closed proposition sits beneath **R1** (dispatch safety):
a selected replay/continuation store that is unavailable, or that cannot durably establish
the state its tier promises, must prevent dispatch. A store was omitted from the graph; that
is not a reason to promote it to a root.

**2 — Retained-evidence reservation fidelity: IN SCOPE.**
A pending/retention marker is security-bearing state. It may exist only under the execution
threshold its semantic owner defines, and a pre-dispatch failure must not leave a marker
readable as executed work. Closes under the retained-evidence/accountability family, with
**R6** consuming the refusal-side relation where a pre-dispatch refusal must rescind a
reservation. The surviving `NotDispatched` / unwired-release findings are real work.

**3 — Outbound credential acquisition: IN SCOPE.**
Unambiguous once MCP-RE claims AWS KMS, GCP KMS and PKCS#11/remote custody. The proposition:
*a credential- or token-bearing outbound request reaches only the authority selected and
validated for that materialized capability.* Primarily beneath **R4**/materialization. Use
the existing `kms_endpoint_policy` authority where it honestly owns the proposition; add
review units rather than inventing another authority. The R9 critical around endpoint
re-pointing is what makes this architecture rather than plumbing.

**4 — Client-sidecar local ingress: IN SCOPE, and it gets its own client-side root.**
A shipped, supported, security-bearing local client path must not let an unrelated browser
origin or DNS-rebinding attacker cause a security-bearing outbound MCP-RE exchange. This is
independent of **R3** response acceptance and must not be folded into it.

**5 — Python and TypeScript SDK exchange paths: IN SCOPE, as a root FAMILY.**
They are shipped supported client paths with measured semantic differences in deadlines,
concurrency and receipt handling, so they may not sit outside the graph by accident. Do
**not** manufacture one language-neutral implementation theorem: where Python and TypeScript
independently implement the security boundary, each gets an independently owned root. The
existing Rust **R3** remains one member of that family.

**6 — Deployment rendering: OUTSIDE the runtime theorem roots, INSIDE release assurance.**
The semantic theorem tree begins at an MCP-RE deployment/request/configuration boundary. It
does not attempt to formally prove Helm, CodeBuild, image contexts and packaging scripts as
part of the runtime protocol. This boundary must be stated explicitly rather than left as an
omission. `OUT_OF_SCOPE` does not mean allowed to be broken: the shipped Helm fail-open is
still fixed, under release/deployment conformance gates.

**7 — The ADR-059 assurance platform: OUTSIDE the product roots, INSIDE the assurance TCB.**
A proof system may not recursively prove its own trustworthiness through the graph it runs.
The historical findings against `tools/verification` become assurance-platform integrity
debt, not product roots. But false-green defects there are what would make the word
`ESTABLISHED` unearned, so they block declaring the assurance exercise closed.

**8 — THM-0042 / `submitted_commitment`: IN SCOPE, and not by editing the sentence.**
The audit called this a statement correction; it is not. Settle and enforce the actual
semantic proposition for submitted-tail correspondence first — including the surviving
both-sides-empty, zero-verified-hop, fabricated-corpus and incomplete-field cases. Only then
restate and re-review THM-0042. Until then **the THM-0042 root branch is reopened, not
papered over.**

## Additional product completeness ruling

**The late `reject_unrepresentable_json` placement is a real defect.** It runs after nonce
consumption and continuation retirement, which contradicts the standing positive claim that
replay and approval resources are spent only for a request that legitimately progresses
through admission. Move the body-representability decision into the pre-admission
request-envelope boundary, beside its sibling shape validation, so an unrepresentable request
cannot burn replay state, retire continuation approval, or take any other irreversible
admission-side effect before refusal. Keep the semantic owner small; do not move unrelated
forwarding logic. **Do not weaken THM-0083's consequence to accommodate the current
placement** — that is the wrong direction.

## Governance ruling A — ASM-0030 and ASM-0032 are restated, not widened

The provisional scope widenings recorded in Layer 1 are **withdrawn**. A scope is not a
restatement, and widening an inaccurate premise does not make it the correct one.

- **ASM-0030** returns to its narrow meaning and scope: the foreign-parser premise about the
  URI/DNS SAN and Common Name identity fields it actually names. Credential currency needs a
  *different* foreign-parser premise — that the parser faithfully reports the issuer and
  subject `Name` encodings, the serial, and the validity instants that authority consumes —
  and that premise gets its own assumption identity.
- **ASM-0032** returns to the parsed-certificate SPKI proposition it actually states. The
  producer behind `signer.tls_public_key_spki_der()` is measured: if the relation is
  MCP-RE-owned it is established locally or structurally; if it genuinely crosses a foreign
  mechanism boundary, a new narrow assumption states *that* boundary.

Never make an inaccurate assumption true by widening its scope.

## Governance ruling B — one authoritative assumption direction

ADR-MCPRE-059 §8 is ruled. **`[[assumption]].scope` is the single authoritative
assumption→consumer relation**, because the assumption owns its own trust blast radius and
`scope` can already express both `unit://` and `boundary://`.

Authored `[[unit]].assumptions` is removed from the manifest schema after migration.
`unit → assumptions` becomes a derived relation for owner views, review packets,
blast-radius views and reviewer presentation.

The consistency gate added in Layer 1 is a **migration proof**, not the destination. The
final architecture has one authority, not two authorities and a policeman: after migration
the schema must make divergence unrepresentable.

## Governance ruling C — the current security-claim authority

The existing signed `docs/spec/security-boundary.md` is **superseded as a current claim
authority**. Its historical signed state is preserved in an explicit archive/superseded
record. Its text is **not** silently rewritten under the old signatures — that would make the
signature record dishonest.

A new canonical `docs/spec/security-boundary.md` is written for the active RFC 9421 /
RFC 9530 architecture and requires a **new owner ratification**. It contains only:

- current positive MCP-RE product-security claims;
- explicit non-claims;
- theorem-root / root-family mapping;
- the explicit distinction between runtime-theorem coverage, deployment/release assurance,
  and the ADR-059 assurance platform as meta-TCB;
- the current active profile.

The old claim and threat matrices become derived or superseded artefacts, not independently
editable competing claim authorities. Selectively updated "authoritative" prose is worse than
obviously stale prose.

**No agent signature.** The new boundary is prepared for one owner ratification return.

## Orphan theorems

Recorded, with no artificial dependency edges added:

| | disposition |
|---|---|
| THM-0002 | intentional auxiliary claim; may join the outbound-credential-acquisition closure naturally once that branch exists |
| THM-0017 | public-API security claim outside the shipped root set |
| THM-0018 | public-API security claim outside the shipped root set |

100% root reachability is not a goal. A true theorem is allowed to remain outside the
system-root closure.

## Assurance Platform Integrity campaign

One bounded campaign, after the product-completeness graph is normalized, over the surviving
false-green classes, in this priority order:

1. evidence bundle surviving a failed run
2. `trust-boundaries` policy absent from fingerprints
3. escape-hatch registration granularity
4. deleted-specification prose false positives
5. prover/solver/toolchain identity
6. proof-dependency build-manifest closure
7. boundary-class cap measured against the actual proof cone
8. lane verdict fidelity
9. undeclared verification-file ownership
10. fork-PR verification integrity
11. ASM-0016 / ASM-0017 tombstones

ASM-0016 and ASM-0017 are **reserved historical gaps** and must never be reused. No semantic
meaning is invented for them.

Platform defects do not become product theorems.

## R9

`r9-dispositions.json` stays authoritative for the 131 cluster dispositions and the Markdown
appendix is generated from it. **Do not open 96 issues.** Implementation work is grouped by
semantic defect and area.

Surviving High/Critical findings must each receive a real disposition before T6 can close:
fixed, or explicitly outside the applicable product claim under these rulings. **A High
finding is not closed merely because it maps to a theorem.**

## T6 (#542)

The R9 re-derivation criterion is satisfied. **#542 does not close yet.** It closes only
after all of:

- the completeness rulings above are encoded in the graph;
- the retained-evidence root is honest again;
- the client, outbound-credential and store branches are established or explicitly bounded;
- the new canonical security-claim boundary is owner-ratified;
- the assurance-platform false-green blockers required to trust that closure are resolved;
- surviving High/Critical R9 findings have dispositions consistent with the ratified claim
  boundary;
- the final missing-edge pass is clean.

#541 continues independently and must not influence theorem selection.

## What may not be inferred from Layer 1

- the audit's *proposed* owner decisions — superseded by this record;
- 204/482 production `.rs` files (42%) as a coverage metric or a target;
- 96 `SURVIVES_AND_MAPPED` as a defect count;
- the provisional ASM-0030 / ASM-0032 scope widenings — withdrawn by ruling A;
- any proposed new root, ahead of the ratified claim boundary.

## Human boundary

The next human boundary is the **new current security-claim boundary document**, and any
genuinely new semantic ambiguity discovered while applying these decisions. Ordinary
implementation, theorem, review-unit and PR consequences of these rulings do not return for
approval; they return as one consolidated packet.
