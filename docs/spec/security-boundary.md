<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Security Boundary

```
STATUS:  RATIFIED — the current canonical MCP-RE security-claim boundary
         Owner: Mats Sundvall, 2026-09-01, over commit 23a727ac. See §7.
         It inherits no signature from any earlier boundary and carries its own.
         AMENDED by the owner on 2026-09-01: §4.1, the replay/continuation split.
         The amendment is recorded in place rather than folded silently into the
         ratified text — see §4.1 for what changed and why it is not a §2 weakening.
```

This document states what MCP-RE protects, and — with equal weight — what it does **not**.
It is the project's honesty gate: a reviewer who reads only this must not come away
over-trusting the system.

It replaces the signed 2026-06-23 boundary, which is preserved unedited at
[`../archive/security/security-boundary-signed-2026-06-23.md`](../archive/security/security-boundary-signed-2026-06-23.md).
That record describes the native / object profile and a single-node claim ceiling, both
historical. Its text was not rewritten under its own signatures, and this document does not
borrow them: it requires a new ratification of its own.

Authority: owner completeness ruling C, 2026-08-31 —
[`../../verification/reviews/rulings/owner-completeness-rulings-2026-08-31.md`](../../verification/reviews/rulings/owner-completeness-rulings-2026-08-31.md).

---

## 0. Three assurance surfaces, and why they are not one

A claim about MCP-RE is only meaningful once you know which surface carries it. There are
three, they are governed differently, and conflating them is how a system comes to be
described as proved when part of it was never in the argument at all.

| surface | what governs it | what a green result means |
|---|---|---|
| **Runtime theorem coverage** | the ADR-MCPRE-059 root graph — declared roots, their support closure, and the registered assumptions | a stated proposition about the running enforcement boundary, resting on named premises |
| **Deployment / release assurance** | release and conformance gates over the shipped artefacts: Helm charts, image build contexts, packaging, port registry, image tags | the artefact matches what the gates check. It is **not** a runtime theorem, and there is none |
| **Assurance platform (meta-TCB)** | the ADR-MCPRE-059 tooling itself — `tools/verification`, the manifests, the lanes | once the platform-integrity obligations are satisfied, a green result is evidence that the lane verdict may be relied upon. Known current false-green defects are disclosed in §5 and must close before final assurance closure. It is a premise of everything above it, **not** a product claim |

The theorem tree begins at an MCP-RE deployment, request or configuration boundary. It does
not attempt to prove Helm, CodeBuild, image contexts or packaging scripts as part of the
runtime protocol, and it does not recursively prove its own tooling: a proof system that
verified its own trustworthiness through the graph it runs would be asserting the thing in
question.

**Outside the runtime roots does not mean unowned.** A shipped fail-open in a Helm template
is a defect that gets fixed under release assurance; a false-green in the verification
platform is a defect that gets fixed under platform integrity. What changes across the
columns is which argument the fix belongs to, never whether it is one.

## 1. The active profile

The one live security carrier is **RFC 9421 HTTP Message Signatures + RFC 9530
Content-Digest**, implemented in `mcp-re-http-profile` (ADR-MCPRE-050).

- The native / object profile (Ed25519-over-JCS, `_meta` envelope) is **dead**. It is not an
  alternative carrier, not a fallback, and not a security mechanism. Material describing it
  is historical.
- **stdio is out of scope.** MCP-RE is HTTP-profile only; external adapters bridge
  stdio↔HTTP outside this boundary.
- Response signing is **delegated-required** (ADR-MCPRE-052). Direct-root response signing
  is not a supported mode and does not exist on the serving path.

## 2. The positive claims, and the root each rests on

Each row is a claim MCP-RE makes about itself, and the root theorem that is the argument for
it. A claim with no root in this table is not a claim this document makes.

| claim | root |
|---|---|
| A caller cannot reach the backend by omitting evidence, presenting another exchange's evidence, presenting a fact the deployment selected no authority for, or handing the pipeline a security value it constructed itself. | **THM-0074** — no unearned dispatch |
| A refusal cannot reach the dispatch, and its own effects cannot be mistaken for those of a served request — including where an approval was spent and the refusal must not read as an ordinary retry. | **THM-0078** — refusal is terminal |
| A response cannot be attributed to the trust root directly, signed by a credential the deployment does not hold or no longer holds, or advertise validity its credential does not authorize. | **THM-0075** — no unearned response attribution |
| **Through the shipped Rust client proxy**, an application is not handed, as this call's answer, a response from another exchange or signer, or one that verified only unbound — and is not led to repeat a side effect by reading silence as *it did not run*. The claim is over that implementation, not over the exchange path in general: the Python and TypeScript SDKs implement the boundary independently and are §4, not §2. | **THM-0076** — a client accepts only an answer to its own request |
| An operator cannot obtain a weaker posture by supplying a combination nobody validated, and a serving component cannot disagree with the owner about what was configured. | **THM-0077** — no unselected posture |
| A runtime that never bound a listener cannot be recorded as a clean drained shutdown. | **THM-0012** — the lifecycle record |
| An auditor cannot be shown a receipt from a log the deployment's pin does not describe, where verification runs through a pin-projected resolver. | **THM-0072** — pinned-service receipt |
| An exchange-owned refusal cannot disappear through projection or ordinary queue loss without that loss itself being represented, within the modeled in-process audit path. | **THM-0071** — typed refusal provenance reaches the record |

The full graph — every subordinate theorem, its owner unit, its evidence and its premises —
is `verification/policy/theorems.toml` and the views generated from it. This table is the
claim surface; that graph is the argument.

## 3. Explicit non-claims

MCP-RE does **not** claim any of the following. Each is stated because a reader could
otherwise reasonably infer it from a claim in §2.

**Containment.** MCP-RE is a policy enforcement point in front of an MCP server, not a
sandbox. It does not constrain what the inner server does once a request is dispatched to
it, does not isolate it, and does not bound its side effects.

**Confidentiality of retained evidence.** No confidentiality is claimed, and none would be
claimed even if retained-evidence correspondence were established: the THM-0042 branch is
about correspondence, not secrecy. A receipt does not carry the retained call bytes, and
that is all — it is not unlinkability, not resistance to inference from digests, and not
resistance to guessing a low-entropy reconstruction and confirming it against the
commitment.

**Durable audit persistence.** THM-0071 is about the modeled in-process path. If the process
disappears, records emitted and not yet drained go with it.

**That a described call ever happened.** Retained-evidence correspondence is not currently
claimed at all (§4). Even once established it would be correspondence only — whatever was
reconstructed is what was committed to — and would not establish that the retained bytes are
themselves valid evidence, nor that the reconstruction is complete.

**Anything about a non-pinned resolver.** THM-0072 says nothing about a verification
performed through a `stated` resolver, which remains a supported non-pin provenance for
prototype and conformance use.

**Cryptographic primitives.** SHA-256 collision resistance, Ed25519 and P-256 soundness, and
the correctness of foreign X.509, ASN.1 and TLS implementations are registered assumptions,
not results. They are in `verification/policy/assumptions.toml` with their consequences
stated. MCP-RE does not prove them and does not claim to.

**MCP-RE's own behaviour, where a proof lane stops at it.** Some current theorem closures
also terminate in registered assumptions over MCP-RE-owned implementation behaviour, where
the current proof or evidence lane treats that behaviour as opaque. These are named
premises, not proofs of that behaviour. They remain visible in
`verification/policy/assumptions.toml` and may later be discharged by stronger local
evidence. A premise being about code this project owns does not make it a result.

**Deployment artefacts as runtime theorems.** See §0.

## 4. Root families ruled in scope and NOT yet established

The completeness ruling of 2026-08-31 found the declared root set incomplete against this
claim surface and ruled the following in scope. **None of them is established yet**, and
until each is, MCP-RE makes no claim in that area. Where a theorem has since been WRITTEN it
is named — a written, unreviewed theorem is not an established one, and naming it here is
what keeps "the argument exists and is unreviewed" distinguishable from "no argument exists". Listing them here rather than omitting
them is the point: an unstated gap is the failure mode this document exists to prevent.

| area | disposition | placement |
|---|---|---|
| **Replay** store durability | in scope; **written, unreviewed** — THM-0086 and THM-0092 | under THM-0077 — the selected tier materializes honestly — and THM-0074: a replay state the request requires and the store cannot establish must prevent dispatch. The second rests on ASM-0040 / ASM-0041, per mechanism |
| **Continuation** correlation durability | in scope, and **not the same shape**; **written and owner-reviewed** — THM-0087 and THM-0093, with THM-0096 the materialization leaf | the capability is OPTIONAL, selected with `--continuation-control-redis-url`: an omitted flag is a legitimate OFF that installs no store and no node-local substitute, and a SELECTED capability that cannot be established refuses startup. Under THM-0077, via THM-0096: the runtime installs exactly the capability the deployment selected. Under THM-0074, via THM-0093: a leg that requires correlation fails closed rather than proceeding unbound, and an absent capability reaches it as a deployment fact rather than as the caller's forged continuation |
| Retained-evidence correspondence | in scope, **NOT CURRENTLY CLAIMED** — THM-0042 branch reopened | the corrected `submitted_commitment` proposition must be independently reviewed and established against genuine retained-evidence correspondence evidence before it returns to §2. The theorem is not to be weakened to make it green |
| Retained-evidence reservation fidelity | in scope | retained-evidence family; a pending marker may exist only under the execution threshold its owner defines |
| Outbound credential acquisition (KMS / STS / metadata / remote signer) | in scope; **written, unreviewed** — THM-0089 and THM-0090 | under THM-0077 / materialization; a credential-bearing outbound call reaches only the authority selected and validated for that capability. THM-0090 ends at the authority NAMED — the address a name resolves to is not closed |
| Client sidecar local ingress | in scope, **its own client-side root**; **declared, unreviewed** — THM-0091 | not folded into THM-0076; an unrelated browser origin or DNS-rebinding attacker must not cause a security-bearing outbound exchange |
| Python and TypeScript SDK exchange paths | in scope, as a **supported-client root family** | each independently implemented boundary gets its own root; the Rust THM-0076 is one member |
| Outbound credential acquisition (KMS / STS / metadata / remote signer) | in scope | under THM-0077 / materialization; a credential-bearing outbound call reaches only the authority selected and validated for that capability |
| Client sidecar local ingress | in scope, **its own client-side root** | not folded into THM-0076; an unrelated browser origin or DNS-rebinding attacker must not cause a security-bearing outbound exchange |
| Python and TypeScript SDK exchange paths | in scope, as a **supported-client root family**; **declared, unreviewed** — THM-0094 (Python) and THM-0095 (TypeScript) | each independently implemented boundary gets its own root; the Rust THM-0076 is one member. The parity fixtures are green while the implementations diverge behaviourally, which is why one theorem over "the SDK" would be a claim about no shipped artefact |
| Deployment rendering | **outside** the runtime roots | release / deployment conformance gates (§0) |
| The ADR-MCPRE-059 assurance platform | **outside** the product roots | assurance TCB (§0); its false-green defects are platform-integrity work |

### 4.1 Amendment — 2026-09-01

**Owner amendment, 2026-09-01.** The row above was one row reading *"Replay / continuation
store durability … the selected tier materializes honestly … a store that cannot establish
its state must prevent dispatch"*. It gave the two stores an identical shape they do not
have: the continuation correlation capability is **opportunistic** — no flag asks for it, it
appears when a shared Redis happens to be configured, and
`serving_capabilities::mrtr_continuation_store` announces its absence and starts rather than
refusing, because refusing would make every single-store deployment unstartable. The
dependent leg fails closed at the continuation binding instead.

So a single row asserting a startup refusal for both was describing behaviour the tree does
not have, and it is now two rows.

**This is a correction to a §4 branch that is explicitly NOT YET ESTABLISHED, not a
weakening of a §2 positive claim.** Neither store appears in §2, nothing moves out of §2,
and no established claim is narrowed: what changes is the accuracy of a statement about work
in scope and not yet done. A §4 row corrected toward what the code actually does is the
document working, and leaving the two shapes conflated would have made the eventual claim
easier to state than to earn.

### 4.2 Amendment — 2026-09-03

**Owner ruling, 2026-09-03 (D1b′).** The continuation row above said the capability is
*opportunistic*. That word was accurate when `serving_capabilities::mrtr_continuation_store`
had no flag of its own and appeared when a shared Redis happened to be configured for
replay. It is no longer: the capability has a dedicated selector,
`--continuation-control-redis-url`, so supplying it IS an explicit request and the
opportunistic rule must not be applied to it.

Two behaviours were corrected in the tree rather than in the prose:

- a build without the `redis_replay` backend previously ignored a non-empty plan and
  announced OFF. It now refuses startup and names the missing build capability. A selected
  security capability is never silently downgraded.
- an answer leg needing correlation in a deployment that holds none previously produced no
  retained bases and was refused downstream as `continuation_binding_failed` — a statement
  about the CALLER. It is now refused where the capability is missing, with the same
  deployment-side classification an outage earns.

The "single-replica MRTR" reading is also withdrawn. It described a fallback the shipped
composition root does not have: with no locator, `app.rs` installs no correlation store at
all, `InMemoryContinuationStore` is a test double and not a production tier, and the open leg
refuses rather than returning an elicitation nothing was kept for. No node-local tier was
installed to make the old sentence true; a node-local tier would be a separate capability
requiring its own explicit selection, and none is offered.

**This corrects a §4 branch that is not yet established, and adds one claim rather than
weakening any.** §4.1 stands as the record of the 2026-09-01 ruling it was correct under;
this supersedes it on the point of *opportunistic*, and nothing in §2 moves.

## 5. Where the boundary is currently weaker than it reads

Stated plainly, because a claim surface that hides its own open edges is worse than one that
has none.

- **THM-0042 is reopened.** Its statement now names `submitted_commitment` and refuses a
  statement that identifies no submission, and its specification review is consequently
  `STALE_CLAIM`. The claim is not established until that review is redone.
- **The `s01` SCITT interop corpus does not evidence retained-evidence correspondence.** Its
  retained artefact records handles rather than the submitted messages, so the submission
  digest is not reproducible from it. The vector is demoted in place: it evidences receipt,
  statement and key-pin interoperation and nothing more. Closing this needs a corpus produced
  by a real signed multi-hop exchange.
- **Assurance-platform false-green classes are open.** Until they are closed, the word
  ESTABLISHED carries less than it appears to. The list and its priority order are in the
  ruling record.
- **THM-0077 does not currently establish, and §2 claims it.** Its specification review is
  `STALE_DEPENDENCY_CLAIM`: the theorem's own claim text is byte-identical to the text the
  owner reviewed, and its dependency closure grew by one premise — THM-0086, the replay
  materialization leaf, which is itself reviewed and established. Nothing about the posture
  claim has weakened and no evidence stopped holding; what is missing is an owner review
  covering the closure as it now stands, which is an event that has not happened. The row
  stays in §2 rather than being moved out, because moving it would report a weakened claim
  where the fact is an unrenewed signature — but a reader must know the difference, which
  is why it is here. Root completeness: 7 of 9.
- **THM-0087 is registered and owner-reviewed** (Batch 5C, 2026-09-03). It states an
  actor-scoped, non-consuming continuation lookup. It was briefly attached to THM-0077 as if
  it were the continuation posture claim; it is not, and that edge was removed on
  2026-09-01. Its position is under THM-0074 reached through THM-0093
  (THM-0051 → THM-0087 → THM-0093 → THM-0074), which is written. There is no direct
  THM-0087 → THM-0074 edge. The posture claim THM-0077 needs is THM-0096, not this.
  **Its scope paragraph is stale and needs an owner amendment**: it says an unavailable
  shared tier does not refuse startup and that an answer leg fails closed at the binding,
  and after the 2026-09-03 continuation-capability campaign a SELECTED tier that cannot be
  established refuses startup and an absent capability is refused before the binding. The
  claim the paragraph excludes is still correctly excluded; the reason given for excluding
  it is no longer the tree's behaviour.
- **Surviving Round-9 findings.** 131 cluster dispositions are recorded in
  `verification/reviews/r9-dispositions.json`. A finding mapping to a theorem is not thereby
  closed.

## 6. What this document is not

It is not a status page, and it is not a place to record work. It states the claim boundary;
the work graph lives in the ruling record and in the ADR-MCPRE-059 registries.

The former [`v0.5-claim-matrix.md`](v0.5-claim-matrix.md) and
[`threat-coverage-matrix.md`](threat-coverage-matrix.md) are **superseded as claim
authorities** and retained as historical artefacts. They are not independently editable
sources of claim truth: a selectively updated "authoritative" document is worse than an
obviously stale one, because only the second announces itself.

## 7. Ratification

**RATIFIED by the owner — Mats Sundvall, 2026-09-01** (Europe/Stockholm), over this
document at commit `23a727ac`, following the four honesty corrections applied at that
commit. The ruling that ordered the rewrite is a separate, earlier event: owner completeness
ruling C of 2026-08-31.

Ratification is an event, not an inference: no conditional, no agreement in principle, and
no signature written on the owner's behalf. This record was written after the event, and the
text ratified is the text at `23a727ac` — the same text this file carries, with this section
and the status banner recording what happened to it.

The ratification states exactly this:

- **§2** is the positive security claim surface MCP-RE may currently make.
- **§3** is the explicit non-claim boundary.
- **§4** records security areas that are in scope but **not yet established**, and are
  therefore **not** current product claims.
- **§5** accurately discloses the known weaknesses in the current assurance state.
- The historical signed boundary remains historical and superseded.
- **It does not establish THM-0042, or any §4 root family, by declaration.**

That last clause is the load-bearing one. Ratifying a boundary that honestly says a branch is
unestablished does not establish it; it ratifies the honesty. A §4 row moves to §2 only by
being established and independently reviewed, never by this section having been signed.

Equally, this signature is not permission to weaken an existing claim. A §2 row whose
evidence stops holding leaves §2; it is not rewritten until it fits what remains.

**Amendments.** §4.1 (2026-09-01) is an owner amendment to a §4 row, made after measurement
showed the row described behaviour the tree does not have. It is recorded as an amendment
rather than an edit because the ratified text is a fixed object: a document that quietly
absorbed corrections would make "ratified at 23a727ac" mean less each time it was right.
