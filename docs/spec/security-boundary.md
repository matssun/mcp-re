<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Security Boundary

```
STATUS:  RATIFIED — the current canonical MCP-RE security-claim boundary
         Owner: Mats Sundvall, 2026-09-01, over commit 23a727ac. See §7.
         It inherits no signature from any earlier boundary and carries its own.
         AMENDED by the owner on 2026-09-01: §4.1, the replay/continuation split.
         The amendment is recorded in place rather than folded silently into the
         ratified text — see §4.1 for what changed and why it is not a §2 weakening.
         AMENDED by the owner on 2026-09-03: THM-0042 moved §4 -> §2, by the route
         §7 reserves — established and independently reviewed — not by declaration.
         See §7.1.
         AMENDED by the owner on 2026-09-05 (v0.17 Slice A): THM-0091, THM-0094 and
         THM-0095 moved §4 -> §2 by that same route; §4 restructured and its three
         duplicated rows removed; stale sentences in §3 and §5 corrected. The
         mapping between this document's claims and the theorem registry's roots
         is now mechanically checked and cannot drift again. See §4.4 and §7.1.
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
| **Through the shipped Rust client proxy**, an application is not handed, as this call's answer, a response from another exchange or signer, or one that verified only unbound — and is not led to repeat a side effect by reading silence as *it did not run*. The claim is over that implementation, not over the exchange path in general: the Python and TypeScript members of this family are the two rows below, and neither establishes anything about this one. | **THM-0076** — a client accepts only an answer to its own request |
| **Through the shipped Python SDK**, the same: an application is not handed another exchange's answer, and the response deadline is enforced rather than suppressed by a fill-to read across several underlying reads. A separate row because the boundary is implemented independently per language and byte-level parity fixtures compare bytes, while every divergence this family exists for is behavioural. | **THM-0094** — the shipped Python SDK accepts only an answer to its own request |
| **Through the shipped TypeScript SDK**, the same claim over that implementation, for the same reason it is not folded into either row above. | **THM-0095** — the shipped TypeScript SDK accepts only an answer to its own request |
| An unrelated browser origin, or a DNS-rebinding attacker reaching the client sidecar's local listener, cannot cause it to sign and emit a security-bearing outbound exchange. The claim ends at admission: what the sidecar does with a request it admitted is the rows above. | **THM-0091** — the sidecar signs only for a request its ingress policy admitted |
| An operator cannot obtain a weaker posture by supplying a combination nobody validated, and a serving component cannot disagree with the owner about what was configured. | **THM-0077** — no unselected posture |
| A runtime that never bound a listener cannot be recorded as a clean drained shutdown. | **THM-0012** — the lifecycle record |
| An auditor cannot be shown a receipt from a log the deployment's pin does not describe, where verification runs through a pin-projected resolver. | **THM-0072** — pinned-service receipt |
| An exchange-owned refusal cannot disappear through projection or ordinary queue loss without that loss itself being represented, within the modeled in-process audit path. | **THM-0071** — typed refusal provenance reaches the record |
| An auditor cannot be shown retained evidence other than the evidence a Signed Statement was made about: the reconstruction a statement commits to is the one presented, the `ChainLabel` inside the commitment is that reconstruction's own, and a record whose submission the statement does not identify is refused rather than reported as bound on the strength of its verified prefix. | **THM-0042** — retained evidence is the evidence the statement was made about |

The full graph — every subordinate theorem, its owner unit, its evidence and its premises —
is `verification/policy/theorems.toml` and the views generated from it. This table is the
claim surface; that graph is the argument.

## 3. Explicit non-claims

MCP-RE does **not** claim any of the following. Each is stated because a reader could
otherwise reasonably infer it from a claim in §2.

**Containment.** MCP-RE is a policy enforcement point in front of an MCP server, not a
sandbox. It does not constrain what the inner server does once a request is dispatched to
it, does not isolate it, and does not bound its side effects.

**Confidentiality of retained evidence.** No confidentiality is claimed, and none follows
from retained-evidence correspondence now that THM-0042 is established: that root is about
correspondence, not secrecy. A receipt does not carry the retained call bytes, and
that is all — it is not unlinkability, not resistance to inference from digests, and not
resistance to guessing a low-entropy reconstruction and confirming it against the
commitment.

**Durable audit persistence.** THM-0071 is about the modeled in-process path. If the process
disappears, records emitted and not yet drained go with it.

**That a described call ever happened.** Retained-evidence correspondence IS claimed —
THM-0042, §2, since 2026-09-03 — and it is correspondence only: whatever was reconstructed
is what was committed to. It does not establish that the retained bytes are themselves
valid evidence, that the reconstruction is complete, or that the call it describes ever
occurred. This paragraph previously read "not currently claimed at all (§4)", which was
true when it was written and was left standing by the 2026-09-03 move; the non-claim it
makes is unchanged, and only the sentence asserting where the claim sits was wrong.

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

## 4. Root families ruled in scope, and where each now stands

The completeness ruling of 2026-08-31 found the declared root set incomplete against this
claim surface and ruled six areas in scope. This section is the record of that ruling and
of what has happened to each area since. Listing them rather than omitting them is the
point: an unstated gap is the failure mode this document exists to prevent, and an area
that closes must be visibly closed rather than quietly deleted.

**Every area the ruling named is now settled.** Three became system roots and are published
in §2; three are established subordinate claims composing under a §2 root. §4.3 records
which, and by what route. The table below therefore holds no open gap — only the two areas
the ruling placed **outside** the runtime roots, which are dispositions about where a
concern is owned rather than gaps in it.

Read the emptiness of the gap column precisely. It says the 2026-08-31 list is closed. It
does **not** say no further area exists: an area enters this section by an owner
completeness ruling and by no other route, and the v0.17 assurance census names candidates
— cross-replica trust-epoch propagation, serving-interval confinement, bounded drain —
that are **not** ruled in scope here and are therefore not claims, not gaps, and not
promises. They are census findings awaiting a ruling. A document that admitted them on its
own would be inferring a ratification, which §7 forbids in as many words.

| area | disposition | placement |
|---|---|---|
| Deployment rendering | **outside** the runtime roots | release / deployment conformance gates (§0) |
| The ADR-MCPRE-059 assurance platform | **outside** the product roots | assurance TCB (§0); its remaining defects are platform-integrity work |

### 4.3 The ruled-in areas, and how each was settled

Recorded here rather than deleted, for the reason §4.1 gives: an area that vanishes from
this document leaves a reader unable to tell a closed gap from one nobody wrote down.
Each row states the route, because the routes differ and §7 reserves only one of them for
reaching §2.

| area | settled as | route |
|---|---|---|
| **Replay** store durability | subordinate claims under §2 | THM-0086 (the selected tier materializes honestly, under THM-0077) and THM-0092 (an unestablished replay state does not dispatch, under THM-0074). What an acknowledged write DURABLY established remains a foreign premise per mechanism — ASM-0040 for Redis, ASM-0041 for etcd — and neither theorem uses it. The durability of the store is trusted, not proved, and §3 governs that |
| **Continuation** correlation durability | subordinate claims under §2 | THM-0087 and THM-0093 under THM-0074, with THM-0096 the materialization leaf under THM-0077. §4.1 and §4.2 record the two corrections this area needed before it could be stated: the capability is selected with `--continuation-control-redis-url` rather than opportunistic, and a selected capability that cannot be established refuses startup |
| Retained-evidence reservation fidelity | subordinate claim under §2 | THM-0088 — a retention artefact reads as a crossing only for an exchange that crossed — under THM-0078. The pending marker may exist only under the execution threshold its owner defines, which is what that claim states |
| Outbound credential acquisition (KMS / STS / metadata / remote signer) | subordinate claims under §2 | THM-0089 and THM-0090 under THM-0077. THM-0090 ends at the authority NAMED: the address a name resolves to is not closed, and that boundary is carried forward unchanged rather than retired with the row |
| Client sidecar local ingress | **§2 claim** — THM-0091 | established and owner-reviewed; moved by the route §7 reserves. Deliberately not folded into THM-0076: that root's subject is response acceptance, and this attack completes before any answer exists |
| Python and TypeScript SDK exchange paths | **§2 claims** — THM-0094, THM-0095 | established and owner-reviewed; moved by the same route. A supported-client root FAMILY, one member per shipped implementation. One theorem over "the SDK" would be a claim about no shipped artefact: the parity fixtures compare bytes, and every divergence the family exists for is behavioural |

The three duplicated rows this table replaces are recorded in §7.1. Each area appeared
twice with different dispositions — one row naming its theorems, one not — so the answer a
reader got depended on which row they reached first. That is now mechanically refused;
see §4.4.

### 4.4 How this section is kept honest

`scripts/claim_surface_gate.py` relates this document to
`verification/policy/theorems.toml` on every merge, and refuses six ways they can diverge:
a declared root with no §2 claim, a §2 claim naming no declared root, one root claimed
twice, a theorem both claimed in §2 and disclaimed here, a §4 area listed twice, and a §2
claim whose owner specification review no longer covers the theorem's current fingerprint.

What it deliberately does **not** do is generate the claim prose. The security consequence
a reader needs is written for that reader; a §2 built by templating theorem titles would be
a worse document that merely happened to agree with the registry. Root identity and
membership are the registry's; the human claim is this document's; only the mapping is
mechanical. And what it cannot see is stated in the gate itself: evidence freshness lives
in an attestation store that is machine-local and gitignored, so no merge-path control can
report it, and this document must never be read as asserting it.

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

- **The `s01` SCITT interop corpus does not evidence retained-evidence correspondence.** Its
  retained artefact records handles rather than the submitted messages, so the submission
  digest is not reproducible from it. The vector is demoted in place: it evidences receipt,
  statement and key-pin interoperation and nothing more, and it is deliberately NOT
  regenerated — that no MCP-RE code produced it is the whole value of that vector. The
  corpus that evidences the claim is `conformance.retained_corpus`, a signed multi-hop
  exchange this implementation produced. THM-0042 is no longer listed here: it was reopened
  when #736 replaced a curated field list with a closed canonical representation, and it
  returned to §2 on 2026-09-03 once the corrected statement was owner-reviewed and
  `review --root-completeness` reported it established. It was not weakened to get there.
- **The assurance platform's priority false-green classes are CLOSED; the class is not.**
  The four defects that directly invalidated a verdict — a stale evidence bundle surviving
  a failed run, `verify` returning 0 while printing FAIL, the five-verdict lane algebra
  collapsing so `UNAVAILABLE` and `SKIPPED` were unreachable, and the deleted-specification
  detector matching prose in a doc comment — are repaired, each with a negative control in
  the platform's own suites. What remains open is named in the ruling record and in #739,
  and none of it is in the "a verdict cannot be believed" tier. This row is not deleted:
  the reader who was told ESTABLISHED carried less than it appeared to is owed the update
  in the same place, and the residual list is still real.

- **ESTABLISHED is a statement about a measured machine, not about this commit.** The
  specification-review axis is source and travels with the repository; the evidence axis
  does not. `.verification/attestations/` is gitignored, so on a clean clone no unit is
  FRESH and no theorem derives established until a lane runs. That is correct — a claim
  about a tree nobody measured would be the false green this platform exists to refuse —
  but it means no merge-path control can report freshness, and none pretends to.
  `scripts/claim_surface_gate.py` therefore checks the mapping and the review axis, and
  says so in its own text.
- **THM-0077's stale review is CLOSED.** This row previously read "THM-0077 does not
  currently establish, and §2 claims it", on a `STALE_DEPENDENCY_CLAIM` caused by the
  dependency closure growing by one premise (THM-0086) after the owner's review. The review
  covering the closure as it now stands has since happened; the theorem's specification
  review is `REVIEWED` at its current fingerprint and it derives established. The row is
  corrected rather than deleted, because a reader who was told a §2 claim was unsigned is
  owed the retraction in the place they read it.

  The count that stood here — "Root completeness: 7 of 9" — was stale in two ways at once,
  and both are worth naming. It counted against a nine-root surface when twelve were
  declared, and it reported a shortfall that no longer existed. `tools/verification/review`
  reports 12 of 12 on a measured tree, and `scripts/claim_surface_gate.py` now refuses the
  divergence that let a hand-written count in this section disagree with the registry at
  all. **No count is restated here.** A number in this document is a second authority over
  a fact the registry owns, and restating it would rebuild exactly what the gate was
  written to prevent.
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
text ratified is the text at `23a727ac`. This file has since MOVED, and §7.1 records every
move — the ratification is not restated over the current text and does not reach it. A
document that said "the same text this file carries" while the file had changed would be
inheriting a signature the way §1 says this document refuses to.

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

### 7.1 Moves since ratification

Each row is a change to the ratified text, with the event that authorized it. Recorded here
rather than folded in, for the reason §4.1 gives: an amendment absorbed silently makes the
ratification read as covering text the owner never saw.

| date | change | authority |
|---|---|---|
| 2026-09-01 | §4.1, the replay/continuation split | owner amendment, recorded in §4.1 |
| 2026-09-03 | **THM-0042 moved §4 → §2**, its §5 open edge closed, and the §3 confidentiality non-claim restated over an established root | owner specification review of 2026-09-03 at merged main `09b5913a`, over theorem fingerprint `sha256:9d769c2c…69d03c6f`; `review --root-completeness` reported it established |
| 2026-09-05 | **THM-0091, THM-0094 and THM-0095 moved §4 → §2.** Three roots that were established and owner-reviewed while §4 still listed them as in scope and not yet established, and which §7.1 recorded no move for | owner ruling of 2026-09-05 authorizing v0.17 Slice A. Each carries a specification-review record covering its current theorem fingerprint — `verification/reviews/specification/THM-0091.json`, `THM-0094.json`, `THM-0095.json` — which is the route §7 reserves. Not a new ratification: the claims were already established, and what had failed was the record of the move |
| 2026-09-05 | **§4 restructured.** Its title stops asserting that every listed area is unestablished; the six ruled-in areas move to a new §4.3 stating how each was settled; the three DUPLICATED rows are removed; §4.4 records the gate | same ruling. The duplicates were `Outbound credential acquisition`, `Client sidecar local ingress` and `Python and TypeScript SDK exchange paths`, each present twice with different dispositions — one row naming its theorems, one not — so a reader's answer depended on which row they reached first. The de-duplication resolves in favour of the row that named its theorems, which is the more specific and was the later addition |
| 2026-09-05 | **§3's retained-evidence parenthetical corrected**, and **§5's THM-0077 and platform-false-green rows corrected** | same ruling. All three were stale in the direction of understating what holds. The non-claims and disclosures they make are unchanged; what was wrong was where each said the claim sat, and a hand-written root-completeness count that disagreed with the registry. No count is restated |
| 2026-09-05 | **§2, §4 and the theorem registry are now mechanically related** by `scripts/claim_surface_gate.py`, on the merge path | same ruling. The gate refuses a declared root with no claim, a claim with no root, a root claimed twice, a theorem both claimed and disclaimed, a duplicated §4 area, an unclassifiable §4 table, and a claim whose specification review no longer covers the theorem's current fingerprint. It does **not** generate claim prose; §4.4 states why |

The 2026-09-03 move is exactly the route the clause above reserves. THM-0042 was reopened —
not newly declared — when #736 replaced a curated field list that omitted `signature-input`
with a closed canonical representation; the statement changed, the prior review went
`STALE_CLAIM`, and the row sat in §4 until the corrected statement was reviewed on its own
terms. **The theorem was not weakened to get there**, which §4's row had required in as many
words. The `s01` non-evidence remains disclosed in §5.

Equally, this signature is not permission to weaken an existing claim. A §2 row whose
evidence stops holding leaves §2; it is not rewritten until it fits what remains.

**Amendments.** §4.1 (2026-09-01) is an owner amendment to a §4 row, made after measurement
showed the row described behaviour the tree does not have. It is recorded as an amendment
rather than an edit because the ratified text is a fixed object: a document that quietly
absorbed corrections would make "ratified at 23a727ac" mean less each time it was right.
