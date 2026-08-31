<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Security Boundary

```
STATUS:  DRAFT — PREPARED FOR OWNER RATIFICATION
         NOT SIGNED. It inherits no signature from any earlier boundary.
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
| **Assurance platform (meta-TCB)** | the ADR-MCPRE-059 tooling itself — `tools/verification`, the manifests, the lanes | you are entitled to believe a lane's verdict. It is a premise of everything above it, **not** a product claim |

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
| An application is not handed, as this call's answer, a response from another exchange or signer, or one that verified only unbound — and is not led to repeat a side effect by reading silence as *it did not run*. | **THM-0076** — a client accepts only its own answer |
| An operator cannot obtain a weaker posture by supplying a combination nobody validated, and a serving component cannot disagree with the owner about what was configured. | **THM-0077** — no unselected posture |
| A runtime that never bound a listener cannot be recorded as a clean drained shutdown. | **THM-0012** — the lifecycle record |
| An auditor cannot be shown a receipt from a log the deployment's pin does not describe, where verification runs through a pin-projected resolver. | **THM-0072** — pinned-service receipt |
| Retained evidence cannot be swapped under a receipt, a truncated call cannot become COMPLETE, and the unverified tail of an incomplete record cannot be substituted. | **THM-0042** — retained-evidence correspondence — **REOPENED, see §5** |
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

**Confidentiality of retained evidence.** THM-0042 establishes correspondence, not secrecy.
A receipt does not carry the retained call bytes, and that is all: it is not unlinkability,
not resistance to inference from digests, and not resistance to guessing a low-entropy
reconstruction and confirming it against the commitment.

**Durable audit persistence.** THM-0071 is about the modeled in-process path. If the process
disappears, records emitted and not yet drained go with it.

**That the call described ever happened.** The retained-evidence claim is correspondence
only: whatever was reconstructed is what was committed to. It does not establish that the
retained bytes are themselves valid evidence, nor that the reconstruction is complete.

**Anything about a non-pinned resolver.** THM-0072 says nothing about a verification
performed through a `stated` resolver, which remains a supported non-pin provenance for
prototype and conformance use.

**Cryptographic primitives.** SHA-256 collision resistance, Ed25519 and P-256 soundness, and
the correctness of foreign X.509, ASN.1 and TLS implementations are registered assumptions,
not results. They are in `verification/policy/assumptions.toml` with their consequences
stated. MCP-RE does not prove them and does not claim to.

**Deployment artefacts as runtime theorems.** See §0.

## 4. Root families ruled in scope and NOT yet established

The completeness ruling of 2026-08-31 found the declared root set incomplete against this
claim surface and ruled the following in scope. **None of them is established yet**, and
until each is, MCP-RE makes no claim in that area. Listing them here rather than omitting
them is the point: an unstated gap is the failure mode this document exists to prevent.

| area | disposition | placement |
|---|---|---|
| Replay / continuation store durability | in scope | under THM-0077 (selected tier materializes honestly) and THM-0074 (a store that cannot establish its state must prevent dispatch) |
| Retained-evidence reservation fidelity | in scope | retained-evidence family; a pending marker may exist only under the execution threshold its owner defines |
| Outbound credential acquisition (KMS / STS / metadata / remote signer) | in scope | under THM-0077 / materialization; a credential-bearing outbound call reaches only the authority selected and validated for that capability |
| Client sidecar local ingress | in scope, **its own client-side root** | not folded into THM-0076; an unrelated browser origin or DNS-rebinding attacker must not cause a security-bearing outbound exchange |
| Python and TypeScript SDK exchange paths | in scope, as a **supported-client root family** | each independently implemented boundary gets its own root; the Rust THM-0076 is one member |
| Deployment rendering | **outside** the runtime roots | release / deployment conformance gates (§0) |
| The ADR-MCPRE-059 assurance platform | **outside** the product roots | assurance TCB (§0); its false-green defects are platform-integrity work |

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

Not signed. This document requires an explicit owner ratification, which is an event and not
an inference — no conditional, no agreement in principle, and no signature written on the
owner's behalf.

Ratifying it means accepting §2 as the claims MCP-RE makes, §3 as the ones it refuses, §4 as
where the boundary is still being built, and §5 as where it is currently weaker than it
reads.
