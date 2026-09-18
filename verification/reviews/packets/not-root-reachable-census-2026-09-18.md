<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 census — what the estate establishes that MCP-RE does not promise

**ADR-MCPRE-068 Phase 1**, the root-set question. ADR-MCPRE-068 §2 measured it and left it
as a number:

> **42 of 127 units are not reachable from any declared root** — they support no system
> promise… *a third of the verification estate is not currently load-bearing for anything
> MCP-RE promises*, and no view says so.

0E built the view. This packet reads it. **43 units on the current tree, 28 of which owe a
falsifier** — and the ratification is explicit that the number is not a reason to invent
roots:

> Do NOT manufacture roots to absorb the measured 42… `NOT-ROOT-REACHABLE` means only: *no
> currently declared system root transitively depends on this proposition.* Phase 1 may
> discover that some reveal missing roots; **change the root set only for semantic reasons.**

This packet finds **one** semantic reason, states it under the five-step procedure, and
explains why the other 34 units are not a second one.

---

## 1. The 43, classified

| cluster | units | of which `critical` | what it is |
|---|---|---|---|
| **A — remote signing custody** | 9 | 5 | the KMS/PKCS#11 seam, its three adapters, credential lifetime, the egress bound. §2 |
| **B — no theorem names them at all** | 14 | 3 | units whose proposition nobody has stated. §3 |
| **C — library and TCB seams** | 8 | 3 | `core.*`, `host.*` — time, content addressing, audit vocabulary, the replay and trust-resolver seams |
| **D — legitimately local** | 12 | 2 | conformance scope, drain, async retention, transport hygiene, text rendering |

Cluster D needs no action and is what NOT-ROOT-REACHABLE is supposed to look like: a
proposition that is real, owned, evidenced, and simply not part of a boundary promise.

---

## 2. The candidate root — remote signing custody

Stated under ADR-MCPRE-068 Phase 1's five-step procedure for a root addition. **It is not
added here.** Root membership is owner-ratified (ADR-MCPRE-059 §21.1), and
`scripts/claim_surface_gate.py` requires a `docs/spec/security-boundary.md` §2 claim row for
every declared root — so adding one is a two-document change that needs the ratification
first.

### 1. The candidate

> **A signature MCP-RE emits under non-exporting custody verifies under the public key that
> deployment advertises, and the seam to the remote signer carries a preimage in and a
> signature out and nothing else.**

### 2. The concrete system consequence

THM-0108's own security consequence states it, and it is externally visible:

> the proxy emitting a response signature **that its own advertised public key cannot
> verify** — a signature relying parties are told to check against a key it was not made
> with.

A relying party that follows the deployment's published key and rejects the signature sees a
protocol failure. One that follows the *signature* accepts an attribution the deployment
cannot account for. Both are boundary failures, and neither is a configuration error a
deployment can observe: the proxy's startup is clean and every signature is well-formed.

### 3. Why no existing root subsumes it

| root | what it covers | why it is not this |
|---|---|---|
| THM-0075 | a response signature is attributable to a delegated credential chaining to the trust root | what a signature MEANS once made. It assumes the signature was made with the advertised key; it does not establish it |
| THM-0077 | the configuration lattice — `proxy.kms_endpoint_authority` (THM-0089) is in its closure | WHERE the proxy will talk to a signer, not WHAT crosses the seam or under which key |
| THM-0064 | non-exporting custody keeps the private key off this process — **root-reachable** | the key does not leave. Silent about whether the signature that comes back is under the key advertised |

The gap is exact and the tree already names it: THM-0064 promises the key stays away, and
nothing promises the signature comes back right. THM-0116's own consequence says so — *"this
is the half THM-0108 states cannot be established at the seam."*

### 4. Which propositions depend on its existence

| theorem | severity | unit(s) |
|---|---|---|
| THM-0108 | critical | `proxy.kms_ed25519_seam` |
| THM-0116 | high | `proxy.aws_kms_adapter`, `proxy.gcp_kms_adapter`, `proxy.pkcs11_adapter` |
| THM-0117 | high | `proxy.aws_sts_credentials`, `proxy.gcp_kms_adapter` |
| THM-0115 | medium | `proxy.remote_signer_call_aws`, `proxy.remote_signer_call_gcp` |
| — | — | `proxy.remote_signer_egress_bound`, `http_profile.delegated_signing_custody` (no theorem — §3) |

Nine units, four theorems, five of the units `critical` by their own direct label. THM-0116
already depends on THM-0108 and THM-0089, so the sub-graph is partly assembled; what it lacks
is a root above it.

### 5. Phase-1 work continues

Recorded and batched. The remaining independent Phase-1 work does not depend on this
ratification, and nothing here is encoded into `root_theorems` before it.

---

## 3. Fourteen units no theorem names

`http_profile.delegated_signing_custody` · `proxy.admission_currency_gate` ·
`proxy.authorization_capability` · `core.content_address` ·
`http_profile.bodyless_acknowledgement` · `http_profile.retained_chain_record` ·
`proxy.admission_configuration_state` (+ `_sole_producer`) ·
`proxy.authorization_configuration_state` · `proxy.operator_facing_redaction` ·
`proxy.trust_epoch_source` · `proxy.capsule_anchor_registration_leaf` ·
`proxy.scrapi_registration_leaf` · `proxy.remote_signer_egress_bound`

Three are `critical` and seven `high`. Each has a description, paths, a battery and — for
twelve of them — an N1 obligation, and **no theorem states what it establishes.** This is
ADR-MCPRE-069's `new-proposition` disposition arriving at the unit layer instead of the
control layer: the evidence is registered, the proposition is not.

It is not the same defect as cluster A. There the propositions exist and no root reaches
them; here the propositions have never been written down. **Neither is fixed by inventing a
root**, and the second is not fixed by inventing a theorem either — §5 of ADR-MCPRE-069 is
explicit that stating a claim is a product step.

`proxy.admission_configuration_state` and its `_sole_producer` sibling are the newest pair,
added by Phase 0D-13, and that landing note already recorded it: *"no theorem owns either
half, so both are NOT-ROOT-REACHABLE."* Phase 0D was right to add them anyway — the split was
about the evidence class — and right not to invent a claim for them.

**P2-N1** — write the propositions for the fourteen, or record for each why the unit
legitimately establishes nothing a claim needs. Severity order, `critical` first.

---

## 4. What this census does not conclude

- **Not that 43 is too many.** A verification estate contains propositions that are real,
  owned and evidenced without being boundary promises; cluster D is twelve of them.
- **Not that NOT-ROOT-REACHABLE lowers an obligation.** It does not, and the 28 owing units
  in this population owe exactly what their direct severity obligates — which is the whole
  content of N3's rejection of root-only severity.
- **Not that the root set is wrong.** Twelve declared roots, one candidate addition, no
  candidate removal. Removing or weakening a root remains an immediate owner escalation and
  this census proposes none.
