<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 decomposition packet — THM-0095, the shipped TypeScript SDK root

**ADR-MCPRE-068 Phase 1**, consequence-first, and the second member of the supported-client
root family. Its companion is
[`thm-0094-consequence-decomposition-2026-09-18.md`](thm-0094-consequence-decomposition-2026-09-18.md);
this packet states only what is different, and says so where it is the same. Layer 1 under
ADR-MCPRE-059 §14.7 — evidence about the tree, not an approval.

The two members are decomposed independently on purpose. THM-0095's own security consequence
says why: *the parity fixtures are green while the two diverge behaviourally*. A packet that
copied the Python analysis across would be doing exactly what the fixtures do.

**The statement itself is NOT changed by the commit that lands this decomposition**, for the
reason the Python packet gives: `scripts/claim_surface_gate.py` refuses a published root
claim whose `theorem_claim` has moved since the owner's specification review. §10 states the
corrections as exact edits, batched with the Python member's.

---

## 1. The root consequence

| | |
|---|---|
| **root theorem** | THM-0095 |
| **declared root severity** | `critical` |
| **worst credible failure consequence** | an application repeats a side effect that already ran; or acts on an answer from another exchange, another signer, or no request at all; or has a request it believes cancelled signed and sent anyway |
| **externally visible security failure** | a tool call with real-world effect executes twice, or executes after the caller cancelled it |

The third column's last clause has no Python counterpart. §2 F7 is why.

---

## 2. Falsifying the root statement

The Python packet's F1–F4 hold here too, measured independently:

- **F1 — the correlation sentence.** `#exchange` passes `take()` the id `record()` returned in
  the same loop iteration. Two of the three named refusals are unreachable from the shipped
  path; they are `CorrelationStore`'s own, at its own API. Corrected the same way, and the
  promise is better supported for naming the core's binding instead.
- **F2 — `depends_on = []` was false.** `THM-0058/0059/0060/0061` are now premises. THM-0126
  is deliberately not: the napi binding derives that fact independently.
- **F3 — the napi binding is in no unit.** `sdk/typescript/src/lib.rs` (695 lines) and
  `trust.rs` (46) build the pinned root resolver and project the core's verdict. Outside every
  fingerprint, no `#[cfg(test)]` module. No unit is invented for it. **P2-A.**
- **F4 — two stated conjuncts are outside the consequence chain.** The read bound
  (availability) and the signer/route policy (request-side attribution). A third joins them
  here: the authorization binding.

Four findings are this member's own.

### F5 — the census is far worse here, and the gap is concentrated where the claim is strongest

167 control functions in the predecessor unit's own paths; **33 declared**.

| file | controls | declared before |
|---|---|---|
| `transport.test.ts` | 69 | 29 |
| `authorization.test.ts` | 31 | **0** |
| `correlation.test.ts` | 24 | 3 |
| `custody.test.ts` | 22 | **0** |
| `transport_replay.test.ts` | 15 | **0** |
| `mtls.test.ts` | 14 | 4 |
| `parity.test.ts` | 29 | 0 |
| others | 13 | 0 |

`transport_replay.test.ts` is the one that matters most. It refuses ONE RECORDED delegated
session six ways — untrusted root anchor, stale trust epoch, wrong audience, revoked delegated
key, one appended byte, and the rejection receipt — and drives a real continuation chain to a
terminal result. That battery is the substance of the Python member's evidence, its
TypeScript twin exists and passes, and no unit named a single control of it. The root's
authenticity clause was, in this member, evidenced by constructed positives.

`authorization.test.ts`'s two seal controls — *gives a caller no way to pass a precomputed
digest*, *the generic provider cannot mint half a pair, refused independently by the native
seam* — were likewise unclaimed. They are the controls the whole bind-not-interpret rule rests
on.

### F6 — the anchor claim named four of the seven things that can be incomplete

THM-0095 says *"a complete configured trust anchor — an incomplete one is refused at
construction rather than defaulted"*. Seven members can be empty and each has a control.
Four were declared: `issuerKeyId`, `issuerPubkeyB64Url`, `expectedAudienceHash`,
`acceptedEpochs`. `issuerTrustDomain`, `issuerSubject` and `verifierAudiences` were not — so
the claim's quantifier was "no member is defaulted" and its evidence was about four of them.

All seven are now `sdk_typescript.trust_anchor_completeness`'s battery. This is the same class
of defect the Python packet found in the other direction (§2 F5 there: Python HAD the controls
and made no claim at all), and the two together are the argument for the family: one
implementation had the claim without the evidence, the other the evidence without the claim.

### F7 — a proposition this member has and the Python member does not

`sdk_typescript.post_close_emission`. After `close()`, `Promise.race` in `send()` decides
which result the CALLER sees and **does not stop the losing arm**. Without an explicit
per-leg guard, an ADR-MCPS-047 continuation chain goes on signing and POSTing fresh answer
legs — and re-prompting a human through `answerInputRequired` — after `onclose` has fired.
That hands the server a valid, fresh, correctly signed request the caller believes it
cancelled.

The Python twin needs no such proposition: its task group really cancels. **This is what the
root family is for.** Two implementations of one promise, and the set of propositions the
promise decomposes into is not the same set.

The guard reads this transport's OWN state, assigned synchronously by `close()`, rather than
`AbortSignal.aborted` — which is what discharges ASM-0043 rather than renewing it, and the
scope already says so. Twelve controls, two of them previously declared.

### F8 — what the falsification did NOT find

No claim here is true only under a configuration subset beyond the declared `engines.node`
set. No caller bypasses the named owner in a way the scope does not already exclude. The
statement's `invents no disposition` clause is exact.

---

## 3. The decomposition

```
THM-0095  the shipped TypeScript SDK accepts only an answer to its own request   critical
│
├── depends_on ─ THM-0058, THM-0059, THM-0060, THM-0061
│
└── supported_by
    exchange_binding            the verifier is given THIS transmission
    verdict_delivery            a non-success is never an acceptance; an empty code is substituted
    execution_report            only what the receipt carried is reported
    local_failure_provenance    a local condition wears no peer vocabulary
    reply_envelope              what reaches the client is rebuilt, not edited
    continuation_drive          only a terminal reply resolves the call
    correlation_lifecycle       answerable only inside its window; nothing leaks
    nonce_floor                 no request is signed under a sub-floor nonce
    notification_delivery       delivered only against a verified bound 202
    trust_anchor_completeness   no anchor member is defaulted; the denylist has a shape
    post_close_emission         nothing is signed or sent after close()          ← §2 F7

    registered, NOT in this chain:
    signer_policy               request-side attribution (22 custody controls)
    bounded_read                availability of the response read
    authorization_binding       which artefacts a request is bound to (31 controls)
```

Eleven leaves against the Python member's ten; three outside the chain against three. Every
leaf's proposition, owner, carrier, class, severity and battery is in
`verification/policy/verification.toml` beside the unit, with the ADR-069 disposition marked
per symbol. The differences from the Python member, stated once:

| | Python | TypeScript |
|---|---|---|
| post-close emission | not a proposition (the task group cancels) | a leaf, `critical` |
| read bound | aggregate + at most one per-recv; worst case stated | `timeoutMs` is both bounds, so the cap is exact |
| `correlation_lifecycle` | `high` | `high` — and its concurrency control is now claimed |
| `verdict_delivery` | — | also owns the EMPTY-wire-code substitution, where the two diverged |

---

## 4. Evidence classes

Every leaf is `tested`, and for one reason more than the Python member's: TypeScript's
compiler refuses illegal *types*, not illegal *values* built at runtime from a caller's
config object, and every seal-shaped sentence here is about the latter. `structural` would be
available for the napi binding, which is Rust — and which is not a unit (§2 F3). `proved`
propositions belong to the core and are reached through the dependency edges. Nothing here is
scoped to a corpus, so nothing is `measured`.

---

## 5. Premises and boundaries

Typed premises reach transitively through THM-0058/0059/0060/0061. No theorem→assumption edge
is created (Ruling 2).

- **ASM-0043 is discharged, not renewed** — see §2 F7 and the theorem's scope.
- **`review-obligation` P2-A** — the napi binding as an unregistered carrier.
- **External boundaries**: Node's `tls`/`http` socket semantics behind the aggregate bound;
  the upstream `@modelcontextprotocol/sdk` `Client` and its schema union, to which
  `reply_envelope` hands a rebuilt envelope; the platform CSPRNG behind `randomBytes`.

---

## 6. ADR-MCPRE-069 dispositions

| | count |
|---|---|
| control functions in the predecessor unit's paths | 167 |
| registered before | 33 |
| registered after | **172** |
| newly registered | **139** |
| dropped | 0 |

| disposition | functions | what landed |
|---|---|---|
| `register` | 139 | each named in the leaf whose proposition it establishes |
| `reattribute` | 0 | — |
| `new-proposition` | 0 registered, 29 identified | §6.1 — the parity oracle |
| `not-evidence` | 13 | §6.2 |
| **blocked** | 5 | `transport_e2e.test.ts` — §6.3 |

The count is not the deliverable. What it means is that **five of this project's eight test
files were evidence for nothing**, and three of those five hold the strongest controls the
project has.

### 6.1 The parity oracle — a `new-proposition` identified and NOT ratified here

29 controls in `parity.test.ts` (and 11 in the Python twin) establish a real proposition:
*both SDKs reproduce the frozen canonical signed preimage byte-for-byte, deterministically,
across every pinned binding form, custody class and continuation leg.* `sdk/PARITY.md` calls
it Gate 1 and states its own limit in terms: *the fixtures pin what the SDKs emit; they cannot
see what the SDKs do.*

No unit holds it, and none is created here. ADR-MCPRE-069 §5 makes `new-proposition` a
two-step disposition with different owners: identification is this layer's, ratification is
the product's. Inventing a unit to absorb 40 controls would also have to answer what its
direct consequence severity is, and that is a claim about what byte divergence between two
SDKs costs — a decision, not a measurement. It is recorded as visible unresolved assurance
debt.

**It must not become a root.** Root membership means MCP-RE makes this as a system security
promise at its boundary; cross-SDK emission parity is an internal consistency contract.

### 6.2 `not-evidence`, with reasons

- **`transport.test.ts` concurrency (11)** — the semaphore bound, six invalid-bound refusals,
  head-of-line behaviour, slot leakage. This root's scope excludes concurrency and throughput
  in terms, and the exclusion is a stated decision rather than an omission.
- **`transport.test.ts` > `still completes when no onmessage is installed` (1)** — an API
  robustness control, not a security proposition.
- **`smoke.test.ts` (2)** — non-empty-string checks over the built package's surface.

### 6.3 `transport_e2e.test.ts` does not run, here too

Five controls, `skipped` in the measured lane — the same finding as the Python member's
§6.1, reached by a different mechanism: this file needs a built `http_profile_proxy` example
that the measured lane does not build. Measured:

```
skipped  test/transport_e2e.test.ts > McpReHttpTransport (live) > fails closed on a tampered response, which never reaches the app
skipped  test/transport_e2e.test.ts > McpReHttpTransport (live) > fails closed on an unsigned response
skipped  ... 3 more
213 passed | 5 skipped
```

They stay unregistered: a declared symbol that does not run is a lane FAILURE. **P2-E**, and
it is now a family-wide finding rather than a Python one — both SDKs' live end-to-end
evidence runs nowhere, on two different causes.

---

## 7. Adequacy

Read forward, the chain is the Python member's with one insertion: after
`post_close_emission` guarantees nothing is signed once the caller has cancelled,
`exchange_binding` guarantees the verifier saw what was sent, the core premises say what the
verdict means, and the remaining nine carry it to the application without adding to it.

**What they deliberately do NOT establish**: that anything is served; that the SDK is
concurrent, fast or available; that the two SDKs emit the same bytes (§6.1); that the napi
binding's projection is faithful (P2-A); that the other two members of the family hold.

---

## 8. The Phase-1 falsifier against the decomposition

| removed | the root's consequence then reachable by |
|---|---|
| `exchange_binding` | a re-serialized body verifies against bytes the peer never saw |
| `verdict_delivery` | a signed rejection receipt is handed up as this call's result |
| `execution_report` | `not_executed` is invented for a receipt that stated nothing |
| `local_failure_provenance` | a local abort is reported as a peer wire code |
| `reply_envelope` | a reply carrying `result` AND `method` is dispatched as a server request |
| `continuation_drive` | an elicitation nobody answers surfaces as the call's answer |
| `correlation_lifecycle` | a response past the TTL is accepted; a peer grows the store |
| `nonce_floor` | a guessable nonce makes a captured answer replayable against a new request |
| `notification_delivery` | an unacknowledged notification is reported as delivered |
| `trust_anchor_completeness` | a defaulted anchor member evaluates the chain under a trust picture nobody configured |
| `post_close_emission` | a cancelled call keeps signing and POSTing fresh answer legs |

Eleven NOs. The inverse question returned `signer_policy`, `bounded_read` and
`authorization_binding`.

---

## 9. Phase-2 obligations

| id | obligation | severity |
|---|---|---|
| **P2-A** | register the napi binding (`sdk/typescript/src/lib.rs`, `trust.rs`) as a production carrier, with controls of its own. Same obligation as the Python member's, same shape, different FFI | critical |
| **P2-B** | `verify-mutations` has no vitest ecosystem, so none of these fourteen `tested` leaves can discharge N1. `_ecosystems.test_argv` and `parse_results` already adapt vitest; the lane needs them plus a runtime graft for the prepared `node_modules` the scratch copy does not carry | critical — blocks every SDK leaf |
| **P2-C** | ADR-069's census tooling is Rust-only; §6 was measured by hand from the vitest JSON report | high |
| **P2-D** | THM-0126's proposition is derived a second time in the napi binding. Remediation belongs with P2-A | medium |
| **P2-E** | `transport_e2e.test.ts` skips in both SDKs, on two different causes. Decide whether the live lane is a registered battery or independent evidence, and make it say which | high |
| **P2-F** | the parity oracle is an identified, unratified proposition over 40 controls in two projects (§6.1). Ratify it at the right altitude or withdraw it | medium |

---

## 10. The claim corrections requested, and not taken

The Python member's C1–C5 apply here unchanged in kind (§2 F1–F4): narrow the correlation
sentence to what `#exchange` reaches, add
`depends_on = ["THM-0058", "THM-0059", "THM-0060", "THM-0061"]`, record the napi binding as
an uncovered carrier, move the read bound from the claim to a stated non-claim, and exclude
request-side attribution by naming the two units that hold it. None weakens the promise.

Three are this member's own:

**C6 — state the post-close clause** (§2 F7). *After `close()`, nothing further is signed or
transmitted: a request still queued at the concurrency semaphore is not signed or POSTed, and
a continuation chain stops rather than signing a fresh answer leg or prompting a human for
one.* Twelve controls carry it and `sdk_typescript.post_close_emission` owns it. The scope's
existing ASM-0043 paragraph already argues the guard reads this transport's own state rather
than a runtime semantic, so the claim is supported by text the owner has already reviewed —
what is missing is the sentence in the statement.

**C7 — quantify the anchor clause honestly** (§2 F6). The statement says *a complete
configured trust anchor — an incomplete one is refused at construction rather than
defaulted*; all seven members are now evidenced, so the claim and its evidence agree for the
first time. No wording change is strictly required, and the recommended one makes the
quantifier explicit (*no member of it is defaulted*) so a future eighth member is visibly
inside the claim.

**C8 — record that `verdict_delivery` owns the empty-wire-code substitution**, which is a
place the two SDKs diverged and which the present statement does not mention.

Applying them is one edit to the entry followed by
`tools/verification/review --fingerprint THM-0095`.
