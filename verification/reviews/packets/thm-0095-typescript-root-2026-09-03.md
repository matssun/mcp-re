<!-- SPDX-License-Identifier: Apache-2.0 -->
# Owner review packet — THM-0095, the shipped TypeScript SDK root (#747)

**One subject.** ADR-MCPRE-059 §14.7 / §28. Layer 1: evidence about the tree, not an approval
and not authoritative state. THM-0042 is not in this packet.

The sibling campaign to THM-0094's, driven to the same bar: the runtime the battery runs on
is named and measured, the support claim is bounded and gated, every declared control can
fail, the registered battery is the authoritative selector, and no assumption is left in the
closure. What follows is what changed, what was measured, and what is still outside.

---

## 1. The claim

### Title

The shipped TypeScript SDK accepts only an answer to its own request

### Statement

> For the shipped TypeScript SDK, an application is not handed, as this call's answer, a
> response from another exchange or signer, or one that verified only unbound — and is not led
> to repeat a side effect by reading silence as *it did not run*.
>
> Every reply is taken from the correlation entry the request created, and a reply binding to
> nothing outstanding, arriving late, or repeating one already answered is refused rather than
> delivered; concurrent exchanges each receive their own. A response is accepted only under a
> complete configured trust anchor — an incomplete one is refused at construction rather than
> defaulted — and only outside the revocation denylist, whose shape is checked so a bare string
> cannot spread into a per-character list. A notification is delivered only against a signed
> acknowledgement. A verified reply that is not a JSON-RPC response to this request is refused
> rather than dispatched. What the application is told about execution is what the receipt
> said: a post-dispatch rejection carries the contract it stated, a receipt that stated none is
> given none, and a local failure travels under the SDK's own prefix.

### Security consequence

> The same consequence as the Python member, over an independently implemented boundary — and
> the reason both exist is that "independently implemented" is a measured fact here rather than
> a caution. The parity fixtures are green while the two diverge behaviourally, so a root over
> one of them would report coverage of the other that no evidence supports.
>
> `invents no disposition for a receipt that stated none` is the control that names the
> difference. Inventing `not_executed` collapses "unknown whether it ran" into "it did not
> run" at the one place that decides whether a caller repeats a side effect.

### Scope

> It is one MEMBER of a root family. THM-0076 is the Rust member and THM-0094 the Python one,
> and none establishes anything about the others.
>
> CONCURRENCY AND THROUGHPUT ARE OUTSIDE IT, and the exclusion is a decision rather than an
> omission: `send_notification_verified()` running outside the concurrency bound its Python
> twin enforces (R9-C061, R9-C109, R9-C110) is a resource ceiling and changes nothing about
> authenticity, correlation or execution.
>
> ONE DEADLINE IS INSIDE IT, and it is the reason deadlines are not excluded wholesale.
> `timeoutMs` is both the per-socket inactivity bound and an aggregate wall clock on reading a
> response (R9-C095), so this SDK will abort a response whose TOTAL download exceeds it — a
> request the server may have executed. What this claim establishes is that the abort surfaces
> as a LOCAL transport outcome carrying no execution assertion, not as a clean failure a caller
> could read as "it did not run". The aggregate bound itself is deliberate: the inactivity
> bound alone bounds nothing, because every byte re-arms it.
>
> THE ABORT RESTS ON NOTHING TRUSTED, and ASM-0043 is discharged rather than renewed. The
> guard that stops a request still queued at the concurrency semaphore from being signed and
> sent after `close()` reads this transport's own state — assigned synchronously by `close()`
> before anything is aborted — rather than `AbortSignal.aborted`, so it depends on this file
> and not on a runtime semantic. The premise's other half, that an abort cannot recall what the
> server already received, is TRUE AND UNUSED: a teardown surfaces as a local outcome carrying
> no wire code and no execution or retry verdict, and asserting nothing needs no premise.
>
> THE SUPPORTED RUNTIME SET IS PART OF THE CLAIM. "The shipped TypeScript SDK" means the
> package as it runs on the runtimes it declares support for: `engines.node` admits
> `^20 || ^22 || ^24 || ^26`, and the battery runs on every one of those major lines at the
> exact versions `toolchains.lock.toml` `[typescript].interpreters` pins. The runtime identity
> is inside this unit's fingerprint, so changing a runtime drops the standing evidence instead
> of silently carrying it; a line outside the set is outside this claim; and
> `scripts/node_runtime_gate.py` refuses a support claim wider than the measured set — or, as
> this package once had, no support claim at all.

### Dependencies and owner

`depends_on = []`. `owner = "sdk_typescript.exchange_path"`, `review_requirement = "Owner
security-specification review"`, `supported_by = ["unit://sdk_typescript.exchange_path"]`.
Root-family member beside THM-0094 and THM-0076.

The last two scope paragraphs are new in this campaign: the abort premise is discharged, and
the supported runtime set is now part of the claim.

---

## 2. The runtime — from unnamed to measured

### What was measured before the work

```
supported set:      UNSTATED. package.json declared no `engines` at all
authoritative root: whatever node was on the runner's PATH, via `npx vitest`
runtime identity:   in no fingerprint
```

An absent `engines` is not a narrow claim but an unreadable one: an unstated range can be
neither satisfied nor exceeded, and every published package is then implicitly claimed to run
everywhere. That is why the Node gate treats it as a failure rather than as a permissive
default.

### What it is now

```toml
[typescript]
state = "resolved"
ecosystem = "typescript"
interpreters = ["20.20.2", "22.23.2", "24.20.0", "26.8.1"]
```

with `engines.node = "^20.0.0 || ^22.0.0 || ^24.0.0 || ^26.0.0"`.

**By major line, not by range.** Node's support lines ARE majors and the odd ones are never
LTS, so `>=20 <27` would claim 21, 23 and 25 — lines nothing measures and nothing ships. The
claim is an explicit disjunction of caret majors, exactly as vitest and the upstream MCP SDK
express theirs, and `scripts/node_runtime_gate.py` reads that form and refuses any other.

**The floor is not a preference:** `@modelcontextprotocol/client` and `…/core` both declare
`node >= 20`.

**Ecosystem-scoped**, like the Python pin: it enters TypeScript units' fingerprints only.

### How the battery is measured

`verify-tests` runs the REGISTERED selection once per pinned runtime, in a prepared
environment, and asks that runtime its own version before a single test runs — a directory
called `.node-v20` holding Node 22 is exactly the substitution the pin exists to refuse. A
missing environment is a FAIL, never a skip.

`scripts/prepare_node_matrix.sh` installs `node@<exact>` from the registry — the official
distribution, integrity-checked like any dependency, with no external version manager on the
runner deciding what the evidence describes — and builds the N-API addon ONCE, its ABI being
stable across versions by construction.

```
node-20.20.2 vitest: 33 passed
node-22.23.2 vitest: 33 passed
node-24.20.0 vitest: 33 passed
node-26.8.1  vitest: 33 passed
```

**The runtime label is the ecosystem's own.** `cpython-26.8.1` on a Node battery describes a
runtime that does not exist, so the record now names `node-26.8.1`.

---

## 3. ASM-0043 — discharged, and its two halves went for different reasons

**First half — LOCAL, and repaired.** The post-queue guard read `AbortSignal.aborted`, so the
property that a request still waiting for a concurrency slot is not signed and sent after
`close()` rested on a runtime semantic: that an already-aborted signal is observable without
yielding. `close()` assigns `#state = Closing` synchronously BEFORE it aborts anything, so the
guard now reads `#state` through one `#refuseIfClosed()` helper — an ordinary field this class
owns. This is the ruling the owner made for ASM-0042 applied to its sibling: a local
enforcement obligation does not become trusted computing base because the mechanism underneath
is foreign.

**Second half — TRUE, and unused.** Nothing local can know whether a request already on the
wire reached the server, and this SDK does not pretend to: a teardown surfaces as
`ConnectionClosed`, a local outcome carrying no wire code and no execution or retry verdict.
A premise is needed to CLAIM something; asserting nothing needs none.

Both are now registered controls:

| control | what it establishes |
|---|---|
| `does not sign or POST a request still queued at the semaphore when close() lands` | the repaired guard: with one slot occupied, two queued sends fail closed and NOTHING reaches the poster |
| `says nothing about execution when close() aborts an in-flight exchange` | the teardown carries no `mcp-re.*` code, no `executionStatus`, no `retrySafety` — the point at which the premise would have become load-bearing again |

```
id                  ASM-0043            (retired, never reused)
description         WITHDRAWN — discharged by unit://sdk_typescript.exchange_path.
scope               []
review_requirement  Withdrawn; nothing trusts it. Any future re-registration is a NEW id.
```

**Assumptions still consumed by `sdk_typescript.exchange_path`: none.**

---

## 4. Two evidence defects found by looking for the Python ones

**The aggregate deadline was measured by nothing this unit declared.** `src/mtls.ts` is inside
the unit's `paths`, so the property was in the fingerprint's source closure — while every
control over it lived in `test/mtls.test.ts` and none was registered. Exactly the gap the
Python root had. Four controls are registered now: the trickling-peer bound, the byte ceiling,
the ordinary round trip as the positive mirror, and the refusal of a timeout that cannot be
honoured.

The evidence was already production-shaped, and that is worth stating rather than assuming: a
real TLS server drips one byte every 50 ms against a 600 ms bound, read through Node's own
`https` client. Unlike the Python reader, this one arms an ABSOLUTE timer when the response
starts, so a peer that goes silent is bounded by the same deadline rather than by a second
mechanism — which is why there is no silent-peer control beside it, and why this member's cap
is the deadline rather than the deadline plus a stall.

**The forced verdicts could not track the core's shape.** Several controls override the native
binding's verdict, which is the right seam — the property is what the TRANSPORT does with a
verdict, and against a recorded receipt nothing distinguishes reading `bound` from hard-coding
it. What separately written object literals cannot do is notice a rename in the core: the
transport would read `undefined` in production while every one of them stayed green. The
members are declared once and checked against `native/binding.d.ts`, which napi GENERATES from
the Rust type, so a rename regenerates it and takes the control red.

---

## 5. Non-falsifiable declared controls — audited

| finding | disposition |
|---|---|
| the forced-verdict literals | unified behind one declared shape, checked against the generated binding declaration (§4) |
| the recorded-fixture controls (`transport_replay`) | replay REAL recorded bytes and assert the adapter reproduces the request byte-for-byte before serving each reply; a hand-rolled lookalike cannot pass |
| the injected-`poster` controls | the poster is a declared public seam of this SDK, so a fake poster IS the production contract |
| the mTLS controls | a real TLS server, real certificates, real client auth; the material is minted per run and never committed |
| the `tls()` self-skip | a registered control that skips is a lane FAILURE, so registering the four mTLS controls also removes the possibility of a silent skip standing in for evidence |

**No known non-falsifiable declared control remains in this root's battery.**

---

## 6. Adversarial and negative-control results

Every weakening below was applied, measured, and reverted.

| weakening | control that went red |
|---|---|
| declare a forced-verdict member `binding.d.ts` does not | `the forced verdicts are the core's own shape` |
| put Node 22 in the directory the v20 pin names | the lane: `the prepared environment reports '22.23.2', so the battery would be measured on a runtime the pin does not name` |
| remove a prepared environment | the lane: `no prepared environment at …` |
| omit `engines.node` / use a range form / claim a line nothing measures / measure a line outside the claim / pin a bare major / pin one major twice / unresolve the pin | `node_runtime_gate.py --selftest`, 9 cases including the positive one |

The mutation lane remains cargo-only, so these are recorded measurements rather than
`[[probe]]` entries no lane could execute.

---

## 7. Evidence and fingerprints

One unit, `unit://sdk_typescript.exchange_path`, class V0, evidence
`test://sdk_typescript/exchange_path/root_battery`, **33** declared controls (26 → 33), no
assumptions, measured on each of the four pinned runtimes.

Declared paths unchanged: `transport.ts`, `correlation.ts`, `authorization.ts`, `custody.ts`,
`mtls.ts`, `index.ts`.

| proposition | controls |
|---|---|
| correlation | concurrent replies each to their own request; no outstanding entry after a failure; a failed exchange does not take down the session; abandoned state cleared on close; the three `fails closed` cases |
| authenticity | the four incomplete-anchor refusals; the revocation-denylist shape; the two notification-acknowledgement refusals |
| terminality | a verified reply carrying a top-level method; one that is not a JSON-RPC response at all |
| execution honesty | preflight-unbound and request-bound receipts; the post-dispatch contract; **invents no disposition for a receipt that stated none**; the two peer-wire-code controls; **the teardown control of §3** |
| the deadline | the four mTLS controls of §4 |
| anti-vacuity | the forced-verdict shape control; the positive mirrors |

```
THM-0095  sha256:c84264536f3bb061904e87c25064663d4cce4dc1c00c10e149e8df6c0c9206c7
  theorem_claim         sha256:e7ebc31ab68b5309d121aa126347e30d83d2d4f2ead04b008c9b02710bd72104
  theorem_dependencies  {}
  review_requirement    Owner security-specification review

unit://sdk_typescript.exchange_path
          sha256:b51390dcd3f9f5065d4f3b67e856f52fef044f65b23cbbf3c358d7cf180cc3b6
```

Measured on the campaign branch; the merged-main values are restated in the PR that lands
this packet, and the specification review must be recorded against those.

Specification review: `UNREVIEWED`. Assumption axis: nothing left to review for this unit.

---

## 8. What is still outside

Concurrency and throughput, by the decision the scope already records — the notification path
running outside the bound its Python twin enforces (R9-C061, R9-C109, R9-C110) is a resource
ceiling and changes nothing about authenticity, correlation or execution.

R9-C095 stays open and is NOT closed by this campaign: `timeoutMs` is still both the
inactivity bound and the aggregate wall clock, with no second knob. The scope states that
conflation rather than hiding it, and what this root establishes is that the abort surfaces as
a local outcome carrying no execution assertion — not that the two bounds are separable.

The Rust and Python members. The proxy's own guarantees. Anything an application does after a
local failure, including its retry policy.
