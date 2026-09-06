# ASM-0029's production instance, and #598's lifecycle reconciliation — 2026-09-06

Two owner rulings of 2026-09-06, executed together because both are annotation rather than
mechanism and both touch the same question: what a document is entitled to say about
behaviour production actually has.

Baseline: main `af582442` (#825, the THM-0104 correction and the test-lane colour fix).
Slice branch `assurance/asm-0029-instance-and-598`.

## 1. ASM-0029 — instantiated, not withdrawn

> *"Do not withdraw the generic verifier premise. The generic verifier accepts an injected
> resolver, so correctness of an arbitrary injected resolver remains an interface
> assumption. Record instead that THM-0099 discharges that premise for the MCP-RE production
> resolver/composition."*

The registry entry keeps its description and its justification unchanged, and gains a closing
paragraph recording the instance. The distinction the paragraph has to carry, and does:

| | what holds |
|---|---|
| the premise | for an ARBITRARY injected resolver, the seam's answer to a queried (keyid, slot) is assumed correct. `resolve_actor` is an injected closure and `ResolvedActor` is deliberately not sealed — every in-process and test resolver is a legitimate producer, which `docs/dev/sealed-owners.md` records as measured. |
| the instance | for the resolver **the MCP-RE composition installs**, the Request-slot half is MEASURED — THM-0099 — because that resolver answers from the materialized trust snapshot, so what it returns for a queried (keyid, Request) is the deployment's own trust decision. |

**Two things the instantiation does not do**, both stated in the entry rather than left to a
reader: an embedder installing its own resolver gets the assumption and not the theorem; and
it does not reach the other selectors — the delegated claims query the seam for a
credential's root issuer kid, where the signing key is authorized by the credential chain
rather than by any seam answer, and THM-0099 says nothing about those.

### THM-0074's consequence: measured, and deliberately unchanged

The ruling says not to change it *"merely to enumerate this terminal unless measurement shows
the current consequence is semantically incomplete."* Measured — the consequence reads:

> A caller cannot reach the backend by omitting evidence, by presenting evidence for a
> different exchange, **by presenting a fact the deployment did not select the authority
> for**, by handing the pipeline a security value it constructed itself, or by having some
> other exchange's establishment succeed.

The emphasised clause already covers this terminal at the altitude a published consequence
speaks at. Naming the resolver there would make the sentence longer and no truer. **Not
changed.**

### The cascade

An assumption's text is not a review-fingerprint component, so no theorem's review record
goes stale from this edit. What moves is the assumption digest, and with it the evidence
freshness of the units that carry ASM-0029 in scope. That is re-attestation, not re-review —
routine maintenance under the mandate, and it does not touch THM-0074/0075/0076's stated
propositions at all.

## 2. #598 — model A, faithfully represented

> *"Lifecycle decision: immutable-listener model A is accepted … Safety across the change is
> cache non-continuity, not a live epoch transition in a surviving cache. Reconcile ADR/docs/
> dormant machinery accordingly."*

ADR-MCPRE-062 (Accepted, supersedes ADR-MCPRE-055) already carries the decision and
`docs/adr/README.md` already carries the supersession row, so the reconciliation owed here is
the two source comments that still asserted the superseded lifecycle:

* `SharedTlsAuthEpoch` — *"the currently-in-force epoch, swapped atomically by a trust
  reload"*;
* `EpochBoundSessionStore` — *"the epoch is a live value rather than a constant fixed at
  construction"*.

Both now say what is true: within a production listener the epoch is a **construction-time
constant**, because the CRL reload worker re-reads only CRLs and every rebuild receives the
same anchors; the change branch is kept because it makes the store's contract **total**, not
because it describes a lifecycle production has; and the safety property across an anchor-set
change is cache **non-continuity**. A `grep` over `docs/` and `mcp-re-proxy/src` now finds no
document or comment claiming a production epoch advances.

### The one scope box not executed as ADR-062 anticipated, and why

ADR-062 §4 lists, under *Retired, in the follow-up*: *"the mutable epoch wrapper **probably**
goes entirely"*. That "probably" is a question, and the answer here is measured rather than
assumed:

* `EpochBoundSessionStore::unwrap_if_current` reads the epoch and compares the stored tag on
  **every session lookup** — a live runtime check on the request path, not dormant machinery.
* What is dormant is only the **change branch** of `SharedTlsAuthEpoch::store`. Under model A
  `republish` on each rebuild publishes an identical epoch and returns `None`; the operator
  log line has never fired outside a test.
* Removing the wrapper would collapse the epoch into a construction-time constant and
  **delete a live comparison**. The tag would still have to be written and compared for the
  store's contract to be total, so the deletion buys a field's mutability and costs a runtime
  invariant.

Deleting a security check that currently executes, to tidy a dormant branch behind it, would
make an existing claim materially less true — so it is **re-scoped rather than retired**, and
flagged for the owner to overturn. If the retirement is preferred it is a small reviewable
diff, but it narrows THM-0103, so it is not taken autonomously.

## 3. What changed, and what did not

| | |
|---|---|
| production code | **none.** Two doc comments; no expression changed. |
| theorem statements, scopes, dependencies | **none.** No review fingerprint moves. |
| claims | none added, none withdrawn, none widened. ASM-0029 is instantiated for one composition and remains the premise for every other. |
| assumptions | 42 → 42. ASM-0029 is **not** discharged: an assumption with a measured instance for one caller is still an assumption for the rest. |
