# ADR-MCPRE-068 Phase 2, slice 20 — the window and the second reader

Two probes, `M245` and `M246`, and the second is the first probe in this campaign whose
control is a **rule over source** rather than a behavioural test.

## 1. Two bounds, and the other one is the operator's

The configured TTL is what the deployment chose; the credential's `exp` is what the delegated
key actually permits. `SigningWindow::over` takes the **minimum**, and `M245` removes it.

Under the weakening a deployment with a generous TTL signs responses advertising validity
**past the credential that signed them** — so a verifier that trusts the advertised window
accepts a response whose signing authority had already lapsed.

`saturating_add` is not a second carrier of the same conjunct, and the measurement shows it:
the expired-credential control goes red too, because a wrapped sum would have compared as a
small number and the `.min` would have hidden it. Two adjacent, distinct defects; this anchor
holds only the bound.

## 2. An absence has no branch to delete

`outstanding_id_provenance` claims the serving path reads the body for *what is this request*
exactly once and never again. That is an **absence**, so the weakening ADDS the second read
rather than removing a check — and only a source-scanning control can see it.

**No behavioural test would.** On a well-formed body the two reads agree. They disagree exactly
where it matters: a body dispatched as a request and acknowledged as a notification means the
tool ran and the caller was told nothing ran.

This is worth recording as a carrier shape of its own, alongside the four from slice 4:

| shape | what the weakening does | what can see it |
|---|---|---|
| one predicate, one proposition | deletes the predicate | a behavioural control |
| composition | deletes one of several disjoint refusals | the control for that refusal |
| one construction, several conjuncts | edits the construction in place | several controls at once |
| **an absence** | **adds the forbidden thing** | **a rule over source** |
| defence in depth | must remove every carrier at once | still one measured instance |

## 3. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.response_signing` | `M245` | critical |
| `proxy.outstanding_id_provenance` | `M246` | critical |

N1 moves 38 -> 36; the probe registry 266 -> 268.

`proxy.signing_credential_provenance` is the neighbouring rule-over-source unit and is **not**
discharged here. Its rules count call sites in the composition root, and a single-anchor
weakening that changes a count without changing what the root does needs its own adjudication
rather than a quick one — deferred to its own slice, not blocked.
