# ADR-MCPRE-068 Phase 2, slice 31 — indeterminate is the true answer

Four probes, `M275`–`M278`, and the medium band closes except for one unit.

## 1. Two registration leaves, two falsifiers, one question

capsule-anchor and SCRAPI answer the same question — **is this statement registered?** —
through different contracts, and each decides certainty in its own code.

`M275` weakens SCRAPI's mapping and leaves capsule-anchor's controls green. `M277` weakens
capsule-anchor's and leaves SCRAPI's green. That is what makes the mechanism-leaf split
load-bearing rather than tidy: a fix to one would not reach the other, so each needs its own
probe.

**The conjunct is the conservative direction in both.** An answer this profile cannot read, or
an exchange that did not complete, says nothing about whether the service ACCEPTED the
statement — the bytes went out and what came back was unreadable. Reporting that as a refusal
sends an operator to re-submit a record the log may already hold, and **a transparency log with
two entries for one call is a worse record than a missing one**, because nothing later can tell
which is the duplicate.

## 2. Prose where a classifier reads a service's own words

When a credential retry fails an operator needs both halves: the 401 that caused the retry, and
the second failure. The obvious way to keep them is to append the cause to the body — and that
is exactly what `M276` does.

It puts an operator-facing sentence into the field `quota_signals` reads for a stated error
name. The classifier looks for one provider's exhaustion vocabulary in the **service's own
answer**; a chained cause is not that answer, so a body containing one can state a quota the
service never stated, and the retry window arms on a sentence this process wrote about itself.

## 3. Off by one is the whole weakening

`M278` uses `ceiling + 1` rather than deleting the comparison, because the interesting failure
is not *no ceiling* — it is a ceiling that is not the number the operator set.

The control that sees it is the **zero** one: a ceiling of zero must admit nothing, and under
`ceiling + 1` it admits exactly one worker, so a deployment that turned local serving off by
setting the ceiling to zero serves one request at a time instead. The slot-release conjuncts
stay green, correctly — this weakening admits one more worker, it does not leak a slot.

## 4. What remains

| unit | severity | why it is still open |
|---|---|---|
| `sdk_typescript.post_close_emission` | critical | defence in depth; the compound-falsifier mechanism is deliberately unbuilt at one measured instance |
| `proxy.evidence_attestation` | high | its e2e battery supplies no commitments, so the pairing weakening is a no-op; see slice 28 |
| `conformance.retained_corpus` | high | not yet attempted |
| `proxy.refusal_audit_emission` | medium | not yet attempted |

## 5. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.scrapi_registration_leaf` | `M275` | medium |
| `proxy.remote_signer_call_gcp` | `M276` | medium |
| `proxy.capsule_anchor_registration_leaf` | `M277` | medium |
| `client.local_serving_pipeline` | `M278` | medium |

N1 moves 8 -> 4; the probe registry 296 -> 300.
