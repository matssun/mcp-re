# ADR-MCPRE-068 Phase 2, slice 32 — the last three, and what is left

Three probes, `M279`–`M281`. After this slice the N1 registry holds **one** row.

## 1. A refusal attributed to nobody

The two audit coordinates are not interchangeable, and the comment beside them says why: `None`
for the Core verdict means Core reached **no** verdict — a policy did — and that policy's token
belongs in the authorization coordinate, never in Core's `reason`.

`M279` passes `None` for the deployment's authorization facet instead of the one the exchange
reached. The record is still written, still well-formed, and still says a refusal occurred. What
it stops saying is **which authority reached it** — and an audit record's whole job is to answer
that. Only a rule over source can see it, for the reason slice 20 recorded.

## 2. The corpus is the artifact

`M280` is the only probe in this registry whose weakening edits a committed **vector** rather
than a source statement. A conformance corpus is a claim that these exact bytes are what the
implementation emits and that they hold together as a record; **a corpus nobody re-derives is a
claim about bytes somebody once produced.**

One character of one `Content-Digest` is the whole mutation, and it takes the regeneration
control red — which is what makes the corpus a measurement rather than a fixture, and what a
reviewer of a regenerated diff is actually relying on.

## 3. The unit slice 28 left open

`proxy.evidence_attestation` is discharged here, and the two earlier failures were both about
the probe rather than the carrier:

| attempt | why it measured nothing |
|---|---|
| exchange the two commitments | a **no-op** — the e2e passes `None` for both |
| restore the old self-check skip | **did not compile** |

`M281` issues the statement over an **empty** chain while everything downstream still holds the
real one. The self-check catches it, which is the point: `verify_retained_evidence` runs against
the reconstruction that is handed back, so a statement committing to anything else cannot be
published at all.

Why the reconstruction is handed back is the other half. A caller that received only the
statement would have to **decode what was just published** to learn the verdict, and an
INCOMPLETE one discovered that way is discovered after the record exists.

## 4. What is left

| unit | severity | state |
|---|---|---|
| `sdk_typescript.post_close_emission` | critical | **the only open N1 obligation** |

Two independent sites each enforce the whole proposition — `#refuseIfClosed()` reading `#state`,
and `#exchange`'s per-leg abort check — so removing either alone leaves every declared control
green, and the one-anchor schema cannot express the weakening that would falsify it.

The standing ruling: one measured instance records the requirement and does not **generalise**
the infrastructure; a narrowly typed multi-anchor weakening is what the single case warrants.
That is the next slice, and it is falsifier construction rather than an owner question.

## 5. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.refusal_audit_emission` | `M279` | medium |
| `conformance.retained_corpus` | `M280` | high |
| `proxy.evidence_attestation` | `M281` | high |

N1 moves 4 -> 1; the probe registry 300 -> 303.
