<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — THM-0078 and THM-0072, decomposed

Two `high` roots. Both survived falsification; neither takes a claim correction. Recorded
together because each is short, and separately from the estate-wide finding one of them
produced (`gate-carriers-are-unowned-2026-09-18.md`).

> **Relationship to `remaining-roots-audit-2026-09-18.md`.** That packet audited this root
> earlier in the campaign, asking *are the leaves honest, and does the graph say what the claim
> needs*. This one asks the Phase-1 question the brief puts first — *try to falsify the root
> statement before decomposing it* — and then decomposes consequence-downward. Neither
> supersedes the other: the audit's findings (probe coverage, unit width) stand as written, and
> nothing here contradicts them.

---

## THM-0078 — "Refusal is terminal, and no refusal-side effect reads as success"

8 declared dependencies, an 11-theorem closure, 10 owners.

### The consequence

If it is false, a refused exchange's effects are mistaken for those of a served one. The
registered consequence names the motivating case in terms: **an approval is spent and the
refusal reads as an ordinary retry**, so the caller retries and the side effect happens twice.

### The propositions

| | proposition | owner | theorem |
|---|---|---|---|
| T1 | a failed obligation reaches a declared refusal terminal BEFORE dispatch | `proxy.dispatch_commitment`, `proxy.refusal_site_totality` | THM-0045, THM-0081 |
| T2 | no fall-through into a success-path dispatch or success response | `proxy.exchange_lifecycle` | THM-0043 |
| T3 | WHERE AN EXCHANGE EXISTS, every refusal-side effect is authorized by the refusal and lifecycle state it was reached from | `proxy.refusal_provenance`, `proxy.audit_record_coordinates`, `proxy.retention_commitment` | THM-0046, THM-0069, THM-0088 |
| T4 | none of those effects can be read as success | `proxy.retention_commitment`, `proxy.response_signing` | THM-0088, THM-0063 |
| T5 | a PRE-EXCHANGE reply claims no exchange state, no execution and no retry contract | `proxy.refusal_site_totality` | THM-0081 |
| T6 | the retry consequence never UNDER-reports what may have happened | `proxy.exchange_lifecycle` | THM-0044 |

### Falsifying it

**Attempt 1 — T5 contradicts THM-0081.** THM-0078 asserts a set of replies with no lifecycle
state; THM-0081 is titled "Every production refusal is inside the exchange lifecycle". Read
as titled, they cannot both hold.

They do. THM-0081's statement is a DISJUNCTION, not the universal its title suggests: every
production refusal is *either* exchange-owned *or* one of the FOUR enumerated pre-exchange
transport replies, "and there is no third, unclassified refusal path". T5's set is THM-0081's
second disjunct, enumerated rather than asserted. The attempt fails on the statement, and it
would have succeeded against the title — which is a reason to read statements.

**Attempt 2 — is T4 a negative nobody owns?** "Cannot be read as success" is an absence
claim, and absence claims are where this estate has been wrong before. It is owned positively:
THM-0088 says a retention artefact "reads as a crossing only for an exchange that CROSSED" —
a biconditional on the artefact, not a hope about readers.

**Attempt 3 — does the root state a biconditional with THM-0074 by accident?** No, and the
scope forbids it in terms: "two separate safety implications and never a biconditional:
stating them as one would make this a liveness claim, which it is not." Consistent with
THM-0074's own liveness disclaimer.

### Evidence

Ten owners, **eight with a registered falsifier** — the best-covered root in the estate.
Two carry debt, both pre-existing:

```
proxy.refusal_provenance  DEBT=high       (THM-0046)
proxy.response_signing    DEBT=critical   (THM-0063 — the same owner that carries THM-0075)
```

`proxy.response_signing` is now measured as an unfalsified owner under THREE roots (THM-0075,
THM-0078, and THM-0075's own closure). That is not new debt; it is the same row, and its
consequence is wider than any single root's packet shows.

### Carrier note

THM-0081's production carrier includes `scripts/refusal_provenance_gate.py` clause 12c, which
holds the served mint to one call site across the whole workspace. The theorem says so in its
own scope, and says why a type would not do: `ServedHttpResponse` is a wire frame with public
fields that the async fleet, the blocking harness and external embedders all construct, so
"privacy would buy nothing, and deleting the battery leaves an out-of-lifecycle exit
compiling". That gate is unowned — see the estate-wide finding.

---

## THM-0072 — "A verified receipt proves registration on the service this deployment pinned"

2 declared dependencies, a 2-theorem closure, 2 owners. The smallest root in the estate.

### Falsifying it

**Attempt 1 — does it claim more than it composes?** Its scope says it "composes the two facts
and adds nothing". The statement's conjunction — the key, the leaf profile AND the position
profile all from one reviewed document — is THM-0068's ("a pinned transparency service is one
operator-reviewed document, or it is not a pin"), and "its root was never supplied" is
THM-0041's. Nothing is added. The attempt fails.

**Attempt 2 — is the conditional a hedge?** "When offline receipt verification is performed
through a resolver PROJECTED FROM a `ScittServiceTrustPin`" narrows the claim to one
provenance. That is a bounded claim, not a hedge, and the scope is explicit about why: the
seam is a `Fn(&str) -> Option<ResolvedTransparencyService>`, so provenance is deployment
wiring, and **"no production wiring was invented to make this claim unconditional."** That
sentence is a model of the discipline this phase is for — the alternative would have been a
root that quantified over a configuration nobody ships.

### Evidence

```
http_profile.scitt_receipt_offline   ['mutation','test']   -             (THM-0072, THM-0041)
http_profile.scitt_service_pin       ['test']              DEBT=high     (THM-0068)
```

The pin owner — the one that decides what a pin IS — is the unfalsified half.

### In-flight note

`http_profile.scitt_receipt_offline` is split into six owners on the SCITT branch. This packet
deliberately does not re-derive that split: doing so would manufacture a conflict for no gain,
and the split's own record is the authority for it.
