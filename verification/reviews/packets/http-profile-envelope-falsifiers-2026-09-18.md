# ADR-MCPRE-068 Phase 2, slice 15 — the reply that answers somebody else

Three probes, `M231`–`M233`, and one control repaired against a docstring that already said
what it was missing.

## 1. A control that named the adversarial case and tested the agreeable one

`ids_correlate_by_value_and_by_type` opens with:

> String and numeric ids both correlate, **by value and by type**. `1` and `"1"` are different
> ids, **which is exactly what a lenient comparison would get wrong.**

and then asserted the two positive cases and nothing else. `M231`'s weakening — comparing the
ids as rendered text — left it green.

That is the shape this lane exists to find: prose stating the property, a battery covering its
easy half. The two negative assertions were added and the probe now takes it red.

Why the weakening is a coercion rather than a deleted check: the proposition is *by value AND
by type*, and `serde_json::Value`'s `PartialEq` is what carries the type half. There is no
comparison operator to soften — the weakening has to go around the type.

What it costs, on this profile specifically: every outstanding id is a signed request's
identity, so an id that correlates leniently delivers **an answer to somebody else's call** as
the answer to this one.

## 2. The union is why it is a refusal and not a parse

`M232` weakens the `method`-member refusal. A body carrying both a legal `result` and a
`method` satisfies the JSON-RPC message schema — **as a request** — so nothing downstream
refuses it. It gets dispatched: sampling, elicitation or roots driven on peer-chosen params,
while the awaiting call never resolves because its id was consumed as an inbound request id.

The SDKs stop the same shape from the other end, by rebuilding the reply from the one member
it carried (`M191` / `M192`). **Two independent refusals of one attacker move at two
boundaries** — composition across layers, not defence in depth within one, and each is
separately falsifiable.

## 3. The issuer's TTL is not the verifier's budget

`M233` weakens the N cap. ADR §5.2 frames why the `[nbf, exp]` window above it is not a second
carrier: the TTL is the ISSUER's choice about how long its snapshot may be acted on; N is the
VERIFIER's own cap. An authority that issues year-long assertions is not misbehaving; an
enforcement point that acts on a year-old snapshot of an authorization decision is. So the
window check passes on exactly the assertions this one exists to refuse.

The `iat`-ahead half travels in the same anchor because a future issuance floors **both** age
computations — this cap and the §5.2 degraded P window — at zero under saturation, and so
passes them for the assertion's whole TTL.

## 4. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `http_profile.request_envelope` | `M231`, `M232` | critical |
| `http_profile.admission_assertion` | `M233` | critical |

N1 moves 50 -> 48; the probe registry 252 -> 255. One control repaired.
