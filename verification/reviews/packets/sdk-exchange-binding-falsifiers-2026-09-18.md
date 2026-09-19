# ADR-MCPRE-068 Phase 2, slice 9 — the proposition that is an absence

`exchange_binding` says:

> the value returned by `sign_request` is the one POSTed and the one passed to the verifier,
> and **nothing is re-derived, re-serialized or reconstructed** for it.

A proposition stated as an absence has no predicate to delete, so the weakening ADDS a step.
Both probes failed on their first measurement, for two different and both instructive
reasons.

## 1. The control could not see a re-serialization

The declared controls read the posted body as JSON:

```python
body = json.loads(calls[0]["body"])
assert body["method"] == "tools/list"
```

`signed.body()` and a re-serialization of it decode to the same document, so an
implementation that re-derived the bytes for either leg kept that control green. The
proposition is about BYTES — the signature covers bytes, and a verdict computed over anything
else answers a question nobody asked — so the control has to be about bytes too.

The written control captures what the poster received and what the core was handed, and
compares them directly. It exists in both SDKs now, and each turns red under its probe.

## 2. The first TypeScript weakening was not a weakening

`JSON.stringify(JSON.parse(x))` round-trips the core's compact output to **the same bytes**,
so `M210`'s first mutation changed nothing and the new control stayed green — truthfully.
Python's twin differs only by an accident of its library: `json.dumps` defaults to `", "` /
`": "` separators, so the same round-trip there does change the bytes.

That is worth stating plainly, because the lane's FAIL meant two different things on the two
occasions:

| occasion | what FAIL meant |
|---|---|
| `M209`, and `M210`'s first control | the battery cannot see the weakening — **write a control** |
| `M210`'s first mutation | the mutation is a no-op — **write a real weakening** |

The lane cannot distinguish them, and should not: both are "this probe demonstrated nothing",
and both are for the author to adjudicate. The weakening now reorders the members, which
preserves the document and changes the serialization — which is what *re-derived* means here.

## 3. Where this leaves the cross-SDK asymmetry count

Slice 7 recorded two measured instances of one SDK's battery covering a half the other's did
not. This slice is **not** a third: here NEITHER SDK had the control, so it is a shared gap
rather than an asymmetry. The count stays at two, and the shape to watch for is still "two
SDKs, one proposition, different halves covered".

## 4. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `sdk_python.exchange_binding` | `M209` | critical, root-reachable |
| `sdk_typescript.exchange_binding` | `M210` | critical, root-reachable |

N1 moves 66 -> 64; the probe registry 230 -> 232. Two controls written, both because a
falsifier proved the existing ones could not see the defect they were about.
