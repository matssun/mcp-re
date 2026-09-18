# ADR-MCPRE-068 Phase 2, slice 4 — the nonce floor's twin, and the reply rebuild

Three probes, `M190`–`M192`, and the reason they are one slice is that both propositions
are carried by something other than a deletable predicate.

## 1. M190 — the twin slice 1 left open

Slice 1 probed the TypeScript nonce floor (`M179`) and left the Python one because the
slice was about the LANE, not about the unit. `_checked_nonce` is sole for the same reason
`checkedNonce` is: it is the one place a nonce is drawn for signing, and both the request
path and the notification path go through it. The floor constrains an OVERRIDE —
`_default_nonce` clears it by construction — so disabling the predicate is the whole
refusal.

## 2. M191 / M192 — the carrier is a REBUILD, not a check

`reply_envelope` states two things, and the weakening that falsifies them is not a deleted
predicate but an in-place edit:

```python
response = _plain_response_object(json.loads(body))   # rebuild
response = json.loads(body)                            # weakened: edit in place
```

Editing the parsed document leaves every other top-level key the server sent. A body
carrying both a legal `result` and a `method` then re-parses as a **server-to-client
request**, and `ClientSession` dispatches it — driving sampling, elicitation or roots on
peer-chosen params, while the awaiting call never resolves because its id has been consumed
as an inbound request id. That is the defect the rebuild removes as a class.

`JSONRPCMessageSchema` downstream is **not** a second carrier. It is a union that accepts a
request, so it validates the method-bearing body happily — as a request. That is exactly the
dispatch the rebuild prevents.

**One carrier, two conjuncts.** `_plain_response_object` / `plainResponseObject` is also
where the neither-`result`-nor-`error` refusal lives, so one anchor turns both of the unit's
declared controls red. This is the inverse of the composition shape recorded in slice 2: not
two checks each holding part of a proposition, but one construction holding two.

## 3. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `sdk_python.nonce_floor` | `M190` | critical, root-reachable |
| `sdk_python.reply_envelope` | `M191` | critical, root-reachable |
| `sdk_typescript.reply_envelope` | `M192` | critical, root-reachable |

N1 moves 81 -> 78; the probe registry 211 -> 214.

## 4. The three carrier shapes now measured

Worth keeping together, because the probe schema's fit depends on which one a unit has:

| shape | example | single anchor suffices? |
|---|---|---|
| one predicate, one proposition | `M179`, `M186` | yes |
| composition — each check refuses what the other admits | `M181` / `M182` | yes, one per check |
| one construction, several conjuncts | `M191`, `M192` | yes, one anchor for all |
| defence in depth — each site enforces the WHOLE proposition | `sdk_typescript.post_close_emission` | **no** — still one measured instance |

The compound-mutation requirement is unchanged at one instance, and is not generalised.
