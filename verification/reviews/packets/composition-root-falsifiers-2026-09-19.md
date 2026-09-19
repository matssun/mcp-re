# ADR-MCPRE-068 Phase 2, slice 23 — what the root can do next

Three probes, `M253`–`M255`, over the three units whose controls are **rules over source**.
Every one of them is about a property no behavioural test can hold, and the weakenings say why.

## 1. The rule reads the call, not the value

No test can look at a compiled binary and ask which credential a signing plane holds. What it
CAN establish is that the composition root **names the source the materializer opened** — so
`M254` renames the binding and changes nothing else. The plane still signs with the same key
today.

That is the point. The rule is about what the root can do **next**: a plane materialized from
anything other than the validated source signs with a credential the deployment did not
validate, on a data plane whose startup transcript describes a different one. The two agreeing
today is not a property anything holds.

## 2. An absence, again, and the ruling it carries

`M253` adds a production reference to `InMemoryContinuationStore`. Nothing installs it; the
mention alone is the weakening, because the rule is about **reach**.

The 2026-09-03 owner ruling is what this holds. `InMemoryContinuationStore` is a `pub` item of
this crate, so nothing but **placement** stops a future composition root from reaching for it
the next time OFF looks inconvenient — and a node-local tier is a different capability with a
different scope, which the OFF posture line does not describe. A deployment that selected no
correlation capability would then hold a store whose correlation does not survive a replica
change, while its transcript says it holds none.

## 3. A clone is the mildest second owner

`M255` replaces `for_signed(signed)` with `for_signed(&signed.clone())`. The cloned value is
**equal today**, so no behaviour changes and no behavioural test could see it — which is
exactly the class of edit the rule exists to catch, because the next one is a reconstruction
rather than a copy and the rule cannot tell the two apart from the outside.

**Not overclaimed:** this shows the rule is load-bearing over the joint it reads, not that a
clone is itself a vulnerability. The proposition is that ONE owner produces both the request
that goes on the wire and the expectation the response is judged against, and the low-level
verifier cannot see that joint at all — which is why this unit exists beside
`client.response_binding_disposition` rather than inside it.

## 4. A measurement failure, recorded

`M254`'s first weakening attacked the rival-constructor rule and **did not build**: a bare
mention of `FileKeySource::` that compiles has to be a real call, and the reachable
constructors are feature-gated. The lane refused it as a measurement failure, which is correct.
The rule it was aimed at stays covered by this unit's other controls; the probe moved to the
materialization rule, which a single anchor can weaken honestly.

## 5. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.continuation_installation` | `M253` | critical |
| `proxy.signing_credential_provenance` | `M254` | critical |
| `client.proxy_request_correspondence` | `M255` | critical |

N1 moves 30 -> 27; the probe registry 274 -> 277. **Every remaining critical N1 obligation is
now discharged except `sdk_typescript.post_close_emission`**, which is blocked on the
compound-falsifier mechanism and deliberately still open at one measured instance.
