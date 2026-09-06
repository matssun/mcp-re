# ASM-0029 — the trust seam's selector, discharged for the production resolver — 2026-09-06

Backlog item 2 of the v0.17 AFK mandate. The completeness audit of 2026-08-31 (§5.2, §11
candidate 1) ranked ASM-0029 — "the trust seam answers its SELECTOR correctly" — as the
single unproved MCP-RE-owned premise that moves the most risk: terminal under three of the
nine roots then declared (THM-0074, THM-0075, THM-0076), mechanism `none:trusted-seam`, and
invisible from THM-0074's security consequence.

Baseline: `assurance/trust-document-interpretation` head `46d23377` (#817: THM-0098), itself
on main `67ee9f30` (#816: THM-0097). Slice branch `assurance/asm-0029-local-discharge`.

## 1. What the premise says, and where it is consumed

ASM-0029 is scoped to `unit://http_profile.verifier_results` and
`boundary.unmodelled_own_behaviour`. It is the verifier's premise: `resolve_actor` is an
injected closure, `ResolvedActor` is deliberately unsealed (`docs/dev/sealed-owners.md`),
and the verifier can check only that the returned actor's `slot` is the slot it asked for
(`verify/floor/trust_slot.rs`). Whether the returned KEY is the one the deployment
authorized for that keyid, and whether the returned IDENTITY is the one that keyid denotes,
the verifier consumes and cannot audit. THM-0014, THM-0016 and THM-0017 name it honestly.

So the premise has two parts that can be discharged separately:

| part | what discharges it | status |
|---|---|---|
| the verifier accepts any resolver | nothing — this is what "injected" means | stays a premise, unchanged |
| the resolver the deployment actually runs answers correctly | a theorem about that resolver | THM-0099, this slice |

## 2. What the production resolver is

`app.rs::build_actor_resolver`, built once by the composition root (THM-0066, source
controls in `serving_trust_seam_test`) over the reloading signer directory and the
revocation-tier resolver. For `(kid, Request)`:

```
signer  = signers.signer_for(kid)          -- the CURRENT snapshot's kid -> signer map
                                             (None => NotTrusted, tier not consulted)
key     = request_trust.resolve(signer, kid) -- the revocation tier
                                             (Unavailable => Unavailable; other Err => NotTrusted)
actor   = { subject: signer, keyid: kid, role: "client", trust_domain, verification_key: key, slot }
```

For `(kid, Response)`: only the deployment's own response kid, with its own identity and
response public key; the tier is never consulted.

## 3. The composition

| conjunct of ASM-0029's Request-slot half | held by |
|---|---|
| `subject` is the signer the current snapshot binds `kid` to | seam: `active_binding_resolves_the_key_the_tier_returns` (subject == the store's signer), probe M105 |
| a `kid` the snapshot does not bind never resolves and never reaches the tier | seam: `slot_discipline_holds` (calls == 0), probe M106 |
| `verification_key` is the tier's answer, on every call, never a boot-time copy | seam: `active_binding…`, `rotated_key_is_served_from_the_tier`, `the_seam_resolves_through_the_tier_rather_than_a_frozen_map` |
| the tier's answer is a key a snapshot within the authority window admitted for `(signer, kid)` | THM-0097 |
| the snapshot's `kid -> signer` map and its resolver are one accepted document's request-slot enrolment; a `kid` is bound to at most one signer | THM-0098 |
| the seam the serving path runs is this one | THM-0066 |

THM-0099 states the conjunction as one public result, owner `proxy.serving_trust_seam`,
`depends_on = [THM-0066, THM-0097, THM-0098]`, no assumption of its own, composed at THM-0074
beside THM-0097 and THM-0098. It is class V0: the seam conjuncts are measured over a
scripted tier and a real `ReloadingTrustStore`, and the tier's and the document's conjuncts
are premises named by id.

One subtlety the statement carries rather than hides: `subject` is read from the current
snapshot on every call, while the key may be a cached answer an earlier snapshot gave for
the same `(subject, kid)` pair within `T`. The cache is keyed by the pair, so both halves
are the document's enrolment for that pair; which document is in force is THM-0097's
window.

## 4. What was NOT done, and why

**ASM-0029's registry entry is not edited.** An assumption's digest is its whole entry
(`_fingerprint.assumption_digest`), carried into every unit in its scope and from there into
THM-0014/0016/0017 and roots THM-0074/0075/0076. Annotating the justification with "the
production instance is THM-0099" would therefore move three root fingerprints and require
the owner's specification review of each — an owner decision, not routine maintenance. The
audit's open finding §5.3(4) — THM-0074's consequence does not mention its terminal — is
likewise a root-text change and is left to the owner. Both are listed for the consolidated
report.

**Nothing about the Response slot beyond THM-0066's sentence.** The proxy's own resolver
answers the Response slot only for its own kid; where that key comes from is THM-0082's.
The client's verification of responses uses the client's trust manifest, a different seam
and a different premise instance, outside this slice.

**No e2e test added.** The mTLS transport-binding suite already shows a request admitted
only when the presented leaf's SAN equals the resolved `subject`; adding another positive
would increase a count, not the evidence.

## 5. Establishment

Probes M105 and M106 red-verified on this tree. `proxy.serving_trust_seam` now declares
`mutation://` evidence, so its attestation needs the whole mutation lane once; the slice's
merge condition is the same as #817's: ordinary CI green on the merge tree, then locally
98/98 theorems established and 12/12 roots complete.
