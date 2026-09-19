# ADR-MCPRE-068 Phase 2, slice 12 — the combinations nobody enforces, and the manifest that is genuine

Four probes, `M220`–`M223`. Both units share a shape worth naming: **the thing they refuse is
otherwise indistinguishable from the thing they accept.**

## 1. One arm is enough, and that is a fact about the proposition

`cross_machine_legality` claims *each illegal combination is refused unconditionally*. So a
single match arm that stops refusing falsifies it — the three arms are three instances of one
rule, not three carriers of one instance.

`M220` weakens the PKCS#11 arm and the exhaustive control (every selector under every other
custody state) goes red, while the matching-state control stays green. That is correct: the
weakening widens what is accepted and never narrows it.

The relation reads **classified owner states**, not raw request fields, which is what makes
this a layer-A boundary rather than a flag check. Under the weakening a
`--pkcs11-tls-key-label` sits silently inert beside an AWS KMS signing source, and the
operator's channel key is not the one they named.

## 2. A refusal that exists because the failure is silent

`M221` weakens X6, the deny-list relation. No reachable authorization profile READS a grant
deny-list, so a configured one enforces nothing — and the operator who supplied it believes
revocation is in force.

Refusing at configuration time is the **only** moment anything says otherwise. There is no
later error, because nothing ever consults the list.

## 3. The manifest an attacker replays is genuine

This is the sharpest case in the slice. A superseded trust manifest is really signed by the
issuer, so on a replay of it:

| gate | verdict on a superseded manifest |
|---|---|
| signature | passes — the issuer signed it |
| profile | passes |
| expiry | passes, if it has not yet expired |
| **version floor** | **the only thing that refuses it** |

The only fact distinguishing *this is the issuer's trust picture* from *this WAS the issuer's
trust picture* is the version already seen. Under `M223`'s weakening, an attacker who can
serve an old manifest re-opens the overlap window it published, and a root retired in the
meantime answers for the issuer again.

`M222` is the neighbouring ordering claim: the deadline outranks every root inside it, and the
anchor set is built at step 6 — after the signature, the profile, the deadline and the floor.
A root's own validity is not a second carrier, because a root can be perfectly valid and still
belong to a trust picture the issuer has replaced. That is what an overlap window is for.

## 4. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `proxy.cross_machine_legality` | `M220`, `M221` | critical |
| `client.trust_manifest_lifecycle` | `M222`, `M223` | critical |

N1 moves 58 -> 56; the probe registry 241 -> 245.
