# ADR-MCPRE-068 Phase 2, slice 11 — the first cargo slice: the KMS custody boundary

Five probes, `M215`–`M219`. The Phase-1 closure put `proxy.kms_endpoint_authority` at the
head of the cargo order — critical, fan-out 6, reaching three roots — and the three units
probed here are the ones that share its subject: what authority is reached, whose key signs,
and whether the signature that comes back is the one that was asked for.

## 1. Spelling and interpretation, and why it is three probes

`kms_endpoint_authority` claims *the host and port a reader sees are the host and port that
will be reached*. Three checks carry it, and they **compose** — each refuses a shape the
others admit:

| probe | refuses | admitted by the others |
|---|---|---|
| `M216` | percent-, IDNA- or separator-encoding | `127.1` is character-legal |
| `M215` | a last label that is a number and is not already the dotted quad | the allowlist accepts every digit |
| `M217` | a port with a leading zero | `0443` is all digits and `u16::from_str` accepts it |

None is redundant with another, and the measurement shows it: `M215`'s weakening leaves the
allowlist's own control green and takes only the rewrite controls red.

What the unit buys is that an operator auditing the configured endpoints and the machine
reaching them agree. Under `M215`'s weakening, `kms.example.internal` in one entry and
`2130706433` in the next look equally unremarkable, and the second is loopback.

## 2. Identities, not locators

`signing_role_separation` compares the response-signing role's public key with the
channel-signing role's **as cryptographic identities**. That is why `M218` weakens
`raw_point() == raw_point()` rather than any config comparison: two roles can name different
mechanisms, different key ids and different endpoints and still materialize the same point.

Under the weakening every deployment reports `Distinct`, and one key signs both the responses
and the channel — so a party holding a channel signature holds a response signature's proof
material.

The third arm, `NotCompared`, is **not** a second carrier. It is the answer when a role
produced no key at all, and a boolean would have to spell it with the same token as
*separate*; the probe leaves that arm's control green, which is correct.

## 3. The only thing that catches a prehash key

`MessageType = RAW` is what the adapter **asks for**. A KMS key configured for DIGEST signs
something else and returns a well-formed 64-byte Ed25519 signature either way, so the length
rule the operand owns admits it. `M219` weakens the local verification, and nothing between
there and the wire re-checks: the signature goes into a response the peer verifies against
the same advertised public key, and the failure surfaces as a remote verification error **on
somebody else's machine**.

## 4. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `proxy.kms_endpoint_authority` | `M215`, `M216`, `M217` | critical — fan-out 6, three roots |
| `proxy.signing_role_separation` | `M218` | critical |
| `proxy.aws_kms_adapter` | `M219` | critical |

N1 moves 61 -> 58; the probe registry 236 -> 241. The cargo lane's mechanism already existed,
so every row here is an individual falsifier rather than a mechanism build — which is exactly
why the closure put it after the two SDK lanes.
