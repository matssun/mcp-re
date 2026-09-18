# ADR-MCPRE-068 Phase 2, slice 14 — the joins that must not collide

Three probes, `M228`–`M230`. Every proposition here is about **injectivity** — two different
things must not become one — and none of the weakenings looks like a bug.

## 1. Deleting a separator is invisible

`M228` removes `SEP` from the replay key's signer slot. The slot is still a string, still
deterministic, still key-bound, and the cache still works. What stops working is injectivity:
two different five-tuples join to one key, so the second is refused as a replay of the first.

Replay admission is where that lands. A false collision means a legitimate request from one
actor is refused because an unrelated one already occupied the key — and the refusal reads as
`mcp-re.replay_detected`, an accusation about the wrong party.

The control is adversarial by construction: each row is a five-tuple whose components
concatenate to the same text without the separator and to different text with it. It could
not have been a randomly chosen corpus.

## 2. A known answer proves the derivation right for ONE operand

`M229` trims a trailing character from the keyid's canonical JWK operand — a collision, not a
typo: two distinct enrolled keys reach one canonical form and therefore one keyid.

**The RFC 8037 A.3 known answer stayed green**, and that is a measured fact about known-answer
controls rather than a defect in this one. A.3's vector simply does not end in the character
this weakening trims, so its derivation is unchanged. Only the corpus controls quantify over
operands, and only they can see a weakening that collides some other pair. Both kinds belong
in the battery, for different reasons, and the `expect_red` list was corrected to say which
one actually measures this.

## 3. One statement, two propositions

`M229` and `M230` share an anchor and are not duplicates. `http_profile.keyid` claims the
derivation is what the RFC says; `http_profile.keyid_selector` claims the keyid **selects** a
key, and it is a separate unit precisely so the primitive's collision resistance stays off the
derivation claim. One production statement carries both, and the campaign's rule is that
granularity follows PROPOSITIONS rather than sites.

Only the first half of the selector's composition is ours, and it is the half this weakening
breaks: a signature from either of two colliding keys verifies under a lookup for the other.

## 4. A control this slice repaired, found by registering evidence

`test_a_unit_without_mutation_evidence_measures_no_mutation_components` asserted emptiness
over `http_profile.keyid` — and went red the moment that unit's probes were registered.

The fixture had an expiry date built into it: **N1 owes a `mutation://` falsifier to every
`tested` proposition**, so any `tested` unit is a temporary example of *has no probes*. The
control now measures a STRUCTURAL unit, which will never acquire mutation evidence, and its
docstring says why.

## 5. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `http_profile.replay_key` | `M228` | critical |
| `http_profile.keyid` | `M229` | critical |
| `http_profile.keyid_selector` | `M230` | critical |

N1 moves 53 -> 50; the probe registry 249 -> 252.
