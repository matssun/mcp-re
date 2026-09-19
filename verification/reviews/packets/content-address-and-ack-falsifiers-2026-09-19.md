# ADR-MCPRE-068 Phase 2, slice 24 — the prefix, the place, and the set

Three probes, `M256`–`M258`, opening the High band. Each proposition is one a reader would call
cosmetic until asked what the weakening admits.

## 1. The prefix is the algorithm

`parse_hash_id` refuses a value without `sha256:`. `M256` accepts one.

`sha256:` names **which hash produced the 32 bytes**. Without it, a caller holding 32 bytes from
anywhere — a different algorithm, a truncated digest, a value it computed itself — gets an
accepted content address. The length check below is not a second carrier: every 32-byte input
passes it, whatever produced them.

The round-trip control stays green, correctly. The weakening **widens** what parses and narrows
nothing, so the shapes that worked still work; only the refusal control can see it.

## 2. The server refuses it too, which is why the proposition is about WHERE

An empty or structurally invalid `artifact_bindings` is rejected as `malformed_evidence` at the
boundary. So under `M257`'s weakening **nothing unsafe reaches an executor** — what changes is
that the client composes it, signs it, spends a round trip, and then reports a local
misconfiguration as a server-side evidence fault. The operator reads a wire error about the
peer for a value in their own configuration.

`validate` is reused rather than re-spelled precisely so the two ends cannot drift, which also
means this is not defence in depth: **one rule, checked at two points in one exchange**, and
the client's is the only one that can name the cause.

## 3. Named sets, not noticed absences

If a verifier merely NOTICED that a body was absent and dropped the content requirements, then
*no content-type because there is no content* and *content-type stripped in flight* would be
the same observation — and an attacker who removes a header would be indistinguishable from a
peer that never sent one.

`M258` weakens the refusal, so a bodyless message carrying a content-type verifies: the
message's own header set no longer has to match the set the signature was computed over. The
content-injection control is a sibling conjunct, not a second carrier — it catches a body
arriving where none was signed, and says nothing about a header arriving alone.

## 4. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `core.content_address` | `M256` | high |
| `client.request_construction` | `M257` | high |
| `http_profile.bodyless_acknowledgement` | `M258` | high |

N1 moves 27 -> 24; the probe registry 277 -> 280.
