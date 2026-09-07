<!-- SPDX-License-Identifier: Apache-2.0 -->
# THM-0076 dependency closure, and the four v0.17 specification/assumption approvals

**Owner ruling of 2026-09-07 — Mats Sundvall.** Layer 2: a decision taken over the layer-1
measurements in [`packets/client-correctness-2026-09-07.md`](../packets/client-correctness-2026-09-07.md)
and [`packets/escape-hatch-site-registration-2026-09-07.md`](../packets/escape-hatch-site-registration-2026-09-07.md).

It ratifies two composition edges and approves four subjects as they are currently stated.
It weakens nothing, and it establishes nothing by declaration: every approval below is
recorded against the exact fingerprint of the tree it describes, and a statement that later
moves takes its own record stale.

## 1. What is approved, as currently stated

| subject | axis | disposition |
|---|---|---|
| **THM-0126** — *A verified reply is not a completed call* | specification | APPROVED as stated |
| **THM-0127** — *The deployable's serving path always runs an anchor refresher* | specification | APPROVED as stated |
| **ASM-0045** — the explicit `Ex…` mirror/correspondence premise | assumption | APPROVED as stated |
| **ASM-0046** — opacity of `ExVerifierPolicy`, `ExProfileAlgorithm`, `ExVerificationKey` | assumption | APPROVED as stated |

The statements are **not** altered to accommodate the fingerprints. The records are a
mechanical transcription of this ruling against the fingerprints the tree already carries;
where a fingerprint and a statement disagreed, the correct outcome would have been to
withhold the record, not to edit the claim. Neither happened: all four match.

ASM-0045 and ASM-0046 open the `assumption` axis, which
[`packets/thm-0094-python-sdk-root-2026-09-03.md`](../packets/thm-0094-python-sdk-root-2026-09-03.md)
recorded as having no records at all. That is a fact about these two subjects only. No other
assumption in the registry gains a record here, and the axis staying open for the other 44 is
not repaired by declaration.

## 2. The two composition edges — RATIFIED

`client-correctness-2026-09-07.md` §"One edge is PROPOSED, not taken" put the THM-0126 →
THM-0076 edge to the owner rather than taking it, because THM-0076 is a **published** claim in
[`docs/spec/security-boundary.md`](../../../docs/spec/security-boundary.md) §2 and adding a
premise republishes it. The refusal was correct, and this is the event it was waiting for.

**Both edges are ratified:**

```
THM-0126 → THM-0076
THM-0127 → THM-0076
```

**Reason.** THM-0076 is a claim over what the SHIPPED Rust client proxy may hand to its
application as this call's answer, under its CURRENT trust configuration.

* THM-0126 owns the newly measured semantic step from a genuinely verified response to a
  terminal, continuation or refusal outcome. Without it, an unclassifiable verified result
  could become a completed answer **without violating the old closure**.
* THM-0127 owns the newly measured composition step that makes the deployable actually
  maintain the trust configuration whose semantics THM-0057 and THM-0120 establish. Without
  it, the refresher itself could remain correct while the deployable stopped starting it and
  went on using anchors after their governing manifest expired.

Neither is outside THM-0076's public consequence. The packet's counter-argument — that
response *acceptance* and what a genuine answer *means* are the next question — is heard and
not taken: the root's own consequence already says "cannot be led to repeat a side effect by
reading silence as *it did not run*", which is a statement about what the caller may conclude
from a verified answer, not only about whether the bytes are genuine.

## 3. What this ruling does NOT do

**THM-0076's statement and security consequence are unchanged.** This is a dependency-closure
correction. The §2 claim prose is unchanged, the root set is unchanged, and no §4 row moves.
The resulting THM-0076 record is a **dependency-only re-affirmation**, approved under this
ruling, and its `notes` says so — an approval that did not distinguish itself from a fresh
reading of a restated claim would make the two indistinguishable later.

**No analogous edge is manufactured for any other root.** An edge is added when a root's own
implementation-specific proposition requires it. THM-0091 remains outside THM-0076 on the
reasoning §4.3 already records, and nothing here reopens it.

## 4. Supply-chain scope for the v0.17 release claim

Ruled deliberately, over the two measurements recorded in #836:

> The v0.17 release qualification claim is that **the Cargo/Rust dependency graphs covered by
> the existing `cargo deny` gate are green for advisories, licenses, bans and sources.**

It is **not** an all-PyPI/all-npm supply-chain claim, and the release notes state it in that
form. The scope is defensible rather than merely convenient:

* the Python SDK declares **no hard runtime Python dependencies**; `mcp` is optional, and
  `cryptography` arrives only under that optional extra;
* the TypeScript SDK has **no ordinary runtime dependency set**; its MCP integrations are
  optional peer dependencies and the lock primarily describes its build/test environment.

Therefore the absence of a PyPI/npm advisory lane **does not block** the v0.17 runtime
dependency claim. Refreshing `sdk/python/uv.lock` off `cryptography 49` is ordinary hygiene
and is done where it costs no semantic dependency change; it is not permitted to hold the
freeze, and it is not permitted to alter MCP-RE's declared dependency or support contract.

Non-Rust build/dev lock auditing is recorded as **future assurance-platform work**, not as an
expansion of the v0.17 release gate.
