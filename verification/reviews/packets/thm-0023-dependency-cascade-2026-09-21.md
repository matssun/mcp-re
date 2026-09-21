# ADR-MCPRE-068 Phase-1 — the seven theorems THM-0023's corrected claim moved beneath

## The cascade, enumerated mechanically

Not assumed from the one failure the gate reported. Every theorem whose fingerprint differs
between `origin/main` (9e0ba722) and this branch, measured on both sides:

| theorem | before → after | class |
|---|---|---|
| `THM-0023` | `72c13626` → `264ae664` | **A — own claim changed** (the source) |
| `THM-0105` | `259d868c` → `eca4e8b3` | **A — own claim changed**, unrelated, no cascade |
| `THM-0024` | `1b56049b` → `ca59453e` | B |
| `THM-0029` | `98d57267` → `5fde219d` | B |
| `THM-0031` | `4845a2f6` → `c01196d8` | B |
| `THM-0033` | `77e25e29` → `eae8065c` | B |
| `THM-0034` | `35f0d73f` → `de7106b3` | B |
| `THM-0074` | `7f350985` → `f2ea5dd1` | B — recorded separately, it is the §2-published root |
| `THM-0080` | `8aaba1b0` → `de55bffc` | B |

**Nine moved. Two are class A. Seven are class B, and all seven trace to THM-0023 alone.**

Derived, per theorem: intersecting each one's `theorem_dependencies` component with the set of
moved sources `{THM-0023, THM-0105}` returns `{THM-0023}` in all seven cases. `THM-0105` is
held by nobody.

## Why each is dependency-only

Measured field by field against `origin/main`'s registry, for all seven:

```
statement                     differing fields: NONE
security_consequence          differing fields: NONE
scope                         differing fields: NONE
review_requirement            differing fields: NONE
direct_consequence_severity   differing fields: NONE
supported_by                  same
depends_on                    edges added/removed: NONE
```

So `theorem_claim` is byte-identical for every one of the seven, and the only fingerprint
component that moved is `theorem_dependencies`, at one entry: `THM-0023`'s corrected claim
digest. This is the class
`verification/claim-corrections/THM-0074-prose-2026-09-18.json` already established —
*"the closure's premise claim digests moved because premise scope prose was corrected"* —
applied to the premise correction recorded today.

The machinery agrees independently: `derive_review_state` classifies all seven as
`STALE_DEPENDENCY_CLAIM` and the two class-A theorems as `STALE_CLAIM`. That distinction is
the review module's own, not this packet's reading.

## Why the ruling covers the cascade

The authority is the one that covers the source. If THM-0023's correction is within
ADR-MCPRE-068 Phase-1 — and the source packet derives that it is — then a dependent theorem
whose own claim is byte-identical has had **nothing about it** changed except which digest its
premise now hashes to. No accepted promise moves, because no accepted text moves.

Had any of the seven shown a moved `statement`, `security_consequence` or `scope`, it would
have been pulled out and investigated on its own, as `THM-0105` was.

## Not an owner review

Seven more `STALE_DEPENDENCY_CLAIM` rows, all correctly stale. These records authorize the
merge path only.
