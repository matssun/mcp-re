# The V2/V3 extracted-model decision — 2026-09-06

Backlog item 7 of the v0.17 AFK mandate. The item asks for a **decision**, not an
implementation: whether v0.17 declares any unit at assurance class V2 or V3 — a machine
proof over a model extracted from production Rust (Charon → Aeneas → Lean 4), entering the
platform as `lean://` evidence.

## Decision

**No unit is declared V2 or V3 in v0.17.** The `lean://` lane stays at its honest
`NOT_REQUIRED`, and #541 (MCPRE-130, T5) remains open and correctly blocked.

## The state, measured on this tree

| fact | value |
|---|---|
| units by class | 76 × V0, 6 × V1 (Verus), **0 × V2/V3** |
| `verify-lean` | `NOT_REQUIRED — no V2/V3 unit declared (pinned, Lean package not established)`; `lakefile.toml` correctly absent |
| toolchain pins | `[charon]`, `[aeneas]`, `[aeneas_lean_backend]`, `[lean]` (`leanprover/lean4:v4.31.0`) all `state = "resolved"` |
| extraction image | `ghcr.io/matssun/mcp-re-verification-extraction@sha256:42318bba…7dce` |
| declared candidate | one unit carries `pilot = "lean-candidate"`: `http_profile.keyid` (THM-0055) |

## Why the decision is forced rather than chosen

The pipeline was run inside the pinned image on 2026-08-30 and the result is recorded in
`verification/baseline/extraction-pilot-measurement-2026-08-30.md` (PR #712). Three findings
decide this, and the first is a hard gate:

1. **The pinned image cannot run the Lean half.** elan in the image holds v4.33.0 while the
   pin is v4.31.0; `/opt/aeneas/backends/lean/.lake` does not exist; mathlib is absent.
   Verified on this tree: the digest in `[extraction_container]` is byte-identical to the one
   measured — it has not moved since it was first pinned — so the finding stands unchanged.
2. **A semantic limit that constrains what a V2 claim could even say.** `alloc::fmt::format`
   extracts as an *uninterpreted axiom*, so any conjunct over a produced string is unprovable
   in the model. `civil_from_days` by contrast extracts fully transparent. The honest first
   V2 proposition is therefore a **totality** claim, never an encoding or round-trip one.
3. **The pipeline does work on production Rust** — `--preset=aeneas` is mandatory and
   `--start-from` keeps extraction off `ed25519-dalek`/`sha2`. So the obstacle is the
   toolchain image, not the target and not the architecture.

## Why declaring one anyway would be worse than not

Declaring a V2/V3 unit is not a statement of intent; it changes what the machinery measures.
`verify-lean` would become REQUIRED and the extraction job's `required` condition would turn
on, so CI would attempt a pipeline the image cannot complete. The outcome is a red lane that
says nothing about the code — or, worse, pressure to soften the lane's verdict, which is the
"do not report a green that measured nothing" failure this project has already repaired twice.
Today's `NOT_REQUIRED` is an accurate report about an absent obligation, and it should stay
accurate.

## What unblocks it, and who can do it

Step 1 of `extraction-pilot-measurement-2026-08-30.md` §4: **an extraction image that can run
Lean** — pinned toolchain installed, Aeneas backend built, mathlib cached, and a new digest
in `[extraction_container]`. That is a toolchain-pin change plus a GHCR publish
(`tools/verification/extraction-image`) — an outward-facing action, an operator decision, and
a change to an identity every fingerprint in the graph carries. It is outside this mandate's
autonomy, which is why this slice records a decision instead of a `lean://` URI. Steps 2–5
(the lakefile, `regenerate-lean`, the totality theorem with its two model-boundary
assumptions, and `verify-lean`'s controls including `sorry` fail-closed) are ordinary work
once step 1 lands.

An earlier attempt to work around it by building the backend inside the running container
ended in `No space left on device`; that is a fact about one workstation's Docker VM and is
recorded only so the next attempt does not repeat it.

## Consequence for the assurance graph

None. No claim is strengthened, narrowed or withdrawn by this decision. The v0.17 graph
remains V0 with a V1 Verus core, and every theorem's class already says so in terms —
"executable and structural, class V0: a battery over production behaviour with each conjunct
mutation-probed, not a machine-checked proof". Nothing in the tree reads as though a machine
proof exists where one does not.
