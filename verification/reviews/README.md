<!-- SPDX-License-Identifier: Apache-2.0 -->

# `verification/reviews/` — human review, as evidence about a fingerprint

ADR-MCPRE-059 §14.7. An approval is **never** a field of the object approved. It is a
record naming the fingerprint that was reviewed:

```json
{
  "axis": "specification",
  "subject": "THM-0001",
  "reviewed_fingerprint": "sha256:…",
  "components": { "theorem_claim": "sha256:…", "…": "…" },
  "reviewer": "mats@sundvall.name"
}
```

One file per `(axis, subject)`, under `<axis>/<subject>.json`.

## Why these are source, while attestations are not

`.verification/` is gitignored, correctly: every attestation in it is re-derivable by
re-running a lane. **A human approval is not re-derivable** — nothing CI can run reproduces
a person having read a claim. Gitignoring these would leave every axis permanently
`UNREVIEWED` on a fresh clone, and an axis that can never be satisfied is one that gets
routed around.

So approving is a commit, exactly as owner ratification in `assumptions.toml` already is.
The history is the audit trail, and because the record names a fingerprint, an approval that
no longer matches the tree announces itself instead of passing quietly.

## The axes, and why they stay apart

| Axis | Subject | Reviewed fingerprint |
|---|---|---|
| `specification` | `THM-NNNN` | the theorem fingerprint — claim, dependency closure, review requirement |
| `assumption` | `ASM-NNNN` | the digest of the assumption's registry entry |
| `audit` | a `[[unit]]` id | the unit fingerprint, which already carries its in-scope assumption closure |

Formal proof is the fourth axis and lives with the attestations, not here. A single
green/red bit across all four would let a passing prover answer for an unreviewed
specification — the substitution this layer exists to refuse.

## What makes a review go stale

Nothing anyone has to remember. Weaken a theorem's `statement`, and `theorem_claim` moves,
so the theorem fingerprint moves, so this record names a fingerprint that no longer exists —
`STALE_CLAIM`, while every prover stays green. Relax its `review_requirement` and the same
thing happens under a different cause, because an approval given under a stronger
requirement is not an approval under a weaker one.

Records carry `components` as well as the aggregate digest so the derivation can name *what*
moved rather than only *that* something did. A record without them still works; it just
reports `STALE_REVIEW` and cannot say why.

Read the state with `tools/verification/review`. Get the digest to put in a record with
`tools/verification/review --fingerprint THM-NNNN`. There is deliberately no command that
writes a record: a tool that could mint an approval on request is the single-command
self-approval §14.7 exists to prevent.

The `specification/` records now carry the owner ruling of 2026-08-30, given over the five
consolidated family packets in `packets/owner-specification-review-2026-08-30.md`. Each
record's `notes` states which family the claim sat in and what the ruling actually said about
it, because "APPROVED" alone does not distinguish a claim that was read and found right from
one that was waved through with its family.


## The three layers, and which directory each lives in

An audit measurement, a decision taken over it, and the authoritative state are three
different things, and turning the first directly into the third is the failure this layout
exists to prevent.

| layer | where | what it is |
|---|---|---|
| 1 — raw measurement | `packets/` | evidence about the tree at a named commit. NON-NORMATIVE, kept permanently, never edited into truth |
| 2 — owner decision | `rulings/` | what the owner decided over a packet: what is in scope, what is bounded out, what may not be inferred |
| 3 — authoritative state | `verification/policy/*.toml`, ADR-MCPRE-059, `docs/spec/security-boundary.md` | changed only by encoding a layer-2 decision |

`r9-dispositions.json` is layer 1 and machine-readable on purpose: 131 cluster dispositions
are a record, not 131 prose entries for a human to maintain, and the appendix table in the
packet is generated from it by `tools/verification/render-r9-dispositions`.
