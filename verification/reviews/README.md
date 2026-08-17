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

The directory is intentionally empty of records — no theorem is declared yet.
