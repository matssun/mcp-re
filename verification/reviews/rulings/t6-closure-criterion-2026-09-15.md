<!-- SPDX-License-Identifier: Apache-2.0 -->
# T6 closure criterion — which clause of release assurance it is

**Owner ruling of 2026-09-15.** Layer 2: a decision about the scope of one issue's done
criterion. It records a disposition; it establishes no theorem, and it changes no tool.

## The question

MCPRE-131 / #542 — *T6: R9 compositional re-verification* — carries as its last done
criterion:

> `tools/verification/review --require-root-complete` passes — the closure mode (§28.8).

On 2026-09-15 that command was, for the first time, invoked mechanically rather than by
hand: `.github/workflows/release-assurance.yml` calls
`tools/verification/release-assurance`, which composes six authorities and runs
`review --require-root-complete` as its binding step. The composed command returned **FAIL**
on its sixth clause while the closure step itself returned **PASS**.

So the criterion has two readings, and this ruling picks one.

## The measurement it is ruled on

Run [34912227345](https://github.com/matssun/mcp-re/actions/runs/34912227345),
`workflow_dispatch` on `5d74ee46ed30d2f586d70e26ff297061872fa075`, tree
`31bdafb6fc2b2ffcb84a443cd18324938f4e24d9`, composing verification run `34910773120`
measured at the same commit:

| clause | verdict |
|---|---|
| `evidence_composition` | PASS |
| `freshness_issuance` | PASS |
| `trusted_premises` | PASS |
| **`root_completeness`** — `review --require-root-complete` | **PASS — the binding closure mode** |
| `published_claims` | PASS |
| `slo_evidence_freshness` | **FAIL** — `SLO EVIDENCE: REMEASURE`, the declared performance surface has MOVED |
| *composed* | `RELEASE ASSURANCE: FAIL` |

The steps are ordered and a failure stops the run, so the root check ran to a verdict of its
own before the SLO question was asked. **Root-completeness closure passed; the composed
command did not.** Those are two sentences and this ruling keeps them apart.

## The ruling

**T6's criterion is the `root_completeness` clause, and it is met.**

T6 is *R9 compositional re-verification*: whether every historic R9 cluster was re-derived
against current `main`, whether what survived was classified and owned, and whether the
resulting theorem architecture composes to established system roots. Nothing in it is a
claim about throughput or tail latency.

`slo_evidence_freshness` is a **release-readiness** fact about the performance surface, not
an assurance fact about the theorem graph. It failed for a reason that is correct and
entirely outside T6's subject: `cargo deny` went red on `main` with GHSA-2mjx-qc3c-rqvc, #876
took `rustls 0.23.43 → 0.23.45`, `Cargo.lock` is a declared performance-surface input, and
rustls is the TLS library on the serving path. The surface genuinely moved and the attested
result genuinely no longer describes this tree. The step is right, and it is right about
something T6 does not assert.

## What is NOT ruled, and what is NOT changed

* **No tool changes.** `tools/verification/release-assurance` keeps all six clauses and keeps
  failing this tree. A release may not be cut here without an SLO remeasurement, and the
  decision is made by `slo_evidence_identity.py --decide` by content, so nobody has to
  remember it.
* **The SLO measurement is owed** — at the next release, which is the sanctioned occasion for
  it. It was deliberately not run to make a tracker closeable: an SLO run belongs to a
  release, it takes the self-hosted host exclusively, and running it for the wrong reason is
  the failure mode the rule exists to prevent.
* **No R9 row's disposition moves.** `verification/reviews/r9-dispositions.json` is
  untouched by this ruling.
* **The fork residual stays as ruled.** `R9-C025` / `R9-C055` remain open on #739 under
  [`v016-release-assurance-boundary-2026-09-03.md`](v016-release-assurance-boundary-2026-09-03.md),
  including its expiry clause: the fork measurement is a fact about history at a date and is
  re-measured before any release that accepts a fork PR.

## Why this closes T6 now when it did not on 2026-09-14

On 2026-09-14 the criterion was satisfied by a **remembered command and a transcribed
verdict** — `review --require-root-complete` had zero invokers in any script and any
workflow, and its v0.16/v0.17 results existed only as sentences in a provenance document.
That is this campaign's own *prose and status are claims, not evidence* finding applied to
its own closure criterion, and it was the right reason not to close.

It is no longer the situation. The verdict above is derived, on a named run, at a named
commit and tree, by a workflow whose continued call of the command is itself checked on the
merge path by `scripts/release_assurance_gate.py`. The closure criterion is now measured.
