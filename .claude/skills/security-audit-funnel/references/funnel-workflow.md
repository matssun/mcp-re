# Stage 2 / Stage 3 workflow mechanics

Stages 2 and 3 reuse the **same** multi-agent audit workflow (the MCPS-harness
clone). The only difference between them is whether the **Verify** phase runs.
There is no separate script to maintain — one workflow, two cut points.

To audit a different service, copy it and change the per-service constants:
`SVC` / `SRC` / `PIN`, the `UNITS` list (review units), `INVARIANTS`, and the
ADR/PRD discussion numbers the Catalog agent fetches via `gh api graphql`.

## Phase layout (reference workflow)

```
phase('Catalog')    → 1 agent: extract the normative property catalog (ADRs/PRDs + code)
phase('Review')     → pipeline over UNITS: 3-lens review (general/conformance/security)
                       ⟶ produces RAW findings per unit
   └─ verifyFinding()  → 3-skeptic Verify gate on each hi/crit finding  ← STAGE 3 ONLY
phase('Invariants') → core-invariant sweep                              ← Stage 3
phase('Synthesize') → assemble the report from machine-validated data   ← Stage 3
```

The Verify gate (`verifyFinding`, ~3 agents/finding) is interleaved into the
Review pipeline. It is ~10× the cost of Review and exists solely to suppress
false positives.

## Stage 2 — pre-run (review, no verify)

Cut the run off **after Review, before `verifyFinding`**. The cleanest way is a
`PRERUN` guard the per-service workflow reads from `args`:

```js
const PRERUN = (typeof args === 'string' ? JSON.parse(args) : args)?.preRun === true
...
// inside the pipeline, after the 3-lens review produces `findings`:
if (PRERUN) return { rawFindings: findings }          // skip verifyFinding entirely
const verifiedHi = (await parallel(hi.map(f => () => verifyFinding(f)))).filter(Boolean)
```

and skip the Invariants + Synthesize phases when `PRERUN`. Return the raw findings
and write them to `work/security-audit-<date>-<round>/<svc>-prerun.json`.

This runs Catalog + Review only (~30 agents for a 10-unit service) and produces
**unverified** findings — the false-positive gate has NOT run, so the bucketing
discipline below is mandatory.

### Bucketing the raw findings (no agents)

Classify each raw finding by category/keyword — deterministic, zero extra cost:

- **act-now (structural)** — `dead-wire`, `noop`/`null`/`stub`, `not wired`,
  `never started`, `no auth`/`unauthenticated`, `not implemented`, `fail-open`,
  `interface-only`. Confirmable from source in seconds → safe to fix pre-verify.
- **defer (behavioral)** — `race`/`TOCTOU`, `signs the wrong bytes`, `ordering`,
  `replay`, `injection`, exploitability/logic claims. False-positive-prone →
  leave for the Stage-3 verify gate. **Never act on these in Stage 2.**

## Reconcile against the finding ledger (between Stage 2 and any verify)

A re-audit must not re-pay the verify cost on a finding already adjudicated in a
prior round. After Stage-2 produces raw findings, reconcile them against the
durable per-target ledger (`<repo>/docs/security/finding-ledger.jsonl`) BEFORE
bucketing or verifying:

```bash
python3 "${CLAUDE_PLUGIN_ROOT:-dot-claude-project/skills/security-audit-funnel}/scripts/ledger.py" \
  reconcile <repo>/docs/security/finding-ledger.jsonl <svc>-prerun.json
```

It buckets every current finding by its fingerprint (`sha1(file-basename | sorted
significant title tokens)` — stable under line drift / reworded titles):

- **new** — never seen → this is the ONLY set that flows into Stage-2 bucketing
  and the Stage-3 verify gate. Everything else is already known.
- **tracked** — `open` / `handled-prior-round` → already filed; link the existing
  issue, do not re-file.
- **regression** — a `fixed` finding reappeared → **loud**; a fix regressed.
- **suppressed** — `false-positive` / `premise` / `constraint` / `superseded`
  / `positive-control` / `informational` → skip; log the count, never silently drop.
- **fuzzy_candidates** — same file + same category but no exact fingerprint →
  surface for human/LLM confirmation; never auto-suppress.

Then ingest the round and disposition new findings (record HOW in
`verified.method` — never claim `gate-3skeptic` unless the gate actually ran):

```bash
ledger.py ingest  <ledger> <svc>-prerun.json --round "<DATE>@<PIN>"
ledger.py set     <ledger> --id <fid> --status fixed --method fix-merged --issue N --pr M
ledger.py stats   <ledger>
```

The ledger is committed to the audited repo (git history = audit trail); the tool
is reusable across services. This is what makes the funnel cheaper every round
instead of constant-cost.

## Stage 3 — full audit

Run the same workflow with `PRERUN` unset (or absent): Catalog + Review +
Verify + Invariants + Synthesize. Because Stage 2's act-now defects are already
fixed, Review surfaces fewer raw findings, so fewer enter Verify — the expensive
phase is smaller at its input. Output the report and, if requested, severity
issues + a remediation epic.

## Recovery note

If a Stage-3 run is killed mid-Verify, do **not** blind-resume: the `parallel()`/
`pipeline()` fan-out re-runs completed agents. Harvest the per-agent transcripts
and run a forward continuation. See memory `reference_workflow_resume_fanout_bug`.
