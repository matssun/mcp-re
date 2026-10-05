---
name: security-remediate
description: "Security fix loop over a catalogued finding ledger: an evaluator/worker/reviewer lane drives each file's findings to a terminal disposition, gated per file by clippy + the module-size ratchet + the file's own tests, per batch by the structural gates + touched crates' test suites, and closed by one script that commits what review accepted. Consumes the security-audit-funnel's findings. Triggers: 'security remediate', 'run the remediation lane', 'fix the audit findings', 'security-remediate'."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
  - Workflow
  - Write
---

# Security Remediate — the lane

The catalog is the `security-audit-funnel` skill's job (Stage 1 prescan + Stage 2
review → a round's `findings.json`). This skill fixes what it found, file by file,
until every finding on the worklist has a terminal disposition.

The design goal is **tokens**: an agent pays for its whole context on every turn,
so a file costs *turns × context*. Everything mechanical — reading the findings,
locating anchors, mapping usages, writing dispositions, running gates, committing —
is a script called once; the agents' turns go to judgment.

All paths below are relative to the repo root; scripts are in
`.claude/skills/security-remediate/scripts/` (`$S` below).

## The pieces

| piece | what it owns |
|---|---|
| `docs/security/finding-ledger.jsonl` | the disposition truth, one row per fingerprint; the worklist is its actionable rows |
| `<round>/packets/` | per-file finding content (claim, impact, remediation), from `make_packets.py` |
| `<round>/deps.json` | Rust/Python import graph: leaf-first order, `related` files, gate tier (`deps_graph.py`) |
| `.claude/workflows/security-remediate-lane.js` | one batch: evaluate (concurrent) → fix (single writer) → review |
| `.claude/agents/security-fix-evaluator.md` / `-worker.md` | the two role definitions (the reviewer is the evaluator in REVIEW mode) |

Ledger statuses — actionable (`open`, `provisional`, `confirmed`, `regression`,
`needs-senior-eval`) are the worklist; `escalated` / `exhausted` block and wait
for a human; everything else is terminal (`fixed`, `false-positive`,
`accepted-risk`, `superseded`, `wontfix`, `duplicate`, `handled-prior-round`,
`positive-control`, `informational`). A closure other than `fixed`/`superseded`/
`duplicate` needs a one-line reason; `fixed` is written only by `finalize.py`,
after a reviewer accepted a landed diff.

## Bootstrap a round (once)

```bash
R=work/security-audit-<date>-<round>
python3 $S/ledger.py reconcile docs/security/finding-ledger.jsonl $R/findings.json   # new / tracked / regression
python3 $S/ledger.py ingest    docs/security/finding-ledger.jsonl $R/findings.json --round "<date>@<round>"
python3 $S/make_packets.py --out $R/packets <every live round's findings.json>
python3 $S/deps_graph.py --scope <JSON list of the worklist's paths> --json $R/deps.json
```

`ingest` is idempotent and also backfills `path` on rows written before the ledger
carried one. Findings a round reports as needing evidence outside its packet enter
as `provisional`: they are work, decided by the evaluator with the whole tree.

## One tick = one batch

```bash
# 0. first tick of a run only: the lane's attribution rests on a green start
python3 $S/batch_gate.py --work-dir $R/work

# 1. select
python3 $S/next_file.py --ledger docs/security/finding-ledger.jsonl --deps $R/deps.json \
    --rounds "<live rounds, comma-separated>" [--order $R/campaign-order.json] --top 6
```

`exhausted: true` → stop: report the disposition summary, and `rulings.py` for the
human queue. Otherwise run the workflow with `files` = the batch, plus `ledger`,
`packets_dir`, `out_dir` (`$R/work`), `progress_log`, `rulings` (the campaign's
owner-rulings documents — binding on every evaluator), and
`registered_agents: true` once the agent types are registered (session start).

```bash
# 2. after the workflow returns: close the attempt record, then the batch
python3 $S/progress.py reconcile --log <log> --files "<batch files>"     # the result's reconcile_cmd
python3 $S/finalize.py --results <workflow result saved as JSON> \
    --ledger docs/security/finding-ledger.jsonl --work-dir $R/work \
    --trailer "Co-Authored-By: ..."                                       # commits + `fixed`
python3 $S/batch_gate.py --files "<files the batch touched>" --work-dir $R/work
```

**The workspace clippy ratchet is authorized at an integration boundary, not by starting a
run** (owner ruling, 2026-09-28): after a batch, before a PR is opened or updated, or when
the owner asks. A single-file (`--top 1`) run passes `--no-clippy-ratchet` to both
`batch_gate.py` calls and reports the ratchet as skipped. If the change touches lint
configuration, the ratchet machinery, shared compiler settings, or anything else with a
credible workspace-wide lint impact, stop and tell the owner why the ratchet is warranted
now.

`finalize.py` commits each accepted file on its own (bisectable), reverts anything
review did not accept (the patch is kept in `$R/work`), marks exactly the accepted
findings `fixed`, and commits the batch's ledger changes.

**Every test a fix adds is a control ADR-MCPRE-069 must disposition, in the same change.**
The census is held at its closure state — no control that nothing claims and no row
covers — and the lane is where new controls come from. The evaluator's package carries a
disposition item for each test it orders (step 8 of its procedure: register into the unit
whose statement the test falsifies and whose `paths` already hold the file, or cite a
proposition, or a not-evidence family), the reviewer rejects a test that landed without
one, and `finalize.py` measures the census once per batch and reverts, patch kept, any
accepted file whose touched files still carry an undispositioned control, naming them.
Without this the lane adds controls faster than anyone dispositions them: the r12 run
left 157 before the census gate caught it. A red `batch_gate.py`
stops the run: bisect over the batch's per-file commits, revert the culprit, and
return its findings to `open`.

Nothing here pushes. Publication is the owner's call.

## The gate, tiered by cost — not everything per file

The writer lane is serialized, so its throughput is the per-file gate's wall
clock. The gate is therefore split by what can be attributed to one writer:

| when | what | why there |
|---|---|---|
| per file (`check.py post` → `rust_gate.py`) | `bazel build --config=lint` over every target that compiles the file (each library flavor is its own target, so every feature configuration; plus the related files' targets above `local`), the module-size ratchet, the file's own unit tests in the unit-test targets built from those libraries (`--test_arg=<module>::`), each `--it` test target the package named | attributable, and seconds-to-a-minute on a warm cache |
| per batch (`batch_gate.py`) | clippy ratchet, module-size, bazel-srcs, unit-closure, verification-trigger, mutation-lane self-test, the ADR-MCPRE-069 control-census ratchet and `control-census --gate`, every `tools/verification/test_*.py` self-test suite, every Python gate `.github/workflows/ci.yml` invokes with bare flags (read from the workflow, so the two cannot drift; the clippy ratchet's compile probes and `--base` invocations stay CI's); the touched closure — every Rust target that depends on a touched file, under `--config=lint`, and every non-manual test target in it |  minutes, and the same answer after one fix or six |
| pre-handover (`scripts/local_gate.sh`) | `bazel test //...` (the only lane that runs the `async_serve` drain tests), the SLO lane | not claimed by this skill |

**Size is measured and recorded, never blocking** (owner direction, 2026-10-04: finish
the security remediation, record structural debt, decompose in a separate campaign after
the ledger closes). A module grown past its baseline, a new file past 200 lines or a
`too_many_lines` count above its baseline is `size-debt` in both gates: the fix lands and
is not refactored for room. `size_debt.py` records in
`docs/security/remediation-size-debt.jsonl` every oversized production file a writer
TOUCHES, grown or not: path, size before and after, delta, origin
(`pre-existing-oversized` / `new-oversized`), the config/module-size-debt.toml entry, and
the commits and findings that changed it — the machine-readable input to the decomposition
run. Growth is charged only to files the writer touched. The repository size ratchets are
unchanged outside this workflow. Nesting depth and every other lint stay hard.

A red per-file gate saves the change as a patch and reverts it, so the next writer
starts on a clean tree and its failures are its own. The `platform` tier (>50
importers) gates like `wide`; pass `platform_needs_ruling: true` to hold such
files for a human instead.

## Escalation

Security-relevant is not human-only. An evaluator escalates only when, after every
ADR, owner ruling and CLAUDE.md rule, two or more admissible remedies remain and
choosing changes a contract, an authority boundary, a compatibility surface or
product behaviour — the four-field test in the evaluator definition. Escalations
that one decision discharges share a `ruling` id; `rulings.py` renders the queue.
An escalation does not stop the lane: the file's other findings are worked, and
the file is parked clean.

## Following a long run

One journal, `<progress_log>.jsonl`, written by every role through the scripts.

```bash
python3 $S/progress.py render --log <log>                  # human view
tail -f <log>.jsonl | python3 $S/progress.py watch          # anomalies, one line each (Monitor)
python3 $S/progress.py stats --log <log>                    # work rate, escalation rate, closure mix
python3 $S/reduce.py --log <log> --ledger docs/security/finding-ledger.jsonl --out <dir> --check [--live]
```

Read `stats` early: a high escalation or closure rate is a policy problem applied
consistently, and it is cheaper to correct at file 20 than at file 200. The watcher
notifies; it never stops or redirects the lane — there is exactly one writer.

## Honesty

A red gate is decisive. A green file means every catalogued finding has a
terminal disposition and the gates above found nothing — not that the file is
secure, and not that the lanes this skill does not run (bazel, SLO) agree.

`python3 .claude/skills/security-remediate/tests/test_*.py` pins the scripts; each
refusal is paired with its positive control.
