---
name: security-audit-funnel
description: "Token-economical, slice-scoped security audit funnel for a service or a semantic review slice of one. Runs a cheap deterministic whole-repo structural pre-scan, then a multi-agent review of one semantic review slice whose findings are partitioned per file for parallel fixing. The adversarial verify gate is opt-in, not the default. Triggers: 'security audit <service>', 'pre-scan <service>', 'is this service ready for a full security audit', 'audit funnel', 'security-audit-funnel'."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
  - Workflow
  - AskUserQuestion
  - Edit
  - Write
---

# Security Audit Funnel

A full multi-agent security audit costs millions of tokens, and you pay that cost
**on every iteration** of the fix→re-audit loop — because after remediation you
cannot trust that fixes did not introduce new problems, so you must re-run. This
skill front-loads cheap gates so a service is **structurally sound and free of
obvious defects before** the expensive verified scan ever runs.

Three stages, cheapest first. Each is a **gate**: stop, surface, fix, re-invoke.

```
Stage 1  Deterministic pre-scan      ~0 tokens   whole repo, always
Stage 2  Review, no verify           ~3/slice    the working audit — every finding kept
Stage 3  Verify gate + synthesis     ~hundreds   OPT-IN, per slice, on request only
```

**Stage 3 is not the destination.** Rounds 8 and 9 ran Stages 1–2 only, and that is now the
default. The verify gate suppresses false positives ahead of a *report*; it earns nothing when
the output is a per-file worklist that a fixing agent opens the source to confirm anyway. Run it
only when asked, and only for a slice whose false-positive rate actually justified it.

**Why this saves tokens** (validated on the first service it ran against): Stage 1 caught the entire
dead-wired-ingestion cluster and the no-auth defect — 21 of 34 criticals — for
zero LLM cost; the full scan had spent ~54 verify agents confirming the same. The
Verify phase (3 skeptics/finding) is ~10× the Review phase and exists only to
suppress **false positives**. Structural facts ("class never instantiated", "no
auth wired") have no false positives, so paying the verify cost on them is waste.
Fixing them before the full scan also shrinks the full scan's Verify input.

---

## Idempotent / re-invocable

This skill is **not** a long-running process. It runs to the next gate, then hands
control back. You "resume" by **re-invoking it after fixes** — it re-reads
persisted state and advances. State lives on disk, never in a live process:

- `work/security-audit-<date>-<round>/<svc>-prescan.json`     — Stage 1 verdict + defects
- `work/security-audit-<date>-<round>/<svc>-prerun.json`       — Stage 2 raw findings (bucketed)
- `work/security-audit-<date>-<round>/<svc>-code-audit-<date>.md` — Stage 3 report

On every invocation: re-run Stage 1 (cheap), then advance to the first stage whose
gate is not yet satisfied. Re-running Stage 1 after a fix round is the point — it
confirms the structural floor still holds and that fixes did not regress it.

---

## Protocol

### Inputs
- **Repository root** — always the whole tree. Stage 1 needs it (below).
- **Slice** — *which semantic review unit Stage 2 audits.* For MCP-RE this is governed by
  ADR-MCPRE-059 P6 and §12; see "Scoping" below. Absent a slice the funnel audits everything,
  which is supported but is the weakest configuration.

### Scoping — the slice is a semantic owner, never a directory

ADR-MCPRE-059 §2.3 is normative: **the primary audit unit is a semantic review unit, not a
directory, file, or arbitrary function.** A directory is a packaging decision; it sometimes
coincides with a security boundary and often does not. A Rust module is evidence of locality,
not a security-review unit.

A slice is one of the four kinds in §12, and the kind decides the context packet:

| Slice kind | Audits | Packet |
|---|---|---|
| **owner** | one semantic authority — Replay, Custody, TlsCustody, TrustRevocation, Admission, ChannelBinding, ContinuationControl, Audit, Retention, VerifiedContext, McpTransportContract, ServerIdentity, DelegatedSigningFacts | that owner, its tests, its formal spec, the narrow types it directly depends on, **and its single serving-path call site** — nothing else |
| **relation** | a cross-machine invariant (X2a, X2b) | the two owners' *established contracts*. Not their implementations. |
| **composition** | Layer-A assembly, startup planning, materialization, serving construction, request pipeline | the orchestrator plus the contracts of what it assembles |
| **capability** | signing authority, credential material, replay authority, network authority, admission, continuation, drain, trust/revocation, delegated assertions — creation to destruction | cuts across the module graph by design |

The owner enumeration is a ruled artifact, not a per-run guess: it must exist and be approved
before a sliced run (ADR-059 §19.2), and it carries a totality gate — every production file
reachable from at least one owner slice, none from two. **Without that gate a file in no slice
is audited by no run while every slice reports clean.**

**Include the call site. Measured, not assumed** (r10 pilot, 2026-08-18: 8 agents, 141
findings, all six lenses returned `too_narrow`). Auditing a gate without its call site
establishes that the gate is correct but not *that it is a gate*: `AdmissionState::is_enforced()`
had no in-packet caller, so no reviewer could decide whether the check runs on the request path
at all. The call site is the **same** security proposition, not a neighbouring one — widening to
it is not widening to composition. Admission needed `http_profile_serve.rs`; Custody needed the
~50 lines of `cli.rs` that consume its violation list.

**Exclude on proposition, not on name.** `config_state/in_flight_limit.rs` shares the word
*admission* with the Admission owner and nothing else — it is the concurrency-ceiling basis,
owned downstream by `async_fleet`. Two lenses flagged it `too_wide` and it cost attention the
undecidable questions needed.

**A deliberate exclusion is cheap when it lands on an ASSUMES and expensive when it lands on a
hot path.** Excluding Custody's provider adapters was right — every place a reviewer wanted them
became a legitimate assumption. But it left one property genuinely undecidable inside the slice:
whether `KmsResponseSigner::sign_response` puts a KMS round-trip on every response depends on
adapter caching. Record such a case; do not let it read as answered.

Owner audits produce `ASSUMES / GUARANTEES / EXPOSES`. Every GUARANTEES line is a candidate
`THM-NNNN`; an ASSUMES line resolving to neither an `ASM-NNNN` nor a named neighbouring owner is
a missing graph edge, and is a finding in its own right.

### Stage 1 — Deterministic structural pre-scan  (always runs)

Run the bundled scanner (stdlib-only, no Bazel/uv needed — it is analysis tooling,
not production code). It is **polyglot and role-aware**: it classifies each file
by language (Python / Rust) AND role (library | binary | comproot | adapter | demo
| test | generated | migration | script), then applies only the checks that role
warrants. The single command works for any target:

```bash
python3 "${CLAUDE_PLUGIN_ROOT:-dot-claude-project/skills/security-audit-funnel}/scripts/prescan.py" \
  <src-dir> --json work/security-audit-<date>-<round>/<svc>-prescan.json [--allow <allow.json>]
```

What it asserts (role-sensitive — a key correctness property):

- **Python service** (has a composition root or HTTP surface): every orchestration
  class is referenced in production; long-runners are wired into the comproot; no
  noop/null impl in the comproot; no `NotImplementedError`-only methods; HTTP
  endpoints have inbound auth wired. A pure Python *library* downgrades dead-wiring
  to advisory (consumers wire it).
- **Rust, any production file** (`<crate>/src/`): no `todo!()`/`unimplemented!()`
  on a shipped path; no `unsafe` unless allowlisted; no panicking call
  (`unwrap`/`expect("…")`/`panic!`/`assert!`) in a security-relevant file unless
  allowlisted.
- **Rust binary / comproot / demo**: a serving surface (`TcpListener`/`serve`/
  `accept`) with **no** verification call is a BLOCK — the Rust analogue of "HTTP
  app with no auth"; a noop/null security impl wired in the comproot is a BLOCK.
- **Rust library**: a security impl never constructed in-repo is **advisory only**
  (downstream consumers construct library types — not a defect).
- Tests / generated / benches / examples / generators outside `src/` are excluded.

`unsafe`, security-path panics, and serve-without-verify are **block-unless-
allowlisted**. Allowlist a justified case inline (`// prescan-allow: unsafe` on the
line) or via `--allow <json>` (`{"unsafe": ["sandbox_linux.rs"], "panic": [...],
"serve-without-verify": ["mcps-demo-fileserver"]}`). Exit `1` = NO-GO.

**Stage 1 always takes the whole repository, even for a sliced run.** Its checks are
inherently non-local: "class never instantiated", "noop wired in the composition root",
"serve surface with no verify call" are all answered from the composition root, which lives
elsewhere in the tree from most of what it wires. Prescanning a slice reports the rest of the
tree's wiring as absent — **false dead-wiring on every slice**, worst on the slices that own the
most-wired types. It costs ~0 tokens, so there is nothing to trade. Apply the slice when
partitioning the output, never to the input.

The finding ledger is likewise whole-repo. A per-slice ledger loses the regression signal for
any finding that moved across a slice boundary.

**Gate 1:**
- **NO-GO** → present the blocking defects (grouped by kind). These are
  heuristics — confirm each from source with Read/Grep before asserting it (e.g.
  `grep -rn "ClassName(" src/`; for Rust confirm the `unsafe`/panic is genuinely on
  an untrusted-input path). Justified-but-intentional blocks (FFI `unsafe`,
  fail-closed `expect` on OS entropy, an intentionally-unverified inner server)
  are **allowlisted**, not "fixed". Then **ask the user** (Fix gate) before
  changing source. **Do not proceed to Stage 2.**
- **GO** → "structural floor clear" (means *audit-ready*, NOT *secure*). Carry any
  `auth-manual-verify` / `verify-manual-verify` warning into Stage 2. Proceed.

### Stage 2 — Review without verification (the working audit)

Run **Catalog + 3-lens Review only**, stopping **before** the Verify phase, over
**one slice**. See `references/funnel-workflow.md` for the `PRERUN` cut point.

Run the slices **bottom-up** — owners, then relations, then compositions, then
capabilities (ADR-059 §19). A relation audit consumes the contracts its owner audits
produced, so running it first wastes the run.

**Keep every finding.** Do not filter to the top severities: the output is a fix
worklist, not a report, and a fixing agent opens the source anyway. Bucketing still
applies, but as *fix ordering*, not as a discard:

- **act-now (structural)** — dead-wiring, noop substitution, missing-auth,
  unimplemented contract, fail-open default. Confirmable from source in seconds.
- **defer (behavioral)** — exploitability/logic/crypto/race claims. False-positive-prone;
  the fixing agent adjudicates these at the file, and only an explicitly requested
  Stage 3 pre-adjudicates them.

**Partition the results by file, under the slice.** This is what makes parallel fixing
possible and what keeps each slice's verdict readable:

```
<round>/<slice>/BY-FILE.md      the fix input, one section per source file
<round>/<slice>/REPORT.md       the same set, severity-ordered
<round>/<slice>/raw.json        every finding, unfiltered
```

One slice's results are never merged into another's before dispositions are recorded.
Reconcile against the whole-repo finding ledger *before* bucketing, so a prior round's
adjudication is not re-paid.

**Gate 2:** present the act-now bucket for this slice; **ask the user** whether to fix.
Then fix per the ONE-FILE-AT-A-TIME rule, and re-run Stages 1+2 on that file until clean.

### Stage 3 — Verify gate (opt-in, not the default)

**Do not run this unless asked.** Rounds 8 and 9 both ended at Stage 2 by design.

Its value is suppressing false positives ahead of a *report* — when the deliverable is a
per-file worklist, the fixing agent performs that adjudication for free while it has the
source open, so the ~10× verify cost buys ordering that the fix loop produces anyway.

Run it when the deliverable really is a report or an external attestation, or when one
slice's behavioral findings proved noisy enough to justify the gate on that slice alone.
Then: the complete workflow with the 3-skeptic Verify gate (≥2/3 confirm from source,
default-invalid) plus synthesis, scoped to that slice.

### Stage 6 — whole-system adversarial pass

After the slices are reviewed, ADR-059 §12 Stage 6 asks one question: **find any security
dependency, authority relationship, assumption, bypass, or composition edge missing from the
assurance graph.** It does not re-derive module internals — it reasons from the slice
contracts and descends into code only where a cross-boundary claim looks suspicious.

A missing edge is an architectural finding, not only a bug: the graph was incomplete.
Never infer `A secure ∧ B secure ∧ C secure ⇒ system secure`; that inference is false and
Stage 6 exists to attack the compositional argument, not to confirm it.

---

## Fix gate (Stages 1 and 2)

When a gate has fixable defects, **ask before fixing** — never auto-batch edits:

> Found N blocking structural defects (Stage 1) / M obvious findings (Stage 2).
> Shall I fix these before continuing the funnel?

Honor the project rules: **one file at a time, explicit approval for multi-file
changes** (CLAUDE.md). Security-relevant fixes (auth, signing, tenant binding)
are ADR-driven — design before coding; do not decide security behavior solo.
After a fix round, **re-invoke this skill** — it re-runs Stage 1 to confirm the
floor still holds, then advances.

Use `AskUserQuestion` for the gate. If the user is AFK/autonomous, default to
*report and stop* at a NO-GO (do not silently run the expensive Stage 3 over
broken code).

**A slice's clean verdict is scoped to that slice.** It says nothing about the owners it
depends on, about the relations it participates in, or about the compositions that assemble
it. Never aggregate per-slice GO verdicts into a statement about the system — that is the
false inference Stage 6 exists to attack.

---

## What each stage can and cannot catch

| Stage | Catches | Cannot catch |
|---|---|---|
| 1 deterministic | unwired classes, noop-in-comproot, missing auth wiring, stub methods | neutered-but-present middleware, any behavioral/logic defect |
| 2 review (unverified) | obvious structural + clear-cut findings, all lenses | false positives are NOT yet filtered — do not trust behavioral claims |
| 3 verify (opt-in) | suppressed false positives ahead of a report | nothing structural left (already gated out) — by design |
| 6 whole-system | missing graph edges, undeclared dependencies, authority duplication, bypasses | anything the slice contracts got wrong internally — that was Stage 2's job |

A **NO-GO / fail is decisive**. A **GO / pass is never a clean bill of health** —
it only means the stage's cheap checks found nothing blocking and the next, more
expensive stage is now worth running.

## The fix round — measured calibration (r10 W1, 2026-08-18)

27 agents, one source file each, 56 findings. What the round established:

**Agents must not run the build or the tests.** They share one working tree and one Bazel
output base, so any build result an agent gets is contaminated by its siblings' half-written edits — and,
more importantly, an agent that cannot run a test cannot report a green it did not measure.
Compilation and tests are CENTRAL, after the fleet lands. This removes the exact failure
mode that killed earlier rounds (agents claiming fixes they had not made) by construction
rather than by review. Cost: the central pass fixes a handful of compile errors. In r10
that was two, against 27 files and ~3000 lines.

**Adjudicate against the REVIEWED COMMIT, not the working tree.** `git show <sha>:<path>`.
Measured failure: the `push_trust` agent marked a finding FALSE-POSITIVE citing code that
only read that way because a sibling agent had fixed it minutes earlier. Right conclusion,
wrong label — the finding was real at the reviewed commit and closed by the sibling's fix.
Parallel agents on one tree silently rewrite each other's evidence base.

**Never rename or delete an existing test function.** Names are load-bearing:
`verification/policy/verification.toml` selects them as `tested_symbols` with `--exact`, so
a rename makes the selection match nothing — a lane that passes on zero tests. Two agents
renamed before this rule was added to the brief; both happened to miss the registry.

**A fix's deliverable is the change PLUS the mutation that reddens its test.** Requiring the
agent to state the exact one-line mutation (not just "I added a test") is what makes the
report checkable without re-reading the diff.

**Name the feature lane in the report.** Three of 27 files were behind non-default features
(`online_ocsp`, `redis_replay`, `async_serve`); a test target built without them compiles
their tests to zero and exits 0. Agents caught this themselves when told the rule.

### The finding class to expect

Most `high` findings were EVIDENCE gaps, not code defects: a guarantee labelled
`test-backed` that no test reached. The code was already correct; the claim was wrong.
Watch for the assertion anti-pattern `assert!(!matches!(x, Ok(Good)))` — it passes on
`Err(_)`, so a fixture that fails early satisfies it. That is how r10's one CRITICAL hid.
