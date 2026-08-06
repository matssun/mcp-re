# Security audit funnel — MCP-RE round 7 @ `5491cdd`, 2026-08-03

> **STATUS: Stages 1 and 2 complete. 153 clusters, all `unreviewed`.**
> `BY-FILE.md` is the fix input — every finding grouped under the file a fixer opens.
> `REPORT.md` is the same set severity-ordered.

**This directory is under `/work/`, which is gitignored. Nothing here goes to the
public repository.** It holds unverified security findings about the current code,
including claims that would be useful to an attacker if published before remediation.

Stages 1 and 2 of `security-audit-funnel` were run. **Stage 3 (the full audit with the
3-skeptic adversarial verify gate) was NOT run**, by standing owner decision — a finding
we are going to fix anyway does not need to be pre-verified. So no finding here has been
through a false-positive filter.

## Where this round was aimed

Round 6 fixed **130 clusters**, including all 25 highs. That is 173 files and +16577
lines of code written under remediation pressure and **never reviewed since**. The
reviewing agents were told this explicitly and told to review the *fix*, not the original
defect. That is where the round paid:

- **53 of 153 clusters are flagged `incomplete_round6_fix`** — a round-6 fix that closes
  the path the finding named and leaves a sibling path open.
- **0 regressions** by ledger fingerprint, and 0 claimed by any agent. Round 6's fixes
  hold where they were applied. The problem is where they were *not* applied.
- **31 clusters land on the 5 modules that did not exist at the round-6 pin**:
  the whole `mcp-re-client` crate, `aws_sts.rs`, `client_revocation.rs`,
  `reloading_trust.rs`, `transparency.rs`.
- **16 clusters are `OLD`** — files untouched since round 6, so genuine round-6 misses.

## Stage 1 detail

First pass **NO-GO**: 2 blocks, both in the new `mcp-re-client` crate. Both read from
source and **allowlisted, not "fixed"**, because both are justified:

| site | class | why allowlisted |
|---|---|---|
| `mcp-re-client/src/main.rs:29` | `unsafe` | `sigaction` install, byte-for-byte the construction already accepted in `mcp-re-proxy/src/main.rs`: zeroed struct, static `extern "C"` handler doing only an atomic store |
| `mcp-re-client` | serve-without-verify | the local leg is *deliberately* plain MCP; verification is cross-crate at `serve.rs:194` → `ClientProxy::handle`, and `config.rs:297` refuses a non-loopback bind unless `local.allow_non_loopback` is set |

The second was **carried into Stage 2 as unit u11's assignment** rather than dismissed:
the loopback guard is the only thing between the network and a live signing identity.
Stage 2 found the guard is real but reachable-around (R7-C016) — see below.

Second pass: **GO**, 0 blocking, 1 warning (the standing `verify-manual-verify` on
`mcp-re-proxy`, assigned to unit u3).

## Cluster counts

163 raw findings from 34 agents (11 units x 3 lenses + catalog), deduplicated to 153
clusters. Clustering is deliberately conservative — a missed merge shows up as two
adjacent entries; a wrong merge hides a defect.

| severity | clusters | act-now (structural) | defer (behavioral) |
|---|---|---|---|
| critical | 0 | 0 | 0 |
| high | 34 | 5 | 29 |
| medium | 86 | 11 | 75 |
| low | 33 | 10 | 23 |
| **total** | **153** | **26** | **127** |

No criticals. Rounds 1-6 have taken the outright bypasses off the board; what is left is
narrower and mostly conditional on a deployment choice.

## Ledger

Carried forward from round 6 (306 entries) and ingested to **469**. Reconcile: **0
regressions**, 0 already-tracked, 97 new by exact fingerprint, 66 fuzzy candidates
(same file + category as an adjudicated round-6 finding, different claim — these are the
"round 6 fixed X in this file, round 7 says Y in the same file" pairs, which is exactly
the incomplete-fix shape this round was hunting).

## Source-confirmed before assertion

Per the funnel's own rule, the structural highs were read from source rather than
batch-trusted. All five confirmed; two changed shape in the reading.

- **R7-C009** — *round 6's headline replay fix cannot run in production.* CONFIRMED and
  this is the round's most important structural fact. `InMemoryAsyncAtomicReplayStore`
  is the only store implementing the per-actor budget (round 6's C058 fix). It does not
  override `durability_class()`, so it declares `SingleProcessReference`
  (`async_replay.rs:103`) — and `app.rs:592` **refuses to start** with any store that
  declares it. The two stores that can serve both declare `Durable` and both say at the
  impl that they hold no ceiling and budget nothing (`async_redis_store.rs:148`,
  `async_etcd_store.rs:205`). So the fix, and its negative control
  `one_actor_cannot_spend_the_whole_ceiling_and_deny_another`, exercise a path
  `app.rs` will not serve with. **Correction to the obvious reading:** this is not by
  itself an exploitable hole — the shipped stores have no ceiling to exhaust. What it
  means is that the round-6 fix protects nothing in production, and the real exposure
  moves to R7-C026/C027/C031: Redis retention is governed by `maxmemory-policy`, which
  nothing verifies, and eviction of a live nonce key re-opens replay.
- **R7-C003/C013** — CONFIRMED, and the asymmetry is the opposite of the one round 6
  fixed. `VerifierPolicy::new` enforces `0..=300` and errors outside (`policy.rs:142`),
  and `response.rs:481` turns that error into `unwrap_or_default()` — a *tighter* 30s
  gate, so the signature path fails safe. But `DelegationVerifyParams.max_clock_skew` is
  a plain `i64` used raw at `delegation.rs:226-227` with **no cap**. A deployment
  configuring 86400 gets a 300s-capped signature gate and a 24-hour-wide
  credential-acceptance window. The doc comment at `response.rs:465` claims "one
  configured skew drives both windows" — it does, but only one of them is bounded.
- **R7-C006** — CONFIRMED. `.dockerignore` excludes `work/` (round 6's R6-C019 fix, with
  a 12-line comment explaining that `work/` is where operators are told to keep filled-in
  cloud credential scripts). `.gcloudignore` does **not** — it lists only `.git/`,
  `target/`, `node_modules/`, `.venv*/`, `sdk/**/dist/`, `sdk/**/native/`, `*.log`. So
  `gcloud builds submit` uploads seven rounds of unremediated findings, and whatever
  credentials the runbooks put there, to Cloud Build. The fix closed the Docker path and
  not the Cloud Build path.
- **R7-C024** — CONFIRMED. Manifest expiry is enforced only inside `refresh_once`
  (`anchors.rs:202`), which runs only on the refresh thread. `main.rs:139` starts that
  thread only when `trust.reload_secs > 0`. Neither `serve.rs` nor the proxy path
  consults `manifest_expires_at`. So at `reload_secs = 0` an expired manifest is never
  withdrawn and the client verifies against expired anchors indefinitely — contradicting
  `anchors.rs:540`, "an expired trust picture must stop verifying, not keep serving".
  The startup warning at `main.rs:154` names only *revocation*, so the operator is told
  half the consequence.
- **R7-C034** — CONFIRMED. The notification branch returns `served(ack)` at
  `http_profile_serve.rs:716`, before the retention block at `:849`. The audit record
  *is* emitted for the 202 (`:715`); retention is not. A client selects whether its
  exchange is retained by omitting the JSON-RPC `id`, which defeats the property round 6
  shipped retention to establish ("a deployment with retention on is asserting it can
  account for what it served").

## The other high-value shapes, unconfirmed

Not yet read from source — these are the behavioral bucket and are stated as the agents
stated them:

- **Unauthenticated KMS/HSM amplification** (R7-C020/C021/C022, `delegated_tls.rs:103`,
  `async_serve.rs:322`): one remote KMS `Sign` per TLS ClientHello, before any
  authentication. If true this is a cheap remote cost-and-latency amplifier.
- **Retention fsync under a process-global mutex on the async runtime** (R7-C001/C002/
  C028, `transparency.rs:206`): the round-6 blocking-I/O cleanup that moved the
  trust-epoch read off the data plane did not cover the retention path it added.
- **Redis eviction re-opens replay** (R7-C026/C027/C031) — see R7-C009 above.
- **Loopback guard reachable-around** (R7-C016, `serve.rs:366`): the guard lives in a
  private `validate()` reached only via `from_json`/`read`; `serve::bind()` and the
  builder do not enforce it.
- **Front-truncated chain attests Complete** (R7-C025, `chain.rs:316`): hop 0's own
  continuation is never checked.

## Files

| file | contents |
|---|---|
| `BY-FILE.md` | **the fix input** — 49 work units, every finding under the file to open, line-ordered, every severity |
| `REPORT.md` | the same 153 clusters severity-ordered, with `[NEW SURFACE]` / `[INCOMPLETE R6 FIX]` tags |
| `clusters.json` | 153 clusters with raw-finding provenance and fix hints |
| `stage2-raw-findings.json` | all 163 raw findings verbatim with bucket/lens/unit/confidence |
| `property-catalog.md` | normative property catalog (46.0k chars) built from `docs/spec/`, the conformance lens's yardstick |
| `reconcile.json` | ledger reconcile output (new / tracked / regression / fuzzy) |
| `finding-ledger.jsonl` | durable ledger, 469 entries across 7 rounds |
| `stage1-prescan.json` | Stage-1 verdict (GO) |
| `stage1-allowlist.json` | source-confirmed allowlist, one justification per entry |
| `stage2-workflow.js` | the Stage-2 workflow script (11 units x 3 lenses), re-runnable |
| `cluster.py`, `render_byfile.py`, `setdisp.py` | clustering, by-file renderer, triage recorder |

## Caveats that bound this round

1. **No verify gate.** Behavioral (`defer`) claims are false-positive-prone by
   construction. Structural (`act-now`) claims are cheap to confirm from source — but
   confirm them; the C009 and C003 corrections above are what that is for.
2. Severity and confidence are each reviewing agent's own, not adjudicated.
3. Cross-lens corroboration raises prior probability; it is not verification.
4. `sdk/typescript` received no deterministic Stage-1 structural scan (the scanner is
   Python + Rust only); its structural checks were done by an LLM lens instead.
5. The gate was **not** re-run before this audit. `HEAD` is the merge of PR #514 and the
   tree is clean, but no `scripts/local_gate.sh` run backs this round the way one backed
   round 6. Run it before fixing, so a fix-induced failure is distinguishable from a
   pre-existing one.
6. Round 6's one open owner ruling — the ADR-MCPRE-051 §7 SLO re-baseline after the TLS
   resumption refusal — is still open and was deliberately not re-filed.

## Remediation run — parallel fan-out, one outage, one recovery

The 120 findings still open after the owner's three clusters were partitioned into
eight disjoint file-ownership groups and worked in parallel, one agent per group. No
agent could edit `mcp-re-core/src/{error,audit}.rs`, any `Cargo.toml`, `VERSION` or
`config/ports.toml`; a fix needing one of those came back as `confirmed-open` naming
the exact change, for the owner to merge centrally.

**All eight agents were killed mid-edit by a quota exhaustion.** None had written its
results file, so every agent's knowledge of what it had already done was lost — while
~6,900 lines of its edits remained in the tree. Two consequences worth recording:

1. **A killed agent leaves a tree that does not compile.** `cargo check --workspace
   --all-targets` exited 101 afterwards: `retain()` had been converted to return a
   future with its own tests still calling `.expect()` on it, `collect_body` was called
   but never written, an `AuditSinkKind` import had been dropped, and
   `spawn_trust_reload_task` had gained a parameter its caller did not pass. Groups B
   and C were entangled through `cli.rs` by one half-changed API, so they were **merged
   into a single owner** on relaunch rather than allowed to race on it.
2. **The replacements had to reconstruct state from `git diff`, not from a report.**
   Each was told which file its predecessor died in and warned that a modified file
   proves nothing about which finding was being worked. This found real damage:
   `pkcs11_keysource.rs` had been left non-compiling (field renamed, neither use site
   updated, no test), and a `--selftest` had been written that aborted on a missing
   import before running a single case — i.e. it would have read as green.

**The process rule this round adds:** an agent must persist its findings file after
every resolved finding, not at the end. Work held only in a context window is lost
whole; work on disk is lost only back to the last write. This is the same class of
error as the earlier one recorded here — that pipeline output is not verification
evidence unless the exit status belongs to the command being claimed and the tested
tree is stable for the duration of the run.

**A second instance of that same trap, hit during remediation.** Two separate
negative-control harnesses (one agent's, one the owner's) reverted a fix, launched
`cargo test`, and blocked — one on the build lock, one on a cold target directory —
leaving the source file in its *mutated* state for many minutes while other work read
it. Both restored correctly, but a mutation harness that can block is a harness that
can publish a half-reverted tree to every concurrent reader. Isolate the target
directory, and treat the restore as the harness's obligation on every exit path.

## Stage-4 SLO: the FAIL is environmental, with a residual worth one quiet-box run

`scripts/local_gate.sh` stage 4 failed on the round-7 tree: median **4450.7 rps**
(6 reps, 4427.6–4491.1) against a floor of 4701.3, anchor 5530.9. Every latency
percentile passed; only throughput fell.

Rather than assert "environmental" from the box's load, the A/B was run: a detached
worktree at the pre-round pin `5491cdd`, measured on the SAME box within the hour.

| tree | median rps | reps | range |
|---|---|---|---|
| pre-round `5491cdd` | 4583.4 | 3 | 4563.0–4636.9 |
| round-7 working tree | 4450.7 | 6 | 4427.6–4491.1 |

**The pre-round tree fails the same floor on the same box.** The shortfall against the
anchor is therefore a property of the machine today (load ~5 on 14 cores, 29 users,
immediately after a full Bazel build), not of anything this round changed. No baseline
may be declared from it, and `ALLOW_NOISY_BOX` was not set.

The residual is the honest part: the two ranges do not overlap, a ~2.9% gap. That is
not explained by the environmental argument, and it is the order of magnitude one would
expect from `reserve()`'s second pre-dispatch fsync chain plus the admission semaphore.
It wants an A/B/B/A on a genuinely quiet box before the round is called
throughput-neutral. What it is NOT is the ~20% regression the raw gate line implies —
reading that number without the A/B would have sent the next investigation at the
serving path for a defect that is not there.
