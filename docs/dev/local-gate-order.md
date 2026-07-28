<!-- SPDX-License-Identifier: Apache-2.0 -->

# Run everything locally first — the gate order

**Rule: `scripts/local_gate.sh` must be green before anything else.** Before opening
a PR, before `gcloud builds submit`, before creating a GKE cluster, before declaring
or refreshing an SLO baseline. Every stage below is free and runs on this machine.
Cloud spend is justified only after the whole local gate passes.

```sh
scripts/local_gate.sh                # stages 1-4 (everything free)
scripts/local_gate.sh --fast         # stages 1-2 (static + code suites)
scripts/local_gate.sh --with-kind    # + stage 5: the fleet proofs on a local cluster
scripts/local_gate.sh --from 3       # resume at a stage after fixing a failure
```

It stops at the first failure and tells you how to resume. Stages are ordered by
cost, so the cheapest thing that can be wrong fails first.

| Stage | What | Cost |
|---|---|---|
| 1 | Structural gates: image tags == `VERSION`, port registry, tracked secrets, Helm fail-closed guards, JCS vocabulary, SLO-harness invocation, SLO-gate self-test | seconds |
| 2 | `cargo test --workspace` **and** the feature-gated backend lane (they are different builds) | minutes |
| 3 | `bazel test //...` + the Gazelle drift gate | minutes |
| 4 | The ADR-MCPRE-051 §7 local SLO lane (`scripts/local_slo_lane.sh`) | ~5 min |
| 5 | The four fleet proofs on a local kind cluster — identical harness, chart and images to GKE (opt-in) | ~15 min |

## Why this order exists

It is not hygiene. Each stage exists because skipping it has already cost something:

- **Stage 1** — the multi-replica harness deployed `:0.12.1` while Cloud Build had
  moved to `:0.13.0`. Four `ImagePullBackOff`s, discovered *after* `gcloud builds
  submit`, on a cluster that was already billing. A one-second script catches it.
- **Stage 2** — the default `cargo test --workspace` does **not** compile the
  non-default feature backends (KMS, PKCS#11, Redis, OCSP, etcd, `async_serve`). A
  change can be green on the default battery and not compile on the serving path.
- **Stage 5** — running the *same* harness on kind before GKE found six deploy
  defects, three of which would have failed the cloud run outright.

## The two traps in the SLO lane

Both produce a lane that **looks green while having measured nothing**, which is
worse than a red one. `scripts/local_slo_lane.sh` makes both impossible; the notes
are here because the raw cargo command still exists in the GKE image and in
`docs/bench/`.

**1. `-- --ignored` runs zero tests.** `tls_load_harness_bench` is **not** an
`#[ignore]` test — the whole file is gated to the `redis_replay` feature lane
instead, which is what keeps it out of the default battery. `--ignored` selects
*only* ignored tests, so cargo runs **0 tests**, exits **0**, and writes no report.
Several docs carried this and were corrected. Use `-- --exact`. The lane script
asserts `test result: ok. 1 passed` and fails loudly otherwise.

**2. A relative `MCP_RE_LOADGEN_OUT` is written somewhere you are not looking.**
Cargo runs a test binary with cwd = the **package** root, so `out.json` lands under
`mcp-re-proxy/`, and the gate then reads nothing. Use an absolute path.

Two more things the lane script handles, worth knowing if you run it by hand:

- The harness **spawns the real CLI** as a child process (`MCP_RE_PROXY_CLI` →
  `target/release/mcp-re-proxy`). Building only the *test* target with
  `--features async_serve,redis_replay` is not enough — the **bin** needs them too.
- It needs Docker (it stands up its own primary+2-replica Redis fleet), or an
  existing one via `MCP_RE_LOADGEN_REDIS_URL`.

## Measure on a quiet box, or do not measure

The local SLO lane is **co-located**: the load generator shares cores with the proxy
it is driving. An unrelated build or test battery on the same machine halves
throughput and triples the tail — a FAIL that says nothing about the code.

This is not hypothetical. On 2026-07-18 a "33% SLO regression" was chased through a
counterbalanced A/B/B/A across two worktrees with per-stage timers, and the finding
was that **v0.12.1 itself** measured ~3225 rps on the loaded box against its own
4906.9 rps anchor. The code was never the variable.

The asymmetry is what makes this tractable: **contention can only depress throughput
and inflate latency, never flatter them.** So `local_slo_lane.sh` waits up to
`SETTLE_SECONDS` (default 300) for the load to fall below 30% of the core count, then:

| Box | Result | Meaning |
|---|---|---|
| quiet | pass / fail | taken at face value |
| loaded | pass | **valid** — it cleared the bar while handicapped, which is conservative |
| loaded | fail | **INCONCLUSIVE** (exit 3), not a regression — re-run quiet to decide |

Declaring or refreshing a baseline still requires a quiet box: a conservative pass is
good enough to gate a change, not to set the number everything else is measured
against.

### If the gate appears to hang at `Running tests/…`

On macOS, a freshly-linked test binary is checked by `syspolicyd` before `main` runs.
When the machine is saturated — especially by another build producing thousands of new
binaries — that check queues, and the test process sits at **0% CPU in `_dyld_start`**
for minutes. It is not a deadlock in the test and it clears on its own:

```sh
ps -o pid,etime,%cpu,stat -p <pid>     # 0.0 %CPU
sample <pid> 1 -mayDie | grep -A2 'Call graph:'   # _dyld_start
```

Same remedy as the SLO lane: run on a quiet box. This is why stage 4 refuses outright
rather than reporting a number it cannot stand behind.

## What is NOT in the local gate

Deliberately out — they need credentials, cost money, or need real cloud hardware:

- Live KMS lanes (AWS/GCP) — `scripts/test-gcp-cloud.sh.example`, the
  `*_live_test.rs` suites. They self-skip without live infra.
- The GKE fleet run and the declared-hardware SLO baseline —
  [`docs/security/gke-slo-baseline-runbook.md`](../security/gke-slo-baseline-runbook.md).
  Stage 5 on kind is the free rehearsal for exactly this.

The local SLO lane is a **relative regression** gate against
`docs/bench/adr-051-baseline-local.json` — a dev box with a co-located loadgen never
states production capacity. Absolute production SLOs come from the GKE run only.
