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
| 1 | Structural gates: image tags == `VERSION`, port registry, tracked secrets, Helm fail-closed guards, JCS vocabulary, SLO-harness invocation, SLO-gate self-test, `cargo fmt --check` over all four manifests | seconds |
| 2 | `cargo clippy -D warnings`, then `cargo test --workspace` **and** the feature-gated backend lane (they are different builds), the local demo, and both SDK downloader suites (maturin wheel + napi package, each with its coverage bar and the parity-oracle regeneration) | minutes |
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
- **Stage 2, the SDK half** — the two downloader artefacts are their own Cargo
  workspaces, and their suites drive the bindings from Python and Node. No cargo or
  Bazel lane reaches them. A nonce-length floor added to `build_signed_request_with`
  therefore passed every local stage and arrived in CI with both downloader jobs red:
  every SDK test nonce and all six frozen parity vectors were below the new floor.
  The gate now builds and runs both, and regenerates the parity oracle from the
  freshly built core — a binding that drifts from the core surfaces as a diff in a
  committed fixture rather than as a test nobody wrote.
- **Stages 1-2, the lint half** — `--workspace` and `cargo fmt --all` reach only the
  ROOT universe. `sdk/python`, `sdk/typescript` and `mcp-re-proxy/tests/mock-pkcs11`
  have their own manifests, and the default feature set does not compile
  `etcd_store.rs` or `redis_store.rs` at all. When these checks were advisory and
  root-default-only, they under-reported the tree's warnings by 19 of 60 and never
  noticed that all three extra manifests were unformatted. Both halves now name
  every manifest, and both are blocking — locally and in CI.
- **Stage 5** — running the *same* harness on kind before GKE found six deploy
  defects, three of which would have failed the cloud run outright.

## Stage 4 is content-addressed now: two identities, not one

The SLO lane was the **only** evidence in this repository that was not content-addressed.
`.verification/attestations` are keyed on a fingerprint and are never re-derived while their
inputs are unchanged; `scripts/local_slo_lane.sh` re-measured unconditionally. So an
unchanged tree object was asked to prove itself twice, and the second attempt failed on host
contention — hours lost on a release with no code delta. The measured proof that it *was*
contention: tree `d8a53be9…` gave 6/6 PASS at median 15,282.6 rps on a quiet box, and the
re-run gave 4/6 FAIL with rep 2 at p99 262,944 us, while 48,000/48,000 requests succeeded
across both rounds. Descheduling, not serving.

`scripts/slo_evidence_identity.py` keys the result. **On two identities, because a
performance result is not a proof result.** A proof is a theorem about the tree, so
`(tree, toolchain)` identifies it completely. A throughput number is a claim about a tree
*running on something*, and the something drifts under an unchanged source tree.

| identity | what it covers | what a change means |
|---|---|---|
| **performance surface** | the inputs declared in [`config/performance-surface.toml`](../../config/performance-surface.toml) — serving source, build configuration, harness, envelope, image definition | the result is **invalid**; measure again |
| **measurement context** | hardware class, OS class, container-runtime class, CPU count, benchmark configuration | the old result is **about a different question**; measure this one |

Reuse needs all three of: same surface, same context, and a record inside the declared
freshness window (90 days). Anything else re-measures **and says which of the three moved** —
a re-measurement with no stated reason is how unconditional re-measurement comes back.

Two rules that keep it honest:

- **Every declared surface input must be git-tracked**, and the script refuses an untracked
  one. A fingerprint input outside the tree makes one commit fingerprint two ways depending
  on whose working copy computed it — a defect this repository has already had once.
- **Only a PASS is attested.** An `INCONCLUSIVE` (contended box) or a `FAIL` is precisely
  what must not become a cache hit; recording one would let a contended run answer for the
  tree until the window expired.

The store is `.verification/slo/`, which — like the attestation store beside it — is
derived evidence and is **not tracked**. Reuse is therefore per-box, which is the right
scope: the measurement context is a class, and a class is not a promise about someone
else's machine.

`SLO_FORCE_REMEASURE=1` bypasses the cache. `--max-age-days N` narrows the window for a
release that wants a fresher number than the standing policy.

## The release-grade run is on the self-hosted runner

Keying the evidence removed the re-measurements that had no reason to happen. It did not
make the remaining ones comparable — this machine runs editors, other workspaces and a
multi-gigabyte container VM, and none of that is declared anywhere.
[`.github/workflows/slo.yml`](../../.github/workflows/slo.yml) runs the same lane on the
self-hosted runner, through `scripts/local_gate.sh --from 4`, so stage 4 has one definition
and the workflow schedules it rather than re-typing it.

**What that buys, and what it does not.** A self-hosted runner application executes one job
at a time, so no other Actions job runs on the host while the lane measures; the workflow's
`concurrency` group serialises it against itself and never cancels a measurement in flight.
Both stop short of "the host is idle": how many runner applications are registered is
runner-host configuration and is not readable from this tree, and nothing in Actions can
speak for what a person started on the box by hand. So idleness is **measured, not
asserted** — the lane reads the 1-minute load average, waits for the box to settle, and
reports a missed tolerance under load as `INCONCLUSIVE` rather than as a regression. There
is no override for that handling and none may be added.

**Stage 4 stays.** The two run in different measurement contexts, which the identity model
already keeps apart: different `hardware_class`, different context digest, separate records.
Run it here as a pre-flight; read the runner's for a release.

## One anchor per hardware class

`hardware_class` is the context field that decides *which question* a number answers, and it
had no declared vocabulary: a class was whatever `MCP_RE_LOADGEN_HW_CLASS` happened to hold,
`adr051_slo_gate.py` compared every report against the one committed anchor whatever class
it carried, and `slo_gate.py` kept a private list of two classes that may never be an SLO
verdict. Three consumers, no shared vocabulary — and the middle one performed a cross-class
comparison silently.

The classes are declared in `[[context.class]]` in
[`config/performance-surface.toml`](../../config/performance-surface.toml), with each class's
own anchor and whether it may ever carry an absolute production-SLO verdict. The gates read
it; the workflow resolves the runner's class from it rather than restating the name, for the
reason [`config/ports.toml`](../../config/ports.toml) exists.

A comparison across classes is not a stricter or a looser gate — it is a gate about a
different question. So the runner's class is declared **with no anchor**, and a run there
reports `UNANCHORED` (exit 4 from the lane, stage 4, and the comparator): measured,
hardware-independent correctness clean, regression band not established. Declaring the
anchor is a deliberate act — a `workflow_dispatch` run on the quiet runner, its reports
committed as that class's anchor, and `regression_anchor` pointed at the file. Until then,
nothing borrows a developer workstation's numbers to adjudicate a different machine's.

## Stage 5 rehearses the SLO Job spec — and did not, for months

After the eight fleet proofs, stage 5 rehearses the **exact** SLO Job spec the cloud
runbooks schedule: `tools/slo/rehearse_job_spec.sh` builds the bench image, side-loads it
into the kind cluster the proofs left up, and runs
`PROVIDER=kind tools/slo/run_slo_job.sh - kind-local 1 …` — the same manifest, the same
Redis sidecars, the same marker-delimited report extraction.

Both cloud runbooks said this all along. **It was not true.** `tools/slo/run_slo_job.sh`
was invoked by no gate and no harness, so the manifest, the sidecar wiring and the report
extraction had never been exercised anywhere except by hand. That is
[`merge_path_gate.py`](../../scripts/merge_path_gate.py)'s failure class one layer up: there
a control exists and nothing required runs it; here a control is *described* and nothing
invokes it. `scripts/rehearsal_claim_gate.py` is what refuses the claim if its caller comes
loose again — it fails both when the invocation stops being reachable and when the sentence
is deleted without the registry entry.

**Two verdicts, never combined.**

| verdict | decided by | proposition |
|---|---|---|
| job-spec rehearsal | `tools/slo/rehearse_job_spec.sh` | the Job applies, runs, produces a readable summary, and completes |
| SLO regression | `scripts/slo_gate.py` | the throughput and latency of a **declared hardware class** meet their targets |

The rehearsal prints a throughput figure, and it is a plumbing figure: a single unpinned
node on a developer box, with `CPU_REQUEST` lowered so the pod is schedulable at all, is
not a hardware class. That rule used to live in a comment. It is now structural —
`slo_gate.py` refuses any report whose `config.hardware_class` is `kind-local` or `smoke`,
by raising rather than by recording a failure, because such a report is not a run that
missed its targets but a run that was never about them.

## Before stages 4 and 5: the disk preflight

Both heavy lanes call `scripts/heavy_lane_disk_preflight.py` **before** they start, and
refuse with `INFRASTRUCTURE_UNAVAILABLE` when a declared free-space floor is not met.

The floors, and the derivation of each number, are in
[`config/heavy-lane-floors.toml`](../../config/heavy-lane-floors.toml). Two filesystems are
measured, because one of them cannot be seen from the host: on Docker Desktop the container
runtime lives inside a VM, so its free space is measured by running `df` inside a container
— using an image that is **already present locally**, since pulling an image to find out
whether there is room to pull images fails on exactly the state this exists to catch.

It is not a control and decides nothing about a change. It decides whether a measurement is
worth starting, and it exists because the alternative already happened twice during v0.17:
with the Docker VM at 100%, the Redis sidecars could not create their append-only
directories, the SLO bench's Redis fleet died, and the kind harness printed
`PROOF FAILED: load generator did not complete` about a proof that had never run.
`docs/releases/v0.17.0-provenance.md` records the measurement — 98 GB, 0 available.

**A red that measured nothing is the inverse of a green that measured nothing, and it costs
more**: it is read as a regression in the code under test, and it was, for a day.

Three exit codes, and the middle one is the point:

| code | verdict | meaning |
|---:|---|---|
| 0 | `PASS` | every declared floor is met |
| 20 | `INFRASTRUCTURE_UNAVAILABLE` | a floor is not met — an environment fact, not a code result |
| 21 | `UNMEASURED` | a floor could not be measured at all; "could not decide" is not "passed" |

`--reclaim` is opt-in and deliberately narrow: it removes `mcp-re-*` images at versions
`VERSION` no longer names, and nothing else. A full disk is not a licence to prune another
project's images, and the running kind cluster's node image is not ephemeral.

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

| any | unanchored class | **UNANCHORED** (exit 4) — measured, correctness clean, no anchor for this class |

Declaring or refreshing a baseline still requires a quiet box: a conservative pass is
good enough to gate a change, not to set the number everything else is measured
against. The self-hosted runner is the quiet box — see *The release-grade run is on the
self-hosted runner* above, and note that "quiet" there is still measured by this same
handling rather than assumed.

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
