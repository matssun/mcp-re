<!-- SPDX-License-Identifier: Apache-2.0 -->

# v0.16 performance investigation — measurement rounds and disposition

Candidate: **`dfd1e8c1a530ec10b7f383954adc537ad88b3fcd`** (PR #811).

This document closes the v0.16 performance investigation. It records what was measured,
under which protocol, on which hardware, and which rounds are release evidence and which
are not. It declares no thresholds and changes none; the authorities remain
[`adr-051-slo-targets.json`](adr-051-slo-targets.json) and
[`adr-051-benchmark-envelope.json`](adr-051-benchmark-envelope.json).

## Why this document exists

Four numbers for "how fast is MCP-RE" were in circulation, spanning 890 to 46,000 rps,
and all four were real. They were not comparable, because they came from three different
measurement protocols on four kinds of hardware. A performance investigation whose
figures cannot be sorted by protocol produces confident comparisons between unrelated
quantities — which is what happened, twice, before the rounds below were separated out.

So the organising rule here is: **a throughput figure is meaningless without its
measurement class.** Every number in this document carries one.

## The three measurement classes

| class | instrument | connection semantics | client | what it answers |
|---|---|---|---|---|
| **A — §7 cold-mTLS** | `tls_load_harness_bench` | cold: one request per connection, full TLS1.3-mTLS handshake each | in-process, co-located with the proxy | regression detection against an anchor measured the same way |
| **B — saturation rig** | `saturation_rig` + N `saturation_loadgen` processes | keepalive, connection reuse | separate processes, corpus pre-signed off the clock | the proxy's own ceiling, with proof the ceiling is the proxy's |
| **C — plumbing** | either, on non-declared hardware | — | — | that the lane runs at all; **never** a capacity figure |

Class A is the ADR-MCPRE-051 §7 release protocol. Class B answers a different question and
its numbers are **not comparable to class A** — the rig's own report embeds that warning in
every file it writes. Class C exists so that a lane can be proven functional on hardware
that cannot produce a baseline.

Mixing A and B is the single largest source of confusion in this investigation's history.

## Rounds, chronologically

### Round 1 — GKE, debug build (up to 2026-07-14) — **INVALID as release evidence**

Class A envelope, but the Job and `Dockerfile.bench` both ran `cargo test` **without
`--release`**. Every GKE §7 figure recorded before 2026-08-06 is a debug build.

Recorded figures, preserved for provenance only: e2-standard-8 and c3-standard-8 in the
~350–500 rps range (358.1 / 452.1 in the re-measurement pair recorded in
[`../security/gke-slo-baseline-runbook.md`](../security/gke-slo-baseline-runbook.md);
402.1 / 499.4 in the `measured_on` block of [`adr-051-slo-targets.json`](adr-051-slo-targets.json)).

**Status: invalid.** A debug binary is not the artefact the release ships.
`production_slo` in the targets file was moved to `invalidated-pending-remeasurement`
for exactly this reason, and the capacity checks in
[`../../scripts/slo_gate.py`](../../scripts/slo_gate.py) skip rather than pass against a
floor derived from it.

The **scaling** factors from this round — e2 0.703, c3 0.671 — are invalid on the same
grounds and for the same reason. See Round 6.

### Round 2 — GKE, release build (2026-08-06) — **valid, the comparison baseline**

Same cluster shape, same v2 envelope, `--release` restored on both sides.

| class | rps | p50 |
|---|---|---|
| e2-standard-8 | 4,390.0 | 25,498 µs |
| c3-standard-8 | 5,228.5 | 20,910 µs |

The 12.3× jump over Round 1 is the debug/release difference and is the bulk of what had
previously looked like a hardware gap against the dev box.

This is the **only round that is like-for-like with the accepted v0.16 figures**, and it is
the comparator used below.

### Round 3 — the ~3.1k GKE round behind `581f247f` — **INVALID, excluded**

An anomalous round used to derive candidate thresholds. Not accepted as release
qualification evidence.

Excluded from the release candidate and not to be relied upon:

- commit `581f247f`;
- throughput floor 1,950 rps;
- scaling floor 0.32;
- the latency ceilings derived from that round.

`581f247f` is **not an ancestor** of `dfd1e8c1` — verified mechanically with
`git merge-base --is-ancestor`, not by reading a log.

### Round 4 — mixed-image GKE run — **INVALID, discarded**

A run in which the three proxy replicas were serving **three different image digests**.
Caused by `image.tag: 0.16.0` with `pullPolicy: IfNotPresent`, which served whatever
each node had cached. The run reported eight passing proofs; it was discarded and re-run
digest-pinned rather than reported.

See "Measurement-system defects" below.

### Round 5 — saturation rig before the SAN repair — **INVALID, measured nothing**

Class B. Every request the rig sent was refused `mcp-re.transport_binding_failed` before
backend dispatch: 100% refused, `backend_cpu_secs` 0.00, no request ever reached the inner
server. Any number attributed to the rig in this window describes nothing.

See "Measurement-system defects" below.

### Round 6 — GKE, release build, candidate `dfd1e8c1` (2026-09-04) — **ACCEPTED**

Class A. The accepted v0.16 performance measurements.

Digest-pinned throughout (`mcp-re-slo-bench@sha256:83d1b043…`), overriding the lane's
mutable-tag default. Cluster: GKE Standard, zonal `us-central1-a`, `default-pool` resized
to 0 and verified at MIG size 0, one node per class, Jobs pinned by nodepool selector.

**e2-standard-8 — capacity**

| metric | value |
|---|---|
| throughput | **4,064.3 rps** |
| p50 added latency | 27,176 µs |
| p99 added latency | 98,930 µs |
| p999 added latency | 137,511 µs |
| successes | 8000 / 8000 |

**c3-standard-8 — capacity**

| metric | value |
|---|---|
| throughput | **4,950.8 rps** |
| p50 added latency | 21,814 µs |
| p99 added latency | 94,564 µs |
| p999 added latency | 111,981 µs |
| successes | 8000 / 8000 |

Retention against the Round 2 like-for-like release-build comparator:

| class | v0.16 | Round 2 | retained |
|---|---|---|---|
| e2-standard-8 | 4,064.3 | 4,390.0 | **92.6%** |
| c3-standard-8 | 4,950.8 | 5,228.5 | **94.7%** |

**This is not a catastrophic performance regression.** It is a single-run figure within
the run-to-run spread this lane has previously shown, on a candidate whose serving-path
sources are byte-identical to the previous candidate (see "Candidate delta" below).

Resolved runtime topology for the capacity lane, **measured rather than assumed** (a probe
pod on each pool reported `nproc`=8 and `cpu.max` unset, so `available_parallelism()` = 8,
and `resolve_topology` returns `min(8, 8)` workers):

- **8 runtime shards × 8 worker threads per shard = 64 serving threads.**

Zero failures across all six runs of this round: 48,000 / 48,000 successes.

### Round 7 — EKS, candidate `dfd1e8c1` (2026-09-04) — **class C, plumbing only**

The declared EKS classes are `m7g.2xlarge` and `c7g.2xlarge`
([`../../deploy/eks/mcp-re-slo-cluster.yaml`](../../deploy/eks/mcp-re-slo-cluster.yaml)).
Both are **barred by the account plan**, confirmed by an actual launch attempt:

```text
InvalidParameterCombination: The specified instance type is not eligible for Free Tier.
```

This is an account-plan restriction, not a quota (`L-1216C47A` is 32 vCPU and ample), and
it is invisible to every read-only API — `describe-instance-type-offerings` lists both
types and `run-instances --dry-run` reports the request would succeed.

The only class the account permitted was **`t4g.small`: 2 vCPU, arm64, burstable**.

| run | resolved topology | rps | p50 µs | ok / fail |
|---|---|---|---|---|
| cores=1 | 1 shard × 2 worker threads | 890.9 | 143,197 | 8000 / 0 |
| cores=8 | 8 shards × 2 worker threads | 927.8 | 134,580 | 8000 / 0 |

`auto` resolved to 2 worker threads, measured by probe (`nproc`=2, no cgroup quota).

**This round provides no AWS-vs-GCP capacity comparison and its throughput is not a
release baseline.** Three independent disqualifiers, any one of which suffices:

1. **Size** — 2 vCPU against GKE's 8.
2. **Architecture** — Graviton arm64 against GKE's x86-64.
3. **Burstable credit state** — `t4g` runs on accumulated CPU credits. The same instance
   class measured **156.3 rps** on 2026-08-01 and **890.9 rps** here: a 5.7× swing that is
   credit accounting, not code.

What the round **does** establish, which is what class C is for: the EKS lane runs
end-to-end against the frozen candidate — authenticated private-ECR pull, the real
`eks.amazonaws.com/nodegroup` selector, digest-pinned image, the three-sidecar WAIT-2
replay tier, marker-based report extraction. 32,000 / 32,000 successes, zero failures.

A shard-topology A/B was also run in this round on the same node (1 shard × 8 worker
threads: 911.0 rps; 8 shards × 8 worker threads: 895.7 rps; ratio 0.983). **It resolves
nothing.** The mechanism under test is `accept` parallelisation across shards, which needs
cores to spread across; on 2 vCPU a null result is the expected outcome whether or not the
effect exists at 8 or 14 cores. It is recorded here as a measurement, not as evidence
either way.

## The local Mac anchor — a separate quantity

[`adr-051-baseline-local.json`](adr-051-baseline-local.json) (v6, 2026-08-06):

| metric | value |
|---|---|
| throughput | **≈15,454.9 rps** |
| p50 / p99 / p999 | 7,927 / 16,037 / 19,495 µs |
| hardware | `apple-m4-pro-14c-dev`, Apple M4 Pro, macOS, 14 cores |
| envelope | class A — cold TLS1.3-mTLS, concurrency 128, 8000 requests |
| resolved topology | **1 runtime shard × 8 Tokio worker threads** |

**This is not directly comparable to the GKE figures**, and it is not a target the cloud
numbers have failed to meet. It is a different machine, a different operating system and a
different resolved runtime topology. Its role in the protocol is as the anchor for the
`local_regression` gate — a hardware-independent check that a change has not regressed the
serving path against its *own* recorded baseline — not as a cross-hardware capacity claim.

### The topology difference, recorded as a candidate factor and nothing more

| lane | runtime shards | worker threads per shard | total serving threads |
|---|---|---|---|
| local v6 anchor (M4 Pro, 14 cores) | 1 | 8 | 8 |
| GKE capacity lane (8 vCPU) | 8 | 8 | 64 |

These are **runtime shards and Tokio worker threads within one process**, not processes.
Each shard owns its own `SO_REUSEPORT` listener; worker threads are the pool depth driving
that shard's reactor and task polling.

This difference is recorded as a **potentially relevant runtime-topology and environment
difference. It is not a proven explanation for the gap.** The project has previously
measured large topology effects in both directions — `resolve_topology`'s own
documentation records 8 shards × 1 worker at 369.0 rps against 1 × 8 at 65.5 rps on an
8-vCPU GKE node under the cold envelope, and the opposite ordering under keepalive — which
is precisely why the factor is worth naming and why naming it is not the same as
demonstrating it. Demonstrating it requires an A/B on one 8-vCPU machine with everything
else held constant. That experiment has not been run and is out of scope here.

## The ~30k–45k historical figures — class B, keepalive

Figures in the 30,000–46,000 rps range originate from the **saturation rig** (class B), not
from the §7 lane. They were measured with:

- **keepalive** connection semantics with connection reuse, not cold per-request handshakes;
- a **multi-process, multi-generator** measurement topology, with the request corpus
  pre-signed before the clock starts;
- the generators, proxy and backend as separate processes so CPU is attributable per tier.

Representative: 8 shards × 8 worker threads reached 44,803 rps, and 16 workers per shard
46,325 rps, on a 14-cpu host — against 10,362 rps for 8 shards × 1 worker on the same host
and instrument.

**These must not be compared with the GKE §7 results.** Amortising the TLS handshake across
a reused connection removes the dominant cost of the cold envelope; the two protocols
measure different things by design. The rig writes the warning into every report it emits:

```text
"NOT comparable to the ADR-MCPRE-051 §7 anchor — different client, different question."
```

For completeness, the post-repair rig run on the candidate produced 8,690–10,840 rps across
a 1/2/4/8-core sweep with all points verdict PROXY and zero failures — measured on a box at
~3.9× its core count in load, and therefore reported as an instrument-liveness result, not
a capacity result.

## Measured GKE scaling factors — measurements, not a verdict

Round 6, `WORKERS_PER_SHARD=1` so `--cores N` means N serving threads:

| class | 1 core | 8 cores | factor |
|---|---|---|---|
| e2-standard-8 | 1,491.3 rps | 4,498.5 rps | **0.377** |
| c3-standard-8 | 1,997.6 rps | 5,328.5 rps | **0.333** |

**No like-for-like release-build predecessor exists for this experiment.** The 0.703 / 0.671
factors on record come from the Round 1 debug build, and no release-build single-core figure
was ever recorded. The two pairs are therefore not comparable, and the drop from 0.70 to
0.38 is **not** evidence of a scaling regression.

These are recorded as measurements. **No scaling SLO is derived from them here**, and the
`per_core_scaling.linear_tolerance_min` in the targets file remains null and unenforced —
the gate skipped it and said so.

## Measurement-system defects found and fixed

Both were defects in the *instruments*, not in the product. Both had been producing
confident output while measuring something other than what was claimed.

### 1. Mutable image tags permitted heterogeneous binaries across replicas

`image.tag: 0.16.0` combined with `pullPolicy: IfNotPresent` meant each node served
whatever it had cached. A fleet run was observed with **three replicas on three different
image digests**, and reported eight passing proofs.

A proof obtained from a fleet that is not running one binary establishes nothing about that
binary. The run was discarded and re-run with every image pinned by immutable digest.

**Fix in practice:** every image in Rounds 6 and 7 was deployed by `@sha256:` digest, and
`tools/slo/run_slo_job.sh`'s mutable-tag default was overridden explicitly at each
invocation. Note that the default in that script is still the mutable tag; the discipline
is currently applied at the call site, not enforced by the script.

### 2. The saturation rig's client SAN went stale after ADR-MCPRE-064

ADR-MCPRE-064 Slice 4 (`5b7e16e0`, #624, 2026-08-24) moved the channel↔request binding
operand to the request **subject**: `bind_request_to_peer` compares the peer identity
extracted from the client leaf against `VerifiedRequestSubject`, which is
`ResolvedActor::identity.subject` and nothing else.

The rig continued minting a client leaf whose URI SAN carried the **composed actor id**
`role:trust_domain:subject:keyid`, which that stage never compares against. Result: every
request the rig sent was refused `mcp-re.transport_binding_failed` before backend dispatch.

| | before repair | after repair |
|---|---|---|
| failures | 80,000 (100%) | 0 |
| `backend_cpu_secs` | 0.00 | 2.48 |
| verdict | INVALID | PROXY |

The rig is a cargo example driven by a script. No test target reaches it and no gate could
see it, so it measured nothing for roughly eleven days while every check on every pull
request stayed green.

**Fix:** `d9951508` binds the rig's leaf to the request subject. The measured quantity is
unchanged — same topology, request construction, replay tier, signing mode, concurrency and
connection semantics.

### The control that stops defect 2 recurring silently

`dfd1e8c1` adds **`scripts/saturation_liveness.sh`**, driving a new `--smoke` mode of the
rig. It stands up the same three tiers with the same fixtures, the same admission posture
and the same replay tier the measurement lane uses, sends one shard / one generator /
2000 requests, and asserts three independent properties — each of which has been the whole
failure on its own:

1. zero refusals;
2. a non-zero completion rate;
3. a backend CPU clock that moved.

It prints **no throughput number** and is not a measurement. The full sweep still requires
a quiet box and stays out of CI.

It is on the merge path: named as a release gate in
[`../../.github/workflows/ci.yml`](../../.github/workflows/ci.yml) and invoked from stage 2
of [`../../scripts/local_gate.sh`](../../scripts/local_gate.sh), with
[`../../scripts/merge_path_gate.py`](../../scripts/merge_path_gate.py) confirming a
workflow names it. Verified in both directions: PASS on the repaired rig, and on a
deliberately re-staled SAN it reports 2000/2000 refused,
`mcp-re.transport_binding_failed`, backend CPU 0.00, exit 1.

The replay fleet moved to `scripts/lib/sat_replay_fleet.sh` so the liveness and measurement
lanes cannot drift into different admission postures, and its readiness check now probes
`WAIT 2` rather than `connected_slaves` — replica attachment is not write acknowledgement,
and the gap produced exactly one spurious refusal per connection on a fleet seconds old.

## Candidate delta — why Round 2 remains the valid comparator

The delta between `6f64db74` and the accepted candidate `dfd1e8c1` touches seven files:
two cargo examples, four scripts, one CI workflow. Verified mechanically:

- every `src/` tree byte-identical;
- `deploy/` and `config/` byte-identical;
- `Cargo.toml`, `Cargo.lock`, `VERSION`, `rust-toolchain.toml` untouched;
- request admission, response signing, replay implementation, chart defaults,
  KMS/Workload-Identity configuration and deployment topology all unchanged.

`deploy/docker/Dockerfile` builds `--bin mcp-re-proxy --locked` and never compiles
examples, so the shipped proxy binary's inputs are identical to the previous candidate's.

## KMS is not on the request path

Recorded because a cloud performance run is where an accidental remote signing dependency
would first show up as latency.

`delegated_wiring.rs` invokes the **root issuer at credential issuance and rotation only**,
on the cold path; per-request RFC 9421 response signing uses the in-memory delegated key
the credential binds. Additionally, the §7 harness is self-contained and passes
`--key-source file` with its own seed, so **the SLO lane involves no KMS at all**, on
either cloud. KMS/IRSA/Workload-Identity custody is a separate release property, proven by
its own lanes.

## Disposition

**v0.16 performance is ACCEPTED at the measured GKE release-build figures** — 4,064.3 rps
on e2-standard-8 and 4,950.8 rps on c3-standard-8, under the standardized ADR-MCPRE-051 §7
cold-TLS1.3-mTLS envelope, retaining 92.6% and 94.7% of the previous comparable
release-build measurements, with 8000/8000 successes on each.

**The substantially higher historical Mac figures belong to different hardware and a
different resolved runtime topology, and the highest of them additionally belong to a
different measurement protocol — the keepalive saturation rig, not the §7 cold-mTLS lane.
Their difference from the cloud figures is a future performance-engineering question, not a
v0.16 release blocker.**

No threshold is declared or re-declared by this document. `production_slo` remains
`invalidated-pending-remeasurement`; the capacity and scaling checks in `slo_gate.py`
continue to skip, and a green exit from that gate on these reports establishes nothing
about capacity.

## Open items — recorded, not actioned

Neither is a release blocker, and both are deliberately left for after the freeze.

1. **Two documents misdescribe the replay tier the §7 harness actually uses.**
   `adr-051-benchmark-envelope.json` records
   `replay_backend: "in-memory reference (--replay-cache memory)"`, and every emitted
   report repeats `"replay_backend": "memory"` from a hardcoded literal at
   `tls_load_harness_bench.rs:1303`. The harness unconditionally passes
   `--replay-durability-tier redis-wait-quorum:2:2000`, and the async per-core plane
   refuses node-local replay outright — 48,000/48,000 successes are impossible under a
   memory tier. The runs used the Redis WAIT-2 tier; the documentation is wrong, not the
   runs.

2. **`adr-051-slo-targets.md` still reads "production_slo DECLARED"** while the
   machine-readable [`adr-051-slo-targets.json`](adr-051-slo-targets.json) it documents
   carries `status: invalidated-pending-remeasurement`. The JSON is the authority and the
   gate reads it; the prose is stale. Correcting it is a status change and was therefore
   left for review rather than made during a freeze.
