<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-051 §7 — SLO Target Declaration (MCPRE-110)

> **⛔ `production_slo` is INVALIDATED — pending re-measurement.** The machine-readable
> authority [`adr-051-slo-targets.json`](adr-051-slo-targets.json) carries
> `status: invalidated-pending-remeasurement`, and it is the authority: `slo_gate.py`
> reads it, SKIPS the capacity and scaling checks, and says so. A green exit from that
> gate establishes nothing about capacity.
>
> The declaration was invalidated because the numbers it derives from were measured on a
> **debug build** — the Job and `Dockerfile.bench` both ran `cargo test` without
> `--release`. Re-declaring requires a deliberate run on the class being declared.
>
> **This is not the same as having no measurements.** The v0.16 GKE release-build
> performance figures are measured and ACCEPTED; they are simply not a declared SLO. The
> three facts, kept distinct:
>
> | fact | state |
> |---|---|
> | v0.16 GKE release-build performance measurements | **accepted** — see [`v016-performance-rounds.md`](v016-performance-rounds.md) |
> | the old production SLO declaration | **invalidated** |
> | a new production SLO threshold set | **not declared** by that campaign |
>
> The envelope itself is unchanged and current: RFC 9421 + RFC 9530 serving path
> (ADR-MCPRE-050) under the canonical **v2 envelope (concurrency 128 / 8000 requests)** —
> the SAME for local and GKE. The local-regression baseline is also on RFC 9421 (see
> [`adr-051-baseline-local.json`](adr-051-baseline-local.json)) and remains ACTIVE. Run
> the local baseline green before any GKE re-run.

> **v0.16 measurement rounds:** which rounds are release evidence, which are invalid, and
> why the Mac, GKE and saturation-rig figures are not comparable —
> [`v016-performance-rounds.md`](v016-performance-rounds.md).

Companion to the measurement envelope
([`adr-051-load-harness-envelope.md`](adr-051-load-harness-envelope.md) /
[`adr-051-benchmark-envelope.json`](adr-051-benchmark-envelope.json)). The
envelope pins the measurement **conditions**; this document declares the
release **SLO targets** and the gate that enforces them, per ADR-MCPRE-051 §7
("benchmark-first, SLO-gated releases").

The machine-readable targets are [`adr-051-slo-targets.json`](adr-051-slo-targets.json),
split into three blocks with **two complementary gates**:

- **`local_regression`** (active) — a hardware-independent day-to-day gate: a fresh
  run vs the committed dev-box anchor [`adr-051-baseline-local.json`](adr-051-baseline-local.json),
  enforced by [`scripts/adr051_slo_gate.py`](../../scripts/adr051_slo_gate.py) (MCPRE-110).
- **`production_slo`** (**invalidated-pending-remeasurement**) — the absolute
  per-hardware SLO, to be measured on the declared GKE class and enforced by
  [`scripts/slo_gate.py`](../../scripts/slo_gate.py) (MCPRE-123 + the MCPRE-110
  production half). Its targets are currently null and the gate skips them.
- **`absolute_gates`** (active) — always-on correctness gates (replay-race,
  bounded-drain) enforced by their own tests.

## Status: production_slo INVALIDATED — pending re-measurement

ADR-MCPRE-051 §7 is deliberate: *"the SLO numbers live with the harness and the
release profile, not in this ADR,"* and *"capacity claims without a pinned
benchmark envelope are marketing, not engineering."* Accordingly the capacity and
scaling numbers were **measured, not asserted** — on real GKE hardware, with the
harness spawning the actual `mcp-re-proxy` async fleet at 1 and 8 cores under the
**v2 canonical envelope (RFC 9421 + RFC 9530, cold TLS1.3-mTLS, concurrency 128,
8000 requests/run)**.

**⛔ The figures below are DEBUG-BUILD measurements and are INVALID as release
evidence.** They are preserved for provenance — the now-invalidated declaration was
derived from them — and must not be used as a floor, a comparator or a scaling
reference. Both the Job and `Dockerfile.bench` ran `cargo test` without `--release`;
release-build re-measurement on the same cluster and envelope produced figures roughly
**12.3× higher**.

| class | 1-core rps | 8-core rps | 8-core p50 / p99 / p999 | per-core linear factor |
|---|---|---|---|---|
| e2-standard-8 *(debug — invalid)* | 71.5 | 402.1 | 237 / 1383 / 1789 ms | 0.703 |
| c3-standard-8 *(debug — invalid)* | 93.0 | 499.4 | 212 / 966 / 1233 ms | 0.671 |

Because those numbers are invalid, so is everything derived from them: the former
throughput floor, the former p50/p99/p999 ceilings and the former per-core factor are
withdrawn, and `production_slo.targets` is null. `slo_gate.py` skips the capacity and
scaling checks rather than passing against a floor measured on the wrong binary.

The 0.703 / 0.671 scaling factors in particular are **not** a predecessor for any
release-build scaling measurement: no release-build single-core figure was ever recorded
under this envelope, so there is nothing like-for-like to compare against. See
[`v016-performance-rounds.md`](v016-performance-rounds.md).

CI runs `slo_gate --selftest` only — shared runners are not release-representative, so
capacity/scaling enforcement must run on declared hardware whenever a declaration is
made again.

Two classes of target, treated differently by the gate:

- **Correctness floors** (`min_success_fraction`, `max_failure_fraction`) — these
  need no hardware baseline; they are invariants of a healthy run. The gate
  enforces them on **every** run, including now. A run that drops requests or
  fails closed spuriously fails the gate.
- **Capacity + scaling targets** (throughput floor, p50/p99/p999 ceilings,
  per-core linear-scaling factor) — these are meaningful only against a declared
  hardware class. They stay `null` until the baseline run below, and the gate
  **skips** null targets with a warning. It enforces them automatically the
  moment they are filled.

This lets the gate be wired and green in CI today (correctness enforced, capacity
skipped) and tighten to full enforcement with a single edit once real numbers
exist — no code change.

## Re-baselining on declared hardware (the rerun procedure)

This procedure was executed for the v0.11 (v1 envelope) and v0.12 (v2 envelope)
declarations. Re-run it to refresh `production_slo` on a new major release or after a
performance pass (full steps + teardown: [`gke-slo-baseline-runbook.md`](../security/gke-slo-baseline-runbook.md)):

0. **First, locally**: `scripts/local_slo_lane.sh` must be green on your box. It is
   free, it runs the same envelope, and a red local lane means the declared-hardware
   run would only spend money to reproduce the same regression.
1. On the declared hardware class, run the load harness at 1 core and at N cores,
   capturing machine reports (`--exact`, NOT `--ignored` — the bench is not an
   `#[ignore]` test, so `--ignored` selects nothing, exits 0 and measures nothing;
   `redis_replay` is required, the bench needs the shared Redis tier; and
   `MCP_RE_LOADGEN_OUT` must be absolute because cargo runs the test from the
   package root):
   ```
   MCP_RE_LOADGEN_HW_CLASS="<class>" MCP_RE_LOADGEN_CORES=1 \
     MCP_RE_LOADGEN_OUT=$PWD/one_core.json \
     cargo test -p mcp-re-proxy --release --features async_serve,redis_replay \
       --test tls_load_harness_bench tls_load_harness_bench -- --exact --nocapture
   MCP_RE_LOADGEN_HW_CLASS="<class>" MCP_RE_LOADGEN_CORES=N \
     MCP_RE_LOADGEN_OUT=$PWD/n_core.json \
     cargo test -p mcp-re-proxy --release --features async_serve,redis_replay \
       --test tls_load_harness_bench tls_load_harness_bench -- --exact --nocapture
   ```
   On GKE this is `tools/slo/run_slo_job.sh`, which already pins all of the above.
2. Derive the release floor/ceilings from that baseline (e.g. throughput floor at
   a chosen fraction of measured median; p99/p999 ceilings at a chosen multiple
   of measured tail), record `production_slo.hardware_class` + `measured_on`, and set
   `production_slo.per_core_scaling.linear_tolerance_min` from `n_core / (one_core * N)`.
3. Set `production_slo.status` to `declared` and enforce on representative hardware:
   ```
   python3 scripts/slo_gate.py --report n_core.json \
     --baseline one_core.json --scaled n_core.json \
     --targets docs/bench/adr-051-slo-targets.json
   ```

Why HITL: shared CI runners are not release-representative for per-core scaling
or tail latency, so the *representative* capacity measurement must run on the
declared hardware. The gate **mechanism** (script + CI wiring + required lanes)
is in place now; only the representative numbers need a real run.

## Targeted dimensions (ADR-051 §7)

| Dimension | Target key | Gate | Enforced now? |
| --- | --- | --- | --- |
| Request-failure = 0 (correctness) | run `results.failures` | `slo_gate.py` | ✅ yes |
| Local-regression throughput/latency | `local_regression.tolerances.*` | `adr051_slo_gate.py` | ✅ yes |
| Aggregate throughput floor | `production_slo.targets.aggregate_throughput_rps_min` | `slo_gate.py` | ⛔ invalidated — target null, gate skips |
| Added latency p50/p99/p999 ceilings | `production_slo.targets.{p50,p99,p999}_added_us_max` | `slo_gate.py` | ⛔ invalidated — target null, gate skips |
| Per-core 1→N linear scaling | `production_slo.per_core_scaling.linear_tolerance_min` | `slo_gate.py` | ⛔ invalidated — target null, gate skips |
| replay-race / bounded-drain | `absolute_gates.*` | dedicated tests | ✅ yes |
