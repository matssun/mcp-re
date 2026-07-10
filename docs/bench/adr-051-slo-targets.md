<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-051 §7 — SLO Target Declaration (MCPRE-110)

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
- **`production_slo`** (declared) — the absolute per-hardware SLO measured on the
  declared GKE class, enforced by [`scripts/slo_gate.py`](../../scripts/slo_gate.py)
  (MCPRE-123 + the MCPRE-110 production half). This is the baseline below.
- **`absolute_gates`** (active) — always-on correctness gates (replay-race,
  bounded-drain) enforced by their own tests.

## Status: production_slo DECLARED (baseline measured on GKE, 2026-07-10)

ADR-MCPRE-051 §7 is deliberate: *"the SLO numbers live with the harness and the
release profile, not in this ADR,"* and *"capacity claims without a pinned
benchmark envelope are marketing, not engineering."* Accordingly the capacity and
scaling numbers were **measured, not asserted** — on real GKE hardware, with the
harness spawning the actual `mcp-re-proxy` async fleet at 1 and 8 cores under the
pinned envelope (cold TLS1.3-mTLS, concurrency 64, 2000 requests/run).

**Measured baseline** (`MCP_RE_LOADGEN_CORES` 1 → 8; verified responses/sec; added
latency µs; 2000/2000 success on every run):

| class | 1-core rps | 8-core rps | 8-core p50 / p99 / p999 | per-core linear factor |
|---|---|---|---|---|
| **e2-standard-8** (declared floor) | 67.9 | 390.2 | 148 / 369 / 508 ms | 0.718 |
| **c3-standard-8** (faster ref) | 90.9 | 481.6 | 122 / 319 / 362 ms | 0.662 |

The **declared floor hardware is the weaker class (e2-standard-8)**: the release
floors/ceilings in the targets JSON are derived from it (throughput floor 250 rps,
p50/p99/p999 ceilings 250/600/900 ms, per-core factor ≥ 0.60), so a run on that
class *or better* clears them — and c3-standard-8 (measured faster) does too. Both
classes pass `slo_gate` in `declared` mode (7 checks each). `status` is now
`declared`; `hardware_class`/`measured_on`/`measurements` record the provenance.

**v0.11 was never gated on the capacity baseline** (it shipped the mechanism +
correctness floors); this baseline promotes the SLO to `declared` with real cloud
numbers. CI still runs `slo_gate --selftest` only — shared runners are not
release-representative, so the capacity/scaling enforcement runs on the declared
hardware, as here.

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

## The follow-up-minor step — baseline run on declared hardware

This is deferred out of v0.11. To move `status` from `provisional` to `declared`
in a later minor release:

1. On the declared hardware class, run the load harness at 1 core and at N cores,
   capturing machine reports:
   ```
   MCP_RE_LOADGEN_HW_CLASS="<class>" MCP_RE_LOADGEN_CORES=1 \
     MCP_RE_LOADGEN_OUT=one_core.json \
     cargo test -p mcp-re-proxy --features async_serve \
       --test tls_load_harness_bench tls_load_harness_bench -- --ignored --nocapture
   MCP_RE_LOADGEN_HW_CLASS="<class>" MCP_RE_LOADGEN_CORES=N \
     MCP_RE_LOADGEN_OUT=n_core.json \
     cargo test -p mcp-re-proxy --features async_serve \
       --test tls_load_harness_bench tls_load_harness_bench -- --ignored --nocapture
   ```
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
| Aggregate throughput floor | `production_slo.targets.aggregate_throughput_rps_min` | `slo_gate.py` | ✅ declared |
| Added latency p50/p99/p999 ceilings | `production_slo.targets.{p50,p99,p999}_added_us_max` | `slo_gate.py` | ✅ declared |
| Per-core 1→N linear scaling | `production_slo.per_core_scaling.linear_tolerance_min` | `slo_gate.py` | ✅ declared |
| replay-race / bounded-drain | `absolute_gates.*` | dedicated tests | ✅ yes |
