#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ADR-MCPRE-051 §7 SLO release gate (MCPRE-123).

Compares a load-harness report (`mcp-re-load-harness-report/v1`, written by
`tls_load_harness_bench.rs` to `MCP_RE_LOADGEN_OUT`) against the declared SLO
targets (`docs/bench/adr-051-slo-targets.json`, MCPRE-110) and FAILS the release
when a run is below a throughput floor, above a latency ceiling, below the
per-core scaling factor, or below the correctness floors.

Honest-by-construction: capacity/scaling targets are `null` until a baseline run
on the declared hardware fills them (the HITL step). The gate ENFORCES every
non-null target plus the correctness floors, and SKIPS null targets with a
warning — so it is wireable and green in CI now, and tightens automatically the
moment real numbers land and `status` flips to `declared`. No fabricated numbers.

Usage:
    slo_gate.py --report run.json --targets docs/bench/adr-051-slo-targets.json
    slo_gate.py --baseline one_core.json --scaled n_core.json --targets ...   # scaling lane
    slo_gate.py --selftest
Exit code 0 = gate passes; 1 = a target/floor is violated; 2 = bad usage/inputs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPORT_SCHEMA = "mcp-re-load-harness-report/v1"
TARGETS_SCHEMA = "mcp-re-slo-targets/v1"


class Gate:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []
        self.checks = 0

    def enforce(self, ok: bool, detail: str) -> None:
        self.checks += 1
        if not ok:
            self.failures.append(detail)

    def skip(self, detail: str) -> None:
        self.warnings.append(detail)


def _success_fraction(report: dict) -> float:
    r = report["results"]
    succ = float(r["successes"])
    fail = float(r["failures"])
    total = succ + fail
    return 1.0 if total == 0 else succ / total


def check_report(report: dict, targets: dict, gate: Gate) -> None:
    """Correctness floors (always) + capacity targets (when non-null)."""
    r = report["results"]

    floors = targets.get("correctness_floors", {})
    if (mn := floors.get("min_success_fraction")) is not None:
        sf = _success_fraction(report)
        gate.enforce(sf >= mn, f"success_fraction {sf:.4f} < min {mn}")
    if (mx := floors.get("max_failure_fraction")) is not None:
        ff = 1.0 - _success_fraction(report)
        gate.enforce(ff <= mx, f"failure_fraction {ff:.4f} > max {mx}")

    cap = targets.get("capacity_targets", {})
    floor = cap.get("throughput_floor_rps")
    if floor is None:
        gate.skip("capacity_targets.throughput_floor_rps is null (not yet measured) — skipped")
    else:
        tput = float(r["throughput_rps"])
        gate.enforce(tput >= floor, f"throughput_rps {tput:.1f} < floor {floor}")

    ceilings = cap.get("added_latency_ceilings_us", {}) or {}
    measured = r.get("added_latency_us", {})
    for pct in ("p50", "p99", "p999"):
        ceil = ceilings.get(pct)
        if ceil is None:
            gate.skip(f"capacity_targets.added_latency_ceilings_us.{pct} is null — skipped")
        else:
            got = float(measured[pct])
            gate.enforce(got <= ceil, f"added_latency_us.{pct} {got:.1f} > ceiling {ceil}")


def check_scaling(baseline: dict, scaled: dict, targets: dict, gate: Gate) -> None:
    st = targets.get("scaling_targets", {})
    factor = st.get("per_core_min_linear_factor")
    one = float(baseline["results"]["throughput_rps"])
    n_cores = int(scaled["config"]["declared_cores"])
    n_tput = float(scaled["results"]["throughput_rps"])
    if n_cores <= 0 or one <= 0:
        gate.enforce(False, f"degenerate scaling inputs (cores={n_cores}, 1-core rps={one})")
        return
    achieved = n_tput / (one * n_cores)
    if factor is None:
        gate.skip(
            f"scaling_targets.per_core_min_linear_factor is null — measured factor "
            f"{achieved:.3f} at {n_cores} cores recorded but not enforced"
        )
    else:
        gate.enforce(
            achieved >= factor,
            f"per-core scaling {achieved:.3f} < min {factor} at {n_cores} cores",
        )


def _load(path: str, schema: str) -> dict:
    doc = json.loads(Path(path).read_text())
    got = doc.get("schema")
    if got != schema:
        raise SystemExit(f"error: {path} has schema {got!r}, expected {schema!r}")
    return doc


def _report_gate(gate: Gate, targets: dict) -> int:
    status = targets.get("status", "provisional")
    print(f"SLO gate — targets status: {status}; checks run: {gate.checks}")
    for w in gate.warnings:
        print(f"  · skip: {w}")
    if gate.failures:
        for f in gate.failures:
            print(f"  ✗ FAIL: {f}")
        print(f"SLO gate: FAILED ({len(gate.failures)} violation(s))")
        return 1
    print("SLO gate: PASS")
    return 0


def run(args: argparse.Namespace) -> int:
    targets = _load(args.targets, TARGETS_SCHEMA)
    gate = Gate()
    if args.baseline or args.scaled:
        if not (args.baseline and args.scaled):
            raise SystemExit("error: --baseline and --scaled must be given together")
        check_scaling(
            _load(args.baseline, REPORT_SCHEMA),
            _load(args.scaled, REPORT_SCHEMA),
            targets,
            gate,
        )
    if args.report:
        check_report(_load(args.report, REPORT_SCHEMA), targets, gate)
    if not (args.report or args.baseline):
        raise SystemExit("error: give --report and/or --baseline/--scaled (or --selftest)")
    return _report_gate(gate, targets)


# --- self-test: synthetic pass + fail, no files ------------------------------

def _synth_report(succ, fail, tput, p50, p99, p999, cores=1):
    return {
        "schema": REPORT_SCHEMA,
        "config": {"declared_cores": cores},
        "results": {
            "successes": succ, "failures": fail, "throughput_rps": tput,
            "added_latency_us": {"p50": p50, "p99": p99, "p999": p999},
        },
    }


def selftest() -> int:
    ok = True

    # 1. Provisional targets (all capacity null): a clean run passes on floors alone.
    prov = {"schema": TARGETS_SCHEMA, "status": "provisional",
            "correctness_floors": {"min_success_fraction": 0.999, "max_failure_fraction": 0.001},
            "capacity_targets": {"throughput_floor_rps": None,
                                 "added_latency_ceilings_us": {"p50": None, "p99": None, "p999": None}},
            "scaling_targets": {"per_core_min_linear_factor": None}}
    g = Gate(); check_report(_synth_report(1000, 0, 5000.0, 100, 900, 3000), prov, g)
    ok &= (not g.failures) and (len(g.warnings) >= 4)

    # 2. Correctness floor bites even when provisional: dropped requests fail.
    g = Gate(); check_report(_synth_report(900, 100, 5000.0, 100, 900, 3000), prov, g)
    ok &= any("success_fraction" in f for f in g.failures)

    # 3. Declared targets: a run below the throughput floor / above a ceiling fails.
    decl = {"schema": TARGETS_SCHEMA, "status": "declared",
            "correctness_floors": {"min_success_fraction": 0.999},
            "capacity_targets": {"throughput_floor_rps": 4000.0,
                                 "added_latency_ceilings_us": {"p50": 500, "p99": 2000, "p999": 5000}}}
    g = Gate(); check_report(_synth_report(1000, 0, 3999.0, 100, 900, 3000), decl, g)
    ok &= any("throughput_rps" in f for f in g.failures)
    g = Gate(); check_report(_synth_report(1000, 0, 9000.0, 100, 9001, 3000), decl, g)
    ok &= any("p99" in f for f in g.failures)
    # A compliant run passes.
    g = Gate(); check_report(_synth_report(1000, 0, 9000.0, 100, 900, 3000), decl, g)
    ok &= not g.failures

    # 4. Scaling lane: below-factor fails, at/above passes.
    scal = {"schema": TARGETS_SCHEMA, "status": "declared",
            "scaling_targets": {"per_core_min_linear_factor": 0.8}}
    g = Gate(); check_scaling(_synth_report(1, 0, 1000.0, 0, 0, 0, cores=1),
                              _synth_report(1, 0, 3000.0, 0, 0, 0, cores=4), scal, g)
    ok &= any("per-core scaling" in f for f in g.failures)  # 3000/(1000*4)=0.75 < 0.8
    g = Gate(); check_scaling(_synth_report(1, 0, 1000.0, 0, 0, 0, cores=1),
                              _synth_report(1, 0, 3400.0, 0, 0, 0, cores=4), scal, g)
    ok &= not g.failures  # 0.85 >= 0.8

    print("slo_gate selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="ADR-MCPRE-051 §7 SLO release gate")
    ap.add_argument("--report", help="load-harness report JSON (MCP_RE_LOADGEN_OUT)")
    ap.add_argument("--baseline", help="1-core report JSON (scaling lane)")
    ap.add_argument("--scaled", help="N-core report JSON (scaling lane)")
    ap.add_argument("--targets", default="docs/bench/adr-051-slo-targets.json")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
