#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ADR-MCPRE-051 §7 PRODUCTION-SLO release gate (MCPRE-123 + MCPRE-110 production half).

The companion to `scripts/adr051_slo_gate.py`: that one is the *local-regression*
gate (a fresh run vs the committed dev-box anchor, hardware-independent). THIS one
is the *absolute production SLO* gate — it enforces the `production_slo` block of
`docs/bench/adr-051-slo-targets.json`, whose numbers are measured on the DECLARED
hardware class (the GKE fleet run, MCPRE-110 production half).

Reads a load-harness report (`mcp-re-load-harness-report/v1`, written by
`tls_load_harness_bench.rs` to `MCP_RE_LOADGEN_OUT`) and FAILS the release when a
run is below the absolute throughput floor, above a latency ceiling, below the
per-core linear-scaling tolerance, or produced any request failures.

Honest-by-construction: while `production_slo.status` is `pending` (targets null),
the gate SKIPS the capacity/scaling checks with a warning — so it is wireable and
green in CI now. It ENFORCES automatically the moment the GKE baseline fills the
numbers and `status` flips to `declared`. No fabricated numbers.

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
# The load harness bumped its report schema to v2 (RFC 9421 v2 canonical envelope);
# the report body shape (results.throughput_rps / added_latency_us / failures,
# config.declared_cores) is unchanged, so the gate accepts either.
ACCEPTED_REPORT_SCHEMAS = ("mcp-re-load-harness-report/v1", "mcp-re-load-harness-report/v2")
TARGETS_SCHEMA = "mcp-re-slo-targets/v1"

#: Hardware classes a report may carry that can NEVER be an SLO verdict, with the reason.
#:
#: An SLO number is a claim about the hardware it ran on. Two classes are structurally
#: incapable of being one, and BOTH produce a perfectly well-formed report with a real
#: throughput figure in it — which is exactly why the refusal has to be structural. The
#: kind Job-spec rehearsal prints ~7,400 rps and `tools/slo/run_slo_job.sh` warns in prose
#: that it "must never be fed to scripts/slo_gate.py as one". A warning in prose is a rule
#: enforced by remembering; this is the same rule enforced by the gate that would be lied to.
NON_DECLARABLE_HW_CLASSES = {
    "kind-local": "a single unpinned node on a developer box (PROVIDER=kind — a plumbing rehearsal)",
    "smoke": "the harness default when MCP_RE_LOADGEN_HW_CLASS is unset — no class was declared at all",
}


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


def _prod(targets: dict) -> dict:
    return targets.get("production_slo", {}) or {}


def _is_declared(targets: dict) -> bool:
    return _prod(targets).get("status") == "declared"


def check_report(report: dict, targets: dict, gate: Gate) -> None:
    """Absolute correctness (always) + production_slo capacity targets (when declared)."""
    r = report["results"]

    # Correctness is hardware-independent and always enforced: a run that dropped
    # requests is never a pass, regardless of production_slo status.
    fails = int(r.get("failures", 0))
    gate.enforce(fails == 0, f"{fails} request failure(s) in the run")

    prod = _prod(targets)
    tgt = prod.get("targets", {}) or {}
    if not _is_declared(targets):
        gate.skip(f"production_slo.status is {prod.get('status', 'unset')!r} "
                  f"(capacity targets null until the GKE baseline) — capacity checks skipped")
        return

    floor = tgt.get("aggregate_throughput_rps_min")
    if floor is None:
        gate.skip("production_slo.targets.aggregate_throughput_rps_min is null — skipped")
    else:
        tput = float(r["throughput_rps"])
        gate.enforce(tput >= floor, f"throughput_rps {tput:.1f} < floor {floor}")

    measured = r.get("added_latency_us", {})
    for pct in ("p50", "p99", "p999"):
        ceil = tgt.get(f"{pct}_added_us_max")
        if ceil is None:
            gate.skip(f"production_slo.targets.{pct}_added_us_max is null — skipped")
        else:
            got = float(measured[pct])
            gate.enforce(got <= ceil, f"added_latency_us.{pct} {got:.1f} > ceiling {ceil}")


def check_scaling(baseline: dict, scaled: dict, targets: dict, gate: Gate) -> None:
    scaling = _prod(targets).get("per_core_scaling", {}) or {}
    factor = scaling.get("linear_tolerance_min")
    one = float(baseline["results"]["throughput_rps"])
    n_cores = int(scaled["config"]["declared_cores"])
    n_tput = float(scaled["results"]["throughput_rps"])
    if n_cores <= 0 or one <= 0:
        gate.enforce(False, f"degenerate scaling inputs (cores={n_cores}, 1-core rps={one})")
        return
    achieved = n_tput / (one * n_cores)
    if factor is None or not _is_declared(targets):
        gate.skip(
            f"production_slo.per_core_scaling.linear_tolerance_min is null/pending — measured "
            f"factor {achieved:.3f} at {n_cores} cores recorded but not enforced"
        )
    else:
        gate.enforce(
            achieved >= factor,
            f"per-core scaling {achieved:.3f} < min {factor} at {n_cores} cores",
        )


def _load(path: str, schema) -> dict:
    doc = json.loads(Path(path).read_text())
    got = doc.get("schema")
    allowed = {schema} if isinstance(schema, str) else set(schema)
    if got not in allowed:
        raise SystemExit(f"error: {path} has schema {got!r}, expected one of {sorted(allowed)!r}")
    return doc


def _load_report(path: str) -> dict:
    """Load a report and refuse one whose hardware class cannot carry an SLO claim.

    Refused before any check runs, and by raising rather than by adding a failure: a
    non-declarable class is not a run that missed its targets, it is a run that was never
    about the targets. Reporting it as a FAIL would invite re-running it until it passes.
    """
    doc = _load(path, ACCEPTED_REPORT_SCHEMAS)
    hw = doc.get("config", {}).get("hardware_class")
    if hw in NON_DECLARABLE_HW_CLASSES:
        raise SystemExit(
            f"error: {path} was measured on hardware_class {hw!r} — "
            f"{NON_DECLARABLE_HW_CLASSES[hw]}.\n"
            "       Such a report is a plumbing result, not an SLO measurement, and this "
            "gate refuses it outright.\n"
            "       A declared-hardware run comes from PROVIDER=gke|eks with a pinned node "
            "pool (docs/security/gke-slo-baseline-runbook.md)."
        )
    return doc


def _report_gate(gate: Gate, targets: dict) -> int:
    status = _prod(targets).get("status", "unset")
    print(f"SLO gate (production_slo) — status: {status}; checks run: {gate.checks}")
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
            _load_report(args.baseline),
            _load_report(args.scaled),
            targets,
            gate,
        )
    if args.report:
        check_report(_load_report(args.report), targets, gate)
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


def _targets(status, targets=None, factor=None):
    return {"schema": TARGETS_SCHEMA,
            "production_slo": {"status": status, "targets": targets or {},
                               "per_core_scaling": {"gated": True, "linear_tolerance_min": factor}}}


def selftest() -> int:
    ok = True

    # 1. Pending targets: a clean run passes on correctness alone; capacity skipped.
    pend = _targets("pending")
    g = Gate(); check_report(_synth_report(1000, 0, 5000.0, 100, 900, 3000), pend, g)
    ok &= (not g.failures) and (len(g.warnings) >= 1)

    # 2. Correctness bites even when pending: dropped requests fail.
    g = Gate(); check_report(_synth_report(900, 100, 5000.0, 100, 900, 3000), pend, g)
    ok &= any("request failure" in f for f in g.failures)

    # 3. Declared targets: below floor / above a ceiling fails.
    decl = _targets("declared",
                    {"aggregate_throughput_rps_min": 4000.0,
                     "p50_added_us_max": 500, "p99_added_us_max": 2000, "p999_added_us_max": 5000})
    g = Gate(); check_report(_synth_report(1000, 0, 3999.0, 100, 900, 3000), decl, g)
    ok &= any("throughput_rps" in f for f in g.failures)
    g = Gate(); check_report(_synth_report(1000, 0, 9000.0, 100, 9001, 3000), decl, g)
    ok &= any("p99" in f for f in g.failures)
    # A compliant run passes.
    g = Gate(); check_report(_synth_report(1000, 0, 9000.0, 100, 900, 3000), decl, g)
    ok &= not g.failures

    # 4. Scaling lane: below-factor fails, at/above passes (only when declared).
    scal = _targets("declared", factor=0.8)
    g = Gate(); check_scaling(_synth_report(1, 0, 1000.0, 0, 0, 0, cores=1),
                              _synth_report(1, 0, 3000.0, 0, 0, 0, cores=4), scal, g)
    ok &= any("per-core scaling" in f for f in g.failures)  # 3000/(1000*4)=0.75 < 0.8
    g = Gate(); check_scaling(_synth_report(1, 0, 1000.0, 0, 0, 0, cores=1),
                              _synth_report(1, 0, 3400.0, 0, 0, 0, cores=4), scal, g)
    ok &= not g.failures  # 0.85 >= 0.8

    # 5. A non-declarable hardware class is REFUSED, and a declared one is not — through
    #    the real loader, because the refusal lives there and a synthetic dict would skip it.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        for hw, refused in (("kind-local", True), ("smoke", True), ("e2-standard-8", False)):
            doc = _synth_report(1000, 0, 5000.0, 100, 900, 3000)
            doc["config"]["hardware_class"] = hw
            path = str(Path(tmp) / f"{hw}.json")
            Path(path).write_text(json.dumps(doc))
            try:
                _load_report(path)
                ok &= not refused
            except SystemExit as exc:
                ok &= refused and hw in str(exc)
        # A report with NO hardware_class at all is not refused: absence is the pre-v2
        # shape, and inventing a refusal for it would fail reports the gate has always
        # accepted. The two named classes are the ones that assert a non-class.
        path = str(Path(tmp) / "absent.json")
        Path(path).write_text(json.dumps(_synth_report(1000, 0, 5000.0, 100, 900, 3000)))
        try:
            _load_report(path)
        except SystemExit:
            ok = False

    print("slo_gate selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="ADR-MCPRE-051 §7 production-SLO release gate")
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
