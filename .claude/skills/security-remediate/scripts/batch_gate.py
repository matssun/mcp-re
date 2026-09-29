"""batch_gate.py — the gate that runs once per batch, not once per file.

The per-file gate (`check.py post`) is what can be attributed to one writer:
the lanes that compile the file, its own tests, the module-size ratchet. What it
leaves out is the work that costs minutes and says the same thing whether it runs
after one fix or after six: the whole-workspace clippy ratchet, the structural
gates, and each touched crate's full test suite. Running those per file would
serialize the writer lane behind them; running them per batch costs one run, and
the per-file commits make a failure bisectable to the file that caused it.

Run it BEFORE the first batch of a run (`--crates` empty): the lane's attribution
rests on starting from a tree measured green. Run it AFTER each batch with the
crates the batch touched.

Two lanes are left to the pre-handover gate (`scripts/local_gate.sh`) and are NOT
claimed here: `bazel test //...` (the only lane that runs the `async_serve` drain
tests) and the SLO lane.

The whole-workspace clippy ratchet is the one long run here, and it is authorized at an
integration boundary — after a batch, before a PR is opened or updated, or on the
owner's ask — never merely because a run started. `--no-clippy-ratchet` omits it for a
single-file (`--top 1`) run, and the result reports it as `skipped`, so the omission is
never read as a pass. A change that touches lint configuration, the ratchet machinery or
shared compiler settings is a reason to stop and ask for the ratchet instead.

Usage:
  batch_gate.py [--crates a,b] [--no-clippy-ratchet] --work-dir DIR
Exit 0 green, 1 a gate failed, 2 a gate could not run.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cargo_gate  # noqa: E402

RATCHET = "scripts/clippy_ratchet_gate.py"
STRUCTURAL = [
    [RATCHET],
    ["scripts/module_size_gate.py"],
    ["scripts/bazel_srcs_gate.py"],
    ["scripts/unit_closure_gate.py"],
    ["scripts/verification_trigger_gate.py"],
    ["tools/verification/test_mutation_lane.py"],
    # ADR-MCPRE-069: every test a fix adds is a control the census must see claimed or
    # dispositioned. `finalize.py` holds a file whose own controls are not; these two are
    # the batch's whole-tree answer — the residue ratchet at its closure state, and the
    # registry's own consistency (orphan rows, missing records, stale selectors).
    ["scripts/control_census_gate.py"],
    ["tools/verification/control-census", "--gate"],
]


def _run(cmd: list[str], log: str) -> int:
    with open(log, "w", encoding="utf-8") as fh:
        return subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT).returncode


def _tail(log: str, n: int = 6) -> list[str]:
    return open(log, encoding="utf-8", errors="replace").read().strip().splitlines()[-n:]


def main() -> int:
    ap = argparse.ArgumentParser(description="once-per-batch gate")
    ap.add_argument("--crates", default="", help="cargo packages the batch touched")
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--no-clippy-ratchet", action="store_true",
                    help="omit the workspace clippy ratchet (single-file run); reported as skipped")
    a = ap.parse_args()
    os.makedirs(a.work_dir, exist_ok=True)
    results = []
    for cmd in STRUCTURAL:
        if a.no_clippy_ratchet and cmd[0] == RATCHET:
            results.append({"gate": cmd[0], "verdict": "skipped",
                            "why": "--no-clippy-ratchet: run at the batch/integration checkpoint"})
            continue
        if not os.path.isfile(cmd[0]):
            results.append({"gate": cmd[0], "verdict": "infra", "why": "missing"})
            continue
        log = os.path.join(a.work_dir, "batch-%s.log" % os.path.basename(cmd[0]))
        rc = _run([sys.executable, *cmd], log)
        results.append({"gate": cmd[0], "verdict": "ok" if rc == 0 else "new-failures",
                        "log": log, **({} if rc == 0 else {"tail": _tail(log)})})

    lane = cargo_gate.feature_lane()
    for pkg in [c.strip() for c in a.crates.split(",") if c.strip()]:
        crate_dir = next((d for d in _crate_dirs() if cargo_gate.package_name(d) == pkg), None)
        feats = [f for f in lane if crate_dir and f in cargo_gate.crate_features(crate_dir)]
        for name, fs in [("default", [])] + ([("features", feats)] if feats else []):
            log = os.path.join(a.work_dir, "batch-test-%s-%s.log" % (pkg, name))
            cmd = cargo_gate.cargo() + ["test", "-p", pkg] + (["--features", ",".join(fs)] if fs else [])
            rc = _run(cmd, log)
            results.append({"gate": "cargo test -p %s (%s)" % (pkg, name),
                            "verdict": "ok" if rc == 0 else "new-failures", "log": log,
                            **({} if rc == 0 else {"tail": _tail(log)})})

    worst = "new-failures" if any(r["verdict"] == "new-failures" for r in results) else \
        "infra" if any(r["verdict"] == "infra" for r in results) else "ok"
    skipped = [r["gate"] for r in results if r["verdict"] == "skipped"]
    print(json.dumps({"verdict": worst, "skipped": skipped, "gates": results}, indent=1))
    return {"ok": 0, "new-failures": 1}.get(worst, 2)


def _crate_dirs() -> list[str]:
    p = subprocess.run(["git", "ls-files", "*Cargo.toml"], capture_output=True, text=True)
    return [os.path.dirname(m) for m in p.stdout.split()]


if __name__ == "__main__":
    sys.exit(main())
