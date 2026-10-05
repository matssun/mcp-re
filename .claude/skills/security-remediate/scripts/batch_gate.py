"""batch_gate.py — the gate that runs once per batch, not once per file.

The per-file gate (`check.py post`) is what can be attributed to one writer:
the targets that compile the file, its own tests, the module-size ratchet. What it
leaves out is the work that costs minutes and says the same thing whether it runs
after one fix or after six: the whole-workspace clippy ratchet, the structural
gates, and the touched closure — every Rust target that depends on a touched file,
linted under `--config=lint`, and every test target in it. Running those per file would
serialize the writer lane behind them; running them per batch costs one run, and
the per-file commits make a failure bisectable to the file that caused it.

Run it BEFORE the first batch of a run (`--files` empty): the lane's attribution
rests on starting from a tree measured green. Run it AFTER each batch with the
files the batch touched.

It also runs every `tools/verification/test_*.py` self-test suite once. They read the
registry and pin measured facts about it — premise totals, the controls each record states —
so a registry-only change moves them while no Rust target notices; they are not per-file
work, and leaving them out let two suites stay red under a green batch gate.

And it runs every Python gate the merge-path workflow (`.github/workflows/ci.yml`) invokes
with bare flags, read from the workflow so the two lists cannot drift. A hand-picked subset
let six merge-path gates go red across many green batches.

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
  batch_gate.py [--files a,b] [--no-clippy-ratchet] --work-dir DIR
Exit 0 green, 1 a gate failed, 2 a gate could not run.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rust_gate  # noqa: E402
import size_debt  # noqa: E402

RATCHET = "scripts/clippy_ratchet_gate.py"
# Gates whose size-only failures are recorded, not blocking, during a remediation run.
SIZE_GATES = {"scripts/module_size_gate.py", RATCHET}
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


VERIFICATION_SUITES = "tools/verification"

#: The merge-path workflow whose Python gates the batch gate also runs.
CI_WORKFLOW = ".github/workflows/ci.yml"

#: CI invocations the batch gate does NOT run: the clippy ratchet and its compile probes
#: (authorized only at an integration boundary, and STRUCTURAL already carries the ratchet),
#: and the workspace-lints probe, which compiles a crate of its own.
CI_EXCLUDED = {
    ("scripts/clippy_ratchet_gate.py",),
    ("scripts/clippy_ratchet_gate.py", "--activation-probe"),
    ("scripts/clippy_ratchet_gate.py", "--nesting-probe"),
    ("scripts/clippy_ratchet_gate.py", "--selftest"),
    ("scripts/workspace_lints_gate.py", "--probe"),
}

_CI_INVOCATION = re.compile(r"python3\s+((?:scripts|tools)/[A-Za-z0-9_./-]+)((?:[ \t]+--[a-z-]+)*)[ \t]*$",
                            re.M)


def _structural_suites() -> set[str]:
    """The self-test suites STRUCTURAL already runs, by file name."""
    return {os.path.basename(cmd[0]) for cmd in STRUCTURAL
            if os.path.dirname(cmd[0]) == VERIFICATION_SUITES}


def verification_suites(work_dir: str, root: str = VERIFICATION_SUITES,
                        already: set[str] | None = None) -> dict:
    """Every `test_*.py` self-test suite under `root`, each run once, as one gate result.

    A suite in `already` (by default the ones STRUCTURAL runs) is not run twice. No suite
    found is `infra`, not `ok`: an empty set would be a green that measured nothing.
    """
    already = _structural_suites() if already is None else already
    suites = sorted(f for f in os.listdir(root) if f.startswith("test_") and f.endswith(".py")
                    and f not in already) if os.path.isdir(root) else []
    if not suites:
        return {"gate": root + "/test_*.py", "verdict": "infra", "why": "no suite found"}
    failed = []
    for suite in suites:
        log = os.path.join(work_dir, "batch-verification-%s.log" % suite)
        if _run([sys.executable, os.path.join(root, suite)], log):
            failed.append({"suite": suite, "log": log, "tail": _tail(log)})
    return {"gate": root + "/test_*.py", "suites": len(suites),
            "verdict": "new-failures" if failed else "ok",
            **({"failed": failed} if failed else {})}


def ci_gates(workflow: str = CI_WORKFLOW) -> list[tuple[str, ...]]:
    """Every Python gate invocation in `workflow` that takes only bare flags, in file
    order and once each. An invocation whose flag takes a value (`--base <sha>`) is the
    workflow's to parameterize and is left out, and so is anything in CI_EXCLUDED."""
    if not os.path.isfile(workflow):
        return []
    seen: list[tuple[str, ...]] = []
    for m in _CI_INVOCATION.finditer(open(workflow, encoding="utf-8").read()):
        cmd = (m.group(1), *m.group(2).split())
        if cmd not in seen and cmd not in CI_EXCLUDED:
            seen.append(cmd)
    return seen


def merge_path_gates(work_dir: str, workflow: str = CI_WORKFLOW,
                     already: set[tuple[str, ...]] | None = None) -> dict:
    """Every gate `ci_gates` finds, each run once, as one gate result.

    The merge path runs these on every push, and a batch gate that ran only its own subset
    let a red one sit unseen through many batches. A gate STRUCTURAL already runs is not
    run twice. No gate found is `infra`, not `ok`."""
    already = {tuple(cmd) for cmd in STRUCTURAL} if already is None else already
    gates = [cmd for cmd in ci_gates(workflow) if cmd not in already]
    if not gates:
        return {"gate": workflow, "verdict": "infra", "why": "no gate invocation found"}
    failed = []
    for cmd in gates:
        name = "-".join(os.path.basename(part) for part in cmd)
        log = os.path.join(work_dir, "batch-ci-%s.log" % name)
        if _run([sys.executable, *cmd], log):
            failed.append({"gate": " ".join(cmd), "log": log, "tail": _tail(log)})
    return {"gate": workflow, "gates": len(gates),
            "verdict": "new-failures" if failed else "ok",
            **({"failed": failed} if failed else {})}


def _run(cmd: list[str], log: str) -> int:
    with open(log, "w", encoding="utf-8") as fh:
        return subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT).returncode


def _tail(log: str, n: int = 6) -> list[str]:
    return open(log, encoding="utf-8", errors="replace").read().strip().splitlines()[-n:]


def main() -> int:
    ap = argparse.ArgumentParser(description="once-per-batch gate")
    ap.add_argument("--files", default="", help="files the batch touched, comma-separated")
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
        verdict, debt = "ok" if rc == 0 else "new-failures", []
        if rc and cmd[0] in SIZE_GATES:
            soft, debt = size_debt.classify(cmd[0], open(log, encoding="utf-8",
                                                         errors="replace").read())
            if soft:
                # Recorded, not blocking (size_debt.py); a row no writer registered — a hand
                # commit — joins the register under HEAD.
                verdict = "size-debt"
                head = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                                      capture_output=True, text=True).stdout.strip()
                size_debt.register_rows(debt, head)
        results.append({"gate": cmd[0], "verdict": verdict, "log": log,
                        **({} if rc == 0 else {"tail": _tail(log)}),
                        **({"debt": debt} if verdict == "size-debt" else {})})

    results.append(verification_suites(a.work_dir))
    results.append(merge_path_gates(a.work_dir))

    files = [f.strip() for f in a.files.split(",") if f.strip()]
    labels = [lbl for lbl in (rust_gate.file_label(f) for f in files) if lbl]
    if labels:
        closure = "rdeps(//..., set(%s))" % " ".join(labels)
        rust = rust_gate.query('kind("^(%s) rule$", %s)' % (rust_gate.RUST_RULES, closure))
        tests = rust_gate.query('kind(".*_test rule$", %s) except attr(tags, "\\bmanual\\b", //...)'
                                % closure)
        for name, targets, cmd in (
                ("lint the touched closure", rust, ["build", "--config=lint", "--keep_going"]),
                ("test the touched closure", tests, ["test", "--test_output=errors", "--keep_going"])):
            if not targets:
                results.append({"gate": name, "verdict": "infra",
                                "why": "the closure of %s holds no such target" % ", ".join(files)})
                continue
            log = os.path.join(a.work_dir, "batch-%s.log" % name.split()[0])
            rc = _run(rust_gate.bazel() + cmd + targets, log)
            results.append({"gate": name, "targets": len(targets),
                            "verdict": "ok" if rc == 0 else "new-failures", "log": log,
                            **({} if rc == 0 else {"tail": _tail(log)})})

    worst = "new-failures" if any(r["verdict"] == "new-failures" for r in results) else \
        "infra" if any(r["verdict"] == "infra" for r in results) else "ok"
    skipped = [r["gate"] for r in results if r["verdict"] == "skipped"]
    debt = [d for r in results for d in r.get("debt", [])]
    print(json.dumps({"verdict": worst, "skipped": skipped, "size_debt": debt,
                      "gates": results}, indent=1))
    return {"ok": 0, "new-failures": 1}.get(worst, 2)


if __name__ == "__main__":
    sys.exit(main())
