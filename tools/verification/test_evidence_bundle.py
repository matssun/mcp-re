# SPDX-License-Identifier: Apache-2.0
"""What a verification run leaves behind, and what its exit status means.

Two false-green classes, both about a run that did NOT establish what a reader concludes
from it. Neither is about a lane being wrong; both are about the platform reporting a run
it did not have.

**The bundle described the last SUCCESSFUL run, not the last run.** `attest` reads
`bundle.json` as "the aggregate verdict of the last verification run" and gates issuance on
it. `verify` wrote it at the end of the lane sweep, so a run that returned earlier —
manifest validation failed, or `--manifests` stopped it — left the previous run's verdict
on disk. A failed run therefore made the tree look measured, and the worse a run failed the
earlier it exited and the more certainly the stale PASS survived it. The repair is
structural rather than two more write calls: `_run` returns a `RunOutcome`, `main` writes
the bundle from it, and there is no exit that states no aggregate.

**Report mode returned 0 for a run that printed `VERIFICATION: FAIL`.** "Not authoritative"
is a statement about what a PASS is worth, not a licence to report a failure as success.
Anything reading the status rather than the verdict line read a failed lane as a pass, and
something did — this repository has already recorded a lane as green off a report-mode exit
status. What `--gate` still decides is INCOMPLETE, which is the mode's real content.

One loader for all of it. Seven suites had hand-built `SourceFileLoader` blocks and none
registered the module in `sys.modules`, so the first `@dataclass` in a loaded tool raised
at import — turning an untouched suite red about a change that was correct.
`_load_tool.load_tool` is the single one.

Run: python3 tools/verification/test_evidence_bundle.py
"""

from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402

verify_tool = load_tool('verify', 'verify_tool')

from _evidence import load_bundle, write_bundle  # noqa: E402


def test_a_failed_run_never_exits_zero():
    """The one that was wrong. FAIL is non-zero in BOTH modes."""
    assert verify_tool.gate_exit_code("FAIL", gate=True) == 1
    assert verify_tool.gate_exit_code("FAIL", gate=False) == 1, (
        "report mode returned 0 for a run that printed VERIFICATION: FAIL"
    )


def test_gate_is_what_decides_incomplete():
    """Without this the control above is satisfied by a mode switch that does nothing.

    INCOMPLETE — nothing measured — is a legitimate development state and is not one to
    accept on the merge path, and that difference is the whole content of `--gate`.
    """
    assert verify_tool.gate_exit_code("INCOMPLETE", gate=True) == 1
    assert verify_tool.gate_exit_code("INCOMPLETE", gate=False) == 0
    assert verify_tool.gate_exit_code("PASS", gate=True) == 0
    assert verify_tool.gate_exit_code("PASS", gate=False) == 0


def test_every_exit_from_a_run_states_an_aggregate():
    """The structural property: `_run` cannot leave without a verdict.

    Read off the syntax rather than the behaviour, because the failure mode is a path that
    does not exist yet. A `return` in `_run` that is not a `RunOutcome` is a run whose
    aggregate is whatever the previous run's was.
    """
    tree = ast.parse((HERE / "verify").read_text(encoding="utf-8"))
    run = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_run"
    )
    returns = [node for node in ast.walk(run) if isinstance(node, ast.Return)]
    assert returns, "the control is vacuous if _run has no returns"
    for node in returns:
        call = node.value
        assert isinstance(call, ast.Call) and getattr(call.func, "id", "") == "RunOutcome", (
            f"verify:_run line {node.lineno} returns without stating an aggregate; "
            f"the bundle would carry the previous run's verdict"
        )


def test_the_bundle_write_happens_once_and_outside_the_run():
    """`main` records what `_run` decided, and nothing else writes.

    Two writers would be two answers to "what did the last run conclude", which is the
    question the file exists to answer.
    """
    source = (HERE / "verify").read_text(encoding="utf-8")
    tree = ast.parse(source)
    writers = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and any(
            isinstance(inner, ast.Call) and getattr(inner.func, "id", "") == "write_bundle"
            for inner in ast.walk(node)
        )
    ]
    assert writers == ["main"], f"write_bundle is called from {writers}, not from main alone"


def test_a_partial_run_is_recorded_as_incomplete_not_left_stale():
    """End to end, against a real previous PASS on disk.

    `verify --manifests` measures no lane. Before, it returned leaving whatever bundle was
    there; after, the file says what actually happened, so `attest` refuses instead of
    inheriting a verdict from a run that no longer describes the tree.
    """
    store = REPO / ".verification" / "evidence"
    path = store / "bundle.json"
    saved = path.read_text(encoding="utf-8") if path.is_file() else None
    try:
        write_bundle(store, "PASS", {"verus": "PASS"}, "stale-revision")
        completed = subprocess.run(
            [sys.executable, str(HERE / "verify"), "--manifests"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        bundle = load_bundle(store)
        assert bundle is not None
        assert bundle["aggregate"] == "INCOMPLETE", bundle
        assert bundle["lanes"] == {"manifests": "PASS"}, bundle
        assert bundle["policy_revision"] != "stale-revision", (
            "the bundle still carries the previous run's revision"
        )
    finally:
        if saved is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(saved, encoding="utf-8")


def test_an_unreadable_policy_revision_does_not_skip_the_write():
    """The manifest-failure path runs after loading already failed.

    An exception escaping the revision lookup would skip the bundle write and restore the
    exact behaviour being removed, so the lookup answers with a marker instead.
    """
    outcome = verify_tool.RunOutcome(1, "FAIL", {"manifests": "FAIL"})
    saved = verify_tool.load_verification
    try:
        verify_tool.load_verification = lambda: (_ for _ in ()).throw(RuntimeError("no manifest"))
        assert outcome.policy_revision() == "<unreadable>"
    finally:
        verify_tool.load_verification = saved
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp)
        write_bundle(store, outcome.aggregate, outcome.lanes, "<unreadable>")
        assert json.loads((store / "bundle.json").read_text())["aggregate"] == "FAIL"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
