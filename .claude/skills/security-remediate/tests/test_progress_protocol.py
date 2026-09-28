"""Regression: the event protocol, and the false-`lost` hole it used to have.

Covers the four properties the harness repair had to establish:

  1. every event carries schema_version / seq / event_id / attempt_id
  2. `seq` is monotonic and gapless even under concurrent appenders
  3. a HANDLED gate failure emits a real terminal event and is NOT reported lost
     -- the negative regression for the defect observed in tick 1, where
     `scope.py` and `settings_info.py` were both reported as "the
     stage died" when in fact the workflow had handled their gate failure
  4. a genuinely abandoned attempt IS still reported lost, and a file that was
     never attempted is reported `not-started` instead -- a different fact

Property 4 is the positive control for property 3. A reconcile that reported
nothing lost would satisfy (3) trivially while being useless, so the same probe
must be shown to still catch a real death.

Run:  python3 .claude/skills/security-remediate/tests/test_progress_protocol.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
PROGRESS_PY = os.path.join(SCRIPTS, "progress.py")
sys.path.insert(0, SCRIPTS)

from _persist import read_jsonl  # noqa: E402

DISPOSAL_COUNTS = "work=2,escalated=3,closed=1"


def _run(*argv: str) -> str:
    p = subprocess.run([sys.executable, PROGRESS_PY, *argv],
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, "progress.py %s failed:\n%s%s" % (argv[0], p.stdout, p.stderr)
    return p.stdout


def test_envelope_carries_every_identity() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "progress")
        _run("append", "--log", log, "--file", "a/b/c.py", "--role", "evaluator",
             "--event", "evaluate", "--tier", "senior", "--model", "opus",
             "--counts", DISPOSAL_COUNTS, "--attempt", "att-001",
             "--run", "audit-2026-09-22",
             "--escalation-ids", "esc-1,esc-2,esc-3", "--work-ids", "w-1,w-2",
             "--evidence-ref", "work/t02/000-c.py.package.json",
             "--note", "three escalations, two work items")
        rec = read_jsonl(log + ".jsonl")[0]
        for field in ("schema_version", "seq", "event_id", "attempt_id", "run_id",
                      "counts_kind", "evidence_ref"):
            assert field in rec, "envelope is missing %r" % field
        assert rec["attempt_id"] == "att-001"
        assert rec["counts_kind"] == "attempt_snapshot", rec["counts_kind"]
        # The gap this fixes: "3 escalations" is now "WHICH three".
        assert rec["escalation_ids"] == ["esc-1", "esc-2", "esc-3"]
        assert rec["work_ids"] == ["w-1", "w-2"]
        print("  envelope: all identity fields present, escalations enumerable  OK")


def test_close_carries_structural_duplicate_and_cluster() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "progress")
        _run("close", "--log", log, "--file", "a/b/c.py", "--id", "62a9229c11f3b961",
             "--status", "accepted-risk", "--severity", "medium", "--attempt", "att-001",
             "--duplicate-of", "0907afb94e8f36bf", "--cluster", "claim-criticality-scalars",
             "--reason", "same proposition seen through the conformance lens")
        rec = read_jsonl(log + ".jsonl")[0]
        assert rec["finding_id"] == "62a9229c11f3b961"
        assert rec["duplicate_of"] == "0907afb94e8f36bf", "duplicate link is not structural"
        assert rec["cluster_id"] == "claim-criticality-scalars"
        print("  close: duplicate_of / cluster_id are fields, not prose  OK")


def test_seq_is_monotonic_and_gapless_under_concurrent_appenders() -> None:
    """Six concurrent appenders, as in a real batch. No duplicate or skipped seq."""
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "progress")

        def appender(k: int) -> None:
            for i in range(5):
                _run("append", "--log", log, "--file", "f%d.py" % k, "--role", "worker",
                     "--event", "fix", "--attempt", "att-%d" % k,
                     "--counts", "applied=%d" % i, "--note", "n")

        threads = [threading.Thread(target=appender, args=(k,)) for k in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        seqs = sorted(r["seq"] for r in read_jsonl(log + ".jsonl"))
        assert seqs == list(range(1, 31)), "seq not gapless/unique: %s" % seqs
        print("  seq: 30 concurrent appends, gapless 1..30, no duplicates  OK")


def test_handled_gate_failure_is_terminal_not_lost() -> None:
    """NEGATIVE REGRESSION for the tick-1 false alarm.

    Before the repair, a gate failure the workflow HANDLED left the attempt's
    last event as `gate exit=1`, which is not in TERMINAL_EVENTS, so reconcile
    synthesized "the stage died". Two of six files in tick 1 were mislabelled
    this way. Now the workflow appends `gate-failed` and reconcile respects it.
    """
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "progress")
        f = "components/demo/widgets/src/widgets/di/scope.py"
        _run("append", "--log", log, "--file", f, "--role", "evaluator",
             "--event", "evaluate", "--attempt", "att-scope", "--counts", DISPOSAL_COUNTS,
             "--note", "two docstring items ordered")
        _run("append", "--log", log, "--file", f, "--role", "worker",
             "--event", "gate", "--attempt", "att-scope", "--counts", "exit=1",
             "--note", "bazel exit 1 from pre-existing toolchain failures")
        _run("append", "--log", log, "--file", f, "--role", "worker",
             "--event", "gate-failed", "--attempt", "att-scope", "--counts", "exit=1",
             "--note", "handled: baseline-delta shows no new failures")

        out = json.loads(_run("reconcile", "--log", log, "--files", f))
        assert out["lost"] == 0, "handled gate failure still reported lost: %s" % out
        assert out["not_started"] == [], out
        print("  gate-failed: handled failure is terminal, reconcile reports 0 lost  OK")


def test_control_a_real_death_is_still_reported_lost() -> None:
    """POSITIVE CONTROL for the test above: reconcile must still catch a death.

    Without this, `lost == 0` could mean "the hole is fixed" or "reconcile stopped
    detecting anything at all", and those are indistinguishable.
    """
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "progress")
        died = "components/common/x/died.py"
        never = "components/common/x/never_attempted.py"
        _run("append", "--log", log, "--file", died, "--role", "evaluator",
             "--event", "evaluate", "--attempt", "att-died", "--counts", "work=2",
             "--note", "ordered work, then the agent died")

        out = json.loads(_run("reconcile", "--log", log, "--files", "%s,%s" % (died, never)))
        assert out["lost"] == 1, "a real death was NOT reported: %s" % out
        assert out["lost_files"] == [died], out
        # And the two are distinguished: never-attempted is not a death.
        assert out["not_started"] == [never], out
        print("  control: real death -> lost=1; never-attempted -> not-started  OK")


def test_retry_does_not_overwrite_the_first_attempt() -> None:
    """The correlation-key fix: two attempts on ONE file stay distinguishable.

    `state.py` was evaluated, went lost, and would be re-dispatched. Keyed on
    path, the retry silently replaced the first attempt in every tally.
    """
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "progress")
        f = "components/demo/widgets/src/widgets/state/state.py"
        # The first attempt dies WITHOUT a terminal event -- that is what a real
        # agent death looks like, and it is why reconcile has to synthesize one.
        _run("append", "--log", log, "--file", f, "--role", "evaluator", "--event", "evaluate",
             "--attempt", "att-first", "--counts", "work=2,escalated=2", "--note", "first")
        _run("append", "--log", log, "--file", f, "--role", "evaluator", "--event", "evaluate",
             "--attempt", "att-retry", "--counts", "work=3,escalated=1", "--note", "retry")
        _run("append", "--log", log, "--file", f, "--role", "evaluator",
             "--event", "no-code-change", "--attempt", "att-retry", "--note", "done")

        rows = read_jsonl(log + ".jsonl")
        attempts = {r["attempt_id"] for r in rows}
        assert attempts == {"att-first", "att-retry"}, attempts
        out = json.loads(_run("reconcile", "--log", log, "--files", f))
        assert out["attempts"] == 2, "retry collapsed onto the first attempt: %s" % out
        assert out["lost"] == 1 and out["lost_attempts"] == ["att-first"], out
        print("  retry: both attempts survive; only the dead one is lost  OK")


def main() -> int:
    tests = [test_envelope_carries_every_identity,
             test_close_carries_structural_duplicate_and_cluster,
             test_seq_is_monotonic_and_gapless_under_concurrent_appenders,
             test_handled_gate_failure_is_terminal_not_lost,
             test_control_a_real_death_is_still_reported_lost,
             test_retry_does_not_overwrite_the_first_attempt]
    failed = 0
    for t in tests:
        print("%s ..." % t.__name__)
        try:
            t()
        except AssertionError as exc:
            failed += 1
            print("  FAIL: %s" % exc)
    print("\n%d/%d passed" % (len(tests) - failed, len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
