"""Controls for the VM participant's process handling.

Everything here runs against ordinary `/bin/sh` chains: no test needs a colima
VM, and none touches the real one. The proposition that CANNOT be established
this way -- that a timed-out `colima ssh` against the live `gh-runner` leaves
nothing behind -- is a live observation, and a unit test must not be allowed to
stand in for it.

What these DO establish is the mechanism the live incident turned on: that
killing a timed-out command reaches its GRANDCHILDREN.

Run:  python3 tools/slo/test_vm_participant.py
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vm_participant  # noqa: E402


def _group_members(group: int) -> list[str]:
    finished = subprocess.run(
        ["pgrep", "-g", str(group)], capture_output=True, text=True, check=False
    )
    return finished.stdout.split()


def _three_generation_chain() -> "subprocess.Popen[str]":
    """The shape `colima ssh` actually has: a parent that outlives its children.

    `colima` spawns `limactl`, which spawns `ssh`. Reproduced with shells so the
    test needs no VM, and deliberately three deep -- a two-deep chain would pass
    even under `proc.kill()`, which is the bug this is about.
    """
    return subprocess.Popen(
        ["/bin/sh", "-c", "/bin/sh -c 'sleep 300' & sleep 300"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def test_terminating_a_group_takes_the_grandchildren() -> None:
    """The regression. Sixteen orphans over a fortnight came from its absence.

    Each survivor held a share of the VM's multiplexed ssh socket, and past a
    threshold the socket stopped answering anyone -- so the VM read as broken
    (`Input/output error`) while being perfectly healthy underneath.
    """
    proc = _three_generation_chain()
    time.sleep(1)
    group = os.getpgid(proc.pid)

    before = _group_members(group)
    assert len(before) >= 3, f"fixture must be three deep, saw {before}"

    vm_participant._terminate_group(group, proc)
    proc.communicate()
    time.sleep(1)

    after = _group_members(group)
    assert after == [], f"orphans survived the group kill: {after}"
    print("ok: group kill removed all %d processes" % len(before))


def test_the_old_behaviour_would_have_left_orphans() -> None:
    """The positive control, and the reason the fix is not merely defensive.

    Without this, the test above could pass against an implementation that
    never had a defect. Killing only the direct child -- exactly what
    `subprocess.run(timeout=...)` does -- must be shown to LEAVE something,
    or there was nothing to fix.
    """
    proc = _three_generation_chain()
    time.sleep(1)
    group = os.getpgid(proc.pid)

    proc.kill()  # the old path: the direct child only
    proc.wait()
    time.sleep(1)

    survivors = _group_members(group)
    assert survivors, "killing the direct child should have left grandchildren"
    print("ok: direct-child kill left %d orphan(s), as the incident showed" % len(survivors))

    # Deliberately NOT communicate() here. The surviving grandchild still holds
    # the inherited stdout pipe open, so communicate() would block until it
    # exits -- 300 seconds. That is the orphan problem reproducing itself
    # inside its own test, and it is worth stating: an orphan does not merely
    # linger, it keeps a file descriptor alive and can hang whoever reads it.
    # Cleanup must name the group explicitly: the leader is already reaped, so
    # a lookup through proc.pid would find nothing and leave the orphans.
    vm_participant._terminate_group(group, proc)
    time.sleep(1)
    assert _group_members(group) == [], "cleanup left orphans behind"
    proc.stdout.close() if proc.stdout else None
    proc.stderr.close() if proc.stderr else None


def test_a_command_that_finishes_returns_its_output() -> None:
    """The happy path, so timeout handling is not the only thing covered.

    A refusal-only suite cannot tell "kills correctly" from "never runs
    anything"; this is the control that separates them.

    Patches the MODULE ATTRIBUTE, not the environment variable. `COLIMA` is
    read once at import time, so setting `MCP_RE_ARBITER_COLIMA` inside a test
    changes nothing and the test silently runs against the REAL colima -- which
    is what the first version of this file did, and it passed for the wrong
    reason until the VM answered differently.
    """
    previous = vm_participant.COLIMA
    vm_participant.COLIMA = "/bin/echo"
    try:
        finished = vm_participant.ssh("hello", timeout=30)
        assert finished.returncode == 0, finished
        assert "hello" in finished.stdout, finished.stdout
        print("ok: a completing command returns rc=0 and its stdout")
    finally:
        vm_participant.COLIMA = previous


def test_a_timeout_raises_and_leaves_nothing(tmp: Path) -> None:
    """Both halves of the contract: it still raises, AND it cleans up.

    A fix that swallowed the timeout would also leave no orphans, and would be
    far worse -- callers decide VM availability from this exception, and
    `worker_count()` turns a missing answer into a refusal precisely so that
    "could not observe" never reads as "idle".

    The stand-in ignores its arguments and sleeps, because `ssh()` fixes the
    argv layout: pointing COLIMA at `/bin/sleep` would produce
    `sleep ssh -p ... -- 300`, which exits immediately on a bad interval and
    would never reach the timeout at all.
    """
    stand_in = tmp / "slow_colima.sh"
    stand_in.write_text("#!/bin/sh\nexec sleep 300\n")
    stand_in.chmod(0o755)

    previous = vm_participant.COLIMA
    vm_participant.COLIMA = str(stand_in)
    try:
        raised = False
        try:
            vm_participant.ssh("anything", timeout=2)
        except subprocess.TimeoutExpired:
            raised = True
        assert raised, "a timeout must still surface as TimeoutExpired"

        time.sleep(1)
        leaked = subprocess.run(
            ["pgrep", "-f", str(stand_in)], capture_output=True, text=True, check=False
        ).stdout.split()
        assert leaked == [], f"the timed-out command left processes behind: {leaked}"
        print("ok: timeout raises TimeoutExpired and leaves no processes")
    finally:
        vm_participant.COLIMA = previous


def main() -> int:
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        tests = [
            (test_terminating_a_group_takes_the_grandchildren, ()),
            (test_the_old_behaviour_would_have_left_orphans, ()),
            (test_a_command_that_finishes_returns_its_output, ()),
            (test_a_timeout_raises_and_leaves_nothing, (tmp,)),
        ]
        for test, argv in tests:
            test(*argv)
        print("\n%d passed" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
