"""Controls for `job_liveness` against REAL processes on this kernel.

The host-gate tests inject a fake process table; that cannot establish that `ps` is read
correctly, that the parent walk finds a real worker, or that a real death is seen. This
spawns a process named like a runner's worker, with a child standing in for the hook.

Run:  python3 tools/slo/test_job_liveness.py
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import job_liveness  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"  {'ok  ' if condition else 'FAIL'} {name}" + (f"  [{detail}]" if detail and not condition else ""))


def child_of(pid: int, table: dict) -> int | None:
    for candidate, (ppid, _, _) in table.items():
        if ppid == pid:
            return candidate
    return None


def main() -> int:
    print("job liveness against real processes")
    check("etime [dd-]hh:mm:ss parses", job_liveness.etime_seconds("1-02:03:04") == 93784
          and job_liveness.etime_seconds("05:06") == 306)

    # `exec -a` names the process like a runner's worker; `; :` keeps sh from exec'ing sleep,
    # so the worker has a real child to walk up from.
    worker = subprocess.Popen(["bash", "-c", "exec -a /tmp/liveness/bin/Runner.Worker "
                               "sh -c 'sleep 120; :'"], start_new_session=True)
    try:
        hook = None
        for _ in range(50):
            hook = child_of(worker.pid, job_liveness.process_table())
            if hook:
                break
            time.sleep(0.1)
        check("the stand-in hook process exists", hook is not None)

        found = job_liveness.own_worker(start_pid=hook) if hook else None
        check("the parent walk finds the Runner.Worker", bool(found) and found["pid"] == worker.pid,
              str(found))
        check("from a process with no worker above it, nothing is found",
              job_liveness.own_worker(start_pid=os.getpid()) is None)
        state = job_liveness.worker_state(found, job_liveness.readable_table())
        check("a running worker is alive", state == "alive", state)

        os.killpg(worker.pid, signal.SIGKILL)
        worker.wait()
        state = job_liveness.worker_state(found, job_liveness.readable_table())
        check("a killed worker is dead", state == "dead", state)
    finally:
        if worker.poll() is None:
            os.killpg(worker.pid, signal.SIGKILL)
            worker.wait()

    check("an unreadable table is unknown, not dead",
          job_liveness.worker_state({"pid": 1, "started": 0}, None) == "unknown")
    total = len(PASSED) + len(FAILED)
    print(f"\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
