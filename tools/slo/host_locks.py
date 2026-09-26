"""Admission locks the KERNEL holds, so that no lock can outlive the job that took it.

WHY
===
The gate used to be files: a record written by the job-started hook and deleted by the
job-completed hook. Anything that stops a job without its completion hook -- `kill -9`, a
crash, a reboot, launchd stopping the runner -- leaves the file behind, and a file does not
know its owner is gone. On 2026-09-26 dev1 held 17 such records, 1 of them live; the SLO
drain waited on all of them, so no SLO could start for twelve days.

A `flock(2)` lock belongs to an open file description. When the last process holding that
description exits, for ANY reason, the kernel drops the lock at that instant. Nothing has to
run, so nothing can fail to run.

THE HOLDER
==========
A hook returns as soon as the job is admitted, so the locks cannot live in the hook. Each
admitted job gets one small holder process (`lock_holder.py`):

  * it takes this job's locks, in the order below, and tells the hook "ADMITTED";
  * it then waits on kqueue for the job's `Runner.Worker` to exit -- event-driven, so it
    wakes the moment the worker dies, by any cause -- and exits, and the kernel frees
    the locks;
  * killed or crashed itself, its locks are freed the same way.

So no cleanup job exists, and none is needed.

THE LOCKS
=========
Three files, one lock each. A lock file is never unlinked or replaced: a recreated file is
a different inode, and a lock on the old one silently stops excluding the new one.

    gate   SLO: EXCLUSIVE for its whole run    everyone else: SHARED, only while admitted
    host   SLO: EXCLUSIVE (= the drain)        every admitted job: SHARED for its lifetime
    heavy  dev1 / dev1-mcp-re jobs: EXCLUSIVE  fast lane and SLO: not taken

    ordinary:  gate SH -> host SH -> release gate
    heavy:     heavy EX -> gate SH -> host SH -> release gate
    slo:       gate EX -> host EX

The SLO takes `gate` first, so from that moment no new job is admitted anywhere, and then
`host`, which the kernel grants only when every admitted job has released its shared lock
-- the drain. A heavy job takes `heavy` BEFORE `gate`, so it never holds `gate` while it
queues, and an SLO is never stuck behind a queued heavy job. flock waiters are served when
the lock frees: a job already blocked on `heavy` gets it before one that arrives later.

WHAT CAN STILL GO WRONG, AND WHICH WAY
=====================================
If a holder is killed while its job keeps running, that job's locks drop early: at worst two
heavy jobs overlap once. That is the only failure, and it never blocks anything. For the
SLO, where an overlap would spoil a measurement, `assert-exclusive` independently counts
live `Runner.Worker` processes. The Linux VM cannot share these locks (advisory locking is
not dependable across virtiofs); it keeps the file-based committed-gate mirror.
"""

from __future__ import annotations

import fcntl
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

LOCKS = ("gate", "host", "heavy")
SH, EX = fcntl.LOCK_SH, fcntl.LOCK_EX

#: plan -> steps. A step is ("take", lock, mode, bound-name) or ("release", lock).
PLANS = {
    "ordinary": [("take", "gate", SH, "gate_wait"), ("take", "host", SH, "gate_wait"),
                 ("release", "gate")],
    "heavy": [("take", "heavy", EX, "heavy_wait"), ("take", "gate", SH, "gate_wait"),
              ("take", "host", SH, "gate_wait"), ("release", "gate")],
    "slo": [("take", "gate", EX, "gate_wait"), ("take", "host", EX, "drain_wait")],
}

HOLDER = Path(__file__).resolve().parent / "lock_holder.py"


def lock_path(root: Path, name: str) -> Path:
    return Path(root) / f"{name}.flock"


def ensure_lock_files(root: Path) -> None:
    """Create any missing lock file. Never truncates, unlinks or replaces one."""
    for name in LOCKS:
        fd = os.open(lock_path(root, name), os.O_RDWR | os.O_CREAT, 0o644)
        os.close(fd)


def would_grant(root: Path, name: str, mode: int) -> bool:
    """Would `mode` on `name` be granted right now? Probes and releases at once."""
    fd = os.open(lock_path(root, name), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)  # closing drops the probe's lock, if it got one
    return True


def holder_env() -> dict:
    """The holder's environment: the hook's, minus the runner's orphan-tracking id.

    At the end of a job the runner kills every process whose environment carries the
    job's RUNNER_TRACKING_ID. The holder must not depend on that: it ends itself when the
    worker exits, and it must never be killed while its job still runs.
    """
    env = dict(os.environ)
    env.pop("RUNNER_TRACKING_ID", None)
    return env


def spawn_holder(root: Path, mirror: Path, key: str, plan: str, watch_pid: int,
                 bounds: dict, record: dict, python: str = sys.executable
                 ) -> Tuple[subprocess.Popen, int]:
    """Start a holder for this job; returns (process, read end of its handshake pipe).

    The holder gets NONE of the hook's stdio. The runner reads the hook's stdout and stderr
    until they close, so a holder that inherited either would keep the hook "running" for
    the whole job and every job on the runner would stall at "Set up job". Its only link
    back is a dedicated pipe, which it closes as soon as it has answered.
    """
    r, w = os.pipe()
    args = [python, str(HOLDER), "--root", str(root), "--mirror", str(mirror),
            "--key", key, "--plan", plan,
            "--watch", str(watch_pid), "--hook", str(os.getpid()), "--ready-fd", str(w),
            "--bounds", json.dumps(bounds), "--record", json.dumps(record)]
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, pass_fds=(w,), close_fds=True,
                            start_new_session=True, env=holder_env())
    os.close(w)
    return proc, r


def await_answer(proc: subprocess.Popen, r: int, timeout_s: float,
                 on_gate: Optional[Callable[[], None]] = None) -> str:
    """The holder's final answer: "ADMITTED" or "REFUSED: <why>".

    An SLO holder first reports "GATE" -- it holds the gate exclusively and is draining --
    and `on_gate` runs then. A holder that exits without a final answer has refused: its
    locks are already gone with it.
    """
    buf = b""
    deadline = time.monotonic() + timeout_s
    try:
        while True:
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode(errors="replace").strip()
                if line == "GATE":
                    if on_gate is not None:
                        on_gate()
                    continue
                return line
            left = deadline - time.monotonic()
            if left <= 0:
                proc.kill()
                return f"REFUSED: the lock holder did not answer within {int(timeout_s)}s"
            ready, _, _ = select.select([r], [], [], min(left, 60))
            if not ready:
                continue
            chunk = os.read(r, 4096)
            if not chunk:
                code = proc.poll()
                return f"REFUSED: the lock holder exited without answering (exit {code})"
            buf += chunk
    finally:
        os.close(r)


def holders(root: Path) -> List[dict]:
    """The holder records, for diagnostics. The locks, not these files, are the truth."""
    out = []
    for f in sorted((Path(root) / "holders").glob("*.json")):
        try:
            out.append(json.loads(f.read_text()))
        except (OSError, json.JSONDecodeError):
            out.append({"key": f.stem, "corrupt": True})
    return out


def lock_state(root: Path) -> dict:
    """Which locks are held, read from the kernel."""
    state = {}
    for name in LOCKS:
        if would_grant(root, name, EX):
            state[name] = "free"
        elif would_grant(root, name, SH):
            state[name] = "shared"
        else:
            state[name] = "exclusive"
    return state


def plan_for(is_slo: bool, runner: str, heavy_runners) -> str:
    if is_slo:
        return "slo"
    return "heavy" if runner in heavy_runners else "ordinary"


def signal_holder(root: Path, key: str) -> Optional[int]:
    """Ask this job's holder to exit now (the completion hook). Returns its pid, if any.

    Only a process whose command line names the holder AND this key is signalled, so a
    recycled pid is never hit. A holder that is already gone needs nothing: its locks went
    with it.
    """
    path = Path(root) / "holders" / f"{key}.json"
    try:
        pid = int(json.loads(path.read_text())["pid"])
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None
    cmd = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                         capture_output=True, text=True).stdout
    if "lock_holder.py" not in cmd or key not in cmd:
        return None
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        return None
    return pid
