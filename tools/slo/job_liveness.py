"""Whether the job that wrote an arbiter record is still running.

WHY THIS EXISTS
===============
Every arbiter record used to be released by one thing only: the job-completed hook. A
runner that is killed, crashes, or loses its host never runs that hook, so its record
stayed forever. Measured on dev1 2026-09-26: 17 records on disk, 1 of them live, the
oldest from 2026-09-14 -- including a job whose runner service was stopped deliberately
that morning, and three from runs GitHub reports as succeeded. Ordinary admission never
read them, which is why CI kept working; the SLO drain waits for every one of them, so no
SLO measurement could have started since 2026-09-14.

THE RULE
========
A record is released when its owner is PROVEN dead, never because it is old. The owner is
the job's `Runner.Worker` process: GitHub's runner starts one per job and it exits when the
job ends, whether by success, failure, cancellation or the runner dying. The hook is a
descendant of that worker, so it can name it.

"Cannot tell" is ALIVE. A record without a worker (written before this module existed, or
from a kernel we cannot see into), or a process table we cannot read, keeps its lock. The
pid is paired with the worker's start time, so a recycled pid is not mistaken for the
original owner.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Callable, Dict, Optional, Tuple

#: A start time within this many seconds of the recorded one is the same process. `etime`
#: has one-second resolution and the two reads are taken at different moments.
START_TOLERANCE_S = 5

WORKER_MARK = "Runner.Worker"

#: pid -> (ppid, seconds since start, command)
ProcessTable = Dict[int, Tuple[int, int, str]]


def etime_seconds(text: str) -> int:
    """`ps -o etime` ([[dd-]hh:]mm:ss) as seconds. Elapsed time has no timezone to get wrong."""
    days, _, clock = text.strip().rpartition("-") if "-" in text else ("", "", text.strip())
    units = [int(x) for x in clock.split(":")]
    return (int(days) * 86400 if days else 0) + sum(
        value * scale for value, scale in zip(reversed(units), (1, 60, 3600)))


def process_table() -> ProcessTable:
    """Every process on this kernel. Raises OSError when `ps` cannot be run."""
    out = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,etime=,command="],
                         capture_output=True, text=True, check=True).stdout
    table: ProcessTable = {}
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[0].isdigit() and parts[1].isdigit():
            try:
                table[int(parts[0])] = (int(parts[1]), etime_seconds(parts[2]), parts[3])
            except ValueError:
                continue
    return table


def own_worker(table_fn: Callable[[], ProcessTable] = process_table,
               start_pid: Optional[int] = None) -> Optional[dict]:
    """The Runner.Worker this hook runs under, as {"pid", "started"}; None if not found."""
    try:
        table = table_fn()
    except (OSError, subprocess.SubprocessError):
        return None
    pid = os.getpid() if start_pid is None else start_pid
    for _ in range(64):
        entry = table.get(pid)
        if entry is None:
            return None
        ppid, elapsed, command = entry
        if WORKER_MARK in command:
            return {"pid": pid, "started": int(time.time()) - elapsed}
        if ppid <= 1:
            return None
        pid = ppid
    return None


def worker_state(worker: Optional[dict], table: Optional[ProcessTable]) -> str:
    """"alive", "dead" or "unknown" for a recorded worker, read against one process table.

    `table` is None when the process table could not be read; that is "unknown".
    """
    if not worker or "pid" not in worker or "started" not in worker or table is None:
        return "unknown"
    entry = table.get(int(worker["pid"]))
    if entry is None:
        return "dead"
    _, elapsed, command = entry
    started = int(time.time()) - elapsed
    if WORKER_MARK not in command or abs(started - int(worker["started"])) > START_TOLERANCE_S:
        return "dead"  # the pid now belongs to some other process
    return "alive"


def readable_table(table_fn: Callable[[], ProcessTable] = process_table) -> Optional[ProcessTable]:
    """The process table, or None when it cannot be read (which callers treat as unknown)."""
    try:
        return table_fn()
    except (OSError, subprocess.SubprocessError):
        return None
