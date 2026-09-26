"""Which Runner.Worker a hook runs under, read from the process table.

The admission hook runs as a child of the job's `Runner.Worker`, which the runner starts
per job and which exits when the job ends -- by success, failure, cancellation, or the
runner dying. The job's lock holder watches that process (see `host_locks`), so the hook
must name it. Elapsed time (`etime`) is used rather than a formatted start date: it has no
timezone to get wrong.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Callable, Dict, Optional, Tuple

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


def readable_table(table_fn: Callable[[], ProcessTable] = process_table) -> Optional[ProcessTable]:
    """The process table, or None when it cannot be read (which callers treat as unknown)."""
    try:
        return table_fn()
    except (OSError, subprocess.SubprocessError):
        return None
