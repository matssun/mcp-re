"""Concurrency-safe persistence primitives for the remediation harness.

(Imported module — no shebang: `ledger.py` and `progress.py` are the entry points.)

WHY THIS EXISTS — the failure it was written against
----------------------------------------------------
On 2026-09-22, tick 1 of a lane run lost **365 open findings** from the
authoritative ledger. The mechanism was not exotic:

    ledger.py::_save()  ->  open(path, "w")   # truncate in place, no lock

Six evaluator agents ran `ledger.py set` concurrently. Each did a full
read-modify-write of the whole file. One process `_load()`ed the ledger while
another was mid-truncate through its own rewrite, got a PARTIAL snapshot, and
then wrote that partial snapshot back as the complete ledger. Every row the
other writer had not yet re-emitted was gone permanently — and the result still
parsed as valid JSONL, so nothing downstream noticed.

Two independent defects, and BOTH must be fixed; either alone is insufficient:

  1. the write was not atomic   -> a reader can observe a half-written file
  2. the critical section was not locked
                                -> two writers can interleave load/save even if
                                   each individual write IS atomic

Fixing only (1) still loses data: with atomic writes, writer A and writer B can
both load state S, each apply their own delta, and each atomically store
S+delta_A / S+delta_B. The second one wins and the first writer's change
vanishes. That is lost-update, not torn-read, and only the lock prevents it.

So the contract here is: **the lock spans the entire read-modify-write critical
section**, and the write within it is atomic. `tests/test_ledger_concurrency.py`
proves both halves, and carries a positive control that reproduces the original
loss so the test is known capable of detecting it.

Re-ingestion with deterministic fingerprints is what RECOVERED the 365 rows. It
is a recovery property and explicitly NOT the concurrency mechanism — do not let
its existence justify an unlocked write.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import sys
import tempfile
import time

# These scripts are invoked directly (`python3 ledger.py …`), not as a package,
# so a sibling import needs the script directory on the path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lock_timeout import LockTimeout  # noqa: E402,F401  (re-exported for callers)

_LOCK_TIMEOUT_S = 120.0
_LOCK_POLL_S = 0.02


@contextlib.contextmanager
def exclusive(path: str, timeout: float = _LOCK_TIMEOUT_S):
    """Hold an exclusive lock covering a COMPLETE read-modify-write section.

    The lock lives on an adjacent `<path>.lock` sentinel rather than on `path`
    itself, because the payload file is swapped by an atomic rename — a lock held
    on the old inode would protect a file that is no longer at that name.

    Usage (the whole section, not just the write):

        with exclusive(ledger):
            rows = read_jsonl(ledger)      # read
            rows[fid]["status"] = "fixed"  # modify   -- one critical section
            atomic_write_lines(ledger, …)  # write
    """
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(lock_path)) or ".", exist_ok=True)
    deadline = time.monotonic() + timeout
    fh = open(lock_path, "a+")
    try:
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise LockTimeout(
                        f"could not acquire {lock_path} within {timeout}s; "
                        "refusing to write unlocked"
                    ) from exc
                time.sleep(_LOCK_POLL_S)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def atomic_write_lines(path: str, lines, *, preserve_inode: bool = False) -> None:
    """Swap `path` to `lines` so no reader can ever observe a partial file.

    Writes a sibling temp file on the SAME filesystem (so the rename is a rename,
    not a copy), fsyncs it, then atomically renames it over the target. A reader
    without the lock still sees either the whole old file or the whole new one.

    `preserve_inode=True` truncate-writes in place instead. That is NOT atomic
    and exists only for a path hardlinked elsewhere that must stay linked. It is
    never used for the ledger.
    """
    data = "".join(line if line.endswith("\n") else line + "\n" for line in lines)
    if preserve_inode:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return

    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".jsonl")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.rename(tmp, path)
        tmp = None
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)


def append_line(path: str, line: str) -> None:
    """Append one record with O_APPEND, which the kernel serializes across writers.

    This is the one persistence path that is safe WITHOUT a lock, and that is a
    deliberate design property of the journal, not an oversight: an append-only
    log with one `write()` per record never rewrites existing bytes, so it has no
    lost-update and no torn-read hazard for records under PIPE_BUF.

    Callers that also need a monotonic sequence number take `exclusive()` around
    the counter read plus this append — see progress.py.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    payload = line if line.endswith("\n") else line + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)


def read_jsonl(path: str) -> list:
    """Parse a JSONL file, skipping blank lines. Raises on a malformed record.

    Deliberately strict: a line that does not parse means the file was written by
    something that bypassed this module, and swallowing it would hide exactly the
    corruption class this module exists to prevent.
    """
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: malformed JSONL record: {exc}") from exc
    return out
