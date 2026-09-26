"""The per-job lock holder. `host_locks` explains why it exists; this is the process.

    lock_holder.py --root R --mirror M --key K --plan {ordinary,heavy,slo}
                   --watch WORKER_PID --hook HOOK_PID --ready-fd FD
                   --bounds '{"gate_wait": s, "heavy_wait": s, "drain_wait": s}'

Structure, and why:

  * The exit watches are registered on kqueue BEFORE any lock is requested. A watched pid
    that is already gone makes registration fail, and the holder exits without taking
    anything -- so a job that died before admission can never end up holding a lock.
  * Locks are taken by a helper thread in blocking `flock` calls. The main thread never
    blocks on a lock: it waits in kqueue, so the moment the worker (or, before admission,
    the hook) exits, it wakes and ends the process -- even while the thread is still queued
    for a lock, whose pending request the kernel then discards.
  * Every exit is `os._exit`. The locks are released by the kernel when the process ends;
    no code path has to remember to release them.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import select
import signal
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate  # noqa: E402
import host_locks  # noqa: E402

MODE_NAME = {host_locks.SH: "shared", host_locks.EX: "exclusive"}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    for flag in ("--root", "--mirror", "--key", "--plan", "--bounds"):
        ap.add_argument(flag, required=True)
    ap.add_argument("--record", default="{}")
    for flag in ("--watch", "--hook", "--ready-fd"):
        ap.add_argument(flag, type=int, required=True)
    a = ap.parse_args(argv)

    root = Path(a.root)
    paths = host_gate.paths(root, Path(a.mirror))
    bounds = json.loads(a.bounds)
    steps = host_locks.PLANS[a.plan]
    record_path = root / "holders" / f"{a.key}.json"
    state = {"answered": False, "admitted": False}

    def answer(line: str) -> None:
        if state["answered"]:
            return
        state["answered"] = True
        try:
            os.write(a.ready_fd, (line + "\n").encode())
        except OSError:
            pass
        try:
            os.close(a.ready_fd)
        except OSError:
            pass

    def finish(code: int) -> None:
        """End the process. The kernel releases every lock this process holds."""
        try:
            if json.loads(record_path.read_text()).get("pid") == os.getpid():
                record_path.unlink()
        except (OSError, ValueError):
            pass
        if a.plan == "slo":
            try:
                host_gate.release_owner(paths, a.key, "the SLO job's lock holder exited")
            except Exception:  # noqa: BLE001 -- the process is ending either way
                pass
        os._exit(code)

    def on_signal(signum, _frame) -> None:
        answer(f"REFUSED: the lock holder was stopped (signal {signum}) before admission")
        finish(0)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, on_signal)

    kq = select.kqueue()
    watched = {a.watch: "the job's Runner.Worker", a.hook: "the admission hook"}
    for pid, what in watched.items():
        try:
            kq.control([select.kevent(pid, select.KQ_FILTER_PROC,
                                      select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                      select.KQ_NOTE_EXIT)], 0)
        except OSError:
            answer(f"REFUSED: {what} (pid {pid}) was already gone; nothing to hold a lock for")
            finish(0)

    notify_r, notify_w = os.pipe()
    kq.control([select.kevent(notify_r, select.KQ_FILTER_READ, select.KQ_EV_ADD)], 0)

    def take() -> None:
        held: dict[str, int] = {}
        try:
            for i, step in enumerate(steps):
                if step[0] == "take":
                    _, name, mode, _bound = step
                    os.write(notify_w, f"P{i}\n".encode())
                    fd = os.open(host_locks.lock_path(root, name), os.O_RDWR | os.O_CREAT, 0o644)
                    held[name] = fd
                    fcntl.flock(fd, mode)
                    if name == "gate" and mode == host_locks.EX:
                        os.write(notify_w, b"G\n")
                else:
                    fd = held.pop(step[1])
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    os.close(fd)
            os.write(notify_w, b"OK\n")
        except OSError as exc:
            os.write(notify_w, f"E{exc}\n".encode())

    threading.Thread(target=take, daemon=True).start()

    deadline = None
    waiting_for = ""
    buf = b""
    while True:
        timeout = None
        if not state["admitted"] and deadline is not None:
            timeout = max(0.0, deadline - time.monotonic())
        events = kq.control(None, 4, timeout)
        if not events and not state["admitted"] and deadline is not None \
                and time.monotonic() >= deadline:
            others = ", ".join(f"{h.get('key')} ({h.get('plan')})"
                               for h in host_locks.holders(root) if h.get("key") != a.key)
            answer(f"REFUSED: waited {waiting_for} and it was not granted. Holders now: "
                   f"{others or 'none recorded'}. Fail-closed: this job executed no workload.")
            finish(3)
        for ev in events:
            if ev.filter == select.KQ_FILTER_PROC:
                if state["admitted"] and ev.ident == a.hook and a.hook != a.watch:
                    continue  # the hook ends normally right after admission
                answer(f"REFUSED: {watched.get(ev.ident, 'a watched process')} exited "
                       "before admission")
                finish(0)
            elif ev.ident == notify_r:
                buf += os.read(notify_r, 4096)
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.startswith(b"P"):
                        _, name, mode, bound = steps[int(line[1:])]
                        seconds = int(bounds[bound])
                        deadline = time.monotonic() + seconds
                        waiting_for = f"{seconds}s for the {name} lock ({MODE_NAME[mode]})"
                    elif line == b"G":
                        try:
                            os.write(a.ready_fd, b"GATE\n")
                        except OSError:
                            pass
                    elif line == b"OK":
                        record_path.parent.mkdir(parents=True, exist_ok=True)
                        host_gate.write_atomic(record_path, {
                            **json.loads(a.record), "pid": os.getpid(), "key": a.key,
                            "plan": a.plan, "watch": a.watch, "admitted_at": host_gate.now()})
                        state["admitted"] = True
                        deadline = None
                        answer("ADMITTED")
                    elif line.startswith(b"E"):
                        answer(f"REFUSED: taking the locks failed: {line[1:].decode()}")
                        finish(3)


if __name__ == "__main__":
    main()
