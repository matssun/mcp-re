"""The VM runner's side of host admission. Runs INSIDE the colima `gh-runner` VM.

`dev1-linux` shares dev1's physical CPUs but not its kernel. It therefore participates in
admission WITHOUT participating in the lock:

  * it READS the committed gate that macOS published by atomic rename, so it observes a
    decision already made -- never a transition in progress. `os.replace` guarantees a
    reader sees the old file or the new one, never a partial one, which is exactly why no
    lock is needed on this side. `fcntl` across virtiofs is not dependable, and a lock that
    silently fails to lock is worse than none.
  * it REPORTS its own running job by writing one uniquely-named file per job into the
    shared mirror, so two writers never touch one file and no cross-kernel locking arises.
    That report is a convenience for diagnostics; the macOS side independently observes the
    VM's real processes, because a report produced by the participant it describes cannot
    establish that the participant is idle.

Deliberately standalone: it imports nothing from `host_gate`, which resolves paths under
/opt that do not exist in this VM.

Installed as ACTIONS_RUNNER_HOOK_JOB_STARTED / _COMPLETED in the VM runner's .env.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# The shared mirror, reached over virtiofs. macOS owns it; this side only reads the gate.
MIRROR = Path(os.environ.get("MCP_RE_ARBITER_MIRROR", "/Users/mats/.runner-arbiter"))
GATE = MIRROR / "gate.json"
VM_ACTIVE = MIRROR / "vm-active"

OPEN, RESERVING, RESERVED, RELEASED = "OPEN", "RESERVING", "RESERVED", "RELEASED"

WAIT_S = int(os.environ.get("MCP_RE_ARBITER_ORDINARY_WAIT_S", 45 * 60))
POLL_S = float(os.environ.get("MCP_RE_ARBITER_POLL_S", 5))

EXIT_OK, EXIT_REFUSED = 0, 1


def job_key() -> str:
    raw = "-".join((
        os.environ.get("RUNNER_NAME", "dev1-linux"),
        os.environ.get("GITHUB_RUN_ID", "0"),
        os.environ.get("GITHUB_RUN_ATTEMPT", "0"),
        os.environ.get("GITHUB_JOB", "job"),
    ))
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in raw)


def read_gate() -> dict:
    """The committed decision, or a refusal.

    Three outcomes are deliberately distinct: a missing file means the host has never been
    reserved (OPEN); an unreadable file means we do not know, and NOT knowing must never be
    treated as OPEN -- that is the fail-open case this whole protocol exists to remove.
    """
    try:
        raw = GATE.read_text()
    except FileNotFoundError:
        return {"state": OPEN}
    except OSError as exc:
        raise RuntimeError(f"cannot read the committed gate at {GATE}: {exc}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"the committed gate is unreadable ({exc}); refusing admission")


def hook_job_started() -> int:
    key = job_key()
    deadline = time.monotonic() + WAIT_S
    announced = False
    while True:
        try:
            gate = read_gate()
        except RuntimeError as exc:
            # Fail closed: an unreadable gate means this runner cannot know whether a
            # reservation stands, and admitting here could invalidate a live measurement.
            print(f"[vm-admission] REFUSED: {exc}", file=sys.stderr)
            return EXIT_REFUSED

        state = gate.get("state", OPEN)
        if state in (OPEN, RELEASED):
            try:
                VM_ACTIVE.mkdir(parents=True, exist_ok=True)
                record = {
                    "key": key,
                    "identity": {
                        "runner": os.environ.get("RUNNER_NAME", "dev1-linux"),
                        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
                        "job": os.environ.get("GITHUB_JOB", "job"),
                        "run_id": os.environ.get("GITHUB_RUN_ID", "0"),
                    },
                    "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "pid": os.getpid(),
                }
                target = VM_ACTIVE / f"{key}.json"
                tmp = target.with_name(target.name + f".tmp.{os.getpid()}")
                tmp.write_text(json.dumps(record, indent=2))
                os.replace(tmp, target)
            except OSError as exc:
                # We cannot announce ourselves, so the macOS side would drain without
                # knowing we exist. Refuse rather than run unannounced.
                print(f"[vm-admission] REFUSED: cannot publish the active record: {exc}",
                      file=sys.stderr)
                return EXIT_REFUSED
            print(f"[vm-admission] admitted {key} (host gate {state})", file=sys.stderr)
            return EXIT_OK

        owner = gate.get("owner", {})
        if time.monotonic() >= deadline:
            print(f"[vm-admission] REFUSED: host reservation "
                  f"{gate.get('reservation_id')} held by {owner.get('runner')} run "
                  f"{owner.get('run_id')} did not release within {WAIT_S}s. "
                  "Fail-closed: this job executed no workload.", file=sys.stderr)
            return EXIT_REFUSED
        if not announced:
            print(f"[vm-admission] waiting: host reserved by {owner.get('runner')} "
                  f"run {owner.get('run_id')} ({gate.get('reservation_id')})", file=sys.stderr)
            announced = True
        time.sleep(POLL_S)


def hook_job_completed() -> int:
    """Remove this job's report. Runs on success, failure and cancellation alike."""
    try:
        (VM_ACTIVE / f"{job_key()}.json").unlink()
        print(f"[vm-admission] released {job_key()}", file=sys.stderr)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"[vm-admission] could not remove the active record: {exc}", file=sys.stderr)
    return EXIT_OK


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "job-started"
    if mode == "job-completed":
        return hook_job_completed()
    return hook_job_started()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
