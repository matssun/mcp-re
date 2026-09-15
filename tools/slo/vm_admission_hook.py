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
import shutil
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


# CAPACITY, AND WHY THIS SIDE NEEDS TWO FLOORS RATHER THAN THE HOST'S ONE.
#
# dev1-linux is the runner that spent a fortnight reporting `online` while accepting work it
# could not run. The host side refuses below a single 25 GB floor; applying that number here
# would be a fleet-wide outage, because MEASURED INSIDE THIS VM on 2026-09-15:
#
#     /                              free  6.6 GB  of   18.3 GB   the guest's own disk
#     /Users/mats/.runner-arbiter    free 51.1 GB  of  926.4 GB   the HOST volume, virtiofs
#
# The guest's entire disk is 18.3 GB, so a 25 GB floor there can never be satisfied and
# every job would be refused forever -- the guard becoming the outage it exists to prevent.
#
# Two volumes genuinely matter and they are checked separately:
#
#   * THE HOST VOLUME, reached over the virtiofs mount that carries the shared mirror.
#     virtiofs reports the underlying host filesystem, verified against `df -h /` on the
#     host in the same minute (51 GB both sides), so this side can see the condition that
#     actually wedged it -- the host filling -- WITHOUT asking the host anything. Same
#     25 GB floor as the macOS side, because it is the same volume and the same number.
#   * THE GUEST'S OWN ROOT, on a much smaller floor. A runaway build filling 18 GB is a
#     real failure and is worth refusing, but it is a different magnitude of problem.
#
# Deliberately duplicated rather than imported: this module resolves nothing under /opt and
# imports nothing from host_gate, for the reason stated in the module docstring.
HOST_VOLUME_REFUSE_GB = float(os.environ.get("MCP_RE_ARBITER_DISK_REFUSE_GB", 25))
GUEST_ROOT_REFUSE_GB = float(os.environ.get("MCP_RE_ARBITER_VM_DISK_REFUSE_GB", 3))

# The lane that makes the disk not-full must never be refused for the disk being full. It is
# labelled for macOS today and so does not land here, but the exemption is stated on both
# sides: a label change must not be able to create a deadlock this far from where it is made.
RECOVERY_REPOSITORY = os.environ.get("MCP_RE_ARBITER_RECOVERY_REPOSITORY", "matssun/code")
RECOVERY_WORKFLOW = os.environ.get(
    "MCP_RE_ARBITER_RECOVERY_WORKFLOW", ".github/workflows/disk-retention.yml")


def workflow_path() -> str:
    """The workflow's path as GITHUB_WORKFLOW_REF carries it, or "" if unidentifiable."""
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not ref or not repo:
        return ""
    before_git_ref = ref.split("@", 1)[0]
    prefix = repo + "/"
    return before_git_ref[len(prefix):] if before_git_ref.startswith(prefix) else ""


def is_recovery() -> bool:
    return (os.environ.get("GITHUB_REPOSITORY", "") == RECOVERY_REPOSITORY
            and workflow_path() == RECOVERY_WORKFLOW)


def capacity_refusal(usage=None) -> str | None:
    """The reason this job must not start, or None to admit.

    Fails OPEN on an unreadable volume, against this module's own fail-closed default and
    for a stated reason: every other refusal here protects a MEASUREMENT, where admitting
    wrongly corrupts an SLO number. This protects CAPACITY, where refusing wrongly stops all
    work on the runner for no reason at all.
    """
    measure = usage or shutil.disk_usage
    for label, path, floor in (
        ("the host volume", MIRROR, HOST_VOLUME_REFUSE_GB),
        ("this VM's own root", Path("/"), GUEST_ROOT_REFUSE_GB),
    ):
        try:
            free = measure(path).free / (1024.0**3)
        except OSError as exc:
            print(f"[vm-admission] capacity unmeasured for {path}: {exc}", file=sys.stderr)
            continue
        if free >= floor:
            continue
        if is_recovery():
            print(f"[vm-admission] {label} is at {free:.1f} GB but this is the recovery "
                  f"lane; admitting", file=sys.stderr)
            return None
        return (f"{label} ({path}) has {free:.1f} GB free, under the {floor:.0f} GB floor "
                f"this runner admits work above. Fail-closed: this job executed no workload. "
                f"The guest and the host are different filesystems, so the volume is named. "
                f"To reclaim, run the disk-retention workflow in matssun/code.")
    return None


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
    # Capacity first, before the gate wait and before any active record is written: a job
    # refused for space must not first queue for up to 45 minutes, nor leave a report behind
    # claiming it is running.
    refusal = capacity_refusal()
    if refusal is not None:
        print(f"[vm-admission] REFUSED: {refusal}", file=sys.stderr)
        return EXIT_REFUSED

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
