"""The colima VM runner as an admission participant, observed from macOS.

`dev1-linux` runs under a different kernel inside the `gh-runner` colima VM, holding 4 of
this host's 14 cores. Two consequences drive everything here:

  * it is INVISIBLE to macOS `pgrep`, so no macOS process scan can ever establish that the
    PHYSICAL host is exclusive -- only that the macOS namespace is;
  * it cannot take the arbiter's `fcntl` mutex, because advisory locking across virtiofs is
    not dependable and a lock that silently fails to lock is worse than none.

So it participates by READING the committed gate mirror and gating itself, while macOS
independently OBSERVES its real processes here. The observation is deliberately not the
VM's own self-report: a report produced by the participant it describes cannot establish
that the participant is idle.

Stopping the unit is a FALLBACK for a participant whose hook is absent or unhealthy, not
the normal mechanism. When it is applied, it is applied only to an already-idle VM: the
unit declares `KillMode=process` with `TimeoutStopSec=5min`, so stopping it mid-job would
SIGKILL that job after five minutes, and ordinary work is never killed to start a benchmark.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arbiter_error import ArbiterError  # noqa: E402

PROFILE = os.environ.get("MCP_RE_ARBITER_VM_PROFILE", "gh-runner")
UNIT = os.environ.get("MCP_RE_ARBITER_VM_UNIT", "actions.runner.matssun-code.dev1-linux")
RUNNER_HOME = os.environ.get("MCP_RE_ARBITER_VM_RUNNER_HOME", "/home/mats.guest/actions-runner")
COLIMA = os.environ.get("MCP_RE_ARBITER_COLIMA", "/opt/homebrew/bin/colima")


def ssh(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a command in the VM, and leave NOTHING behind when it times out.

    `subprocess.run(timeout=...)` kills only the DIRECT child. This command is
    a three-generation chain -- `colima` spawns `limactl`, which spawns `ssh` --
    so a timeout killed `colima` and reparented `limactl` and `ssh` to PID 1,
    where they lived forever holding a share of the VM's multiplexed ssh
    socket.

    Measured 2026-09-15: sixteen such orphans, the oldest 15 days 22 hours,
    including a `limactl shell ... systemctl is-active` that is this module's
    own `service_active()` probe. Past a threshold the mux socket stopped
    answering anyone, so `colima ssh` returned `Input/output error` and the VM
    was unreachable to every caller -- for a fortnight, with `dev1-linux` still
    reporting `online` to GitHub and accepting jobs it could not run.

    The VM was never broken. Killing the orphans restored it instantly, with no
    restart: it had simply run out of usable ssh channels.

    So the timeout is not the fix and never was -- every call here already had
    one. `start_new_session=True` puts the whole chain in its own process
    group, and killing that group on timeout takes the grandchildren with it.
    """
    with subprocess.Popen(
        [COLIMA, "ssh", "-p", PROFILE, "--", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as proc:
        # Captured HERE, while the leader is certainly alive. Reading it later
        # from `proc.pid` is unreliable: once the leader has exited and been
        # reaped, `os.getpgid` raises and the cleanup would have no group to
        # signal -- leaving exactly the orphans it exists to remove.
        group = _group_of(proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # The group, not the process. os.killpg reaches limactl and ssh;
            # proc.kill() would not, which is the entire defect.
            _terminate_group(group, proc)
            # Safe now: the writers are gone, so the pipes are at EOF. Before
            # the group kill this call would block on a grandchild holding the
            # inherited stdout, which is the same defect one layer along.
            stdout, stderr = proc.communicate()
            raise subprocess.TimeoutExpired(proc.args, timeout, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


def _group_of(proc: "subprocess.Popen[str]") -> int | None:
    """The process group of a just-spawned child, or None if it already exited."""
    try:
        return os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError, OSError):
        return None


def _terminate_group(group: int | None, proc: "subprocess.Popen[str]") -> None:
    """SIGTERM the process group, then SIGKILL whatever is still there.

    SIGTERM first so `ssh` can close its channel cleanly -- a SIGKILLed client
    can leave the mux master believing the channel is still open, which is the
    state this function exists to avoid creating.

    Failures are swallowed deliberately: the group may be partly gone already,
    and a cleanup path that can itself raise would abandon the orphans it was
    called to remove.
    """
    if group is None:
        try:
            proc.kill()
        except OSError:
            pass
        return

    try:
        os.killpg(group, signal.SIGTERM)
    except OSError:
        pass

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if not _group_alive(group):
            return
        time.sleep(0.2)

    try:
        os.killpg(group, signal.SIGKILL)
    except OSError:
        pass


def _group_alive(group: int) -> bool:
    """Whether any process remains in the group.

    Asks about the GROUP, not about the leader. Waiting on the leader alone is
    what made the original bug invisible: it exits promptly and its children do
    not, so "the child is gone" and "nothing is left" are different claims.
    """
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True


def available() -> bool:
    if not Path(COLIMA).exists():
        return False
    try:
        return ssh("true", timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def worker_count() -> int:
    """Live Runner.Worker processes INSIDE the VM.

    Raises rather than returning 0 when it cannot look: "I could not observe the VM" and
    "the VM is idle" must never collapse into the same answer, because the second one
    licenses a measurement and the first one must refuse it.
    """
    try:
        r = ssh("sh", "-c", "pgrep -c Runner.Worker || true", timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ArbiterError(
            f"could not observe the VM's runner processes ({exc}); refusing to claim the "
            "physical host is quiet."
        ) from exc
    try:
        return int((r.stdout or "0").strip() or 0)
    except ValueError:
        raise ArbiterError(f"unparseable worker count from the VM: {r.stdout!r}")


def unit_active() -> bool:
    return (ssh("systemctl", "is-active", UNIT, timeout=60).stdout or "").strip() == "active"


def read_env() -> str:
    return ssh("sh", "-c", f"cat {RUNNER_HOME}/.env 2>/dev/null || true", timeout=60).stdout or ""


def read_file(path: str) -> str:
    return ssh("sh", "-c", f"cat '{path}' 2>/dev/null || true", timeout=60).stdout or ""


def is_executable(path: str) -> bool:
    return (ssh("sh", "-c", f"test -x '{path}' && echo yes || echo no", timeout=60).stdout or "").strip() == "yes"


def inhibit_fallback() -> dict:
    """Stop the VM listener. FALLBACK ONLY -- for a participant that cannot gate itself."""
    if not available():
        raise ArbiterError("cannot reach the VM to apply the inhibition fallback")
    if (n := worker_count()) > 0:
        raise ArbiterError(f"VM has {n} worker(s); refusing to stop its unit mid-job")
    r = ssh("sudo", "systemctl", "stop", UNIT, timeout=360)
    if r.returncode != 0:
        raise ArbiterError(f"could not stop {UNIT}: {(r.stderr or '').strip()}")
    # Verify, do not assume: the exclusivity claim rests on this being true, not requested.
    if unit_active() or worker_count() > 0:
        raise ArbiterError(f"{UNIT} did not verifiably stop")
    return {"unit": UNIT, "verified_inactive": True}


def release_fallback() -> dict:
    if not available():
        return {"released": False, "detail": "VM unreachable"}
    r = ssh("sudo", "systemctl", "start", UNIT, timeout=360)
    return {"released": r.returncode == 0, "detail": (r.stderr or "").strip()[:200]}


def listener_loaded_env() -> bool | None:
    """Has the VM's systemd unit restarted since its .env was written?

    The macOS freshness check cannot answer this -- `pgrep` does not cross the kernel
    boundary -- so the VM answers it about itself. None means "cannot tell", which callers
    treat as not-participating rather than as participating.

    THE COMPARISON HAPPENS INSIDE THE VM, in one shell, against one clock.
    This previously reconstructed a wall-clock start from
    `ExecMainStartTimestampMonotonic` plus a boot epoch derived from `uptime -s`, then
    compared that against the .env mtime. Those two have DIFFERENT ORIGINS -- CLOCK_MONOTONIC
    excludes suspended time and the boot estimate drifts -- so on a VM up for two days the
    reconstruction landed 107 seconds early and reported a listener that had started 55
    seconds AFTER its .env as predating it. That refused a real SLO run on 2026-09-12.

    `ExecMainStartTimestampUsec` is empty on this systemd, so the human
    `ExecMainStartTimestamp` is converted by `date -d` in the same shell that reads the
    mtime. No value crosses the kernel boundary except the answer.
    """
    probe = ssh("sh", "-c",
                f'S=$(date -d "$(systemctl show -p ExecMainStartTimestamp --value {UNIT})" +%s 2>/dev/null);'
                f' E=$(stat -c %Y {RUNNER_HOME}/.env 2>/dev/null);'
                ' if [ -n "$S" ] && [ -n "$E" ]; then'
                '   if [ "$S" -ge "$E" ]; then echo fresh; else echo stale; fi;'
                ' else echo unknown; fi', timeout=90)
    answer = (probe.stdout or "").strip()
    if answer == "fresh":
        return True
    if answer == "stale":
        return False
    return None
