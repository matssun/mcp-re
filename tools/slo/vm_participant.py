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
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arbiter_error import ArbiterError  # noqa: E402

PROFILE = os.environ.get("MCP_RE_ARBITER_VM_PROFILE", "gh-runner")
UNIT = os.environ.get("MCP_RE_ARBITER_VM_UNIT", "actions.runner.matssun-code.dev1-linux")
RUNNER_HOME = os.environ.get("MCP_RE_ARBITER_VM_RUNNER_HOME", "/home/mats.guest/actions-runner")
COLIMA = os.environ.get("MCP_RE_ARBITER_COLIMA", "/opt/homebrew/bin/colima")


def ssh(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([COLIMA, "ssh", "-p", PROFILE, "--", *args],
                          capture_output=True, text=True, timeout=timeout)


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
    boundary -- so the VM reports it from systemd's own start timestamp. None means
    "cannot tell", which callers treat as not-participating rather than as participating.
    """
    started = ssh("systemctl", "show", "-p", "ExecMainStartTimestampMonotonic",
                  "--value", UNIT, timeout=60).stdout.strip()
    env_epoch = ssh("sh", "-c", f"stat -c %Y {RUNNER_HOME}/.env 2>/dev/null || echo 0",
                    timeout=60).stdout.strip()
    boot_epoch = ssh("sh", "-c", "date -d \"$(uptime -s)\" +%s 2>/dev/null || echo 0",
                     timeout=60).stdout.strip()
    try:
        start_abs = int(boot_epoch) + int(started) // 1_000_000
        return start_abs >= int(env_epoch)
    except (TypeError, ValueError):
        return None
