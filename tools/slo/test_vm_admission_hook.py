"""Controls for the VM runner's side of admission, capacity in particular.

Runs on any machine: no VM, no colima, no mirror. Every measurement is injected, because the
numbers that matter here are ones this host cannot reproduce -- an 18.3 GB guest disk seen
from a 926 GB host.

Run:  python3 tools/slo/test_vm_admission_hook.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vm_admission_hook  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []

CODE_REPO = "matssun/code"
RETENTION_WORKFLOW = ".github/workflows/disk-retention.yml"
CI_WORKFLOW = ".github/workflows/pr-gate.yml"

GB = 1024**3


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    mark = "ok  " if condition else "FAIL"
    suffix = f"  [{detail}]" if detail and not condition else ""
    print(f"  {mark} {name}{suffix}")


def usage(host_free_gb: float, guest_free_gb: float):
    """A disk_usage stand-in that answers differently per volume.

    The two volumes MUST answer differently: a stub returning one number for both would make
    the two-floor design untestable, which is the whole proposition here.
    """
    def measure(path):
        free = host_free_gb if Path(path) == vm_admission_hook.MIRROR else guest_free_gb
        return SimpleNamespace(free=free * GB, total=0, used=0)
    return measure


def env(repository: str, workflow: str) -> None:
    os.environ["GITHUB_REPOSITORY"] = repository
    os.environ["GITHUB_WORKFLOW_REF"] = f"{repository}/{workflow}@refs/heads/main"


def test_capacity() -> None:
    print("\nVM capacity admission")
    saved = dict(os.environ)
    env(CODE_REPO, CI_WORKFLOW)
    try:
        # THE REGRESSION THIS FILE EXISTS FOR.
        #
        # Measured inside the gh-runner VM on 2026-09-15: the guest root is 18.3 GB total
        # with 6.6 GB free, while the host volume behind the virtiofs mirror had 51.1 GB.
        # Applying the host's 25 GB floor to the guest would refuse EVERY job on dev1-linux
        # forever -- the guard becoming the outage it exists to prevent. This pins the real
        # numbers, so collapsing the two floors into one fails here.
        check("the real measured VM state is admitted",
              vm_admission_hook.capacity_refusal(usage(51.1, 6.6)) is None)

        # The host filling is the condition that actually wedged this runner, and this side
        # sees it through virtiofs without asking the host anything.
        host_low = vm_admission_hook.capacity_refusal(usage(9.0, 6.6))
        check("a starved HOST volume refuses, seen from inside the VM", host_low is not None)
        check("and the refusal names the host volume and both numbers",
              bool(host_low) and "host volume" in host_low and "9.0" in host_low
              and "25" in host_low, detail=str(host_low))

        # The guest has its own, much smaller floor. Below it, a runaway build is refused.
        guest_low = vm_admission_hook.capacity_refusal(usage(51.1, 1.0))
        check("a starved GUEST root refuses on its own smaller floor", guest_low is not None)
        check("and that refusal names the guest floor, not the host's",
              bool(guest_low) and "own root" in guest_low and "3 GB floor" in guest_low,
              detail=str(guest_low))

        # The positive control for both: plenty everywhere is admitted. Without it, every
        # refusal above would also pass against a function that refused unconditionally.
        check("room on both volumes is admitted",
              vm_admission_hook.capacity_refusal(usage(400.0, 12.0)) is None)

        # Fail open, deliberately and against this module's own default.
        def unreadable(_path):
            raise OSError("simulated statfs failure")
        check("an unmeasurable volume admits rather than refuses",
              vm_admission_hook.capacity_refusal(unreadable) is None)

        # The recovery lane, asserted at the SAME starved measurement as the refusal above.
        # Asserting it with room would hold with the exemption deleted.
        env(CODE_REPO, RETENTION_WORKFLOW)
        check("the retention lane is admitted below the floor",
              vm_admission_hook.capacity_refusal(usage(9.0, 6.6)) is None)

        # ...and it is the workflow that is exempt, not the repository: matssun/code is also
        # every ordinary CI job that runs here.
        env(CODE_REPO, CI_WORKFLOW)
        check("another workflow in the same repository is still refused",
              vm_admission_hook.capacity_refusal(usage(9.0, 6.6)) is not None)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_the_hook_consults_the_guard() -> None:
    """That `job-started` ASKS. A correct predicate nothing calls refuses nothing.

    Deleting the `capacity_refusal()` call from `hook_job_started` leaves every check above
    green while a starved runner admits work exactly as it did during the fortnight outage.
    """
    print("\nthe VM hook consults the guard")
    saved = dict(os.environ)
    tmp = Path(tempfile.mkdtemp())
    real_mirror, real_active = vm_admission_hook.MIRROR, vm_admission_hook.VM_ACTIVE
    real_usage = vm_admission_hook.shutil.disk_usage
    try:
        env(CODE_REPO, CI_WORKFLOW)
        os.environ["GITHUB_RUN_ID"] = "555"
        vm_admission_hook.MIRROR = tmp
        vm_admission_hook.VM_ACTIVE = tmp / "vm-active"
        vm_admission_hook.shutil.disk_usage = usage(9.0, 6.6)

        rc = vm_admission_hook.hook_job_started()
        check("a starved host refuses through the hook entry point",
              rc == vm_admission_hook.EXIT_REFUSED, detail=f"returned {rc}")

        # Refused before anything is published. A report left behind would tell the macOS
        # side a job is running here, and block the SLO drain on a job that never started.
        check("a refused job publishes no active record",
              not list((tmp / "vm-active").glob("*.json"))
              if (tmp / "vm-active").exists() else True)

        # The positive control: the same entry point admits when there is room, and DOES
        # publish. Without it the refusal above would pass against a hook that always
        # refused -- which is a dead runner, the exact failure being removed.
        vm_admission_hook.shutil.disk_usage = usage(400.0, 12.0)
        rc = vm_admission_hook.hook_job_started()
        check("a host with room admits through the hook entry point",
              rc == vm_admission_hook.EXIT_OK, detail=f"returned {rc}")
        check("and the admitted job DID publish an active record",
              len(list((tmp / "vm-active").glob("*.json"))) == 1)
    finally:
        vm_admission_hook.MIRROR, vm_admission_hook.VM_ACTIVE = real_mirror, real_active
        vm_admission_hook.shutil.disk_usage = real_usage
        os.environ.clear()
        os.environ.update(saved)


def main() -> int:
    print("vm-admission controls — no VM, no colima, no mirror")
    for fn in (test_capacity, test_the_hook_consults_the_guard):
        fn()
    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 74}\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
