"""Controls for the installer's own drift check.

Runs entirely in temp directories: nothing here reads /opt, the mirror, or a runner.

The proposition under test is narrow and was violated in production: THE TEXT
`installed_drift` EXPECTS MUST BE THE TEXT `install` WRITES. When those two disagree,
`--verify` reports drift against bytes that are exactly correct -- a false red on the
gate at slo.yml:168, which is worse than a missing check, because the lane fails while
naming a file nobody has touched.

Run:  python3 tools/slo/test_install_arbiter.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import install_arbiter as ia  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []

WRAPPERS = (("job-started", "job-started.sh"), ("job-completed", "job-completed.sh"))
VM_WRAPPERS = (("job-started", "vm-job-started.sh"),
               ("job-completed", "vm-job-completed.sh"))


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    mark = "ok  " if condition else "FAIL"
    suffix = f"  [{detail}]" if detail and not condition else ""
    print(f"  {mark} {name}{suffix}")


def test_verify_accepts_what_install_writes() -> None:
    """The round trip, which is the whole claim.

    A tree written by the installer's own templates must verify clean. Nothing else
    establishes that the two halves agree -- reading either one alone looks correct.
    """
    print("\ninstaller round trip")
    tmp = Path(tempfile.mkdtemp())
    root, mirror, here = tmp / "root", tmp / "mirror", Path(__file__).resolve().parent
    (root / "bin").mkdir(parents=True)
    (mirror / "bin").mkdir(parents=True)

    # Write exactly what `install` writes, from the same templates.
    for command, filename in WRAPPERS:
        (root / "bin" / filename).write_text(ia.WRAPPER.format(root=root, command=command))
    for command, filename in VM_WRAPPERS:
        (mirror / "bin" / filename).write_text(
            ia.VM_WRAPPER.format(mirror=mirror, command=command))
    for name in ia.SOURCES:
        (root / "bin" / name).write_bytes((here / name).read_bytes())
    (mirror / "bin" / "vm_admission_hook.py").write_bytes(
        (here / "vm_admission_hook.py").read_bytes())

    drift = ia.installed_drift(root=root, mirror=mirror, here=here)
    bad = [d for d in drift if d["state"] != "MATCHES"]
    check("a tree written by the installer verifies clean", not bad,
          detail=str([(d["state"], d["file"]) for d in bad]))

    # Positive control. Without it the assertion above would also hold against a drift
    # check that returned an empty list, or one that called everything MATCHES.
    check("the drift check inspected every tracked file",
          len(drift) == len(ia.SOURCES) + 1 + len(WRAPPERS) + len(VM_WRAPPERS),
          detail=f"{len(drift)} entries")
    (mirror / "bin" / "vm-job-started.sh").write_text("#!/bin/sh\nexec true\n")
    tampered = ia.installed_drift(root=root, mirror=mirror, here=here)
    check("and it reports a tampered VM wrapper as DIFFERS",
          any(d["state"] == "DIFFERS" and d["file"].endswith("vm-job-started.sh")
              for d in tampered))


def test_the_two_wrapper_templates_are_distinct() -> None:
    """Why the bug was possible, pinned so a future edit cannot hide it.

    The host wrapper execs `runner_arbiter.py` under ROOT; the VM's execs
    `vm_admission_hook.py` under the MIRROR, because /opt is not mounted in the guest at
    all. If these ever collapsed into one template, the round-trip test above would pass
    trivially and say nothing.
    """
    print("\nthe templates are genuinely different")
    host = ia.WRAPPER.format(root=Path("/opt/x"), command="job-started")
    vm = ia.VM_WRAPPER.format(mirror=Path("/Users/m/.mirror"), command="job-started")
    check("the host wrapper execs the host arbiter", "runner_arbiter.py" in host)
    check("the VM wrapper execs the VM hook", "vm_admission_hook.py" in vm)
    check("and the VM wrapper names no /opt path", "/opt" not in vm, detail=vm)


def main() -> int:
    print("installer controls — temp directories only, no /opt, no runner")
    for fn in (test_verify_accepts_what_install_writes,
               test_the_two_wrapper_templates_are_distinct):
        fn()
    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 74}\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
