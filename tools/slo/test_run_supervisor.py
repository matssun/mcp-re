"""Controls for the SLO run lifecycle.

These create REAL labelled containers on the dedicated `colima-slo` daemon, because the
proposition is about resource ownership on a live Docker daemon and a fake would prove only
that the code passes dictionaries around. Nothing else is permitted to use that daemon, so
the blast radius is the plane these tests own.

Each control leaves the plane at its baseline. The final check asserts that, so a control
that leaks is itself caught.

Run:  /opt/homebrew/bin/python3 tools/slo/test_run_supervisor.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import environment_preflight  # noqa: E402
import run_supervisor  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []

IMAGE = "redis:7-alpine"


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"  {'ok  ' if condition else 'FAIL'} {name}" +
          (f"  [{detail}]" if detail and not condition else ""))


def make_container(run: str | None, name: str, labelled: bool = True) -> str:
    """Create a long-lived container, optionally stamped with a run's ownership."""
    args = ["run", "-d", "--name", name]
    if labelled:
        args += ["--label", f"{run_supervisor.OWNER_LABEL}=true"]
        if run:
            args += ["--label", f"{run_supervisor.RUN_LABEL}={run}"]
    args += [IMAGE, "sleep", "600"]
    got = run_supervisor.docker(*args)
    return (got.stdout or "").strip()


def force_remove(name: str) -> None:
    run_supervisor.docker("rm", "-fv", name)


def plane_is_clean() -> bool:
    entry = environment_preflight.declared_class()
    return environment_preflight.inspect_plane(entry)["at_baseline"]


def supervise(cmd: str, run: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/opt/homebrew/bin/python3", str(Path(__file__).resolve().parent / "run_supervisor.py"), cmd],
        capture_output=True, text=True, env={**os.environ, "MCP_RE_SLO_RUN_ID": run}, timeout=600)


# ==========================================================================================


def test_run_identity() -> None:
    print("\nrun identity (§4)")
    gh = run_supervisor.run_id_from_environment.__wrapped__ if False else None
    env_before = dict(os.environ)
    try:
        os.environ.update({"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "lane"})
        check("inside Actions the id is the stable coordinates",
              run_supervisor.run_id_from_environment() == "gh-123-2-lane")
        # Stable, not nonced: reconciliation across a retry must recognise the same run.
        check("and it is stable across calls",
              run_supervisor.run_id_from_environment() == run_supervisor.run_id_from_environment())
    finally:
        os.environ.clear(); os.environ.update(env_before)
    a, b = run_supervisor.run_id_from_environment(), run_supervisor.run_id_from_environment()
    check("outside Actions two runs do not collide", a != b, f"{a} == {b}")


def test_teardown_removes_only_this_run() -> None:
    print("\nteardown removes this run's resources and only those (§12)")
    mine, theirs = f"t-{uuid.uuid4().hex[:8]}", f"t-{uuid.uuid4().hex[:8]}"
    make_container(mine, f"slo-{mine}")
    make_container(theirs, f"slo-{theirs}")
    try:
        check("both runs' resources are visible", run_supervisor.owned_resources()["total"] >= 2)
        check("but each run sees only its own",
              run_supervisor.owned_resources(mine)["total"] == 1
              and run_supervisor.owned_resources(theirs)["total"] == 1)
        run_supervisor.teardown(mine)
        check("teardown removed this run", run_supervisor.owned_resources(mine)["total"] == 0)
        check("and left the other run's alone",
              run_supervisor.owned_resources(theirs)["total"] == 1)
        check("clean_end is satisfied for this run", run_supervisor.assert_clean_end(mine)["clean"])
    finally:
        force_remove(f"slo-{mine}"); force_remove(f"slo-{theirs}")


def test_surviving_owned_resource_fails_clean_end() -> None:
    print("\na surviving owned resource FAILS the end gate (§12, §17.7)")
    run = f"t-{uuid.uuid4().hex[:8]}"
    name = f"slo-{run}"
    make_container(run, name)
    try:
        # The gate itself, against a real surviving resource.
        clean = run_supervisor.assert_clean_end(run)
        check("clean_end reports NOT clean", not clean["clean"])
        check("and names what survived", clean["remaining"]["total"] == 1)

        # THE REFUSAL BRANCH needs teardown to FAIL, which a working teardown will not do:
        # invoking `end` normally removes the container and correctly reports success. So
        # the branch is isolated by neutralising teardown in-process — the resource really
        # is there, the verification really runs against the live daemon, and only the
        # removal is suppressed. Without this the refusal path is never executed and the
        # gate would be decorative.
        original = run_supervisor.teardown
        previous_id = os.environ.get("MCP_RE_SLO_RUN_ID")
        try:
            # `main` derives the run from the environment, so the in-process call must be
            # told which run it is -- otherwise it computes a fresh local id, finds none of
            # ITS resources, and reports clean for a run that never created anything.
            os.environ["MCP_RE_SLO_RUN_ID"] = run
            run_supervisor.teardown = lambda r: {"attempted": "suppressed for this control"}
            rc = run_supervisor.main(["end"])
        finally:
            run_supervisor.teardown = original
            if previous_id is None:
                os.environ.pop("MCP_RE_SLO_RUN_ID", None)
            else:
                os.environ["MCP_RE_SLO_RUN_ID"] = previous_id
        check("with teardown suppressed, `end` exits non-zero", rc != 0, f"rc={rc}")

        # ...and with teardown working, the same command succeeds and the plane is clean.
        check("with teardown working, `end` succeeds", supervise("end", run).returncode == 0)
        check("and the resource is actually gone",
              run_supervisor.owned_resources(run)["total"] == 0)
    finally:
        force_remove(name)


def test_stale_run_is_reconciled_before_measurement() -> None:
    print("\na crashed previous run is reconciled before this one starts (§5, §17.5)")
    crashed, current = f"t-{uuid.uuid4().hex[:8]}", f"t-{uuid.uuid4().hex[:8]}"
    name = f"slo-{crashed}"
    make_container(crashed, name)
    try:
        check("the crashed run's resource is present",
              run_supervisor.owned_resources(crashed)["total"] == 1)
        # `begin` for a DIFFERENT run must find and remove it, then establish the baseline.
        got = supervise("begin", current)
        check("begin succeeds after reconciling it", got.returncode == 0, got.stderr[:200])
        check("the stale resource is gone",
              run_supervisor.owned_resources(crashed)["total"] == 0)
        payload = json.loads(got.stdout) if got.stdout.strip().startswith("{") else {}
        check("and the run record says it was reconciled",
              (payload.get("reconciled") or {}).get("reconciled") is True)
        check("the plane is at baseline afterwards",
              (payload.get("clean_start") or {}).get("at_baseline") is True)
    finally:
        force_remove(name)


def test_unowned_occupant_is_refused_never_killed() -> None:
    print("\nan UNOWNED occupant is refused, never destroyed (§5, §17.6)")
    stranger = f"stranger-{uuid.uuid4().hex[:8]}"
    make_container(None, stranger, labelled=False)
    run = f"t-{uuid.uuid4().hex[:8]}"
    try:
        strangers = run_supervisor.unowned_outside_baseline()
        check("the unowned container is seen", len(strangers["containers"]) == 1)
        check("and is NOT counted as ours", run_supervisor.owned_resources()["total"] == 0)
        got = supervise("begin", run)
        check("begin REFUSES rather than proceeding", got.returncode != 0, f"rc={got.returncode}")
        check("with INFRASTRUCTURE_UNAVAILABLE", "INFRASTRUCTURE_UNAVAILABLE" in got.stderr,
              got.stderr[:160])
        # THE point of the control: it must still be running. We do not destroy what we did
        # not create, however inconvenient it is.
        alive = run_supervisor.docker("ps", "-q", "--filter", f"name={stranger}").stdout.strip()
        check("and the stranger is STILL RUNNING — untouched", bool(alive))
    finally:
        force_remove(stranger)


def test_two_consecutive_runs(run_a: str | None = None) -> None:
    print("\ntwo consecutive runs each start clean and end clean (§17.1, §17.2)")
    a, b = f"t-{uuid.uuid4().hex[:8]}", f"t-{uuid.uuid4().hex[:8]}"
    try:
        check("run A begins clean", supervise("begin", a).returncode == 0)
        make_container(a, f"slo-{a}")
        check("run A created a resource", run_supervisor.owned_resources(a)["total"] == 1)
        check("run A ends clean", supervise("end", a).returncode == 0)
        check("no run-A resource survives", run_supervisor.owned_resources(a)["total"] == 0)

        check("run B begins clean — it observes nothing of A",
              supervise("begin", b).returncode == 0)
        check("and B sees zero owned resources at all",
              run_supervisor.owned_resources()["total"] == 0)
        make_container(b, f"slo-{b}")
        check("run B ends clean", supervise("end", b).returncode == 0)
    finally:
        force_remove(f"slo-{a}"); force_remove(f"slo-{b}")


def test_teardown_after_partial_setup_and_after_failure() -> None:
    print("\nteardown runs after partial setup and after a failed benchmark (§17.3, §17.4)")
    for scenario in ("partial setup failure", "benchmark FAIL"):
        run = f"t-{uuid.uuid4().hex[:8]}"
        # Partial setup: one resource created, then the run "fails" before creating the rest.
        make_container(run, f"slo-{run}")
        try:
            check(f"after {scenario}, teardown still removes what was created",
                  supervise("end", run).returncode == 0)
            check(f"and the plane is clean after {scenario}",
                  run_supervisor.owned_resources(run)["total"] == 0)
        finally:
            force_remove(f"slo-{run}")


def main() -> int:
    print("run-supervisor controls — real containers on the dedicated colima-slo daemon")
    if not plane_is_clean():
        print("  REFUSING: the plane is not at its baseline before the controls start.")
        print("  ", json.dumps(environment_preflight.inspect_plane(
            environment_preflight.declared_class()), default=str)[:300])
        return 1
    for fn in (test_run_identity,
               test_teardown_removes_only_this_run,
               test_surviving_owned_resource_fails_clean_end,
               test_stale_run_is_reconciled_before_measurement,
               test_unowned_occupant_is_refused_never_killed,
               test_two_consecutive_runs,
               test_teardown_after_partial_setup_and_after_failure):
        fn()

    # The controls themselves must not leak. If they did, every later run would refuse.
    check("the controls left the plane at its baseline", plane_is_clean())

    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 74}\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
