"""The SLO run lifecycle authority: one owner for every ephemeral measurement resource.

WHY IT IS NOT THE HOST ARBITER, AND NOT THE HARNESS
===================================================

Two separate authorities, both necessary:

    host arbiter  (host_gate)      answers "is another RUNNER working on this machine?"
    run supervisor (this)          answers "is anything left over from a previous SLO RUN,
                                   and did this run remove everything it created?"

Host exclusivity says nothing about a Redis fleet or a proxy child surviving a crashed run.
Their load is real, it lands in the quiescence window, and a fleet answering on a port the
new run expects to own would be measured as though this run had started it.

And it is not the harness, because the harness is INSIDE cargo. `RedisFleet`'s `Drop` guard
is a genuine fast path -- milliseconds on a normal exit and on a panic -- but it is the
frame that disappears when the job is cancelled or the process is killed. A cleanup
authority must survive the thing it cleans up after, so it runs one level out.

THE ORDERING, AND WHY RECONCILE COMES BEFORE QUIESCE
====================================================

    reserve host ─▶ drain runners        (host_gate, already done when we are called)
    reconcile previous runs' leftovers
    assert clean start                   exact baseline, or refuse
    quiesce                              ONLY now does the clock start
    create run id ─▶ start resources ─▶ await readiness
    measure
    teardown                             ALWAYS, including failure and cancellation
    assert clean end                     or the result is not attestable
    persist ─▶ release host

Measuring load decay while a stale proxy is still running folds that load into the "quiet
box" the run claims to have measured on. Reconciliation must therefore precede quiescence,
not follow it.

OWNERSHIP, AND WHAT WE REFUSE TO TOUCH
======================================

Every Docker resource a run creates carries `com.mcp-re.slo=true` and
`com.mcp-re.slo.run=<RUN_ID>`. Reconciliation acts ONLY on resources whose ownership is
established that way. An unlabelled container holding a port we need is somebody else's
process; that is INFRASTRUCTURE_UNAVAILABLE and no benchmark runs. We never `pkill mcp-re`,
never remove by name pattern, never "kill whatever owns port X".

Resources left by a SIGKILL or a power loss are not cleaned by this run's teardown -- no
code of ours executed. They are repaired by the NEXT run's reconciliation, which is exactly
why ownership has to be a durable label rather than a live object's destructor.

TEARDOWN IS PART OF THE VERDICT
===============================

A measurement that passes every performance criterion and leaves a container running has
violated its environmental contract. Its number was taken on a plane we can no longer
characterise, and reusing it would propagate that. So `assert_clean_end` is a gate:

    performance ∧ clean-start ∧ exclusivity ∧ quiescence ∧ teardown  =  attestable
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import environment_preflight  # noqa: E402

SCHEMA = "mcp-re-slo-run/v1"

OWNER_LABEL = "com.mcp-re.slo"
RUN_LABEL = "com.mcp-re.slo.run"

#: Where run manifests live. Durable, because reconciliation needs to read the manifest of
#: a run whose process is long gone -- and beside the evidence store rather than inside the
#: Actions checkout, which is cleaned between runs.
RUNS_ROOT = Path(os.environ.get("MCP_RE_SLO_RUNS_ROOT", "/opt/verification/slo-runs"))

GRACE_S = float(os.environ.get("MCP_RE_SLO_TEARDOWN_GRACE_S", 10))
VERIFY_S = float(os.environ.get("MCP_RE_SLO_TEARDOWN_VERIFY_S", 30))

EXIT_OK, EXIT_REFUSED, EXIT_UNAVAILABLE = 0, 1, 2


class LifecycleError(RuntimeError):
    """A refusal. The caller must not measure, and must not attest."""


def run_id_from_environment() -> str:
    """Stable execution coordinates, with a nonce only where they do not exist.

    Outside Actions there is no run id to be had, so a nonce keeps two local runs from
    claiming each other's resources. Inside Actions the coordinates are stable and a nonce
    would defeat reconciliation across an attempt.
    """
    run = os.environ.get("GITHUB_RUN_ID")
    if run:
        attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        job = os.environ.get("GITHUB_JOB", "job")
        return f"gh-{run}-{attempt}-{job}"
    return f"local-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def endpoint() -> str:
    return environment_preflight.endpoint(environment_preflight.declared_class())


def docker(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return environment_preflight.docker(endpoint(), *args, timeout=timeout)


# ==========================================================================================
# what exists, and who owns it
# ==========================================================================================


def owned_resources(run: str | None = None) -> dict:
    """Docker resources carrying our label, optionally narrowed to one run.

    `run=None` means every SLO-owned resource regardless of which run made it -- that is
    what reconciliation asks. A specific run is what teardown verification asks.
    """
    selector = [f"label={OWNER_LABEL}=true"]
    if run:
        selector.append(f"label={RUN_LABEL}={run}")
    filters: list[str] = []
    for s in selector:
        filters += ["--filter", s]

    containers = [c for c in (docker("ps", "-aq", *filters).stdout or "").split() if c]
    networks = [n for n in (docker("network", "ls", "-q", *filters).stdout or "").split() if n]
    volumes = [v for v in (docker("volume", "ls", "-q", *filters).stdout or "").split() if v]
    return {"containers": containers, "networks": networks, "volumes": volumes,
            "total": len(containers) + len(networks) + len(volumes)}


def unowned_outside_baseline() -> dict:
    """Things on the plane that are NOT ours, and therefore not ours to remove."""
    entry = environment_preflight.declared_class()
    plane = environment_preflight.inspect_plane(entry)
    ours = set(owned_resources()["containers"])
    strangers = [c for c in plane["containers"] if c["id"] not in ours
                 and f"{OWNER_LABEL}=true" not in (c.get("labels") or "")]
    return {"containers": strangers, "unapproved_images": plane["unapproved_images"]}


# ==========================================================================================
# reconcile -> clean start
# ==========================================================================================


def reconcile_previous(current_run: str) -> dict:
    """Remove resources owned by PREVIOUS runs. Never anything unowned.

    Graceful first, then forced, then VERIFIED. A removal command that returns success is
    not evidence the resource is gone -- only re-reading the daemon is.
    """
    before = owned_resources()
    stale_containers = [c for c in before["containers"]
                        if current_run not in (docker("inspect", "-f",
                                                      "{{index .Config.Labels \"" + RUN_LABEL + "\"}}",
                                                      c).stdout or "")]
    removed = {"containers": [], "networks": [], "volumes": []}

    for cid in stale_containers:
        docker("stop", "-t", str(int(GRACE_S)), cid)
        docker("rm", "-fv", cid)
        removed["containers"].append(cid)

    # Networks and volumes carry the label too, so they are addressed the same way. A
    # network still holding a container refuses removal, which is why containers go first.
    for net in before["networks"]:
        if docker("rm", "-f", "--", net).returncode == 0 or docker("network", "rm", net).returncode == 0:
            removed["networks"].append(net)
    for vol in before["volumes"]:
        if docker("volume", "rm", "-f", vol).returncode == 0:
            removed["volumes"].append(vol)

    deadline = time.monotonic() + VERIFY_S
    while owned_resources()["total"] > len(owned_resources(current_run)["containers"]):
        if time.monotonic() >= deadline:
            break
        time.sleep(1)

    after = owned_resources()
    survivors = [c for c in after["containers"] if c in stale_containers]
    return {"found": before, "removed": removed, "survivors": survivors,
            "reconciled": not survivors}


def assert_clean_start(current_run: str) -> dict:
    """The exact declared baseline, or a refusal that says which kind of problem it is."""
    entry = environment_preflight.declared_class()
    env = environment_preflight.verify_environment(entry)
    plane = environment_preflight.inspect_plane(entry)
    strangers = unowned_outside_baseline()
    leftovers = owned_resources()

    problems: list[str] = []
    if not env["verified"]:
        problems.append(f"the plane is not the declared environment: {env['mismatches']}")
    if leftovers["total"]:
        problems.append(f"SLO-owned resources from a previous run remain: {leftovers}")
    if strangers["containers"]:
        # NOT ours. This is an infrastructure condition, not something to clear.
        problems.append(
            f"INFRASTRUCTURE_UNAVAILABLE: {len(strangers['containers'])} unowned "
            f"container(s) occupy the measurement plane. They were not created by an SLO "
            f"run and will not be removed; resolve manually.")
    if strangers["unapproved_images"]:
        problems.append(f"unapproved images on the plane: {strangers['unapproved_images']}")

    return {"at_baseline": not problems, "problems": problems,
            "environment_verified": env["verified"], "plane": plane}


# ==========================================================================================
# the run record
# ==========================================================================================


def manifest_path(run: str) -> Path:
    return RUNS_ROOT / f"{run}.json"


def write_manifest(run: str, **fields: object) -> dict:
    RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    path = manifest_path(run)
    record = json.loads(path.read_text()) if path.exists() else {
        "schema": SCHEMA, "run_id": run, "created_at": _now(), "events": []}
    record.update(fields)
    record["events"].append({"at": _now(), **{k: v for k, v in fields.items() if k != "events"}})
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True, default=str))
    os.replace(tmp, path)
    return record


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ==========================================================================================
# teardown -> clean end
# ==========================================================================================


def teardown(run: str) -> dict:
    """Remove everything this run created. Unconditional: called on every exit path."""
    mine = owned_resources(run)
    for cid in mine["containers"]:
        docker("stop", "-t", str(int(GRACE_S)), cid)
        docker("rm", "-fv", cid)
    for net in mine["networks"]:
        docker("network", "rm", net)
    for vol in mine["volumes"]:
        docker("volume", "rm", "-f", vol)
    return {"attempted": mine}


def assert_clean_end(run: str) -> dict:
    """Verify by re-reading the daemon. A teardown that ran is not a teardown that worked."""
    deadline = time.monotonic() + VERIFY_S
    remaining = owned_resources(run)
    while remaining["total"] and time.monotonic() < deadline:
        time.sleep(1)
        remaining = owned_resources(run)
    return {"clean": remaining["total"] == 0, "remaining": remaining}


# ==========================================================================================
# CLI -- the lane drives these in order
# ==========================================================================================


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="slo-run-supervisor", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run-id", help="print the run identity for this execution")
    sub.add_parser("begin", help="reconcile previous runs, then assert the clean baseline")
    sub.add_parser("end", help="tear down this run and assert the plane is clean again")
    sub.add_parser("status", help="what is on the plane, and who owns it")
    args = parser.parse_args(argv)

    run = os.environ.get("MCP_RE_SLO_RUN_ID") or run_id_from_environment()

    try:
        if args.cmd == "run-id":
            print(run)
            return EXIT_OK

        if args.cmd == "begin":
            reconciled = reconcile_previous(run)
            clean = assert_clean_start(run)
            write_manifest(run, phase="begin", reconciled=reconciled, clean_start=clean)
            print(json.dumps({"run_id": run, "reconciled": reconciled,
                              "clean_start": clean}, indent=2, default=str))
            if not reconciled["reconciled"]:
                raise LifecycleError(
                    f"previous runs' resources survived reconciliation: {reconciled['survivors']}")
            if not clean["at_baseline"]:
                unavailable = any("INFRASTRUCTURE_UNAVAILABLE" in p for p in clean["problems"])
                raise LifecycleError("; ".join(clean["problems"])) if not unavailable else \
                    LifecycleError("INFRASTRUCTURE_UNAVAILABLE: " + "; ".join(clean["problems"]))
            return EXIT_OK

        if args.cmd == "end":
            torn = teardown(run)
            clean = assert_clean_end(run)
            write_manifest(run, phase="end", teardown=torn, clean_end=clean)
            print(json.dumps({"run_id": run, "teardown": torn, "clean_end": clean},
                             indent=2, default=str))
            if not clean["clean"]:
                raise LifecycleError(
                    f"SLO RESULT: INFRASTRUCTURE_FAILURE — resources created by {run} "
                    f"survived teardown: {clean['remaining']}. The measurement is NOT "
                    f"attestable: cleanup success is part of the validity of the result.")
            return EXIT_OK

        if args.cmd == "status":
            print(json.dumps({
                "run_id": run, "endpoint": endpoint(),
                "owned_all_runs": owned_resources(),
                "owned_this_run": owned_resources(run),
                "unowned": unowned_outside_baseline(),
            }, indent=2, default=str))
            return EXIT_OK

    except LifecycleError as exc:
        print(f"slo-run-supervisor REFUSED: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE if "INFRASTRUCTURE_UNAVAILABLE" in str(exc) else EXIT_REFUSED

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
