"""Controls for the physical-host admission gate.

Everything here runs against temp directories: no test writes /opt, and none needs a runner.
The propositions that CANNOT be established this way -- that two real runner applications on
dev1 honour the gate -- are exercised live and recorded separately; a unit test must not be
allowed to stand in for that.

Run:  python3 tools/slo/test_host_gate.py
"""

from __future__ import annotations

import itertools
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate  # noqa: E402
from arbiter_error import ArbiterError  # noqa: E402
from job_identity import JobIdentity  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []

CODE_REPO = "matssun/code"
MCPRE_REPO = "matssun/mcp-re"
CI_WORKFLOW = ".github/workflows/ci.yml"
SLO_WORKFLOW = ".github/workflows/slo.yml"


def workflow_ref(repository: str, workflow: str) -> str:
    """The shape GitHub puts in GITHUB_WORKFLOW_REF."""
    return f"{repository}/{workflow}@refs/heads/main"


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    mark = "ok  " if condition else "FAIL"
    suffix = f"  [{detail}]" if detail and not condition else ""
    print(f"  {mark} {name}{suffix}")


def fresh() -> dict:
    tmp = Path(tempfile.mkdtemp())
    paths = host_gate.paths(tmp / "root", tmp / "mirror")
    host_gate.ensure_layout(paths)
    return paths


def ordinary(n: int = 1, runner: str = "dev1") -> JobIdentity:
    return JobIdentity(runner, CODE_REPO, workflow_ref(CODE_REPO, CI_WORKFLOW),
                       CI_WORKFLOW, str(n), "1", f"job{n}")


def slo(n: int = 99, runner: str = "dev1-mcp-re") -> JobIdentity:
    return JobIdentity(runner, MCPRE_REPO, workflow_ref(MCPRE_REPO, SLO_WORKFLOW),
                       SLO_WORKFLOW, str(n), "1", "slo")


# ==========================================================================================
# capacity admission
# ==========================================================================================

RETENTION_WORKFLOW = ".github/workflows/disk-retention.yml"


def recovery(n: int = 700) -> JobIdentity:
    """The lane that makes the disk not-full, as GitHub presents it to the hook."""
    return JobIdentity("dev1", CODE_REPO, workflow_ref(CODE_REPO, RETENTION_WORKFLOW),
                       RETENTION_WORKFLOW, str(n), "1", "retention")


def with_work_path(tmp: Path):
    """A hook environment naming a work path, which is what work_volume() reads."""
    return {"RUNNER_TEMP": str(tmp)}


def test_capacity_refusal() -> None:
    print("\ncapacity admission")
    p = fresh()
    tmp = p["root"]

    # Everything below fixes the SAME simulated free space and varies only the identity or
    # the threshold. A test that let free space float would prove nothing: above the floor
    # every job is admitted, so an "admitted" assertion holds with the guard deleted.
    starved = lambda _volume: 3.0      # noqa: E731  -- 3 GB, far under the 25 GB floor
    roomy = lambda _volume: 400.0      # noqa: E731

    env = with_work_path(tmp)
    old_environ = dict(os.environ)
    os.environ.update(env)
    try:
        refused = False
        try:
            host_gate.refuse_if_disk_exhausted(p, ordinary(1), measure=starved)
        except ArbiterError as exc:
            refused = True
            message = str(exc)
        check("an ordinary job is refused below the floor", refused)

        # The positive control. Without it the refusal above also passes against a guard
        # that refuses everything, which would be a total outage rather than a guard.
        admitted = True
        try:
            host_gate.refuse_if_disk_exhausted(p, ordinary(2), measure=roomy)
        except ArbiterError:
            admitted = False
        check("the same job is admitted above the floor", admitted)

        # THE DISCRIMINATING PAIR, both at 3 GB. The recovery lane is the cure for the
        # condition being refused; a guard that refused it would deadlock the host. Note
        # this is asserted at the SAME free space as the refusal above -- asserting it at
        # 400 GB would hold with the exemption deleted.
        recovered = True
        try:
            host_gate.refuse_if_disk_exhausted(p, recovery(), measure=starved)
        except ArbiterError:
            recovered = False
        check("the retention lane is admitted below the floor", recovered)

        # ...and it is the WORKFLOW that is exempt, not the repository. matssun/code runs
        # CI here too, and exempting the whole repository would exempt nearly everything.
        impostor_refused = False
        try:
            host_gate.refuse_if_disk_exhausted(p, ordinary(3), measure=starved)
        except ArbiterError:
            impostor_refused = True
        check("another workflow in the same repository is still refused", impostor_refused)

        # The refusal is read by an operator who has no context, so it must name the volume
        # it measured: the host and the colima VM measure DIFFERENT filesystems through this
        # same code, and a number without its volume cannot be checked.
        check("the refusal names the volume and both numbers",
              str(tmp) in message and "3.0" in message and "25" in message,
              detail=message if refused else "no refusal")

        # Fail-open, deliberately and against the rest of this file's direction: an
        # unreadable volume must not stop all work on the host.
        def unreadable(_volume):
            raise OSError("simulated statvfs failure")

        open_on_failure = True
        try:
            host_gate.refuse_if_disk_exhausted(p, ordinary(4), measure=unreadable)
        except ArbiterError:
            open_on_failure = False
        check("an unmeasurable volume admits rather than refuses", open_on_failure)
    finally:
        os.environ.clear()
        os.environ.update(old_environ)

    # A hook environment naming no work path at all cannot be measured either, and must not
    # refuse. Asserted with the work-path variables absent rather than by faking a failure.
    for var in ("RUNNER_WORKSPACE", "GITHUB_WORKSPACE", "RUNNER_TEMP"):
        os.environ.pop(var, None)
    unnamed_ok = True
    try:
        host_gate.refuse_if_disk_exhausted(p, ordinary(5), measure=starved)
    except ArbiterError:
        unnamed_ok = False
    check("a job whose work path is unknown is not refused", unnamed_ok)
    os.environ.clear()
    os.environ.update(old_environ)


def test_the_hook_consults_the_guard() -> None:
    """That `job-started` ASKS. The predicate being correct is not enough.

    The checks above prove `refuse_if_disk_exhausted` decides correctly. They say NOTHING
    about whether the admission path calls it -- delete that one line from
    `cmd_job_started` and every one of them stays green while a full host admits work
    exactly as it did during the fortnight outage. This is the same gap a poison pill found
    in the retention collector, arriving at a different seam.
    """
    print("\nthe hook consults the guard")
    import runner_arbiter

    p = fresh()
    old_environ = dict(os.environ)
    os.environ["RUNNER_TEMP"] = str(p["root"])
    real_free_gb = host_gate.free_gb
    try:
        host_gate.free_gb = lambda _volume: 3.0
        rc = runner_arbiter.cmd_job_started(p, ordinary(10))
        check("a starved host refuses through the hook entry point", False,
              detail=f"returned {rc} instead of raising")
    except ArbiterError:
        check("a starved host refuses through the hook entry point", True)
    finally:
        host_gate.free_gb = real_free_gb
        os.environ.clear()
        os.environ.update(old_environ)

    # Refused BEFORE any state is written. A job that left an active record behind would
    # leak one per refused job, and on the SLO path would reserve the whole host and then
    # refuse -- closing every runner behind a job that never ran.
    check("a refused job leaves no active record", not list(p["active"].glob("*.json")))
    check("a refused job leaves the gate open",
          host_gate.read_gate(p).get("state", host_gate.OPEN) == host_gate.OPEN)

    # The positive control: the same entry point admits when there is room. Without it the
    # refusal above would pass against a `cmd_job_started` that raised unconditionally.
    p2 = fresh()
    os.environ["RUNNER_TEMP"] = str(p2["root"])
    try:
        host_gate.free_gb = lambda _volume: 400.0
        rc = runner_arbiter.cmd_job_started(p2, ordinary(11))
        check("a host with room admits through the hook entry point", rc == 0)
        check("and the admitted job DID leave an active record",
              len(list(p2["active"].glob("*.json"))) == 1)
    except ArbiterError:
        check("a host with room admits through the hook entry point", False)
    finally:
        host_gate.free_gb = real_free_gb
        os.environ.clear()
        os.environ.update(old_environ)


# ==========================================================================================
# identification
# ==========================================================================================


def test_identification() -> None:
    print("\nSLO identification (§4)")
    check("the SLO workflow path identifies the owner", slo().is_slo)
    check("an ordinary workflow does not", not ordinary().is_slo)

    # The identity is the workflow PATH, not the job title: a title match would admit any
    # workflow that happened to call its job "slo".
    impostor = JobIdentity("dev1", CODE_REPO, workflow_ref(CODE_REPO, CI_WORKFLOW),
                           CI_WORKFLOW, "5", "1", "slo")
    check("a job merely NAMED slo is ordinary", not impostor.is_slo)

    # Same workflow path, wrong repository -- another repo cannot reserve this host's SLO.
    foreign = JobIdentity("dev1", CODE_REPO, workflow_ref(CODE_REPO, SLO_WORKFLOW),
                          SLO_WORKFLOW, "6", "1", "slo")
    check("the same path in another repository is ordinary", not foreign.is_slo)

    # An empty environment must not accidentally be the owner.
    check("an unidentifiable job is ordinary", not JobIdentity.from_env({}).is_slo)

    parsed = JobIdentity.from_env({
        "GITHUB_REPOSITORY": MCPRE_REPO,
        "GITHUB_WORKFLOW_REF": workflow_ref(MCPRE_REPO, SLO_WORKFLOW),
        "RUNNER_NAME": "dev1-mcp-re", "GITHUB_RUN_ID": "7", "GITHUB_JOB": "slo"})
    check("the real hook env shape parses to the owner", parsed.is_slo,
          f"got path={parsed.workflow_path!r}")


# ==========================================================================================
# the ordering that closes the race
# ==========================================================================================


def test_reserve_then_drain() -> None:
    print("\nreserve-first-then-drain (§2)")
    paths = fresh()
    first = ordinary(1)
    host_gate.admit_ordinary(paths, first, wait_s=1)
    host_gate.grant_reservation(paths, slo())

    # The invariant: after the grant, NO new non-owner job may be admitted -- which is what
    # stops the queue refilling while the owner waits for the drain.
    try:
        host_gate.admit_ordinary(paths, ordinary(2), wait_s=1)
        check("a new ordinary job is refused during a reservation", False, "it was admitted")
    except ArbiterError:
        check("a new ordinary job is refused during a reservation", True)

    # ...while work that was ALREADY running is left alone to finish.
    check("the pre-existing job is still active", len(host_gate.active_records(paths)) == 1)
    host_gate.job_completed(paths, first)
    check("the pre-existing job drains normally", len(host_gate.active_records(paths)) == 0)


def test_ordinary_first_then_slo() -> None:
    print("\nordinary wins the mutex first (§13)")
    paths = fresh()
    first = ordinary(1)
    host_gate.admit_ordinary(paths, first, wait_s=1)
    gate = host_gate.grant_reservation(paths, slo())
    check("the reservation is granted even over a running job",
          gate["state"] == host_gate.RESERVING)
    check("but the owner is not yet RESERVED", gate["state"] != host_gate.RESERVED)

    host_gate.job_completed(paths, first)
    drained = host_gate.await_drain(paths, slo(), lambda: 0, wait_s=5)
    check("drain completes once the ordinary job finishes", isinstance(drained, list))
    host_gate.activate(paths, slo(), {"established": True, "duration_s": 60})
    check("the owner then reaches RESERVED",
          host_gate.read_gate(paths)["state"] == host_gate.RESERVED)


def test_second_slo_cannot_overlap() -> None:
    print("\ntwo SLO measurements cannot overlap (§13)")
    paths = fresh()
    host_gate.grant_reservation(paths, slo(1))
    try:
        host_gate.grant_reservation(paths, slo(2))
        check("a second SLO reservation is refused", False, "it was granted")
    except ArbiterError:
        check("a second SLO reservation is refused", True)
    again = host_gate.grant_reservation(paths, slo(1))
    check("the SAME owner re-entering is idempotent", again["state"] == host_gate.RESERVING)


# ==========================================================================================
# simultaneous admission -- the property that must never be observed
# ==========================================================================================


def racer(args) -> str:
    root, mirror, kind, n = args
    paths = host_gate.paths(Path(root), Path(mirror))
    ident = slo(n) if kind == "slo" else ordinary(n)
    try:
        if kind == "slo":
            host_gate.grant_reservation(paths, ident)
            return "slo-reserved"
        host_gate.admit_ordinary(paths, ident, wait_s=0)
        return "ordinary-admitted"
    except ArbiterError:
        return f"{kind}-refused"


def test_simultaneous_admission() -> None:
    print("\nsimultaneous admission, driven concurrently (§13)")
    violations = 0
    rounds = 40
    for r in range(rounds):
        paths = fresh()
        args = [(str(paths["root"]), str(paths["mirror"]), "slo", 500 + r)]
        args += [(str(paths["root"]), str(paths["mirror"]), "ordinary", i) for i in range(6)]
        with multiprocessing.Pool(len(args)) as pool:
            pool.map(racer, args)
        gate = host_gate.read_gate(paths)
        owner_key = gate.get("owner", {}).get("key")
        actives = [a for a in host_gate.active_records(paths) if a.get("key") != owner_key]
        # THE forbidden state: an owner holding the host while a non-owner is also admitted.
        # A job admitted BEFORE the grant is legitimate -- it drains. One admitted AFTER is
        # the violation, and each record's own timestamp is what separates the two.
        if gate.get("state") in (host_gate.RESERVING, host_gate.RESERVED) and actives:
            granted_at = gate.get("created_at", "")
            if [a for a in actives if a.get("started_at", "") > granted_at]:
                violations += 1
    check(f"no round observed a reservation plus a post-grant non-owner ({rounds} rounds)",
          violations == 0, f"{violations} violations")


# ==========================================================================================
# fail-closed behaviour
# ==========================================================================================


def test_fail_closed() -> None:
    print("\nfail-closed (§5)")
    paths = fresh()
    host_gate.grant_reservation(paths, slo())
    start = time.monotonic()
    try:
        host_gate.admit_ordinary(paths, ordinary(3), wait_s=2)
        check("a bounded wait ends in refusal, not admission", False, "admitted")
    except ArbiterError:
        check("a bounded wait ends in refusal, not admission", True)
    check("the wait was actually bounded", time.monotonic() - start < 20)

    # A corrupt gate must not read as an open host. This is THE fail-open case.
    corrupt = fresh()
    corrupt["gate"].write_text("{ not json")
    try:
        host_gate.read_gate(corrupt)
        check("a corrupt gate refuses rather than reading as OPEN", False, "parsed")
    except ArbiterError:
        check("a corrupt gate refuses rather than reading as OPEN", True)

    # An unobservable VM must refuse too: "cannot see" is not "is idle".
    unseen = fresh()
    host_gate.grant_reservation(unseen, slo())

    def unobservable() -> int:
        raise ArbiterError("VM unreachable")

    try:
        host_gate.await_drain(unseen, slo(), unobservable, wait_s=2)
        check("an unobservable VM refuses the drain", False, "drain succeeded")
    except ArbiterError:
        check("an unobservable VM refuses the drain", True)

    # A busy VM blocks the drain even when macOS looks completely clear -- the case a
    # macOS-only pgrep can never see.
    busy_vm = fresh()
    host_gate.grant_reservation(busy_vm, slo())
    try:
        host_gate.await_drain(busy_vm, slo(), lambda: 2, wait_s=2)
        check("a busy VM blocks the drain though macOS is clear", False, "drain succeeded")
    except ArbiterError:
        check("a busy VM blocks the drain though macOS is clear", True)


def test_completion_releases_on_every_path() -> None:
    print("\ncompletion releases on every outcome (§6)")
    for outcome in ("success", "workflow failure", "cancelled",
                    "benchmark INCONCLUSIVE", "benchmark FAIL"):
        paths = fresh()
        owner = slo()
        host_gate.grant_reservation(paths, owner)
        host_gate.activate(paths, owner, {"established": True, "duration_s": 1})
        result = host_gate.job_completed(paths, owner)
        released = (result["released_reservation"]
                    and host_gate.read_gate(paths)["state"] == host_gate.RELEASED)
        check(f"reservation released after {outcome}", released)
        host_gate.admit_ordinary(paths, ordinary(9), wait_s=1)
        check(f"normal admission resumes after {outcome}",
              len(host_gate.active_records(paths)) == 1)


def fake_worker(pid: int = 4242, started: int | None = None) -> dict:
    return {"pid": pid, "started": int(time.time()) - 600 if started is None else started}


def table_with(worker: dict | None):
    """A process table in which `worker` (if any) is a live Runner.Worker."""
    def table() -> dict:
        if worker is None:
            return {}
        elapsed = int(time.time()) - worker["started"]
        return {worker["pid"]: (1, elapsed, "/runner/bin/Runner.Worker spawnclient 1 2")}
    return table


def unreadable_table() -> dict:
    raise OSError("ps unavailable")


def test_crash_leaves_closed_not_open() -> None:
    print("\nrunner crash / missing completion hook (§6)")
    # LIVE owner, completion hook not (yet) run: the host stays closed.
    paths = fresh()
    owner = slo()
    worker = fake_worker()
    host_gate.grant_reservation(paths, owner, worker=worker, table_fn=table_with(worker))
    host_gate.activate(paths, owner, {"established": True, "duration_s": 1})
    gate = host_gate.read_gate(paths)
    check("the reservation survives while its owner lives", gate["state"] == host_gate.RESERVED)
    try:
        host_gate.admit_ordinary(paths, ordinary(4), wait_s=1, table_fn=table_with(worker))
        check("the host stays CLOSED while the owner lives", False, "admitted")
    except ArbiterError:
        check("the host stays CLOSED while the owner lives", True)
    check("the record carries operator recovery instructions",
          "recover" in json.dumps(gate.get("stale_recovery", {})))

    # No elapsed time releases it. A TTL here would be fail-open at the worst moment.
    host_gate.write_atomic(paths["gate"], {**gate, "created_at": "2000-01-01T00:00:00Z"})
    try:
        host_gate.admit_ordinary(paths, ordinary(5), wait_s=1, table_fn=table_with(worker))
        check("age alone does NOT release a reservation", False, "an old reservation opened")
    except ArbiterError:
        check("age alone does NOT release a reservation", True)

    # UNKNOWN owner (no worker recorded, or no process table): still closed.
    for label, recorded, table in (("no worker was recorded", None, table_with(None)),
                                   ("the process table is unreadable", worker, unreadable_table)):
        paths = fresh()
        host_gate.grant_reservation(paths, owner, worker=recorded, table_fn=table)
        try:
            host_gate.admit_ordinary(paths, ordinary(6), wait_s=1, table_fn=table)
            check(f"closed when {label}", False, "admitted")
        except ArbiterError:
            check(f"closed when {label}", True)

    # DEAD owner: the next admission decision releases it and admits.
    paths = fresh()
    host_gate.grant_reservation(paths, owner, worker=worker, table_fn=table_with(worker))
    host_gate.activate(paths, owner, {"established": True, "duration_s": 1})
    try:
        host_gate.admit_ordinary(paths, ordinary(7), wait_s=1, table_fn=table_with(None))
    except ArbiterError as exc:
        check("a DEAD owner does not hold the host", False, str(exc))
    gate = host_gate.read_gate(paths)
    check("a DEAD owner's reservation is released", gate["state"] == host_gate.RELEASED
          and "reaper" in gate.get("released_by", ""))
    check("the mirror sees the release too",
          json.loads(paths["mirror_gate"].read_text())["state"] == host_gate.RELEASED)
    check("and ordinary work is admitted behind it", len(host_gate.active_records(paths)) == 1)

    # A recycled pid is not the owner: same pid, different start time.
    paths = fresh()
    host_gate.grant_reservation(paths, owner, worker=worker, table_fn=table_with(worker))
    impostor = fake_worker(worker["pid"], worker["started"] + 3600)
    try:
        host_gate.admit_ordinary(paths, ordinary(8), wait_s=1, table_fn=table_with(impostor))
    except ArbiterError as exc:
        check("a recycled pid is not taken for the owner", False, str(exc))
    check("a recycled pid does not keep a dead owner's reservation",
          host_gate.read_gate(paths)["state"] == host_gate.RELEASED)


# ==========================================================================================
# quiescence
# ==========================================================================================


def test_quiescence() -> None:
    print("\nquiescence adjudication (§8)")
    ncpu = os.cpu_count() or 1

    # The exact reading that was wrongly declared quiet: load1 had decayed, load5/load15
    # had not. The correction exists so that this reading is NOT admitted.
    failed = tuple(v * ncpu / 14 for v in (3.48, 5.73, 5.61))
    result = host_gate.await_quiescence(wait_s=1, loadavg=lambda: failed, sleep=lambda s: None)
    check("the failed run's load is REFUSED as quiescent", not result["established"],
          f"l1/l5/l15={failed}")

    # POISON PILL for the load5/load15 clauses. Re-evaluate that same reading against a
    # load1-only predicate: it PASSES. So those two clauses are what carry the refusal --
    # they are load-bearing, not decorative, and dropping them reinstates the defect.
    load1_only_verdict = failed[0] <= ncpu * host_gate.Q_LOAD1 * 1.30
    check("PILL: a load1-only predicate admits the failed reading",
          load1_only_verdict,
          f"load1 fraction {failed[0] / ncpu:.2f} vs idle floor 0.10 — barely separable")

    quiet = (ncpu * 0.05,) * 3
    result = host_gate.await_quiescence(wait_s=60, loadavg=lambda: quiet, sleep=lambda s: None)
    check("a genuinely quiet host is admitted", result["established"])
    check("admission required consecutive samples",
          len(result["samples"]) >= host_gate.Q_SAMPLES)

    # A single quiet sample among noisy ones must not admit: the counter has to reset.
    # The noisy tail is infinite because `sleep` is stubbed out here -- the loop spins far
    # faster than the wall clock it is bounded by, so a finite fixture runs dry first and
    # the test fails on its own scaffolding rather than on the property.
    noisy = itertools.chain([(ncpu * 0.05,) * 3], itertools.repeat((ncpu * 0.9,) * 3))
    result = host_gate.await_quiescence(wait_s=1, loadavg=lambda: next(noisy),
                                        sleep=lambda s: None)
    check("one quiet sample among noise does not admit", not result["established"])

    # The measured idle floor of dev1 must actually satisfy the policy, or the lane can
    # never run. A threshold below the floor would be a permanently INCONCLUSIVE gate.
    floor = (ncpu * 0.10, ncpu * 0.125, ncpu * 0.113)
    result = host_gate.await_quiescence(wait_s=60, loadavg=lambda: floor, sleep=lambda s: None)
    check("dev1's MEASURED idle floor satisfies the policy", result["established"],
          "thresholds must be reachable on the real host")


# ==========================================================================================
# participation and the cross-kernel mirror
# ==========================================================================================


def test_participation() -> None:
    print("\nparticipation is required, not assumed (§7)")
    check("a hook line is parsed from .env",
          host_gate.hook_from_env_text(
              "LANG=C\nACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/x/hook.sh\n") == "/opt/x/hook.sh")
    check("an .env without the hook yields None",
          host_gate.hook_from_env_text("LANG=C\nPATH=/usr/bin\n") is None)
    result = host_gate.verify_participation(vm_read_env=None, vm_check_exec=None)
    vm_entry = [e for e in result["runners"] if e["name"] == "dev1-linux"][0]
    check("an unreachable VM is NOT counted as participating", not vm_entry["participating"])
    check("every registered runner is evaluated",
          len(result["runners"]) == len(host_gate.REGISTERED_RUNNERS)
          and len(result["runners"]) >= 3)
    check("the VM is one of them", any(e["kernel"] == "linux-vm" for e in result["runners"]))

    # A declared-but-absent hook must not count: the declaration is not the mechanism.
    declared_only = host_gate.verify_participation(
        vm_read_env=lambda p: "ACTIONS_RUNNER_HOOK_JOB_STARTED=/nope/missing.sh\n",
        vm_check_exec=lambda p: False)
    vm_entry = [e for e in declared_only["runners"] if e["name"] == "dev1-linux"][0]
    check("a declared but non-executable hook is not participation",
          not vm_entry["participating"])


def test_drain_refusal_names_the_blocker() -> None:
    """A drain that gives up must say WHICH job held the host, and release it.

    The reservation closes the host to every runner from the moment it is granted, so a
    drain that cannot complete is a fleet-wide outage until it expires. On 2026-09-12 that
    ran most of an hour. Two properties follow, and both are checked here rather than
    assumed: the bound is short enough to be a nuisance instead of an outage, and the
    refusal identifies the blocker so nobody has to go read the arbiter log to find it.
    """
    print("\na drain that gives up names the blocker and releases (blast radius)")
    check("the drain bound is at most 30 minutes", host_gate.DRAIN_WAIT_S <= 30 * 60,
          f"{host_gate.DRAIN_WAIT_S}s")

    paths = fresh()
    blocker = ordinary(7, runner="dev1")
    host_gate.admit_ordinary(paths, blocker, wait_s=1)
    host_gate.grant_reservation(paths, slo())
    try:
        host_gate.await_drain(paths, slo(), lambda: 0, wait_s=2)
        check("the drain refuses when work will not finish", False, "it returned")
    except ArbiterError as exc:
        message = str(exc)
        check("the drain refuses when work will not finish", True)
        check("and the refusal NAMES the blocking runner and job",
              "dev1" in message and blocker.job in message, message[:140])
        check("and says the work was not killed", "NOT killed" in message, message[:140])

    # The owner's job-completed hook is what reopens the host; the refusal must not leave
    # the reservation standing, or the outage outlives the attempt.
    host_gate.job_completed(paths, slo())
    check("the reservation is released so ordinary work resumes",
          host_gate.read_gate(paths)["state"] == host_gate.RELEASED)
    host_gate.admit_ordinary(paths, ordinary(8), wait_s=1)
    check("and a new ordinary job is admitted again", True)


def test_listener_freshness_is_timezone_independent() -> None:
    """Regression control for the false refusal of 2026-09-12 06:08.

    `listener_started_after_env` parsed `ps -o lstart=` with strptime/mktime. `ps` prints
    LOCAL time; `mktime` interprets in the PROCESS's timezone. A hook running inside a
    runner job without TZ set therefore read 21:19 CEST as 21:19 UTC -- two hours early --
    which put the listener before its own .env and reported a correctly-hooked runner as
    NOT participating. The SLO job refused itself.

    The answer must not depend on the caller's clock settings, so it is asked under two
    timezones two hours apart. Anything reading a formatted local timestamp fails this.
    """
    print("\nlistener freshness does not depend on the caller's timezone (regression)")
    runner = "/Users/mats/dev/actions-runner-mcp-re"
    if not Path(runner, ".env").exists():
        check("SKIPPED — this control needs the real runner install", True)
        return

    answers = {}
    for tz in ("UTC", "Europe/Stockholm", "America/Los_Angeles"):
        got = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,%r);import host_gate;"
             "print(host_gate.listener_started_after_env(%r))"
             % (str(Path(__file__).resolve().parent), runner)],
            capture_output=True, text=True, env={**os.environ, "TZ": tz}, timeout=120)
        answers[tz] = got.stdout.strip()

    check("every timezone gives the same answer", len(set(answers.values())) == 1, str(answers))
    check("and that answer is True for a listener started after its .env",
          set(answers.values()) == {"True"}, str(answers))


def test_mirror_is_published_for_the_other_kernel() -> None:
    print("\nthe committed mirror the VM reads (cross-kernel rule)")
    paths = fresh()
    host_gate.grant_reservation(paths, slo())
    check("the mirror exists", paths["mirror_gate"].exists())
    mirrored = json.loads(paths["mirror_gate"].read_text())
    authoritative = json.loads(paths["gate"].read_text())
    check("the mirror matches the authoritative record",
          mirrored["reservation_id"] == authoritative["reservation_id"])
    check("the mirror names the OWNER, not merely a boolean",
          mirrored.get("owner", {}).get("runner") == "dev1-mcp-re")
    check("the reservation carries id, state and creation time",
          all(mirrored.get(k) for k in ("state", "reservation_id", "created_at")))
    check("and stale-recovery information", bool(mirrored.get("stale_recovery")))
    host_gate.job_completed(paths, slo())
    check("release is mirrored too",
          json.loads(paths["mirror_gate"].read_text())["state"] == host_gate.RELEASED)


def test_vm_reported_jobs_block_drain() -> None:
    print("\nthe VM's own report participates in drain")
    paths = fresh()
    host_gate.grant_reservation(paths, slo())
    (paths["vm_active"] / "dev1-linux-77-1-build.json").write_text(json.dumps({
        "key": "dev1-linux-77-1-build",
        "identity": {"runner": "dev1-linux", "job": "build"},
        "started_at": host_gate.now()}))
    records = host_gate.active_records(paths)
    check("a VM-reported job appears in the active set", len(records) == 1)
    check("and is labelled as VM-reported", records[0]["reported_by"] == "vm")
    try:
        host_gate.await_drain(paths, slo(), lambda: 0, wait_s=2)
        check("a VM-reported job blocks the drain", False, "drain succeeded")
    except ArbiterError:
        check("a VM-reported job blocks the drain", True)


# ==========================================================================================
# liveness: records are released by proof of death, never by age
# ==========================================================================================


def test_dead_records_are_reaped() -> None:
    print("\nrecords of jobs that died without their completion hook")
    live, dead = fake_worker(1001), fake_worker(1002)
    both = {live["pid"]: (1, int(time.time()) - live["started"], "x/Runner.Worker")}
    table = lambda: dict(both)  # noqa: E731 -- only `live` is running
    paths = fresh()
    host_gate.admit_ordinary(paths, ordinary(1, "dev1-fast-1"), wait_s=1, worker=live, table_fn=table)
    host_gate.admit_ordinary(paths, ordinary(2, "dev1-fast-2"), wait_s=1, worker=dead, table_fn=table)
    host_gate.admit_ordinary(paths, ordinary(3, "dev1-b"), wait_s=1, worker=None, table_fn=table)
    keys = {r["key"] for r in host_gate.active_records(paths)}
    check("the dead job's record is gone, the live and the unknown remain",
          keys == {ordinary(1, "dev1-fast-1").key, ordinary(3, "dev1-b").key}, str(keys))
    check("the reaped record is kept for inspection",
          (paths["reaped"] / f"{ordinary(2, 'dev1-fast-2').key}.json").exists())

    with host_gate.mutex(paths):
        host_gate.reap_dead_owners(paths, unreadable_table)
    check("an unreadable process table reaps nothing",
          len(host_gate.active_records(paths)) == 2)

    # The drain reaps too, so a dead job cannot hold an SLO drain for its whole budget.
    paths = fresh()
    host_gate.admit_ordinary(paths, ordinary(4, "dev1-fast-1"), wait_s=1, worker=dead, table_fn=table)
    owner = slo()
    host_gate.grant_reservation(paths, owner, table_fn=table)
    try:
        drained = host_gate.await_drain(paths, owner, lambda: 0, wait_s=2, table_fn=table)
        check("a dead job does not hold the SLO drain", drained == [])
    except ArbiterError as exc:
        check("a dead job does not hold the SLO drain", False, str(exc))


def test_heavy_slot() -> None:
    print("\none heavy job on the host at a time; the fast lane is never in it")
    saved = host_gate.HEAVY_RUNNERS
    host_gate.HEAVY_RUNNERS = frozenset({"dev1", "dev1-mcp-re"})
    try:
        a, b = fake_worker(2001), fake_worker(2002)
        table = lambda: {w["pid"]: (1, int(time.time()) - w["started"], "x/Runner.Worker")  # noqa: E731
                         for w in (a, b)}
        paths = fresh()
        code_bazel = ordinary(10, "dev1")
        host_gate.admit_ordinary(paths, code_bazel, wait_s=1, heavy_wait_s=1, worker=a, table_fn=table)
        mcpre = JobIdentity("dev1-mcp-re", MCPRE_REPO, workflow_ref(MCPRE_REPO, CI_WORKFLOW),
                            CI_WORKFLOW, "11", "1", "verification")
        try:
            host_gate.admit_ordinary(paths, mcpre, wait_s=1, heavy_wait_s=1, worker=b, table_fn=table)
            check("a second heavy job waits (and refuses at its bound)", False, "admitted")
        except ArbiterError as exc:
            check("a second heavy job waits (and refuses at its bound)", True)
            check("the refusal names the holder", code_bazel.key in str(exc), str(exc))
        check("a refused waiter leaves no waiting record",
              not list(paths["waiting"].glob("*.json")))

        host_gate.admit_ordinary(paths, ordinary(12, "dev1-fast-1"), wait_s=1, heavy_wait_s=1,
                                 table_fn=table)
        check("the fast lane is admitted while the heavy slot is held",
              len(host_gate.active_records(paths)) == 2)

        host_gate.job_completed(paths, code_bazel)
        host_gate.admit_ordinary(paths, mcpre, wait_s=1, heavy_wait_s=1, worker=b, table_fn=table)
        check("the next heavy job runs once the holder completes",
              mcpre.key in {r["key"] for r in host_gate.active_records(paths)})

        # A holder that dies without its completion hook frees the slot.
        paths = fresh()
        dead = fake_worker(2099)
        host_gate.admit_ordinary(paths, code_bazel, wait_s=1, heavy_wait_s=1, worker=dead,
                                 table_fn=lambda: {})
        host_gate.admit_ordinary(paths, mcpre, wait_s=1, heavy_wait_s=1, worker=b, table_fn=table)
        check("a dead holder does not keep the heavy slot",
              {r["key"] for r in host_gate.active_records(paths)} == {mcpre.key})

        # Oldest waiter first: an older live waiter blocks a newer arrival...
        paths = fresh()
        older = JobIdentity("dev1-mcp-re", MCPRE_REPO, "", CI_WORKFLOW, "20", "1", "verification")
        host_gate.write_atomic(paths["waiting"] / f"{older.key}.json", {
            "key": older.key, "identity": {"runner": "dev1-mcp-re"},
            "since": time.time() - 60, "worker": a})
        try:
            host_gate.admit_ordinary(paths, ordinary(21, "dev1"), wait_s=1, heavy_wait_s=1,
                                     worker=b, table_fn=table)
            check("an older heavy waiter goes first", False, "the newer job was admitted")
        except ArbiterError as exc:
            check("an older heavy waiter goes first", older.key in str(exc), str(exc))
        # ...but a DEAD waiter (a cancelled job) does not block the queue.
        host_gate.write_atomic(paths["waiting"] / f"{older.key}.json", {
            "key": older.key, "identity": {"runner": "dev1-mcp-re"},
            "since": time.time() - 60, "worker": fake_worker(2098)})
        host_gate.admit_ordinary(paths, ordinary(22, "dev1"), wait_s=1, heavy_wait_s=1,
                                 worker=b, table_fn=table)
        check("a dead waiter does not block the queue",
              not list(paths["waiting"].glob("*.json"))
              and len(host_gate.active_records(paths)) == 1)
    finally:
        host_gate.HEAVY_RUNNERS = saved


def test_stopped_participants_are_quiet() -> None:
    print("\na stopped runner or VM is quiet; an unreachable one is not")
    root = "/Users/x/dev/actions-runner-dev1-fast-2"
    running = lambda: {7: (1, 5, f"{root}/bin/Runner.Listener run")}  # noqa: E731
    updated = lambda: {7: (1, 5, f"{root}/bin.2.337.0/Runner.Worker spawnclient")}  # noqa: E731
    other = lambda: {7: (1, 5, f"{root}-other/bin/Runner.Listener run")}  # noqa: E731
    check("a runner with no listener or worker is stopped", host_gate.runner_is_stopped(root, dict))
    check("a running listener is not stopped", not host_gate.runner_is_stopped(root, running))
    check("a worker from an updated bin.<version> dir is not stopped",
          not host_gate.runner_is_stopped(root, updated))
    check("another runner whose path extends this one does not count",
          host_gate.runner_is_stopped(root, other))
    check("an unreadable process table is not 'stopped'",
          not host_gate.runner_is_stopped(root, unreadable_table))

    stopped_vm = host_gate.verify_participation(vm_read_env=None, vm_stopped=True)
    vm_entry = [e for e in stopped_vm["runners"] if e["name"] == "dev1-linux"][0]
    check("a VM Lima reports Stopped participates", vm_entry["participating"])
    unreachable = host_gate.verify_participation(vm_read_env=None, vm_stopped=False)
    vm_entry = [e for e in unreachable["runners"] if e["name"] == "dev1-linux"][0]
    check("a running-but-unreachable VM still does not", not vm_entry["participating"])


def main() -> int:
    print("host-gate controls — temp directories only, no /opt, no runner")
    # The heavy slot serializes dev1 jobs; the older tests admit several at once, so they run
    # with it off, and test_heavy_slot switches it on for itself.
    host_gate.HEAVY_RUNNERS = frozenset()
    for fn in (test_identification, test_reserve_then_drain, test_ordinary_first_then_slo,
               test_second_slo_cannot_overlap, test_simultaneous_admission, test_fail_closed,
               test_completion_releases_on_every_path, test_crash_leaves_closed_not_open,
               test_quiescence, test_participation,
               test_drain_refusal_names_the_blocker,
               test_listener_freshness_is_timezone_independent,
               test_mirror_is_published_for_the_other_kernel,
               test_vm_reported_jobs_block_drain,
               test_capacity_refusal, test_the_hook_consults_the_guard,
               test_dead_records_are_reaped, test_heavy_slot,
               test_stopped_participants_are_quiet):
        fn()
    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 74}\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
