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


def test_crash_leaves_closed_not_open() -> None:
    print("\nrunner crash / missing completion hook (§6)")
    paths = fresh()
    owner = slo()
    host_gate.grant_reservation(paths, owner)
    host_gate.activate(paths, owner, {"established": True, "duration_s": 1})
    # Simulate the completion hook never running: the record simply persists.
    gate = host_gate.read_gate(paths)
    check("the reservation survives a crash", gate["state"] == host_gate.RESERVED)
    try:
        host_gate.admit_ordinary(paths, ordinary(4), wait_s=1)
        check("the host stays CLOSED after a crash", False, "admitted")
    except ArbiterError:
        check("the host stays CLOSED after a crash", True)
    check("the record carries operator recovery instructions",
          "recover" in json.dumps(gate.get("stale_recovery", {})))

    # No elapsed time releases it. A TTL here would be fail-open at the worst moment.
    host_gate.write_atomic(paths["gate"], {**gate, "created_at": "2000-01-01T00:00:00Z"})
    try:
        host_gate.admit_ordinary(paths, ordinary(5), wait_s=1)
        check("age alone does NOT release a reservation", False, "an old reservation opened")
    except ArbiterError:
        check("age alone does NOT release a reservation", True)


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
    check("all three registered runners are evaluated", len(result["runners"]) == 3)
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


def main() -> int:
    print("host-gate controls — temp directories only, no /opt, no runner")
    for fn in (test_identification, test_reserve_then_drain, test_ordinary_first_then_slo,
               test_second_slo_cannot_overlap, test_simultaneous_admission, test_fail_closed,
               test_completion_releases_on_every_path, test_crash_leaves_closed_not_open,
               test_quiescence, test_participation,
               test_drain_refusal_names_the_blocker,
               test_listener_freshness_is_timezone_independent,
               test_mirror_is_published_for_the_other_kernel,
               test_vm_reported_jobs_block_drain):
        fn()
    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 74}\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
