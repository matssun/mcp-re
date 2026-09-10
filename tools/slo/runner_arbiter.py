"""CLI for the physical-host admission gate. See `host_gate` for the protocol and why.

Entry points, in the order the host uses them:

    job-started            ACTIONS_RUNNER_HOOK_JOB_STARTED, every runner application
    assert-exclusive       the clause slo.yml evaluates before stage 4
    job-completed          ACTIONS_RUNNER_HOOK_JOB_COMPLETED, every runner application
    status / dump-env      diagnostics
    recover                operator-only clearing of stale state

Exit codes are the contract with the hooks: a non-zero from `job-started` means the runner
does not execute the job, which is how admission is refused.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_gate  # noqa: E402
import vm_participant  # noqa: E402
from arbiter_error import ArbiterError  # noqa: E402
from job_identity import JobIdentity  # noqa: E402

EXIT_OK, EXIT_REFUSED, EXIT_INCONSISTENT = 0, 1, 3


def vm_workers_or_refuse():
    """The drain loop's VM observation. An unreachable VM refuses; it never reads as idle."""
    def probe() -> int:
        if not vm_participant.available():
            raise ArbiterError(
                "the colima VM hosting dev1-linux is unreachable, so its runner cannot be "
                "observed. Refusing: an unobserved runner is not a quiet runner."
            )
        return vm_participant.worker_count()
    return probe


def vm_readers() -> dict:
    """Participation probes, or None when the VM cannot be reached at all."""
    if not vm_participant.available():
        return {"vm_read_env": None, "vm_check_exec": None, "vm_check_fresh": None}
    return {"vm_read_env": lambda path: vm_participant.read_file(path),
            "vm_check_exec": vm_participant.is_executable,
            "vm_check_fresh": vm_participant.listener_loaded_env}


def cmd_job_started(paths, ident: JobIdentity) -> int:
    if not ident.is_slo:
        host_gate.admit_ordinary(paths, ident)
        return EXIT_OK

    # Owner path: reserve FIRST, so no runner can admit replacement work while we drain.
    host_gate.grant_reservation(paths, ident)

    # Participation is checked before drain: if a runner is not gating itself, draining it
    # proves nothing, because it may accept new work the moment it goes idle.
    participation = host_gate.verify_participation(**vm_readers())
    if not participation["all_participating"]:
        missing = [e for e in participation["runners"] if not e["participating"]]
        names = [e["name"] for e in missing]
        # FALLBACK, not the normal mechanism: a participant that cannot gate itself is
        # stopped instead, and only if it is already idle.
        if names == ["dev1-linux"] and vm_participant.available():
            host_gate.log(paths, "participation.fallback", runner="dev1-linux",
                          detail=missing[0]["detail"])
            proof = vm_participant.inhibit_fallback()
            host_gate.write_atomic(paths["root"] / "vm-inhibition.json", proof)
        else:
            raise ArbiterError(
                f"runner application(s) {names} are not participating in host admission. "
                "Refusing to measure: an unhooked runner is unobserved, not quiet."
            )

    host_gate.await_drain(paths, ident, vm_workers_or_refuse())
    quiescence = host_gate.await_quiescence()
    host_gate.write_atomic(paths["root"] / f"quiescence-{ident.key}.json", quiescence)
    if not quiescence["established"]:
        raise ArbiterError(
            "host did not become quiescent within the bounded wait; refusing to begin a "
            "release-grade measurement on a busy machine. Report INCONCLUSIVE."
        )
    host_gate.activate(paths, ident, quiescence)
    return EXIT_OK


def cmd_assert_exclusive(paths, ident: JobIdentity) -> int:
    """Every clause the closing claim rests on, evaluated and recorded together."""
    problems: list[str] = []
    gate = host_gate.read_gate(paths)

    if gate.get("state") != host_gate.RESERVED:
        problems.append(f"gate state is {gate.get('state')}, not {host_gate.RESERVED}")
    if gate.get("owner", {}).get("key") != ident.key:
        problems.append("this run does not own the reservation")

    others = [r for r in host_gate.active_records(paths) if r.get("key") != ident.key]
    if others:
        problems.append(f"{len(others)} non-owner ACTIVE record(s) remain")

    participation = host_gate.verify_participation(**vm_readers())
    inhibited = (paths["root"] / "vm-inhibition.json").exists()
    if not participation["all_participating"] and not inhibited:
        names = [e["name"] for e in participation["runners"] if not e["participating"]]
        problems.append(f"runner application(s) not participating: {names}")

    macos = host_gate.macos_workers()
    if len(macos) > 1:
        problems.append(f"{len(macos)} macOS Runner.Worker processes observed")

    # The claim is about the PHYSICAL host, so the VM must be observed directly. A macOS
    # pgrep can never stand as proof here -- it cannot see the VM's kernel at all.
    vm_workers = None
    try:
        if vm_participant.available():
            vm_workers = vm_participant.worker_count()
            if vm_workers:
                problems.append(f"{vm_workers} Runner.Worker process(es) live in the VM")
        else:
            problems.append("the VM could not be observed")
    except ArbiterError as exc:
        problems.append(str(exc))

    qpath = paths["root"] / f"quiescence-{ident.key}.json"
    quiescence = json.loads(qpath.read_text()) if qpath.exists() else None
    if not quiescence or not quiescence.get("established"):
        problems.append("quiescence was not established for this reservation")

    verdict = {
        "schema": host_gate.SCHEMA,
        "assertion": "physical-host-exclusive",
        "host": socket.gethostname(),
        "at": host_gate.now(),
        "reservation_id": gate.get("reservation_id"),
        "gate_state": gate.get("state"),
        "reserved_at": gate.get("created_at"),
        "activated_at": gate.get("activated_at"),
        "owner_run_id": gate.get("owner", {}).get("run_id"),
        "non_owner_active": len(others),
        "participation": participation,
        "vm_inhibition_fallback_applied": inhibited,
        "macos_runner_workers": macos,
        "vm_runner_workers": vm_workers,
        "quiescence": quiescence,
        "physical_host_exclusive": not problems,
        "problems": problems,
    }
    host_gate.write_atomic(paths["root"] / f"assertion-{ident.key}.json", verdict)
    print(json.dumps(verdict, indent=2, default=str))
    return EXIT_OK if not problems else EXIT_INCONSISTENT


def cmd_status(paths) -> int:
    reachable = vm_participant.available()
    print(json.dumps({
        "root": str(paths["root"]), "mirror": str(paths["mirror"]),
        "gate": host_gate.read_gate(paths),
        "active": host_gate.active_records(paths),
        "macos_runner_workers": host_gate.macos_workers(),
        "vm_unit_active": vm_participant.unit_active() if reachable else "unreachable",
        "vm_runner_workers": vm_participant.worker_count() if reachable else "unreachable",
        "participation": host_gate.verify_participation(**vm_readers()),
        "loadavg": os.getloadavg(), "ncpu": os.cpu_count(),
    }, indent=2, default=str))
    return EXIT_OK


def cmd_recover(paths, args) -> int:
    if not args.i_verified_no_owner_job_is_running:
        print("refusing: a stale reservation is an operator condition, not a timer's to "
              "clear. Confirm no owner job is live, then pass "
              "--i-verified-no-owner-job-is-running.", file=sys.stderr)
        return EXIT_REFUSED
    live = host_gate.macos_workers()
    if live:
        print(f"refusing: {len(live)} Runner.Worker process(es) still running ({live}). "
              "Clearing now would fail open.", file=sys.stderr)
        return EXIT_REFUSED
    if vm_participant.available() and vm_participant.worker_count() > 0:
        print("refusing: the VM still has a live Runner.Worker.", file=sys.stderr)
        return EXIT_REFUSED
    if args.clear_reservation:
        with host_gate.mutex(paths):
            host_gate.commit(paths, {"schema": host_gate.SCHEMA, "state": host_gate.OPEN,
                                     "recovered_at": host_gate.now()})
        if (paths["root"] / "vm-inhibition.json").exists():
            vm_participant.release_fallback()
            (paths["root"] / "vm-inhibition.json").unlink(missing_ok=True)
        host_gate.log(paths, "recover.reservation_cleared")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="runner-arbiter", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--mirror", type=Path, default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, helptext in (
        ("job-started", "ACTIONS_RUNNER_HOOK_JOB_STARTED entry point"),
        ("job-completed", "ACTIONS_RUNNER_HOOK_JOB_COMPLETED entry point"),
        ("assert-exclusive", "the physical-host exclusivity clause slo.yml evaluates"),
        ("status", "human-readable host state"),
        ("dump-env", "print the hook environment (SLO identification study)"),
    ):
        sub.add_parser(name, help=helptext)
    rec = sub.add_parser("recover", help="operator-only clearing of stale state")
    rec.add_argument("--clear-reservation", action="store_true")
    rec.add_argument("--i-verified-no-owner-job-is-running", action="store_true")

    args = parser.parse_args(argv)
    paths = host_gate.paths(args.root, args.mirror)
    host_gate.ensure_layout(paths)
    ident = JobIdentity.from_env()

    try:
        if args.cmd == "job-started":
            return cmd_job_started(paths, ident)

        if args.cmd == "job-completed":
            result = host_gate.job_completed(paths, ident)
            if result["released_reservation"] and (paths["root"] / "vm-inhibition.json").exists():
                # Only release what we applied. A VM left stopped is a visible, safe
                # condition; a VM left running during a measurement would not be.
                vm_participant.release_fallback()
                (paths["root"] / "vm-inhibition.json").unlink(missing_ok=True)
            return EXIT_OK

        if args.cmd == "assert-exclusive":
            return cmd_assert_exclusive(paths, ident)

        if args.cmd == "status":
            return cmd_status(paths)

        if args.cmd == "dump-env":
            keys = sorted(k for k in os.environ
                          if k.startswith(("GITHUB_", "RUNNER_", "ACTIONS_")))
            print(json.dumps({"env": {k: os.environ[k] for k in keys},
                              "derived": asdict(ident), "is_slo": ident.is_slo}, indent=2))
            return EXIT_OK

        if args.cmd == "recover":
            return cmd_recover(paths, args)

    except ArbiterError as exc:
        print(f"runner-arbiter REFUSED: {exc}", file=sys.stderr)
        host_gate.log(paths, "refused", cmd=args.cmd, reason=str(exc))
        return EXIT_REFUSED

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
