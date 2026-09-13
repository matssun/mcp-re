"""The physical-host admission gate shared by every runner application on dev1.

WHY
===

`slo.yml` asserted that "a self-hosted runner APPLICATION executes one job at a time, so no
other Actions job runs here". Measured false on 2026-09-10. dev1 hosts THREE registered
runner applications which do not compete for jobs -- they compete for the machine:

    dev1         /Users/mats/dev/actions-runner         -> github.com/matssun/code    (macOS)
    dev1-mcp-re  /Users/mats/dev/actions-runner-mcp-re  -> github.com/matssun/mcp-re  (macOS)
    dev1-linux   /home/mats.guest/actions-runner        -> github.com/matssun/code    (colima VM)

Serving different repositories, GitHub schedules all three concurrently. The failed rep ran
at host load 12.43 beside another runner.

THE INVARIANT
=============

    Once a host reservation is granted, no runner on this physical host may admit a NEW
    non-owner job until the reservation is released.

Admission is decided in a pre-job hook, the only place a job can still be refused: it runs
synchronously after GitHub assigns the job and before any step executes. A workflow cannot
refuse work already handed to a runner, which is why this does not live in YAML.

RESERVE FIRST, THEN DRAIN
=========================

The reservation is granted BEFORE the owner looks at who else is active. The reverse order
admits the exact failure being removed, because the queue refills in the gap:

    check quiet -> another runner accepts work -> SLO starts          WRONG

With reserve-first, work already executing drains while NO replacement work is admitted
anywhere on the host.

    OPEN --grant--> RESERVING(owner) --drained+quiescent--> RESERVED(owner) --> RELEASED --> OPEN

The reservation is an OWNED record, never a boolean: a bare "SLO running" flag cannot say
who holds it, cannot tell the owner's own job from a stranger's, and leaves an operator
facing a stuck host with nothing to act on.

TWO KERNELS, ONE AUTHORITY
==========================

`fcntl` is authoritative for state TRANSITIONS, and only on macOS. It is deliberately NOT
stretched across the virtiofs boundary into the VM, where advisory locking is not
dependable -- a lock that silently fails to lock is worse than no lock, because the code
reads as though it were safe.

The VM is therefore an ADMISSION PARTICIPANT, not a lock participant. macOS commits a
decision; the VM reads that committed decision and gates its own execution:

    /opt/verification/runner-arbiter/gate.json   authoritative, macOS only, fcntl-guarded
    ~/.runner-arbiter/gate.json                  committed mirror, atomic-renamed, readable
                                                 from BOTH kernels

Publication is `os.replace`, so a VM reader sees either the previous committed state or the
new one, never a partial write. That is precisely why the reader needs no lock: it does not
participate in the transition, it obeys the outcome.

FAIL-CLOSED, INCLUDING THE PARTICIPATION QUESTION
=================================================

A runner that cannot read the gate must not admit work. And the owner must not MEASURE
unless every registered runner application is known to participate: an unhooked runner is
not a quiet runner, it is an unobserved one. Where participation cannot be confirmed,
stopping that listener remains an acceptable FALLBACK (see `vm_participant`), but it is no
longer the normal mechanism.

Stale reservations are an operator condition. No TTL releases one: a timer that clears a
live reservation is fail-open at the worst possible moment.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arbiter_error import ArbiterError  # noqa: E402
from job_identity import JobIdentity  # noqa: E402

SCHEMA = "mcp-re-host-gate/v1"

OPEN, RESERVING, RESERVED, RELEASED = "OPEN", "RESERVING", "RESERVED", "RELEASED"

# Installed OUTSIDE either runner application directory on purpose: a runner self-update
# rewrites its own tree, and `config.sh remove` deletes it outright.
ROOT = Path(os.environ.get("MCP_RE_ARBITER_ROOT", "/opt/verification/runner-arbiter"))

# The narrowest read path the two kernels share. /opt is not mounted in the VM; /Users is.
MIRROR = Path(os.environ.get("MCP_RE_ARBITER_MIRROR", str(Path.home() / ".runner-arbiter")))

# Runner hooks have no built-in timeout, so an unbounded wait wedges a runner permanently
# with nothing to show an operator. Every wait is bounded; every expiry REFUSES.
ORDINARY_WAIT_S = int(os.environ.get("MCP_RE_ARBITER_ORDINARY_WAIT_S", 45 * 60))

# HOW LONG THE HOST MAY STAY CLOSED WHILE THE OWNER DRAINS.
#
# This is not merely the owner's patience -- it is the blast radius. From the moment the
# reservation is granted, NO new ordinary job is admitted on ANY runner, which is what stops
# the queue refilling while pre-existing work finishes. So the bound is how long one
# already-running job can hold the whole machine closed to CI.
#
# It was 60 minutes, and that was measured to be too generous. On 2026-09-12 a genrule hung
# (see PR #8470) and the reservation sat behind it; the host was closed to every repository
# for the better part of an hour before the bound expired. One stalled job should not cost
# the fleet an hour.
#
# 30 minutes, because the trade is asymmetric: an SLO that gives up is re-dispatched at no
# cost to anyone, while a closed host blocks every other PR on the machine. A legitimate
# ordinary job longer than this simply means the benchmark retries later, which is the
# cheaper failure.
DRAIN_WAIT_S = int(os.environ.get("MCP_RE_ARBITER_DRAIN_WAIT_S", 30 * 60))
POLL_S = float(os.environ.get("MCP_RE_ARBITER_POLL_S", 5))

#: How often the drain re-announces what it is waiting on. It used to say so ONCE, so a
#: stalled drain looked identical to a fast one from the outside and the operator had to go
#: read the arbiter log to find out which job was holding the host.
DRAIN_ANNOUNCE_S = float(os.environ.get("MCP_RE_ARBITER_DRAIN_ANNOUNCE_S", 60))

# Quiescence. The old rule read load1 once. The failed run shows why one instantaneous
# sample cannot carry a release-grade claim:  1m=3.48 "quiet",  5m=5.73,  15m=5.61 --
# load1 had decayed while the box still worked through another runner's job. load5/load15
# hold that memory, so all three are read and the condition must HOLD across samples.
#
# THRESHOLDS ARE MEASURED, NOT PICKED. From 63 samples over 10.3 min on dev1 (14 CPUs),
# and from the failed run, as fractions of CPU count:
#
#                       load1   load5   load15
#     dev1 at rest      0.10    0.125   0.11     <- floor: 3 runner listeners + 2 colima VMs
#     dev1 at-rest max  0.23    0.17    0.14
#     THE FAILED RUN    0.25    0.41    0.40
#     threshold here    0.20    0.25    0.30
#
# Read the load1 column: the failed run's load1 was 0.25 against a floor of 0.10 and an
# ordinary at-rest peak of 0.23. load1 BARELY separates the failure from an idle box, which
# is exactly how a one-sample load1 rule declared that host quiet. load5 and load15 are the
# clauses doing the discriminating -- they exceed their thresholds by 64% and 33% -- so the
# policy is load5/load15 first and load1 only as a fast-moving corroborator.
#
# Consecutive sampling is the other half. dev1's load1 touches 0.23 at rest under ordinary
# background activity, so any single sample is noisy; requiring Q_SAMPLES consecutive quiet
# observations means ~60s of SUSTAINED quiet, which no transient satisfies.
Q_LOAD1 = float(os.environ.get("MCP_RE_ARBITER_Q_LOAD1", 0.20))
Q_LOAD5 = float(os.environ.get("MCP_RE_ARBITER_Q_LOAD5", 0.25))
Q_LOAD15 = float(os.environ.get("MCP_RE_ARBITER_Q_LOAD15", 0.30))
Q_SAMPLES = int(os.environ.get("MCP_RE_ARBITER_Q_SAMPLES", 6))
Q_INTERVAL_S = float(os.environ.get("MCP_RE_ARBITER_Q_INTERVAL_S", 10))
Q_WAIT_S = int(os.environ.get("MCP_RE_ARBITER_Q_WAIT_S", 20 * 60))

# Every runner application sharing this physical host. The owner refuses to measure unless
# each is confirmed to participate in admission.
REGISTERED_RUNNERS = (
    {"name": "dev1", "kernel": "darwin", "root": "/Users/mats/dev/actions-runner"},
    {"name": "dev1-mcp-re", "kernel": "darwin", "root": "/Users/mats/dev/actions-runner-mcp-re"},
    {"name": "dev1-linux", "kernel": "linux-vm",
     "root": os.environ.get("MCP_RE_ARBITER_VM_RUNNER_HOME", "/home/mats.guest/actions-runner")},
)


# ==========================================================================================
# layout
# ==========================================================================================


def paths(root: Path | None = None, mirror: Path | None = None) -> dict[str, Path]:
    r = Path(root or ROOT)
    m = Path(mirror or MIRROR)
    return {
        "root": r, "mirror": m,
        "lock": r / "lock", "gate": r / "gate.json", "active": r / "active",
        "log": r / "arbiter.log", "mirror_gate": m / "gate.json",
        "vm_active": m / "vm-active",
    }


def ensure_layout(p: dict[str, Path]) -> None:
    p["active"].mkdir(parents=True, exist_ok=True)
    p["vm_active"].mkdir(parents=True, exist_ok=True)
    if not p["lock"].exists():
        p["lock"].touch()


def log(p: dict[str, Path], event: str, **fields: object) -> None:
    rec = {"t": time.time(), "iso": now(), "event": event, **fields}
    try:
        with p["log"].open("a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
    except OSError:
        pass
    print(f"[host-gate] {event} {json.dumps(fields, default=str)}", file=sys.stderr)


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ==========================================================================================
# the mutex -- guards TRANSITIONS only
# ==========================================================================================


@contextmanager
def mutex(p: dict[str, Path]):
    """Short-lived exclusive lock around one state transition.

    `fcntl.flock`, not a create-if-absent test, because

        if not path.exists(): path.write(...)

    leaves a window in which a second process passes the same test -- the very race this
    exists to close. Held only across a transition, never across a wait: a hook that slept
    holding this would deadlock every other hook on the host.
    """
    fh = p["lock"].open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def write_atomic(path: Path, payload: dict) -> None:
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))
    os.replace(tmp, path)


def commit(p: dict[str, Path], gate: dict) -> None:
    """Publish the authoritative record, then mirror it for the other kernel."""
    write_atomic(p["gate"], gate)
    try:
        p["mirror"].mkdir(parents=True, exist_ok=True)
        write_atomic(p["mirror_gate"], gate)
    except OSError as exc:
        # A mirror we cannot publish means the VM cannot learn the decision, so the host is
        # not reservable. Surfaced rather than swallowed.
        raise ArbiterError(f"could not publish the committed gate mirror: {exc}") from exc


# ==========================================================================================
# reading
# ==========================================================================================


def read_gate(p: dict[str, Path]) -> dict:
    try:
        raw = p["gate"].read_text()
    except FileNotFoundError:
        return {"schema": SCHEMA, "state": OPEN}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        # A corrupt gate is NOT "open". Treating an unreadable record as absence is the
        # fail-open case, and it would fire exactly when the host is already in trouble.
        raise ArbiterError(
            f"gate.json is unreadable ({exc}); refusing rather than assuming the host is "
            "free. Inspect it, then use `recover` once no owner job is live."
        ) from exc


def active_records(p: dict[str, Path]) -> list[dict]:
    """macOS ACTIVE records plus whatever the VM reported about itself.

    The VM's self-report is a convenience for diagnostics, never the proof: a report that
    depends on the participant it describes cannot establish that participant is idle.
    `vm_participant.worker_count()` observes the real processes instead.
    """
    out: list[dict] = []
    for d, src in ((p["active"], "macos"), (p["vm_active"], "vm")):
        for f in sorted(d.glob("*.json")):
            try:
                rec = json.loads(f.read_text())
            except (OSError, json.JSONDecodeError):
                rec = {"key": f.stem, "corrupt": True}
            rec["reported_by"] = src
            out.append(rec)
    return out


# ==========================================================================================
# ordinary admission
# ==========================================================================================


def admit_ordinary(p: dict[str, Path], ident: JobIdentity, wait_s: int = ORDINARY_WAIT_S) -> None:
    """Admit an ordinary job, or refuse. Blocks while a non-owner reservation stands."""
    deadline = time.monotonic() + wait_s
    announced = False
    gate: dict = {}
    while True:
        with mutex(p):
            gate = read_gate(p)
            state = gate.get("state", OPEN)
            owner = gate.get("owner", {})
            if owner.get("key") == ident.key:
                log(p, "ordinary.is_owner", key=ident.key)
                return
            if state in (OPEN, RELEASED):
                write_atomic(p["active"] / f"{ident.key}.json", {
                    "schema": SCHEMA, "kind": "active", "key": ident.key,
                    "identity": asdict(ident), "pid": os.getpid(), "started_at": now(),
                })
                log(p, "ordinary.admitted", key=ident.key, waited=announced)
                return
        if time.monotonic() >= deadline:
            raise ArbiterError(
                f"refusing admission: host reservation {gate.get('reservation_id')} held by "
                f"runner {gate.get('owner', {}).get('runner')} run "
                f"{gate.get('owner', {}).get('run_id')} did not release within {wait_s}s. "
                "Fail-closed: this job executed no workload."
            )
        if not announced:
            log(p, "ordinary.waiting", key=ident.key, reservation=gate.get("reservation_id"))
            announced = True
        time.sleep(POLL_S)


def job_completed(p: dict[str, Path], ident: JobIdentity) -> dict:
    """Release whatever this job held: success, failure and cancellation alike."""
    removed_active = False
    released = False
    with mutex(p):
        try:
            (p["active"] / f"{ident.key}.json").unlink()
            removed_active = True
        except FileNotFoundError:
            pass
        try:
            gate = read_gate(p)
        except ArbiterError:
            gate = {}
        if gate.get("owner", {}).get("key") == ident.key:
            commit(p, {**gate, "state": RELEASED, "released_at": now()})
            released = True
    log(p, "job.completed", key=ident.key,
        removed_active=removed_active, released_reservation=released)
    return {"removed_active": removed_active, "released_reservation": released}


# ==========================================================================================
# owner admission
# ==========================================================================================


def grant_reservation(p: dict[str, Path], ident: JobIdentity) -> dict:
    """Atomically move OPEN -> RESERVING(owner). Nothing else is admitted after this."""
    with mutex(p):
        gate = read_gate(p)
        state = gate.get("state", OPEN)
        if state in (RESERVING, RESERVED):
            owner = gate.get("owner", {})
            if owner.get("key") != ident.key:
                raise ArbiterError(
                    f"host already reserved ({gate.get('reservation_id')}) by run "
                    f"{owner.get('run_id')} on {owner.get('runner')}; two SLO measurements "
                    "may not overlap."
                )
            return gate
        granted = {
            "schema": SCHEMA,
            "state": RESERVING,
            "reservation_id": str(uuid.uuid4()),
            "owner": {"key": ident.key, **asdict(ident)},
            "host": socket.gethostname(),
            "created_at": now(),
            "activated_at": None,
            "released_at": None,
            "pid": os.getpid(),
            "stale_recovery": {
                "policy": "operator-only",
                "note": "No TTL releases this reservation. If the owning runner dies before "
                        "its completion hook runs, this record persists and the host stays "
                        "closed until an operator runs `runner-arbiter recover`, which "
                        "itself refuses while any Runner.Worker lives. A stuck host is a "
                        "visible, safe condition; an auto-released reservation is a silent, "
                        "unsafe one.",
                "recover_command": "runner-arbiter recover --clear-reservation "
                                   "--i-verified-no-owner-job-is-running",
            },
        }
        commit(p, granted)
        log(p, "gate.reserved", reservation_id=granted["reservation_id"], owner=ident.key)
        return granted


def await_drain(p: dict[str, Path], ident: JobIdentity, vm_workers,
                wait_s: int = DRAIN_WAIT_S) -> list[dict]:
    """Let already-running work finish. No replacement work can be admitted meanwhile.

    `vm_workers` is a callable returning the VM's live worker count, injected so this stays
    testable without a VM and so the VM observation is explicit rather than hidden here.
    """
    started = time.monotonic()
    deadline = started + wait_s
    announced: list[dict] = []
    last_announce = 0.0
    while True:
        others = [r for r in active_records(p) if r.get("key") != ident.key]
        vm_n = vm_workers()
        if not others and vm_n == 0:
            log(p, "gate.drained", drained=announced)
            return announced

        waiting_on = [{"key": r.get("key"),
                       "runner": r.get("identity", {}).get("runner"),
                       "job": r.get("identity", {}).get("job"),
                       "reported_by": r.get("reported_by")} for r in others]
        if not announced:
            announced = waiting_on

        if time.monotonic() >= deadline:
            # Name the blocker. A refusal that says only "did not drain" sends the operator
            # to the arbiter log to discover WHICH job held the host, which is a step they
            # should not have to take while CI is blocked.
            blockers = ", ".join(
                f"{w['runner']}:{w['job']}" for w in waiting_on) or f"{vm_n} VM worker(s)"
            raise ArbiterError(
                f"pre-existing work did not drain within {wait_s}s and the host reservation "
                f"is being released so ordinary work can resume. Still running: {blockers} "
                f"(non-owner active={len(others)}, vm workers={vm_n}). The benchmark was NOT "
                f"measured beside it, and that work was NOT killed — re-dispatch the SLO when "
                f"the host is quieter."
            )

        # Re-announce periodically. Said once, a stalled drain is indistinguishable from a
        # fast one until somebody reads the log.
        elapsed = time.monotonic() - started
        if elapsed - last_announce >= DRAIN_ANNOUNCE_S or last_announce == 0.0:
            log(p, "gate.draining", waited_s=int(elapsed), budget_s=wait_s,
                waiting_on=waiting_on, vm_workers=vm_n)
            last_announce = elapsed
        time.sleep(POLL_S)


def activate(p: dict[str, Path], ident: JobIdentity, quiescence: dict) -> dict:
    """RESERVING -> RESERVED. The owner may now measure."""
    with mutex(p):
        gate = read_gate(p)
        if gate.get("owner", {}).get("key") != ident.key:
            raise ArbiterError("cannot activate a reservation this job does not own")
        activated = {**gate, "state": RESERVED, "activated_at": now(),
                     "quiescence": {"established": quiescence.get("established"),
                                    "duration_s": quiescence.get("duration_s")}}
        commit(p, activated)
        log(p, "gate.activated", reservation_id=activated.get("reservation_id"))
        return activated


# ==========================================================================================
# quiescence
# ==========================================================================================


def await_quiescence(wait_s: int = Q_WAIT_S, loadavg=os.getloadavg, sleep=time.sleep) -> dict:
    ncpu = os.cpu_count() or 1
    t1, t5, t15 = ncpu * Q_LOAD1, ncpu * Q_LOAD5, ncpu * Q_LOAD15
    deadline = time.monotonic() + wait_s
    started = time.monotonic()
    samples: list[dict] = []
    consecutive = 0
    while True:
        l1, l5, l15 = loadavg()
        quiet = l1 <= t1 and l5 <= t5 and l15 <= t15
        samples.append({"at": now(), "l1": round(l1, 2), "l5": round(l5, 2),
                        "l15": round(l15, 2), "quiet": quiet})
        consecutive = consecutive + 1 if quiet else 0
        base = {"ncpu": ncpu, "thresholds": {"load1": t1, "load5": t5, "load15": t15},
                "consecutive_required": Q_SAMPLES,
                "duration_s": round(time.monotonic() - started, 1)}
        if consecutive >= Q_SAMPLES:
            return {"established": True, **base, "samples": samples}
        if time.monotonic() >= deadline:
            return {"established": False, **base, "samples": samples[-24:]}
        sleep(Q_INTERVAL_S)


# ==========================================================================================
# participation -- an unhooked runner is unobserved, not quiet
# ==========================================================================================


def hook_from_env_text(text: str) -> str | None:
    for line in text.splitlines():
        if line.strip().startswith("ACTIONS_RUNNER_HOOK_JOB_STARTED="):
            return line.split("=", 1)[1].strip()
    return None


def listener_started_after_env(runner_root: str) -> bool | None:
    """Has the RUNNING listener actually loaded the current .env?

    Declaring the hook is not the same as enforcing it. A runner reads `.env` once, at
    listener startup, so a listener older than the file is running WITHOUT the hook while
    the file on disk says otherwise -- the precise shape of a fail-open: a config that
    reads as safe and a process that is not. Measured on dev1 2026-09-10, where the hook
    was written at 21:18 and the listener had been up since Sep 3.

    None means "cannot tell", which callers must treat as not-participating rather than as
    participating.
    """
    try:
        env_mtime = Path(runner_root, ".env").stat().st_mtime
    except OSError:
        return None
    try:
        found = subprocess.run(["pgrep", "-f", f"{runner_root}/bin/Runner.Listener"],
                               capture_output=True, text=True)
    except OSError:
        return None
    pids = [p for p in found.stdout.split() if p.strip().isdigit()]
    if not pids:
        return None
    # ELAPSED time, not a formatted start date.
    #
    # This read `ps -o lstart=` and parsed it with `time.strptime` + `time.mktime`. That
    # was wrong in a way that only appeared inside a runner job: `ps` prints the start in
    # LOCAL time while `mktime` interprets it in the PROCESS's timezone, so a hook running
    # without TZ set resolved 21:19 CEST as 21:19 UTC -- two hours early, which put the
    # listener before the 21:18 .env and reported a correctly-hooked runner as not
    # participating. It refused a real SLO run on 2026-09-12 at 06:08.
    #
    # `etime` is elapsed seconds since start. It has no timezone, no locale-dependent month
    # name and no date format, so the class of bug cannot recur here.
    try:
        elapsed = subprocess.run(["ps", "-o", "etime=", "-p", pids[0]],
                                 capture_output=True, text=True).stdout.strip()
        if not elapsed:
            return None
        days, _, clock = elapsed.rpartition("-") if "-" in elapsed else ("", "", elapsed)
        units = [int(x) for x in clock.split(":")]
        seconds = (int(days) * 86400 if days else 0) + sum(
            value * scale for value, scale in zip(reversed(units), (1, 60, 3600)))
    except (OSError, ValueError):
        return None
    return (time.time() - seconds) >= env_mtime


def verify_participation(vm_read_env=None, vm_check_exec=None,
                         vm_check_fresh=None) -> dict:
    """Confirm every registered runner consults this gate before admitting work."""
    results = []
    for r in REGISTERED_RUNNERS:
        entry = {"name": r["name"], "kernel": r["kernel"], "participating": False,
                 "hook": None, "detail": ""}
        try:
            if r["kernel"] == "darwin":
                hook = hook_from_env_text(Path(r["root"], ".env").read_text())
                entry["hook"] = hook

                # DIRECT EVIDENCE beats inference. If this code is executing, it was
                # launched BY a runner's job-started hook -- so for THAT runner, the
                # question "has the listener loaded the hook configuration?" is already
                # answered in the affirmative by our own existence. Asking a timestamp
                # heuristic instead is strictly weaker and was observed to disagree: the
                # SLO job on dev1-mcp-re refused itself while running from dev1-mcp-re's
                # own hook, which is a contradiction the heuristic cannot represent.
                if (os.environ.get("RUNNER_NAME") == r["name"]
                        and os.environ.get("ACTIONS_RUNNER_HOOK_JOB_STARTED")):
                    entry["participating"] = True
                    entry["listener_loaded_env"] = True
                    entry["detail"] = "proven directly: this check is running from its hook"
                    results.append(entry)
                    continue

                fresh = listener_started_after_env(r["root"])
                entry["listener_loaded_env"] = fresh
                if not (hook and Path(hook).exists()):
                    entry["detail"] = "no ACTIONS_RUNNER_HOOK_JOB_STARTED, or hook absent"
                elif fresh is None:
                    entry["detail"] = "no running listener found, or its start time is unreadable"
                elif not fresh:
                    entry["detail"] = ("the hook is declared but this listener predates the "
                                       ".env that declares it — restart required before the "
                                       "hook is in force")
                else:
                    entry["participating"] = True
            else:
                if vm_read_env is None:
                    entry["detail"] = "VM unreachable"
                else:
                    hook = hook_from_env_text(vm_read_env(f"{r['root']}/.env"))
                    entry["hook"] = hook
                    fresh = vm_check_fresh() if vm_check_fresh else None
                    entry["listener_loaded_env"] = fresh
                    if not hook:
                        entry["detail"] = "no ACTIONS_RUNNER_HOOK_JOB_STARTED in the VM .env"
                    elif not (vm_check_exec and vm_check_exec(hook)):
                        entry["detail"] = "hook declared but not executable in the VM"
                    elif fresh is None:
                        entry["detail"] = "could not establish when the VM listener started"
                    elif not fresh:
                        entry["detail"] = ("the VM listener predates the .env declaring the "
                                           "hook — restart required before it is in force")
                    else:
                        entry["participating"] = True
        except OSError as exc:
            entry["detail"] = str(exc)
        results.append(entry)
    return {"all_participating": all(e["participating"] for e in results), "runners": results}


def macos_workers() -> list[int]:
    """Independent fail-safe, NOT the lock.

    Catches a broken hook install, a missing ACTIVE record, or an unknown fourth runner.
    Never sufficient on its own: it cannot see the VM's kernel, so it can never establish
    that the PHYSICAL host is exclusive.
    """
    try:
        r = subprocess.run(["pgrep", "-f", "Runner.Worker"], capture_output=True, text=True)
    except OSError:
        return []
    return [int(x) for x in r.stdout.split() if x.strip().isdigit()]
