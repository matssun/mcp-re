"""Regression: six concurrent ledger writers must not lose a single finding.

This reproduces the 2026-09-22 incident in which tick 1 of the KMS remediation
run silently destroyed 365 open findings (5915 -> 5550 rows) while every line
still parsed as valid JSONL.

THE TEST CARRIES ITS OWN POSITIVE CONTROL. Per CLAUDE.md, a passing safety test
is worthless until it has been shown capable of failing: `test_positive_control_
legacy_save_loses_rows` runs the ORIGINAL unlocked read-modify-write algorithm
under the same six-writer load and asserts that it DOES lose rows. If that
control ever stops losing rows, this whole module has stopped measuring anything
and the "safe" test below is vacuous.

The control is made deterministic with an explicit barrier rather than left to a
timing race, because a flaky control is indistinguishable from a fixed bug.

Run:  python3 .claude/skills/security-remediate/tests/test_ledger_concurrency.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
LEDGER_PY = os.path.join(SCRIPTS, "ledger.py")
# The security-audit-funnel skill keeps its OWN copy of ledger.py (a separate
# file, not a link) and it carried the identical unlocked `_save`. Fixing one
# copy and not the other would leave the same data-loss defect live behind a
# different entry point, so both are proved here.
FUNNEL_LEDGER_PY = os.path.abspath(os.path.join(
    os.path.dirname(HERE), "..", "security-audit-funnel", "scripts", "ledger.py"))
sys.path.insert(0, SCRIPTS)

from _persist import atomic_write_lines, exclusive, read_jsonl  # noqa: E402

N_WRITERS = 6
N_ROWS = 400


def _seed(path: str) -> list:
    rows = [{"id": "%04x" % i, "file": "f%d.py" % (i % 7), "path": "components/x/f%d.py" % (i % 7),
             "severity": "medium", "category": "conformance", "title": "finding %d" % i,
             "status": "open", "verified": {}, "refs": {}, "notes": ""}
            for i in range(N_ROWS)]
    atomic_write_lines(path, [json.dumps(r, sort_keys=True) for r in rows])
    return rows


def _legacy_save(path: str, by_id: dict) -> None:
    """The ORIGINAL ledger.py::_save — truncate in place, no lock, no temp file."""
    ordered = sorted(by_id.values(), key=lambda e: (e.get("file", ""), e["id"]))
    with open(path, "w") as fh:
        for e in ordered:
            fh.write(json.dumps(e, sort_keys=True) + "\n")


def _legacy_load(path: str) -> dict:
    out = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue          # the original swallowed a torn line, exactly so
            out[e["id"]] = e
    return out


def test_positive_control_legacy_save_loses_rows() -> None:
    """CONTROL: the unlocked algorithm must LOSE rows, proving the probe works.

    The barrier forces the interleaving that happened in production: every writer
    reads the ledger BEFORE any writer stores it, so each one stores a snapshot
    that is missing its siblings' changes. Last store wins; the rest evaporate.
    """
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ledger.jsonl")
        _seed(path)
        gate = threading.Barrier(N_WRITERS)

        def writer(k: int) -> None:
            by_id = _legacy_load(path)          # read
            gate.wait()                         # ... all readers hold a stale snapshot
            by_id["new-%d" % k] = {             # modify: each adds a DISTINCT row
                "id": "new-%d" % k, "file": "z.py", "path": "z.py", "severity": "high",
                "category": "x", "title": "added by writer %d" % k, "status": "open",
                "verified": {}, "refs": {}, "notes": ""}
            _legacy_save(path, by_id)           # write

        threads = [threading.Thread(target=writer, args=(k,)) for k in range(N_WRITERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        survived = {r["id"] for r in read_jsonl(path)}
        added = {"new-%d" % k for k in range(N_WRITERS)}
        lost = added - survived
        assert lost, (
            "POSITIVE CONTROL FAILED: the unlocked algorithm lost nothing, so this "
            "test cannot detect the defect it exists to detect. Do not trust the "
            "safe-path assertion below until this control loses rows again."
        )
        print("  control: unlocked algorithm lost %d of %d concurrent writes  OK"
              % (len(lost), len(added)))


def test_locked_save_loses_nothing() -> None:
    """The fixed primitive: lock spans read->modify->write, so every write lands."""
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ledger.jsonl")
        _seed(path)
        gate = threading.Barrier(N_WRITERS)

        def writer(k: int) -> None:
            gate.wait()                         # maximise contention on the lock
            with exclusive(path):               # <- the whole section, not just the store
                by_id = {r["id"]: r for r in read_jsonl(path)}
                by_id["new-%d" % k] = {
                    "id": "new-%d" % k, "file": "z.py", "path": "z.py", "severity": "high",
                    "category": "x", "title": "added by writer %d" % k, "status": "open",
                    "verified": {}, "refs": {}, "notes": ""}
                atomic_write_lines(path, [json.dumps(v, sort_keys=True)
                                          for v in sorted(by_id.values(), key=lambda e: e["id"])])

        threads = [threading.Thread(target=writer, args=(k,)) for k in range(N_WRITERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        rows = read_jsonl(path)
        ids = {r["id"] for r in rows}
        missing = {"new-%d" % k for k in range(N_WRITERS)} - ids
        assert not missing, "lost concurrent writes: %s" % sorted(missing)
        assert len(rows) == N_ROWS + N_WRITERS, (
            "row count not conserved: %d, expected %d" % (len(rows), N_ROWS + N_WRITERS))
        print("  locked primitive: %d rows, all %d concurrent writes landed  OK"
              % (len(rows), N_WRITERS))


def _cli_concurrency(cli: str, label: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ledger.jsonl")
        _seed(path)
        targets = ["%04x" % i for i in range(N_WRITERS)]

        procs = [subprocess.Popen(
            [sys.executable, cli, "set", path, "--id", fid,
             "--status", "false-positive", "--method", "manual-source",
             "--note", "closed by concurrent writer %s" % fid],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for fid in targets]
        for p in procs:
            out, err = p.communicate(timeout=120)
            assert p.returncode == 0, "%s set failed: %s%s" % (label, out, err)

        rows = read_jsonl(path)
        assert len(rows) == N_ROWS, "row count not conserved: %d != %d" % (len(rows), N_ROWS)
        by_id = {r["id"]: r for r in rows}
        unapplied = [f for f in targets if by_id[f]["status"] != "false-positive"]
        assert not unapplied, (
            "lost-update through %s: %s still open" % (label, unapplied))
        print("  %s: %d rows conserved, all %d concurrent dispositions applied  OK"
              % (label, len(rows), N_WRITERS))


def test_real_ledger_cli_under_six_concurrent_setters() -> None:
    """End-to-end on the REAL `ledger.py set` CLI — the path the agents invoke.

    The unit test above proves the primitive. This proves the primitive is
    actually WIRED IN, which is the failure mode that produced the incident: the
    original code had a perfectly good `_save`, it just was not locked.
    """
    _cli_concurrency(LEDGER_PY, "security-remediate CLI")


def test_funnel_ledger_cli_under_six_concurrent_setters() -> None:
    """The funnel skill's separate copy of the same CLI, same defect, same fix."""
    assert os.path.exists(FUNNEL_LEDGER_PY), FUNNEL_LEDGER_PY
    _cli_concurrency(FUNNEL_LEDGER_PY, "security-audit-funnel CLI")


def test_reader_never_observes_a_partial_ledger() -> None:
    """A concurrent reader sees the whole old file or the whole new one — never half.

    This is the torn-read half of the incident, and it is what made the damage
    invisible: a truncated ledger still parsed, so nothing raised.
    """
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ledger.jsonl")
        _seed(path)
        stop = threading.Event()
        short_reads = []

        def reader() -> None:
            while not stop.is_set():
                try:
                    n = len(read_jsonl(path))
                except (ValueError, FileNotFoundError):
                    short_reads.append("unparseable")
                    continue
                if n not in (N_ROWS, N_ROWS + 1):
                    short_reads.append(n)

        r = threading.Thread(target=reader)
        r.start()
        try:
            for _ in range(40):
                with exclusive(path):
                    by_id = {x["id"]: x for x in read_jsonl(path)}
                    by_id["extra"] = {"id": "extra", "file": "z.py", "path": "z.py",
                                      "severity": "low", "category": "x", "title": "t",
                                      "status": "open", "verified": {}, "refs": {}, "notes": ""}
                    atomic_write_lines(path, [json.dumps(v, sort_keys=True)
                                              for v in by_id.values()])
                with exclusive(path):
                    by_id = {x["id"]: x for x in read_jsonl(path) if x["id"] != "extra"}
                    atomic_write_lines(path, [json.dumps(v, sort_keys=True)
                                              for v in by_id.values()])
        finally:
            stop.set()
            r.join()
        assert not short_reads, "reader observed a partial ledger: %s" % short_reads[:5]
        print("  atomic swap: no partial ledger observed across 80 swaps  OK")


def main() -> int:
    tests = [test_positive_control_legacy_save_loses_rows,
             test_locked_save_loses_nothing,
             test_real_ledger_cli_under_six_concurrent_setters,
             test_funnel_ledger_cli_under_six_concurrent_setters,
             test_reader_never_observes_a_partial_ledger]
    failed = 0
    for t in tests:
        print("%s ..." % t.__name__)
        try:
            t()
        except AssertionError as exc:
            failed += 1
            print("  FAIL: %s" % exc)
    print("\n%d/%d passed" % (len(tests) - failed, len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
