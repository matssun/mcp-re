"""Regression: the reducer is deterministic, and every check it makes can fire.

The ruling required two proofs of the reducer: replay twice and get identical
derived state, and show that baseline-clean results are not vacuous.

The second is the one that matters. `problems: []` and `status_disagreements: []`
read as "everything is fine" and read IDENTICALLY to "this check is incapable of
detecting anything". CLAUDE.md is explicit that a probe finding nothing
everywhere has not been shown capable of finding anything, so every negative
assertion below is paired with a positive control that injects the exact defect
and asserts the reducer names it.

Controls here:
  ledger cross-check    -> flip one ledger status, expect a disagreement
  ledger population     -> delete a ledger row, expect closure-absent-from-ledger
  sequence integrity    -> remove one event, expect the seq gap named
  counts-as-checksum    -> assert a closed count that the identities contradict

Run:  python3 .claude/skills/security-remediate/tests/test_reduce_determinism.py
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)

from _persist import atomic_write_lines, read_jsonl  # noqa: E402
import reduce  # noqa: E402
from reduce import reduce_journal  # noqa: E402

RUN = "test-run"


def _event(seq, **kw):
    rec = {"schema_version": 1, "seq": seq, "event_id": "evt-%04d" % seq,
           "run_id": RUN, "ts": "2026-09-22T10:%02d:00Z" % seq,
           "role": "evaluator", "file": "a/b/c.py", "tier": "senior",
           "model": "opus", "note": "n"}
    rec.update(kw)
    return rec


def _fixture(td, *, drop_seq=None, closed_assertion=2):
    """One attempt: evaluate (asserting 2 closures) + 2 closes + terminal."""
    log = os.path.join(td, "progress")
    ledger = os.path.join(td, "ledger.jsonl")
    events = [
        _event(1, event="evaluate", attempt_id="att-1",
               counts={"closed": closed_assertion, "escalated": 1, "work": 0},
               counts_kind="attempt_snapshot", escalation_ids=["esc-a"]),
        _event(2, event="close", attempt_id="att-1", finding_id="f001", id="f001",
               status="false-positive", severity="high"),
        _event(3, event="close", attempt_id="att-1", finding_id="f002", id="f002",
               status="duplicate", severity="medium", duplicate_of="f001",
               cluster_id="claim-x"),
        _event(4, event="no-code-change", attempt_id="att-1",
               counts={"closed": closed_assertion, "escalated": 1, "work": 0},
               counts_kind="attempt_snapshot"),
    ]
    if drop_seq is not None:
        events = [e for e in events if e["seq"] != drop_seq]
    atomic_write_lines(log + ".jsonl", [json.dumps(e, sort_keys=True) for e in events])

    rows = [
        {"id": "f001", "file": "c.py", "path": "a/b/c.py", "severity": "high",
         "status": "false-positive", "title": "t1"},
        {"id": "f002", "file": "c.py", "path": "a/b/c.py", "severity": "medium",
         "status": "duplicate", "title": "t2"},
        {"id": "f003", "file": "c.py", "path": "a/b/c.py", "severity": "critical",
         "status": "escalated", "title": "t3", "ruling_id": "ADR-ZT-FND-012"},
    ]
    atomic_write_lines(ledger, [json.dumps(r, sort_keys=True) for r in rows])
    return log, ledger


def test_replay_twice_is_identical() -> None:
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _fixture(td)
        a_state, a_att = reduce_journal(log, ledger)
        b_state, b_att = reduce_journal(log, ledger)
        a = json.dumps(a_state, sort_keys=True, indent=1)
        b = json.dumps(b_state, sort_keys=True, indent=1)
        assert a == b, "derived state is not byte-identical across replays"
        assert json.dumps(a_att, sort_keys=True) == json.dumps(b_att, sort_keys=True)
        assert a_state["problems"] == [], a_state["problems"]
        print("  determinism: two replays byte-identical (%d bytes)  OK" % len(a))


def test_clusters_collapse_observations_onto_defects() -> None:
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _fixture(td)
        state, _ = reduce_journal(log, ledger)
        t = state["totals"]
        assert t["finding_observations"] == 2, t
        assert t["duplicate_observations"] == 1, t
        # EXACTLY one defect. The earlier form of this assertion was
        # `unique < observations + 1`, which is true even when nothing collapses
        # at all -- a derived-quantity assertion that let a real bug through.
        # Name the number the mechanism must produce, not a range containing it.
        assert t["unique_defect_clusters"] == 1, (
            "f002 duplicates f001, so two observations must collapse to ONE defect; "
            "got %d" % t["unique_defect_clusters"])
        assert sorted(next(iter(state["clusters"].values()))) == ["f001", "f002"], \
            state["clusters"]
        print("  clustering: %d observations -> %d unique defect cluster(s)  OK"
              % (t["finding_observations"], t["unique_defect_clusters"]))


def test_ledger_escalations_are_enumerable_by_ruling() -> None:
    """The gap that motivated this: WHICH escalations, not how many."""
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _fixture(td)
        _, att = reduce_journal(log, ledger)
        by_ruling = att["UNRESOLVED_ESCALATIONS_BY_RULING"]
        assert by_ruling.get("ADR-ZT-FND-012") == ["f003"], by_ruling
        assert att["UNRESOLVED_ESCALATIONS_TOTAL"] == 1, att
        assert att["UNRESOLVED_ESCALATIONS_BY_SEVERITY"] == {"critical": 1}, att
        print("  escalations: grouped by ruling, enumerable by id  OK")


def test_control_ledger_status_disagreement_is_detected() -> None:
    """CONTROL: flip a ledger status; the cross-check must name it."""
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _fixture(td)
        rows = read_jsonl(ledger)
        for r in rows:
            if r["id"] == "f001":
                r["status"] = "open"          # journal says false-positive
        atomic_write_lines(ledger, [json.dumps(r, sort_keys=True) for r in rows])

        state, att = reduce_journal(log, ledger)
        kinds = {p["kind"] for p in state["problems"]}
        assert "ledger-journal-status-disagreement" in kinds, (
            "CONTROL FAILED: the cross-check did not notice a flipped status, so its "
            "clean report on the real run proves nothing")
        d = state["ledger_check"]["status_disagreements"]
        assert d and d[0]["finding_id"] == "f001", d
        assert att["INTEGRITY_PROBLEMS"], "attention.json hid the problem"
        print("  control: flipped ledger status detected (%s: %s vs %s)  OK"
              % (d[0]["finding_id"], d[0]["journal"], d[0]["ledger"]))


def test_control_lost_ledger_row_is_detected() -> None:
    """CONTROL for the 365-row incident: a closure whose ledger row vanished."""
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _fixture(td)
        rows = [r for r in read_jsonl(ledger) if r["id"] != "f002"]
        atomic_write_lines(ledger, [json.dumps(r, sort_keys=True) for r in rows])

        state, _ = reduce_journal(log, ledger)
        kinds = {p["kind"] for p in state["problems"]}
        assert "closure-absent-from-ledger" in kinds, (
            "CONTROL FAILED: a deleted ledger row was not detected — this is exactly "
            "the 2026-09-22 loss and the reducer must catch it")
        assert state["ledger_check"]["absent_from_ledger"] == ["f002"]
        print("  control: vanished ledger row detected (f002)  OK")


def test_control_sequence_gap_is_detected() -> None:
    """CONTROL: remove one event; the seq gap must be named."""
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _fixture(td, drop_seq=3)
        state, att = reduce_journal(log, ledger)
        assert state["sequence_gaps"] == [3], state["sequence_gaps"]
        kinds = {p["kind"] for p in state["problems"]}
        assert "missing-events" in kinds, (
            "CONTROL FAILED: a missing event left no trace, so `seq` is decorative")
        assert att["SEQUENCE_GAPS"] == [3]
        print("  control: missing event detected as seq gap [3]  OK")


def test_control_counts_assertion_mismatch_is_detected() -> None:
    """CONTROL: counts are a checksum, so a false assertion must be reported."""
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _fixture(td, closed_assertion=7)   # identities say 2
        state, _ = reduce_journal(log, ledger)
        kinds = {p["kind"] for p in state["problems"]}
        assert "counts-assertion-mismatch" in kinds, (
            "CONTROL FAILED: a false `closed` assertion was accepted, so counts are "
            "being trusted as state rather than checked as a claim")
        mm = state["attempts"]["att-1"]["counts_mismatch"]
        assert mm["closed"] == {"asserted": 7, "derived": 2}, mm
        print("  control: false counts assertion detected (asserted 7, derived 2)  OK")


def test_counts_snapshots_are_not_double_counted() -> None:
    """`evaluate` and the terminal event repeat the same tally — sum would be 4."""
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _fixture(td)
        state, _ = reduce_journal(log, ledger)
        a = state["attempts"]["att-1"]
        assert a["asserted_counts"]["closed"] == 2, a["asserted_counts"]
        assert a["derived"]["closed"] == 2, a["derived"]
        assert not a["counts_mismatch"], a["counts_mismatch"]
        print("  snapshots: repeated tally not summed (2, not 4)  OK")


def test_an_early_close_completed_by_review_is_classified_separately() -> None:
    """`gate-failed` then `review` is a SUPERSEDED close, not a contradiction.

    Three tick-2 attempts were closed `gate-failed` by a worker acting under a
    contract that was then corrected, and were afterwards genuinely reviewed.
    That is real history and must stay in the record — but reporting it as a
    generic integrity problem leaves a permanent unresolved entry, and a report
    that never clears is one people stop reading.
    """
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "progress")
        events = [
            _event(1, event="evaluate", attempt_id="att-1", counts={"work": 1},
                   counts_kind="attempt_snapshot"),
            _event(2, event="gate-failed", attempt_id="att-1", counts={"exit": 1}),
            _event(3, event="review", attempt_id="att-1"),
        ]
        atomic_write_lines(log + ".jsonl", [json.dumps(e, sort_keys=True) for e in events])
        state, _ = reduce_journal(log)
        kinds = {p["kind"] for p in state["problems"]}
        assert "terminal-superseded" in kinds, state["problems"]
        assert "multiple-terminal-events" not in kinds, state["problems"]
        a = state["attempts"]["att-1"]
        assert a["terminal"] == "review", a["terminal"]
        assert a["superseded_terminals"] == ["gate-failed"], a
        print("  superseded: gate-failed -> review classified as superseded  OK")


def test_control_a_genuine_contradictory_double_close_still_fires() -> None:
    """CONTROL: without this, the branch above could silence ALL double-closes.

    `review` then `exhausted` is two stages disagreeing about how the attempt
    ended, which is the thing the check exists to catch.
    """
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "progress")
        events = [
            _event(1, event="evaluate", attempt_id="att-1", counts={"work": 1},
                   counts_kind="attempt_snapshot"),
            _event(2, event="review", attempt_id="att-1"),
            _event(3, event="exhausted", attempt_id="att-1"),
        ]
        atomic_write_lines(log + ".jsonl", [json.dumps(e, sort_keys=True) for e in events])
        state, _ = reduce_journal(log)
        kinds = {p["kind"] for p in state["problems"]}
        assert "multiple-terminal-events" in kinds, (
            "CONTROL FAILED: a genuine contradictory double-close was silenced, so "
            "the superseded branch has swallowed the check it was meant to refine")
        print("  control: review -> exhausted still reported as a contradiction  OK")


# -- golden journal + one-mutation-one-code suite --------------------------------
#
# A golden journal that reduces to ZERO problems of any class is the positive
# control for the whole suite: without it, "mutation M produced code C" could
# be C plus noise the golden journal was already emitting. Every mutation below
# changes one thing and asserts the EXACT set of codes, not "C is among them".

FIXTURES = os.path.join(HERE, "fixtures")


def _golden_events():
    return [
        _event(1, event="evaluate", attempt_id="att-1",
               counts={"closed": 2, "escalated": 1, "work": 1},
               counts_kind="attempt_snapshot", escalation_ids=["esc-a"],
               work_ids=["w1"], evidence_ref="evidence/att-1.package.json"),
        _event(2, event="close", attempt_id="att-1", finding_id="f001", id="f001",
               status="false-positive", severity="high"),
        _event(3, event="close", attempt_id="att-1", finding_id="f002", id="f002",
               status="duplicate", severity="medium", duplicate_of="f001",
               cluster_id="claim-x"),
        _event(4, event="fix", attempt_id="att-1", role="worker",
               counts={"applied": 1, "not_applied": 0}),
        _event(5, event="gate", attempt_id="att-1", role="worker", counts={"exit": 0}),
        _event(6, event="review", attempt_id="att-1", role="reviewer",
               counts={"rejected": 0}),
    ]


def _golden_ledger():
    return [
        {"id": "f001", "path": "a/b/c.py", "severity": "high", "status": "false-positive"},
        {"id": "f002", "path": "a/b/c.py", "severity": "medium", "status": "duplicate"},
        {"id": "f003", "path": "a/b/c.py", "severity": "critical", "status": "escalated",
         "ruling_id": "ADR-ZT-FND-012"},
    ]


def _write(td, events, ledger_rows, *, raw_tail=b""):
    """Write a journal + ledger + evidence tree under td. Returns (log, ledger)."""
    log = os.path.join(td, "progress")
    ledger = os.path.join(td, "ledger.jsonl")
    with open(log + ".jsonl", "wb") as fh:
        for e in events:
            fh.write(json.dumps(e, sort_keys=True).encode() + b"\n")
        fh.write(raw_tail)
    atomic_write_lines(ledger, [json.dumps(r, sort_keys=True) for r in ledger_rows])
    os.makedirs(os.path.join(td, "evidence"), exist_ok=True)
    with open(os.path.join(td, "evidence", "att-1.package.json"), "w") as fh:
        fh.write("{}\n")
    return log, ledger


def _codes(state, *, include_info=False):
    return sorted({p["code"] for p in state["problems"]
                   if include_info or p["class"] != "info"})


def _reduce(td, events, ledger_rows=None, **kw):
    log, ledger = _write(td, events, _golden_ledger() if ledger_rows is None else ledger_rows,
                         raw_tail=kw.pop("raw_tail", b""))
    return reduce_journal(log, ledger, repo_root=td, **kw)


def test_golden_journal_reduces_to_zero_problems() -> None:
    with tempfile.TemporaryDirectory() as td:
        state, att = _reduce(td, _golden_events())
        assert state["problems"] == [], state["problems"]
        assert state["verdict"] == "pass"
        assert att["UNRESOLVED_WORK"] == [], att["UNRESOLVED_WORK"]
        assert state["attempts"]["att-1"]["work_resolved"] == ["w1"]
        # Positive half of every all-negative assertion above: the collections
        # the checks iterate over are populated, so "no problems" is not emptiness.
        assert state["events"] == 6 and state["totals"]["finding_observations"] == 2
        assert state["ledger_check"]["checked"] is True
        print("  golden: 6 events, 2 closures, ledger checked, zero problems  OK")


def _mutation(name, expected, mutate_events=None, mutate_ledger=None, **kw):
    """One mutation of the golden journal must produce EXACTLY `expected`."""
    events, ledger_rows = _golden_events(), _golden_ledger()
    if mutate_events:
        events = mutate_events(events)
    if mutate_ledger:
        ledger_rows = mutate_ledger(ledger_rows)
    with tempfile.TemporaryDirectory() as td:
        state, _ = _reduce(td, events, ledger_rows, **kw)
        got = _codes(state)
        assert got == sorted(expected), "%s: expected %s, got %s — %s" % (
            name, sorted(expected), got, state["problems"])
        print("  mutation %-34s -> %s  OK" % (name, ",".join(got) or "(none)"))
        return state


def _set(seq, **kw):
    def f(events):
        for e in events:
            if e["seq"] == seq:
                e.update(kw)
        return events
    return f


def _append_event(**kw):
    def f(events):
        return events + [_event(len(events) + 1, attempt_id="att-1", **kw)]
    return f


def test_mutations_each_produce_exactly_one_code() -> None:
    _mutation("remove-event", ["SEQ-002"],
              lambda ev: [e for e in ev if e["seq"] != 4])
    _mutation("duplicate-seq", ["SEQ-001"],
              lambda ev: ev + [dict(ev[4], event_id="evt-extra")])
    _mutation("duplicate-event-id", ["EVT-001"], _set(4, event_id="evt-0003"))
    _mutation("run-id-changes-within-attempt", ["RUN-001"], _set(5, run_id="other-run"))
    _mutation("delete-terminal", ["ATT-003"], lambda ev: ev[:-1])
    _mutation("second-contradictory-terminal", ["ATT-001"], _append_event(event="exhausted"))
    _mutation("stage-after-terminal", ["ATT-002"],
              _append_event(event="fix", role="worker"))
    _mutation("close-after-terminal", ["ATT-002"],
              _append_event(event="close", finding_id="f003", id="f003",
                            status="escalated", severity="critical"),
              lambda rows: rows)
    _mutation("dangling-duplicate-of", ["FND-002"], _set(3, duplicate_of="f999"))
    _mutation("altered-snapshot-count", ["CNT-001"],
              _set(1, counts={"closed": 5, "escalated": 1, "work": 1}))
    _mutation("flipped-ledger-status", ["LED-002"], None,
              lambda rows: [dict(r, status="open") if r["id"] == "f001" else r for r in rows])
    _mutation("deleted-ledger-row", ["LED-001"], None,
              lambda rows: [r for r in rows if r["id"] != "f002"])
    _mutation("unknown-event-type", ["SCH-001"], _set(4, event="patch"))
    _mutation("stage-missing-required-role", ["SCH-001"], _set(4, role=""))
    # The one deliberate cascade: `status` is consumed by the schema check, the
    # derived closed-count and the ledger comparison, so an unknown status is
    # correctly three findings, not one.
    _mutation("close-with-unknown-status", ["CNT-001", "LED-002", "SCH-001"],
              _set(2, status="closed-ish"))
    _mutation("review-names-unordered-work", ["WRK-001"], _set(6, work_ids=["w9"]))
    _mutation("partial-review-without-ids", ["WRK-002"],
              _set(6, counts={"rejected": 1}))
    _mutation("evidence-ref-missing", ["EVD-001"],
              _set(1, evidence_ref="evidence/absent.json"))


def test_duplicate_of_cycle_is_exactly_fnd_003() -> None:
    """`A dup B, B dup A` has no canonical target. Union-find would absorb it into
    one class and report nothing — so the directed check must see it first."""
    def cycle(ev):
        ev = _set(2, status="duplicate", duplicate_of="f002")(ev)
        return _set(3, cluster_id="")(ev)
    state = _mutation("duplicate-of-cycle", ["FND-003"], cycle,
                      lambda rows: [dict(r, status="duplicate") if r["id"] == "f001" else r
                                    for r in rows])
    p = [p for p in state["problems"] if p["code"] == "FND-003"]
    assert len(p) == 1 and p[0]["detail"] == ["f001", "f002"], p


def test_controls_that_must_not_fire() -> None:
    """Valid shapes that a careless invariant would report."""
    # cluster_id is a label, not a reference: it may name no finding at all.
    _mutation("dangling-cluster-id(control)", [], _set(3, cluster_id="no-such-finding"))

    # Several run_ids across DIFFERENT attempts is a long-lived journal, not a defect.
    def second_attempt(ev):
        return ev + [
            _event(7, event="evaluate", attempt_id="att-2", run_id="tick-2",
                   counts={"closed": 0, "work": 0}, counts_kind="attempt_snapshot"),
            _event(8, event="no-code-change", attempt_id="att-2", run_id="tick-2",
                   counts={"closed": 0, "work": 0}, counts_kind="attempt_snapshot"),
        ]
    _mutation("two-run-ids-two-attempts(control)", [], second_attempt)

    # Clock order is not journal order: concurrent agents may stamp backwards.
    _mutation("ts-out-of-order(control)", [],
              _set(4, ts="2026-09-22T09:00:00Z"))

    # A close that precedes its attempt's evaluate is legitimate (tick2-004 did it).
    def close_first(ev):
        ev[0]["seq"], ev[1]["seq"] = 2, 1
        return ev
    _mutation("close-before-evaluate(control)", [], close_first)


def test_truncated_final_record() -> None:
    """Live: the incomplete tail is dropped, warned, and the rest reduced.
    Final audit: the same bytes are an input failure (exit 2)."""
    partial = b'{"attempt_id": "att-1", "event": "rev'
    with tempfile.TemporaryDirectory() as td:
        state, _ = _reduce(td, _golden_events(), raw_tail=partial, live=True)
        assert _codes(state) == ["JNL-002"], state["problems"]
        assert state["source"]["last_complete_seq"] == 6
        assert state["source"]["events_reduced"] == 6
        assert state["source"]["journal_bytes_dropped_incomplete"] == len(partial)
        with open(os.path.join(td, "progress.jsonl"), "rb") as fh:
            whole = fh.read()
        assert state["source"]["journal_sha256"] == \
            hashlib.sha256(whole[:-len(partial)]).hexdigest(), \
            "provenance must hash the bytes REDUCED, not the file as found"
        print("  live truncated tail: JNL-002, seq 6 retained, sha over reduced prefix  OK")

        rc = reduce_run(["--log", os.path.join(td, "progress"),
                         "--ledger", os.path.join(td, "ledger.jsonl"), "--check"])
        assert rc == 2, "non-live truncated tail must be exit 2, got %d" % rc
        print("  final-audit truncated tail: exit 2  OK")


def test_malformed_middle_record_is_exit_2_even_live() -> None:
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _write(td, _golden_events(), _golden_ledger())
        with open(log + ".jsonl", "rb") as fh:
            lines = fh.read().split(b"\n")
        lines[2] = b'{"broken": '
        with open(log + ".jsonl", "wb") as fh:
            fh.write(b"\n".join(lines))
        rc = reduce_run(["--log", log, "--ledger", ledger, "--check", "--live"])
        assert rc == 2, "a malformed record that is not the final one is corruption; got %d" % rc
        print("  malformed middle record under --live: exit 2  OK")


def test_unstable_live_snapshot_withholds_ledger_checks() -> None:
    """Simulate a writer landing between the stat-before and stat-after of
    EVERY read. Live: LED-900, and a planted ledger disagreement must NOT be
    reported as corruption. Final audit: the same condition is exit 2."""
    real = reduce._file_stat
    ticks = iter(range(10_000))
    reduce._file_stat = lambda p: (next(ticks), 0)
    try:
        flip = [dict(r, status="open") if r["id"] == "f001" else r for r in _golden_ledger()]
        with tempfile.TemporaryDirectory() as td:
            state, _ = _reduce(td, _golden_events(), flip, live=True)
            assert _codes(state) == ["LED-900"], state["problems"]
            assert state["source"]["snapshot_stable"] is False
            assert state["ledger_check"]["checked"] is False
            print("  unstable live snapshot: LED-900 only, disagreement withheld  OK")
            rc = reduce_run(["--log", os.path.join(td, "progress"),
                             "--ledger", os.path.join(td, "ledger.jsonl"), "--check"])
            assert rc == 2, "a moving input in a final audit must be exit 2, got %d" % rc
            print("  unstable final-audit input: exit 2  OK")
    finally:
        reduce._file_stat = real
    # CONTROL: the same flipped ledger, stable reads -> the disagreement IS an error.
    _mutation("flipped-ledger-stable-live(control)", ["LED-002"], None,
              lambda rows: [dict(r, status="open") if r["id"] == "f001" else r for r in rows],
              live=True)


def test_evidence_resolution_ignores_the_working_directory() -> None:
    with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as elsewhere:
        log, ledger = _write(td, _golden_events(), _golden_ledger())
        cwd = os.getcwd()
        try:
            os.chdir(elsewhere)
            a, _ = reduce_journal(log, ledger, repo_root=td)
            os.chdir(td)
            b, _ = reduce_journal(log, ledger, repo_root=td)
        finally:
            os.chdir(cwd)
        assert _codes(a) == _codes(b) == [], (a["problems"], b["problems"])
        # CONTROL: the ref really is checked against the root, not ignored.
        c, _ = reduce_journal(log, ledger, repo_root=elsewhere)
        assert _codes(c) == ["EVD-001"], c["problems"]
        print("  evidence: same answer from two CWDs; wrong root -> EVD-001  OK")


def test_exit_codes_follow_class_not_open_work() -> None:
    with tempfile.TemporaryDirectory() as td:
        # Open escalation (f003 in the ledger) + an in-flight attempt: state, not failure.
        events = _golden_events() + [
            _event(7, event="evaluate", attempt_id="att-2", work_ids=["w2"],
                   counts={"work": 1}, counts_kind="attempt_snapshot")]
        log, ledger = _write(td, events, _golden_ledger())
        base = ["--log", log, "--ledger", ledger, "--repo-root", td]
        assert reduce_run(base + ["--check", "--live"]) == 0, "open work must not fail --check"
        # warning-only (ATT-003 outside --live) is still exit 0
        assert reduce_run(base + ["--check"]) == 0
        # an error-class problem fails --check, and ONLY --check
        _write(td, _set(1, counts={"closed": 5, "work": 1})(_golden_events()), _golden_ledger())
        assert reduce_run(base + ["--check"]) == 1
        assert reduce_run(base) == 0
        print("  exit codes: open work 0, warning 0, error 1 under --check only  OK")


def test_report_and_provenance_are_deterministic() -> None:
    with tempfile.TemporaryDirectory() as td:
        log, ledger = _write(td, _golden_events(), _golden_ledger())
        s1, a1 = reduce_journal(log, ledger, repo_root=td)
        s2, a2 = reduce_journal(log, ledger, repo_root=td)
        r1, r2 = reduce.render_report(s1, a1), reduce.render_report(s2, a2)
        assert r1 == r2
        src = s1["source"]
        for k in ("auditor_version", "journal_sha256", "ledger_sha256",
                  "last_complete_seq", "events_reduced", "live"):
            assert k in src and "| %s |" % k in r1, k
        assert src["last_complete_seq"] == 6 and src["events_reduced"] == 6
        assert src["live"] is False
        print("  report: byte-identical across replays, provenance surfaced  OK")


def test_frozen_real_run_excerpt() -> None:
    """Integration: tick 2 of a real lane run (seq 42-74), anonymized and its ledger
    rows, copied into tests/fixtures. Never reads the live, still-growing files.

    Evidence packages are deliberately NOT frozen, and the evidence root is the
    fixture directory: so EVD-001 must fire for exactly the eight refs — which
    also proves the root, not the working directory or the real repository, is
    what refs resolve against.
    """
    state, att = reduce_journal(os.path.join(FIXTURES, "demo-tick2-progress"),
                                os.path.join(FIXTURES, "demo-tick2-ledger.jsonl"),
                                repo_root=FIXTURES)
    assert state["source"]["events_reduced"] == 33
    assert state["source"]["last_complete_seq"] == 74
    assert _codes(state) == ["CNT-001", "EVD-001"], _codes(state)
    cnt = [p for p in state["problems"] if p["code"] == "CNT-001"]
    assert [(p["attempt_id"], p["detail"]) for p in cnt] == [
        ("att-demo-tick2-003", {"closed": {"asserted": 0, "derived": 4}})], cnt
    sup = sorted(p["attempt_id"] for p in state["problems"] if p["code"] == "ATT-004")
    assert sup == ["att-demo-tick2-000", "att-demo-tick2-001", "att-demo-tick2-002"], sup
    assert len([p for p in state["problems"] if p["code"] == "EVD-001"]) == 8
    # W1 on tick2-000 was withheld; the partial review NAMED only W2 as accepted.
    assert att["UNRESOLVED_WORK"] == ["b97f185f9e04c962"], att["UNRESOLVED_WORK"]
    assert state["ledger_check"]["checked"] and not state["ledger_check"]["status_disagreements"]
    print("  frozen tick-2: CNT-001 on tick2-003, 3x ATT-004, 1 unresolved work item  OK")


def reduce_run(argv):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return reduce.run(argv)


def main() -> int:
    tests = [test_golden_journal_reduces_to_zero_problems,
             test_mutations_each_produce_exactly_one_code,
             test_duplicate_of_cycle_is_exactly_fnd_003,
             test_controls_that_must_not_fire,
             test_truncated_final_record,
             test_malformed_middle_record_is_exit_2_even_live,
             test_unstable_live_snapshot_withholds_ledger_checks,
             test_evidence_resolution_ignores_the_working_directory,
             test_exit_codes_follow_class_not_open_work,
             test_report_and_provenance_are_deterministic,
             test_frozen_real_run_excerpt,
             test_replay_twice_is_identical,
             test_an_early_close_completed_by_review_is_classified_separately,
             test_control_a_genuine_contradictory_double_close_still_fires,
             test_clusters_collapse_observations_onto_defects,
             test_ledger_escalations_are_enumerable_by_ruling,
             test_control_ledger_status_disagreement_is_detected,
             test_control_lost_ledger_row_is_detected,
             test_control_sequence_gap_is_detected,
             test_control_counts_assertion_mismatch_is_detected,
             test_counts_snapshots_are_not_double_counted]
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
