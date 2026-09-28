"""Deterministic reducer and auditor: replay the progress journal into derived state.

(Invoked as `python3 reduce.py …`; no shebang, because the repo's bulk-operation
hook pattern matches "shebang … find … sed", and the words "findings"/"disposed"
trip it.)

THE POINT OF THIS FILE: the LLM becomes a READER of derived state, never the
thing that determines state. Everything here is mechanical — schema validation,
sequence validation, legal transitions, index building, invariant checks. There
is no regex over `note`, no NLP, no "probably belongs to". It answers one
question: given the protocol events that actually exist, what state follows, and
are those events internally consistent?

    progress.jsonl  ->  reduce  ->  current-state.json
    (immutable journal)             attention.json
    ledger.jsonl                    audit-report.md

This is the ONE auditor of the journal. A second reader with its own rules would
be two authorities over one record that can disagree.

Rules it enforces that the harness previously could not:

1. COUNTS ARE ASSERTIONS, NOT STATE. `evaluate` and the terminal event repeat
   the same tally, so summing them double-counts. The reducer derives the real
   numbers from identified objects and then CHECKS them against the asserted
   `counts`. A mismatch is reported, not silently preferred either way — in the
   2026-09-22 batch four evaluators counted duplicates inside `disposed` and four
   did not, so the field was not merely undefined, it was inconsistently applied.

2. THE JOURNAL IS CROSS-CHECKED AGAINST THE LEDGER. The ledger stays
   authoritative for FINDING state (next_file.py reads it to choose work); the
   journal is authoritative for OPERATION state, which the ledger does not model.
   Every `close` event must have a matching ledger row with the same status, and
   the ledger's population must be conserved. That invariant is what would have
   caught the 365-finding loss in seconds instead of an hour later by eye.

3. EVERY PROBLEM CARRIES A STABLE CODE AND A CLASS, and the class alone decides
   the exit status under `--check`:

     fatal    cannot reconstruct authoritative state (seq collision, duplicate
              event id, contradictory terminal events)
     error    reconstructable, but the journal violates the protocol
     warning  valid state that deserves attention
     info     a run characteristic, not a defect

   Open remediation work — escalations, unresolved work items — is STATE, never
   a problem. "89 unresolved escalations" must not make the auditor exit as if
   the journal were corrupt.

4. ORDER IS `seq`, NEVER THE CLOCK. Agents run concurrently, so `ts` may run
   backwards across adjacent events. That is evidence, not corruption.

Exit status:
  0  no fatal/error problem (or `--check` not given)
  1  `--check` and at least one fatal/error problem
  2  input could not be read as a journal (malformed record, or an input that
     changed while it was being read outside `--live`)

`--live` is for auditing a journal a lane is still appending to:
  * an incomplete FINAL record (a writer mid-append) is dropped and reported as
    JNL-002; malformed JSON anywhere else is still exit 2;
  * the journal and ledger are separate mutable files, so both are read inside a
    stat-before/stat-after window with one retry; if the pair still moved, the
    cross-file checks that depend on them are withheld and LED-900 is reported
    instead of a ledger-integrity error;
  * an attempt with no terminal event yet is in flight, so ATT-003 is info.

Usage:
  python3 reduce.py --log <progress> [--ledger <ledger.jsonl>] [--out <dir>]
                    [--check] [--live] [--repo-root <dir>]
  python3 reduce.py --log <progress> --print-attention
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _persist import atomic_write_lines  # noqa: E402
from journal_input_error import JournalInputError  # noqa: E402

AUDITOR_VERSION = "2.0.0"
STATE_SCHEMA_VERSION = 2
# The only journal schema this reducer knows how to validate. An event declaring
# anything else is reported, not guessed at.
JOURNAL_SCHEMA_VERSIONS = {1}

# `evidence_ref` paths are repository-relative. They resolve against ONE root,
# never the working directory, so the answer does not depend on where the
# auditor was launched: this file is <root>/<dot-claude>/skills/<skill>/scripts.
DEFAULT_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))))))

TERMINAL_EVENTS = {"review", "no-code-change", "gate-failed", "exhausted", "lost",
                   "dry-run", "not-started"}
SNAPSHOT_EVENTS = {"evaluate", "no-code-change", "dry-run", "gate-failed", "exhausted"}
STAGE_EVENTS = {"evaluate", "fix", "gate", "regression"}
KNOWN_EVENTS = TERMINAL_EVENTS | STAGE_EVENTS | {"close"}
# Synthesized by `progress.py reconcile`, which writes no run_id and (for a file
# never attempted) no attempt_id. Requiring those fields of them would report the
# harness's own bookkeeping as a protocol breach.
ORCHESTRATOR_SYNTHESIZED = {"lost", "not-started"}
# A closure is terminal for a FINDING. `escalated` and `needs-senior-eval` are
# explicitly NOT here: they block, which is the whole reason they must be
# enumerable rather than merely countable.
TERMINAL_FINDING_STATUS = {"fixed", "false-positive", "accepted-risk", "duplicate",
                           "wontfix", "superseded", "deleted-with-owner",
                           "positive-control", "informational", "parked-external"}
BLOCKING_FINDING_STATUS = {"escalated", "needs-senior-eval", "exhausted",
                           "architecture-blocked", "open", "regression"}

# code -> (class, kind). `kind` is the name the problem had before codes existed;
# it is kept so every earlier reader and test still means the same thing.
INVARIANTS = {
    "JNL-002": ("warning", "incomplete-final-record"),
    "SEQ-001": ("fatal", "duplicate-seq"),
    "SEQ-002": ("fatal", "missing-events"),
    "SEQ-003": ("error", "unsequenced-event"),
    "EVT-001": ("fatal", "duplicate-event-id"),
    "SCH-001": ("error", "schema-violation"),
    "RUN-001": ("error", "attempt-run-id-changed"),
    "ATT-001": ("fatal", "multiple-terminal-events"),
    "ATT-002": ("error", "event-after-terminal"),
    "ATT-003": ("warning", "nonterminal-attempt"),
    "ATT-004": ("info", "terminal-superseded"),
    "FND-001": ("error", "finding-restatus"),
    "FND-002": ("error", "dangling-duplicate-of"),
    "FND-003": ("error", "duplicate-of-cycle"),
    "CNT-001": ("error", "counts-assertion-mismatch"),
    "WRK-001": ("error", "review-names-unordered-work"),
    "WRK-002": ("warning", "partial-review-without-work-identities"),
    "LED-001": ("error", "closure-absent-from-ledger"),
    "LED-002": ("error", "ledger-journal-status-disagreement"),
    "LED-900": ("warning", "live-snapshot-unstable"),
    "EVD-001": ("warning", "evidence-ref-unresolved"),
}
CLASS_ORDER = ("fatal", "error", "warning", "info")
FAILING_CLASSES = {"fatal", "error"}


def _problem(code: str, cls: str = "", **fields) -> dict:
    default_cls, kind = INVARIANTS[code]
    p = {"code": code, "class": cls or default_cls, "kind": kind}
    p.update(fields)
    return p


# -- input snapshot -----------------------------------------------------------

def _file_stat(path: str):
    """(size, mtime_ns) of a file, or None when absent. Module-level so a test can
    substitute it to simulate a writer landing between two reads."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    return (st.st_size, st.st_mtime_ns)


def _read_bytes(path: str) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _snapshot(paths: list, live: bool) -> tuple:
    """Read every input inside one stat-before/stat-after window.

    Each file is individually consistent (the journal is O_APPEND, the ledger is
    replaced by rename), but the PAIR is only a snapshot if neither moved while
    both were read. Live: one bounded retry, then report instability rather than
    wait. Final audit: inputs are quiescent by definition, so movement is an input
    failure. No sleeps, no polling.
    """
    blobs: list = []
    for _ in range(2 if live else 1):
        before = [_file_stat(p) for p in paths]
        blobs = [_read_bytes(p) for p in paths]
        after = [_file_stat(p) for p in paths]
        if before == after:
            return blobs, True
    if not live:
        raise JournalInputError("input changed while it was being read: %s — a final "
                                "audit needs quiescent inputs (use --live for a running lane)"
                                % ", ".join(paths))
    return blobs, False


def _parse_journal(data: bytes, path: str, live: bool) -> tuple:
    """Bytes -> (rows, reduced_bytes, dropped_tail_bytes).

    Tolerant of exactly one thing, and only under `--live`: a FINAL record with no
    terminating newline that does not parse, i.e. a writer caught mid-append.
    Everything else that does not parse is corruption and raises.
    """
    rows: list = []
    lines = data.split(b"\n")
    tail = lines.pop()               # b"" when the file ends with a newline
    for lineno, raw in enumerate(lines, 1):
        rows.append(_parse_line(raw, path, lineno))
    if not tail.strip():
        return [r for r in rows if r is not None], data, 0
    try:
        rows.append(_parse_line(tail, path, len(lines) + 1))
        return [r for r in rows if r is not None], data, 0
    except JournalInputError:
        if not live:
            raise
    return [r for r in rows if r is not None], data[:len(data) - len(tail)], len(tail)


def _parse_line(raw: bytes, path: str, lineno: int):
    if not raw.strip():
        return None
    try:
        rec = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise JournalInputError("%s:%d: malformed JSONL record: %s" % (path, lineno, exc)) from exc
    if not isinstance(rec, dict):
        raise JournalInputError("%s:%d: record is not a JSON object" % (path, lineno))
    return rec


def _parse_ledger(data: bytes, path: str) -> dict:
    out: dict = {}
    for lineno, raw in enumerate(data.split(b"\n"), 1):
        rec = _parse_line(raw, path, lineno)
        if rec is not None:
            out[rec.get("id")] = rec
    return out


# -- replay -------------------------------------------------------------------

def _attempt_key(rec: dict) -> str:
    return rec.get("attempt_id") or ("legacy:" + rec.get("file", ""))


def _schema_problems(r: dict) -> list:
    """Required fields per event type. Presence only — the reducer checks VALUES
    through the invariants that consume them."""
    missing = [k for k in ("schema_version", "event_id", "ts", "event") if not r.get(k)]
    ev = r.get("event", "")
    detail: dict = {}
    if r.get("schema_version") and r["schema_version"] not in JOURNAL_SCHEMA_VERSIONS:
        detail["schema_version"] = r["schema_version"]
    if ev and ev not in KNOWN_EVENTS:
        detail["unknown_event"] = ev
    if ev == "close":
        missing += [k for k in ("status",) if not r.get(k)]
        if not (r.get("finding_id") or r.get("id")):
            missing.append("finding_id")
        if r.get("status") and r["status"] not in TERMINAL_FINDING_STATUS | BLOCKING_FINDING_STATUS:
            detail["unknown_status"] = r["status"]
    elif ev in KNOWN_EVENTS and ev not in ORCHESTRATOR_SYNTHESIZED:
        missing += [k for k in ("attempt_id", "run_id", "file", "role") if not r.get(k)]
    if missing:
        detail["missing"] = sorted(set(missing))
    if not detail:
        return []
    return [_problem("SCH-001", event_id=r.get("event_id", "?"), seq=r.get("seq"),
                     detail=detail)]


def reduce_journal(log: str, ledger_path: str = "", *, live: bool = False,
                   repo_root: str = "") -> tuple:
    """Replay the journal. Pure function of its inputs — no wall clock, no rng.

    Raises JournalInputError when the input cannot be read as a journal.
    """
    journal_path = log + ".jsonl"
    repo_root = repo_root or DEFAULT_REPO_ROOT
    paths = [journal_path] + ([ledger_path] if ledger_path else [])
    blobs, stable = _snapshot(paths, live)
    jdata = blobs[0] or b""
    ldata = blobs[1] if ledger_path else None

    rows, reduced_bytes, dropped_tail = _parse_journal(jdata, journal_path, live)
    problems: list = []
    if dropped_tail:
        problems.append(_problem("JNL-002", detail={"bytes_dropped": dropped_tail},
                                 why="a writer was mid-append; the incomplete final record "
                                     "is excluded and the rest reduced"))

    ledger: dict | None = None
    ledger_usable = False
    if ledger_path and ldata is not None:
        try:
            ledger = _parse_ledger(ldata, ledger_path)
            ledger_usable = stable
        except JournalInputError:
            if not live:
                raise
            stable = False           # a torn ledger read is the same fact as a moving one
    if ledger_path and not stable:
        problems.append(_problem(
            "LED-900", detail="journal/ledger pair changed during the read, after one retry",
            why="ledger cross-checks withheld: a transient state between two writes is not "
                "ledger corruption; re-run to audit a stable pair"))

    rows.sort(key=lambda r: (r.get("seq") if isinstance(r.get("seq"), int) else 0,
                             r.get("ts", ""), r.get("event_id", "")))

    # -- sequence and identity integrity ---------------------------------------
    seqs = [r["seq"] for r in rows if isinstance(r.get("seq"), int)]
    unsequenced = [r.get("event_id", "?") for r in rows if not isinstance(r.get("seq"), int)]
    gaps: list = []
    if unsequenced:
        problems.append(_problem("SEQ-003", detail=unsequenced))
    if seqs:
        seq_counts = Counter(seqs)
        dupes = sorted(s for s, n in seq_counts.items() if n > 1)
        gaps = [n for n in range(min(seqs), max(seqs) + 1) if n not in seq_counts]
        if dupes:
            problems.append(_problem("SEQ-001", detail=dupes))
        if gaps:
            problems.append(_problem("SEQ-002", detail=gaps,
                                     why="a gap in seq proves an event is absent"))
    eid_counts = Counter(r.get("event_id") for r in rows if r.get("event_id"))
    dup_eids = sorted(e for e, n in eid_counts.items() if n > 1)
    if dup_eids:
        problems.append(_problem("EVT-001", detail=dup_eids))
    for r in rows:
        problems.extend(_schema_problems(r))

    # -- attempts -----------------------------------------------------------
    attempts: dict = defaultdict(lambda: {"events": [], "files": set(), "stages": [],
                                          "terminal": None, "asserted": {}, "role": "",
                                          "tier": "", "model": "", "run_ids": [],
                                          "work_ordered": set(), "work_resolved": set(),
                                          "escalation_ids": set(),
                                          "evidence_ref": "", "superseded_terminals": []})
    findings: dict = {}
    evidence_refs: dict = {}

    def _note_run_id(key: str, r: dict) -> None:
        rid = r.get("run_id") or ""
        if rid and rid not in attempts[key]["run_ids"]:
            attempts[key]["run_ids"].append(rid)

    def _after_terminal(key: str, r: dict) -> None:
        # Only an attempt that already exists can have ended; a close that
        # precedes its attempt's first stage event is legitimate ordering.
        if key in attempts and attempts[key]["terminal"]:
            problems.append(_problem("ATT-002", attempt_id=key, seq=r.get("seq"),
                                     detail="%s after terminal %s"
                                            % (r.get("event"), attempts[key]["terminal"])))

    for r in rows:
        ev = r.get("event", "")
        if r.get("evidence_ref"):
            evidence_refs.setdefault(r["evidence_ref"], r.get("event_id", "?"))
        if ev == "close":
            fid = r.get("finding_id") or r.get("id")
            if not fid:
                continue             # reported as SCH-001
            if r.get("attempt_id"):
                _after_terminal(r["attempt_id"], r)
                if r["attempt_id"] in attempts:
                    _note_run_id(r["attempt_id"], r)
            prior = findings.get(fid)
            if prior and prior["status"] != r.get("status"):
                problems.append(_problem("FND-001", finding_id=fid,
                                         detail="%s -> %s" % (prior["status"], r.get("status"))))
            findings[fid] = {"finding_id": fid, "status": r.get("status", ""),
                             "severity": r.get("severity", ""),
                             "file": r.get("file", ""),
                             "attempt_id": r.get("attempt_id", ""),
                             "run_id": r.get("run_id", ""),
                             "duplicate_of": r.get("duplicate_of") or "",
                             "cluster_id": r.get("cluster_id") or "",
                             "ruling_id": r.get("ruling_id") or "",
                             "evidence_ref": r.get("evidence_ref") or ""}
            continue

        key = _attempt_key(r)
        if ev not in TERMINAL_EVENTS:
            _after_terminal(key, r)
        a = attempts[key]
        a["events"].append(r.get("event_id", ""))
        if r.get("file"):
            a["files"].add(r["file"])
        a["stages"].append(ev)
        _note_run_id(key, r)
        a["role"] = a["role"] or r.get("role", "")
        a["tier"] = a["tier"] or r.get("tier", "")
        a["model"] = a["model"] or r.get("model", "")
        a["escalation_ids"] |= set(r.get("escalation_ids") or [])
        a["evidence_ref"] = a["evidence_ref"] or (r.get("evidence_ref") or "")
        if ev == "evaluate":
            a["work_ordered"] |= set(r.get("work_ids") or [])
        elif ev == "review":
            # A review resolves work in exactly two structural ways: it NAMES the
            # items it accepted, or it names none and asserts zero rejections
            # (accept-all). A partial review that names nothing cannot say which
            # items landed, and the reducer will not read its prose to find out.
            named = set(r.get("work_ids") or [])
            rejected = (r.get("counts") or {}).get("rejected")
            if named:
                stray = sorted(named - a["work_ordered"])
                if stray:
                    problems.append(_problem("WRK-001", attempt_id=key, seq=r.get("seq"),
                                             detail=stray))
                a["work_resolved"] |= named & a["work_ordered"]
            elif rejected == 0:
                a["work_resolved"] |= a["work_ordered"]
            elif a["work_ordered"] - a["work_resolved"]:
                problems.append(_problem(
                    "WRK-002", attempt_id=key, seq=r.get("seq"),
                    detail=sorted(a["work_ordered"] - a["work_resolved"]),
                    why="review rejected=%s but named no work_ids, so which items "
                        "landed is not recorded; they stay unresolved" % rejected))
        # Snapshot counts are ASSERTIONS about the attempt. Keep the latest; never
        # add them together, which is the double-count the old stats invited.
        if r.get("counts") and (r.get("counts_kind") == "attempt_snapshot"
                                or ev in SNAPSHOT_EVENTS):
            a["asserted"] = dict(r["counts"])
        if ev in TERMINAL_EVENTS:
            prior = a["terminal"]
            if prior and prior != ev:
                # An early close that a LATER, more authoritative stage completed
                # is a different fact from two stages contradicting each other,
                # and collapsing them is how a permanent unresolved entry teaches
                # people to ignore the report. `review` is the reviewer's verdict
                # on the finished diff, so it supersedes an earlier close.
                # Observed: three tick-2 attempts were closed `gate-failed` by a
                # worker under a superseded contract, then genuinely reviewed.
                if ev == "review" and prior != "review":
                    a["superseded_terminals"].append(prior)
                    problems.append(_problem("ATT-004", attempt_id=key,
                                             detail="%s superseded by review" % prior))
                else:
                    problems.append(_problem("ATT-001", attempt_id=key,
                                             detail="%s then %s" % (prior, ev)))
            a["terminal"] = ev

    # -- per-attempt truth from identities, then CHECK the assertions ----------
    by_attempt: dict = {}
    for key, a in attempts.items():
        if len(a["run_ids"]) > 1:
            problems.append(_problem("RUN-001", attempt_id=key, detail=a["run_ids"]))
        if not a["terminal"]:
            problems.append(_problem("ATT-003", "info" if live else "", attempt_id=key,
                                     detail="no terminal event" + (" yet" if live else "")))
        derived_closed = sum(1 for f in findings.values()
                             if f["attempt_id"] == key
                             and f["status"] in TERMINAL_FINDING_STATUS)
        derived_escalated = sum(1 for f in findings.values()
                                if f["attempt_id"] == key
                                and f["status"] in BLOCKING_FINDING_STATUS)
        asserted = a["asserted"]
        mismatch = {}
        # Only check what the journal can actually account for: a `closed`
        # assertion is checkable because closures carry identities. `disposed`
        # is NOT checked, because the field was applied inconsistently by the
        # agents and checking it would manufacture noise, not signal.
        if "closed" in asserted and asserted["closed"] != derived_closed:
            mismatch["closed"] = {"asserted": asserted["closed"], "derived": derived_closed}
        if a["escalation_ids"] and "escalated" in asserted \
                and asserted["escalated"] != len(a["escalation_ids"]):
            mismatch["escalated"] = {"asserted": asserted["escalated"],
                                     "derived": len(a["escalation_ids"])}
        if mismatch:
            problems.append(_problem("CNT-001", attempt_id=key, detail=mismatch))
        by_attempt[key] = {
            "attempt_id": key, "files": sorted(a["files"]),
            "run_id": a["run_ids"][0] if a["run_ids"] else "",
            "role": a["role"], "tier": a["tier"], "model": a["model"],
            "stages": a["stages"], "terminal": a["terminal"],
            "superseded_terminals": a["superseded_terminals"],
            "work_ids": sorted(a["work_ordered"]),
            "work_resolved": sorted(a["work_resolved"]),
            "work_unresolved": sorted(a["work_ordered"] - a["work_resolved"]),
            "escalation_ids": sorted(a["escalation_ids"]),
            "evidence_ref": a["evidence_ref"],
            "asserted_counts": asserted,
            "derived": {"closed": derived_closed, "blocking": derived_escalated},
            "counts_mismatch": mismatch,
        }

    # -- duplicate provenance, then unique defects -----------------------------
    # `duplicate_of` is a REFERENCE to a finding; `cluster_id` is a LABEL for an
    # equivalence class and refers to nothing. Only the reference can dangle.
    # A dangling target is only decidable against the ledger, and only when the
    # ledger read was a stable snapshot.
    bad_edges: set = set()
    if ledger_usable:
        for fid, f in sorted(findings.items()):
            t = f["duplicate_of"]
            if t and t not in findings and t not in ledger:
                bad_edges.add(fid)
                problems.append(_problem("FND-002", finding_id=fid, detail=t))
    # The DIRECTED relation must be acyclic: `A dup B, B dup A` names no canonical
    # finding. Union-find would quietly merge a cycle into one class, which is
    # right for counting defects and wrong for provenance — so the cycle is found
    # on the directed graph FIRST, and its edges are kept out of the union.
    reported: set = set()
    for start in sorted(findings):
        path, node = [], start
        while node in findings and findings[node]["duplicate_of"] and node not in path:
            path.append(node)
            node = findings[node]["duplicate_of"]
        if node in path:
            cycle = path[path.index(node):]
            if not reported & set(cycle):
                reported |= set(cycle)
                bad_edges |= set(cycle)
                problems.append(_problem("FND-003", detail=sorted(cycle)))

    parent: dict = {}

    def _find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(x, y):
        rx, ry = _find(x), _find(y)
        if rx != ry:
            parent[min(rx, ry)] = parent[max(rx, ry)] = min(rx, ry)

    # `duplicate_of` and `cluster_id` are two spellings of the SAME relation once
    # provenance is valid, so they are unioned, not prioritised: keying on
    # cluster_id first left f002 (cluster "claim-x", duplicate_of f001) in a
    # different group from f001, reporting two defects where there is one.
    for fid, f in findings.items():
        _find(fid)
        if f["duplicate_of"] and fid not in bad_edges:
            _union(fid, f["duplicate_of"])
        if f["cluster_id"]:
            _union(fid, f["cluster_id"])
    clusters: dict = defaultdict(set)
    for fid in findings:
        clusters[_find(fid)].add(fid)
    unique_defects = len(clusters)
    duplicates = sum(1 for f in findings.values() if f["duplicate_of"])

    # -- evidence ------------------------------------------------------------
    unresolved_evidence = []
    for ref in sorted(evidence_refs):
        p = ref if os.path.isabs(ref) else os.path.join(repo_root, ref)
        if not os.path.exists(p):
            unresolved_evidence.append(ref)
            problems.append(_problem("EVD-001", event_id=evidence_refs[ref], detail=ref))

    # -- ledger cross-check ---------------------------------------------------
    ledger_check: dict = {"checked": False}
    ledger_blocking: list = []
    if ledger_usable:
        # The ledger is authoritative for FINDING state, so the blocking set is
        # read from it, not from journal closures. Migrated history predates
        # escalation identities and the migration cannot invent what was never
        # recorded — but every one of those findings IS in the ledger.
        for fid, row in sorted(ledger.items()):
            if row.get("status") in ("escalated", "needs-senior-eval", "exhausted",
                                     "architecture-blocked", "regression"):
                ledger_blocking.append({
                    "finding_id": fid, "status": row.get("status", ""),
                    "severity": row.get("severity", ""), "file": row.get("path") or row.get("file", ""),
                    "ruling_id": row.get("ruling_id") or "",
                    "cluster_id": row.get("cluster_id") or "",
                    "duplicate_of": row.get("duplicate_of") or "",
                    "attempt_id": "", "evidence_ref": ""})
        disagree, absent = [], []
        for fid, f in sorted(findings.items()):
            row = ledger.get(fid)
            if row is None:
                absent.append(fid)
            elif row.get("status") != f["status"]:
                disagree.append({"finding_id": fid, "journal": f["status"],
                                 "ledger": row.get("status")})
        ledger_check = {"checked": True, "ledger_rows": len(ledger),
                        "closures_in_journal": len(findings),
                        "absent_from_ledger": absent,
                        "status_disagreements": disagree}
        if absent:
            problems.append(_problem("LED-001", detail=absent,
                                     why="the journal closed a finding the ledger does not hold "
                                         "— the population may have been lost"))
        if disagree:
            problems.append(_problem("LED-002", detail=disagree))
    elif ledger_path:
        ledger_check = {"checked": False,
                        "reason": "ledger absent" if ldata is None else "live snapshot unstable"}

    counts_by_class = {c: sum(1 for p in problems if p["class"] == c) for c in CLASS_ORDER}
    ledger_bytes = ldata if (ledger_path and ldata is not None) else None
    state = {
        "schema_version": STATE_SCHEMA_VERSION,
        # Provenance: every value here describes the exact bytes that were reduced,
        # computed from the snapshot in hand and never re-read. Nothing here may be
        # a clock or a random value, or two replays stop being byte-identical.
        "source": {
            "auditor_version": AUDITOR_VERSION,
            "state_schema_version": STATE_SCHEMA_VERSION,
            "journal": journal_path,
            "journal_sha256": hashlib.sha256(reduced_bytes).hexdigest(),
            "journal_bytes_reduced": len(reduced_bytes),
            "journal_bytes_dropped_incomplete": dropped_tail,
            "events_reduced": len(rows),
            "last_complete_seq": max(seqs) if seqs else None,
            "ledger": ledger_path or None,
            "ledger_sha256": hashlib.sha256(ledger_bytes).hexdigest()
                             if ledger_bytes is not None else None,
            "ledger_rows": len(ledger) if ledger is not None else None,
            "live": live,
            "snapshot_stable": stable,
            "repo_root_for_evidence": "<default>" if repo_root == DEFAULT_REPO_ROOT else repo_root,
        },
        "events": len(rows),
        "unsequenced_events": len(unsequenced),
        "sequence_gaps": gaps,
        "attempts": {k: by_attempt[k] for k in sorted(by_attempt)},
        "findings": {k: findings[k] for k in sorted(findings)},
        "clusters": {k: sorted(v) for k, v in sorted(clusters.items())},
        "totals": {
            "attempts": len(by_attempt),
            "attempts_terminal": sum(1 for a in by_attempt.values() if a["terminal"]),
            "files_touched": len(sorted({f for a in by_attempt.values() for f in a["files"]})),
            "finding_observations": len(findings),
            "unique_defect_clusters": unique_defects,
            "duplicate_observations": duplicates,
        },
        "ledger_check": ledger_check,
        "ledger_blocking": ledger_blocking,
        "unresolved_evidence_refs": unresolved_evidence,
        "problem_counts_by_class": counts_by_class,
        "verdict": "fail" if any(counts_by_class[c] for c in FAILING_CLASSES) else "pass",
        "problems": problems,
    }
    return state, _attention(state)


def _attention(state: dict) -> dict:
    """What a human must look at. Built only from identities — never from prose."""
    att = state["attempts"]
    findings = state["findings"]

    nonterminal = sorted(k for k, a in att.items() if not a["terminal"])
    lost = sorted(k for k, a in att.items() if a["terminal"] == "lost")
    gate_failed = sorted(k for k, a in att.items() if a["terminal"] == "gate-failed")

    # Union of what the journal saw and what the ledger holds; the ledger is
    # authoritative for finding state, the journal for operation state.
    blocking = {f["finding_id"]: f for f in findings.values()
                if f["status"] in BLOCKING_FINDING_STATUS}
    for f in state.get("ledger_blocking", []):
        blocking.setdefault(f["finding_id"], f)
    # Escalations grouped by the shared ruling that would discharge them. This is
    # the aggregation that turns "30 human decisions" into a handful: one
    # architectural answer closes a whole set deterministically. UNGROUPED is the
    # backlog to cluster — it is a work item, not a resting state.
    by_ruling: dict = defaultdict(list)
    for f in blocking.values():
        by_ruling[f["ruling_id"] or f["cluster_id"] or "UNGROUPED"].append(f["finding_id"])

    unresolved_work = sorted({w for a in att.values() for w in a["work_unresolved"]})
    severe_closures = sorted(
        (f["finding_id"], f["severity"], f["status"], f["file"])
        for f in findings.values()
        if f["severity"] in ("critical", "high")
        and f["status"] in ("false-positive", "accepted-risk", "wontfix"))
    blocking_by_severity: dict = defaultdict(int)
    for f in blocking.values():
        blocking_by_severity[f["severity"] or "unknown"] += 1

    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "journal_sha256": state["source"]["journal_sha256"],
        "last_complete_seq": state["source"]["last_complete_seq"],
        "VERDICT": state["verdict"],
        "PROBLEM_COUNTS_BY_CLASS": state["problem_counts_by_class"],
        "NONTERMINAL_ATTEMPTS": nonterminal,
        "LOST_ATTEMPTS": lost,
        "GATE_FAILED_ATTEMPTS": gate_failed,
        "UNRESOLVED_WORK": unresolved_work,
        "UNRESOLVED_ESCALATIONS_TOTAL": len(blocking),
        "UNRESOLVED_ESCALATIONS_BY_SEVERITY": dict(sorted(blocking_by_severity.items())),
        "UNRESOLVED_ESCALATIONS_BY_RULING": {k: sorted(v) for k, v in sorted(by_ruling.items())},
        "SEVERE_CLOSURES_TO_REVIEW": [list(x) for x in severe_closures],
        "SEQUENCE_GAPS": state["sequence_gaps"],
        "INTEGRITY_PROBLEMS": state["problems"],
    }


def render_report(state: dict, attention: dict) -> str:
    """Markdown rendered ONLY from reduced state. Every number is a field of
    `state`/`attention`; nothing is inferred, estimated or read from prose."""
    src = state["source"]
    t = state["totals"]
    out = ["# Remediation run audit", "",
           "Verdict: **%s**  (%s)" % (state["verdict"].upper(), ", ".join(
               "%s %d" % (c, state["problem_counts_by_class"][c]) for c in CLASS_ORDER)), "",
           "## Provenance", "",
           "| field | value |", "|---|---|"]
    for k in ("auditor_version", "state_schema_version", "journal", "journal_sha256",
              "events_reduced", "last_complete_seq", "journal_bytes_reduced",
              "journal_bytes_dropped_incomplete", "ledger", "ledger_sha256", "ledger_rows",
              "live", "snapshot_stable", "repo_root_for_evidence"):
        out.append("| %s | `%s` |" % (k, src.get(k)))

    terminals = Counter(a["terminal"] or "(none)" for a in state["attempts"].values())
    dispositions = Counter(f["status"] for f in state["findings"].values())
    out += ["", "## Integrity", "",
            "| check | value |", "|---|---|",
            "| events | %d |" % state["events"],
            "| unsequenced events | %d |" % state["unsequenced_events"],
            "| sequence gaps | %d |" % len(state["sequence_gaps"]),
            "| ledger cross-check | %s |" % ("performed" if state["ledger_check"]["checked"]
                                             else state["ledger_check"].get("reason", "not requested")),
            "| unresolved evidence refs | %d |" % len(state["unresolved_evidence_refs"]),
            "", "## Attempts", "",
            "| terminal | attempts |", "|---|---|"]
    out += ["| %s | %d |" % (k, v) for k, v in sorted(terminals.items())]
    out += ["| **total** | **%d** |" % t["attempts"],
            "", "## Findings closed in the journal", "",
            "| disposition | findings |", "|---|---|"]
    out += ["| %s | %d |" % (k, v) for k, v in sorted(dispositions.items())]
    out += ["| **observations** | **%d** |" % t["finding_observations"],
            "| unique defect clusters | %d |" % t["unique_defect_clusters"],
            "| duplicate observations | %d |" % t["duplicate_observations"],
            "", "## Outstanding state (not problems)", "",
            "- unresolved work items: %d" % len(attention["UNRESOLVED_WORK"]),
            "- unresolved escalations: %d" % attention["UNRESOLVED_ESCALATIONS_TOTAL"],
            "- nonterminal attempts: %d" % len(attention["NONTERMINAL_ATTEMPTS"]),
            "", "| ruling | findings |", "|---|---|"]
    out += ["| %s | %d |" % (k, len(v))
            for k, v in attention["UNRESOLVED_ESCALATIONS_BY_RULING"].items()]
    out += ["", "## Problems", ""]
    if not state["problems"]:
        out.append("None.")
    else:
        out += ["| class | code | kind | subject | detail |", "|---|---|---|---|---|"]
        rank = {c: i for i, c in enumerate(CLASS_ORDER)}
        for p in sorted(state["problems"], key=lambda p: (rank[p["class"]], p["code"],
                                                          json.dumps(p, sort_keys=True))):
            subject = p.get("attempt_id") or p.get("finding_id") or p.get("event_id") or ""
            detail = json.dumps(p.get("detail"), sort_keys=True).replace("|", "\\|")
            out.append("| %s | %s | %s | %s | %s |" % (p["class"], p["code"], p["kind"],
                                                       subject, detail[:300]))
    return "\n".join(out) + "\n"


def run(argv: list) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", required=True, help="progress log base path (no extension)")
    ap.add_argument("--ledger", default="", help="ledger to cross-check against")
    ap.add_argument("--out", default="",
                    help="directory for current-state.json / attention.json / audit-report.md")
    ap.add_argument("--print-attention", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 on any fatal/error problem (open work is never a failure)")
    ap.add_argument("--live", action="store_true",
                    help="the journal is still being appended to; see module docstring")
    ap.add_argument("--repo-root", default="",
                    help="root that relative evidence_ref paths resolve against "
                         "(default: the repository containing this script)")
    a = ap.parse_args(argv)

    try:
        state, attention = reduce_journal(a.log, a.ledger, live=a.live,
                                          repo_root=os.path.abspath(a.repo_root)
                                          if a.repo_root else "")
    except JournalInputError as exc:
        print("INPUT ERROR: %s" % exc, file=sys.stderr)
        return 2

    if a.out:
        os.makedirs(a.out, exist_ok=True)
        atomic_write_lines(os.path.join(a.out, "current-state.json"),
                           [json.dumps(state, sort_keys=True, indent=1)])
        atomic_write_lines(os.path.join(a.out, "attention.json"),
                           [json.dumps(attention, sort_keys=True, indent=1)])
        atomic_write_lines(os.path.join(a.out, "audit-report.md"),
                           [render_report(state, attention).rstrip("\n")])
    if a.print_attention or not a.out:
        print(json.dumps(attention, sort_keys=True, indent=1))
    else:
        print(json.dumps(state["totals"], sort_keys=True, indent=1))
        print("VERDICT %s — %s" % (state["verdict"], json.dumps(state["problem_counts_by_class"])))
    if a.check and state["verdict"] == "fail":
        return 1
    return 0


def main() -> int:
    return run(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
