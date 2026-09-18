#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""What a recorded ADR-MCPRE-068 Phase-1 claim correction may and may not buy.

The module exists to let a gate tell a recorded correction from an arbitrary claim edit. A
test suite for it is therefore mostly about the SECOND half: every way a record could be
written that must NOT be accepted. A mechanism that only ever says yes would be the
claim-surface gate switched off with extra steps.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _claim_corrections import (  # noqa: E402
    CorrectionError,
    chain,
    load_corrections,
)

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"  — {detail}" if not ok and detail else ""))
    if not ok:
        FAILURES.append(name)


A, B, C = "sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64


def record(**over) -> dict:
    base = {
        "subject": "THM-0001",
        "authority": "adr-068-phase1",
        "ruling": "the campaign ruling of 2026-09-18",
        "packet": "verification/reviews/packets/x.md",
        "from_fingerprint": A,
        "to_fingerprint": B,
        "changed_components": ["theorem_claim"],
        "reason": "the decomposition measured the old wording as unreachable",
        "root_consequence_unchanged": True,
        "product_behavior_unchanged": True,
        "severity_before": "critical",
        "severity_after": "critical",
        "corrections": [
            {"id": "C1", "field": "statement", "old": "o", "new": "n", "reason": "why"}
        ],
    }
    base.update(over)
    return base


def load_one(raw: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "r.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        return load_corrections(Path(tmp))


def refuses(name: str, raw: dict, expect: str) -> None:
    try:
        load_one(raw)
    except CorrectionError as exc:
        check(name, expect in str(exc), f"got {exc}")
        return
    check(name, False, "the record was ACCEPTED")


print("where the register lives")
from _claim_corrections import corrections_root  # noqa: E402

_repo = Path(__file__).resolve().parents[2]
check(
    "the register is NOT under verification/reviews/",
    _repo / "verification" / "reviews" not in corrections_root(_repo).parents,
    "scripts/registry_approval_gate.py requires every record under reviews/ to name a "
    "reviewed_fingerprint, and a correction is not a review",
)
check(
    "the register is under verification/",
    (_repo / "verification") in corrections_root(_repo).parents,
    "a record that is not in the tree cannot be audited from a clone",
)

print("\nthe record schema")
check("a well-formed record loads", bool(load_one(record())))
refuses("an unknown key is refused", {**record(), "approved": True}, "unknown key")
refuses("a missing key is refused", {k: v for k, v in record().items() if k != "reason"}, "missing required key")
refuses("a non-theorem subject is refused", record(subject="ASM-0001"), "not a theorem id")
refuses("an unknown authority is refused", record(authority="because-i-said-so"), "not one of")
refuses("an empty ruling is refused", record(ruling="   "), "authorizes itself")
refuses("an empty reason is refused", record(reason=""), "arbitrary edit with a filename")
refuses(
    "a record that will not assert the promise is unchanged is refused",
    record(root_consequence_unchanged=False),
    "owner escalation, not a correction",
)
refuses(
    "a record that will not assert the product boundary is unchanged is refused",
    record(product_behavior_unchanged=False),
    "owner escalation, not a correction",
)
refuses(
    "correcting the review REQUIREMENT is refused",
    record(changed_components=["theorem_review_requirement"]),
    "not corrections this ruling covers",
)
refuses(
    "an unjustified severity change is refused",
    record(severity_before="critical", severity_after="medium"),
    "independently justified",
)
check(
    "a JUSTIFIED severity change is admitted",
    bool(load_one(record(severity_before="critical", severity_after="medium",
                         severity_justification="the consequence was re-derived from the leaf"))),
)
refuses("an empty corrections list is refused", record(corrections=[]), "documents nothing")
refuses(
    "a correction whose old equals its new is refused",
    record(corrections=[{"id": "C1", "field": "statement", "old": "s", "new": "s", "reason": "r"}]),
    "changes nothing",
)
refuses(
    "a correction naming a field outside the claim is refused",
    record(corrections=[{"id": "C1", "field": "owner", "old": "a", "new": "b", "reason": "r"}]),
    "not one of",
)
refuses(
    "duplicate correction ids are refused",
    record(corrections=[
        {"id": "C1", "field": "statement", "old": "a", "new": "b", "reason": "r"},
        {"id": "C1", "field": "scope", "old": "a", "new": "b", "reason": "r"},
    ]),
    "duplicate correction id",
)

print("\nthe packet a record points at")
def packet_case(name, packet, expect):
    import tempfile as _t
    with _t.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "verification" / "reviews" / "packets").mkdir(parents=True)
        (root / "verification" / "reviews" / "packets" / "real.md").write_text("x")
        recs = root / "recs"
        recs.mkdir()
        (recs / "r.json").write_text(json.dumps(record(packet=packet)), encoding="utf-8")
        try:
            load_corrections(recs, root)
        except CorrectionError as exc:
            check(name, expect is not None and expect in str(exc), f"got {exc}")
            return
        check(name, expect is None, "the record was ACCEPTED")

packet_case("a packet this tree holds is admitted", "verification/reviews/packets/real.md", None)
packet_case("a packet this tree lacks is refused", "verification/reviews/packets/nope.md", "does not hold")
packet_case("an empty packet is refused", "   ", "`packet` is empty")

print("\nthe chain")
check("a single link from the reviewed fingerprint is accepted", chain([record()], A, B)[0])
check(
    "two links chain",
    chain([record(), record(from_fingerprint=B, to_fingerprint=C)], A, C)[0],
)
check(
    "a chain that does not START at the review is refused",
    not chain([record()], C, B)[0],
    chain([record()], C, B)[1],
)
check(
    "NO review to correct from is refused",
    not chain([record()], None, B)[0],
    "a correction is a delta on a reviewed claim",
)
check(
    "a chain that does not END at the tree is refused",
    not chain([record()], A, C)[0],
)
check(
    "a record off the chain is a DEAD ROW and fails",
    not chain([record(), record(from_fingerprint=C, to_fingerprint=A)], A, B)[0],
)
check("no record at all is refused", not chain([], A, B)[0])
check(
    "two records from the same fingerprint are ambiguous and refused",
    not chain([record(), record(to_fingerprint=C)], A, B)[0],
)
check(
    "a cycle terminates and is refused",
    not chain([record(), record(from_fingerprint=B, to_fingerprint=A)], A, C)[0],
)

print("\nTHE PROPERTY THE WHOLE MECHANISM IS FOR")
# An arbitrary edit is exactly the case where the tree has moved and no record names the
# move. It must be indistinguishable, to this module, from any other unrecorded edit.
check(
    "an unrecorded edit after a recorded correction is refused",
    not chain([record()], A, C)[0],
    "the claim moved again after the last recorded correction",
)
check(
    "the refusal SAYS the claim moved again",
    "moved again" in chain([record()], A, C)[1],
)

print(f"\n{len(FAILURES)} failure(s)")
sys.exit(1 if FAILURES else 0)
