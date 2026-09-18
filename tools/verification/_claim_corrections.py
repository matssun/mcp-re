# SPDX-License-Identifier: Apache-2.0
"""Recorded ADR-MCPRE-068 Phase-1 claim corrections — §14.7, and what it is NOT.

A theorem's `theorem_claim` is `statement + security_consequence + scope`, so correcting any
of them moves the fingerprint and the owner's specification review goes stale. That is
correct and stays correct: `scripts/claim_surface_gate.py` refuses to publish a claim nobody
has approved in its present form, and this module does not soften that rule.

What it adds is the ability to tell two things apart that the gate could not:

    an ARBITRARY claim edit          nothing says what moved, why, or from what
    a RECORDED Phase-1 correction    a signed-off campaign ruling authorizes a class of
                                     precision and dependency corrections, and each one
                                     carries the old text, the new text, the reason from the
                                     decomposition, and the assertions that make it that
                                     class rather than a different one

The owner's ruling of 2026-09-18 is the authority, and it is narrow:

> Phase 1 already authorizes correction of a theorem statement when decomposition
> demonstrates that the old wording overstates or misdescribes what production establishes,
> **provided the accepted system promise is not weakened, removed, or materially expanded.**

## The chain, and why it starts at the owner

A correction record names `from_fingerprint` and `to_fingerprint`. A theorem's corrections
are accepted only when they form an UNBROKEN chain whose first link starts at the fingerprint
the owner's specification review actually covers, and whose last link ends at the fingerprint
the tree has now.

That is what keeps the owner's review the base of the authority rather than a thing routed
around: a correction is a recorded DELTA on a reviewed claim, and a claim with no review to
start from has nothing to correct. It is also one-shot — the next edit produces a fingerprint
no record names, and the gate refuses again.

## What is deliberately NOT changed

`derive_review_state` still returns `STALE_CLAIM`. The specification-review axis is about
whether a human read THIS text, and a correction record is not a human reading it. So:

    merge path      a recorded correction publishes            (this module)
    release path    establishment still needs the owner's review (`_review`, unchanged)

An ADR-MCPRE-059 §28.8 closure run therefore still asks for the human, which is the honest
place for that question and the reason this module may exist at all. Recording a correction
as an approval would be the single-command self-approval §14.7 exists to prevent.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Where correction records live — in the tree, beside the reviews they extend, for the
#: reason `_review` gives: a record that is not in the tree cannot be audited from a clone.
CORRECTIONS_DIR = ("reviews", "claim-corrections")

#: The record schema, CLOSED. Same rule as `_review._RECORD_KEYS`: a key outside this set is
#: a fact this schema cannot compare, and a record carrying one would be read as authorizing
#: something it never described.
_KEYS = {
    "subject",
    "authority",
    "ruling",
    "packet",
    "from_fingerprint",
    "to_fingerprint",
    "changed_components",
    "corrections",
    "reason",
    "root_consequence_unchanged",
    "product_behavior_unchanged",
    "severity_before",
    "severity_after",
    "severity_justification",
    "dependency_correction",
}
_OPTIONAL = {"severity_justification", "dependency_correction"}

#: The authorities a record may claim, CLOSED. A record naming anything else is refused
#: rather than read as some default — "authorized by something" is not an authority.
AUTHORITIES = {"adr-068-phase1"}

#: What the gate may be asked to accept a correction over. `theorem_review_requirement` is
#: deliberately absent: relaxing WHO must review a claim is not a precision correction, and a
#: record could not assert it away.
CORRECTABLE_COMPONENTS = {"theorem_claim", "theorem_dependencies"}

#: A per-correction entry inside `corrections`, CLOSED.
_CORRECTION_KEYS = {"id", "field", "old", "new", "reason"}

#: The fields of a claim a correction may be about.
_CORRECTION_FIELDS = {"statement", "security_consequence", "scope", "depends_on"}


class CorrectionError(Exception):
    """A record this module refuses. Fail-closed: never a silently ignored file."""


def corrections_root(repo_root: Path) -> Path:
    return repo_root.joinpath("verification", *CORRECTIONS_DIR)


def _validate(raw: object, where: str) -> dict:
    if not isinstance(raw, dict):
        raise CorrectionError(f"{where}: not a JSON object")
    unknown = set(raw) - _KEYS
    if unknown:
        raise CorrectionError(f"{where}: unknown key(s) {sorted(unknown)}")
    missing = _KEYS - _OPTIONAL - set(raw)
    if missing:
        raise CorrectionError(f"{where}: missing required key(s) {sorted(missing)}")
    if not str(raw["subject"]).startswith("THM-"):
        raise CorrectionError(f"{where}: subject {raw['subject']!r} is not a theorem id")
    if raw["authority"] not in AUTHORITIES:
        raise CorrectionError(
            f"{where}: authority {raw['authority']!r} is not one of {sorted(AUTHORITIES)}. "
            f"A record may not name an authority this module cannot check."
        )
    if not str(raw.get("ruling", "")).strip():
        raise CorrectionError(
            f"{where}: `ruling` is empty. The record must name the ruling that authorizes "
            f"it, or it authorizes itself."
        )
    if not str(raw.get("reason", "")).strip():
        raise CorrectionError(
            f"{where}: `reason` is empty. A correction without the reason from the "
            f"decomposition is an arbitrary edit with a filename."
        )
    for flag in ("root_consequence_unchanged", "product_behavior_unchanged"):
        if raw.get(flag) is not True:
            raise CorrectionError(
                f"{where}: `{flag}` is {raw.get(flag)!r}, not true. The ruling authorizes "
                f"corrections that leave the accepted promise and the product boundary "
                f"alone; a record that cannot assert both is outside it and is an owner "
                f"escalation, not a correction."
            )
    changed = raw.get("changed_components")
    if not isinstance(changed, list) or not changed:
        raise CorrectionError(f"{where}: `changed_components` must be a non-empty list")
    outside = sorted(set(map(str, changed)) - CORRECTABLE_COMPONENTS)
    if outside:
        raise CorrectionError(
            f"{where}: `changed_components` names {outside}, outside "
            f"{sorted(CORRECTABLE_COMPONENTS)}. Those are not corrections this ruling covers."
        )
    if raw["severity_before"] != raw["severity_after"] and not str(
        raw.get("severity_justification", "")
    ).strip():
        raise CorrectionError(
            f"{where}: severity moves {raw['severity_before']!r} -> "
            f"{raw['severity_after']!r} with no `severity_justification`. The ruling allows "
            f"a severity change only when independently justified."
        )
    entries = raw.get("corrections")
    if not isinstance(entries, list) or not entries:
        raise CorrectionError(
            f"{where}: `corrections` is empty. The durable old->new record IS the artefact; "
            f"a record with no entries documents nothing."
        )
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        ewhere = f"{where} corrections[{index}]"
        if not isinstance(entry, dict):
            raise CorrectionError(f"{ewhere}: not an object")
        unknown = set(entry) - _CORRECTION_KEYS
        if unknown:
            raise CorrectionError(f"{ewhere}: unknown key(s) {sorted(unknown)}")
        missing = _CORRECTION_KEYS - set(entry)
        if missing:
            raise CorrectionError(f"{ewhere}: missing key(s) {sorted(missing)}")
        if entry["field"] not in _CORRECTION_FIELDS:
            raise CorrectionError(
                f"{ewhere}: field {entry['field']!r} not one of {sorted(_CORRECTION_FIELDS)}"
            )
        if entry["id"] in seen:
            raise CorrectionError(f"{ewhere}: duplicate correction id {entry['id']!r}")
        seen.add(entry["id"])
        if entry["old"] == entry["new"]:
            raise CorrectionError(
                f"{ewhere}: `old` equals `new`. A correction that changes nothing is a row "
                f"that will outlive the reason it was written for."
            )
        if not str(entry.get("reason", "")).strip():
            raise CorrectionError(f"{ewhere}: `reason` is empty")
    return raw


def _packet_defect(record: dict, repo_root: Path, where: str) -> str | None:
    """The packet a record names must be a file this tree holds.

    The same rule the module-size and obligation registries follow for `review_ref` and
    `decomposition_ref`: a record that points at reasoning nobody can read is a record whose
    reason cannot be checked, and the reason IS the thing that makes it a correction rather
    than an edit.
    """
    packet = str(record.get("packet", "")).strip()
    if not packet:
        return f"{where}: `packet` is empty"
    if not (repo_root / packet).is_file():
        return (
            f"{where}: names packet {packet!r}, which this tree does not hold. A correction "
            f"points at the decomposition that justifies it, not at a memory of one."
        )
    return None


def load_corrections(root: Path, repo_root: Path | None = None) -> dict[str, list[dict]]:
    """Every record on disk, grouped by subject, ordered by the chain they form.

    UNPARSABLE IS A FAILURE, not an omission. `_review.load_reviews` may drop a bad record
    because dropping one leaves an axis UNREVIEWED, which withholds establishment. Here the
    opposite is true: dropping a record would remove the thing a gate is about to consult,
    and the gate would then report the plain staleness defect for a reason that is not the
    real one. So this raises.
    """
    out: dict[str, list[dict]] = {}
    if not root.is_dir():
        return out
    for path in sorted(root.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CorrectionError(f"{path.name}: unreadable ({exc})") from exc
        record = _validate(raw, path.name)
        if repo_root is not None:
            defect = _packet_defect(record, repo_root, path.name)
            if defect:
                raise CorrectionError(defect)
        out.setdefault(str(record["subject"]), []).append(record)
    return out


def chain(
    records: list[dict], reviewed_fingerprint: str | None, current_fingerprint: str
) -> tuple[bool, str]:
    """Whether `records` carry `reviewed_fingerprint` all the way to `current_fingerprint`.

    Returns (accepted, reason). The chain must be TOTAL: every record for the subject
    participates, because a record that names no link in the walk is a dead row, and a dead
    row hides the next live one — the same rule the module-size and obligation registries
    follow.
    """
    if not records:
        return False, "no correction record"
    if not reviewed_fingerprint:
        return False, (
            "no specification review to correct from: a correction is a delta on a claim "
            "the owner reviewed, and there is no such claim here"
        )
    by_from = {str(r["from_fingerprint"]): r for r in records}
    if len(by_from) != len(records):
        return False, "two records start from the same fingerprint; the chain is ambiguous"
    walked: list[dict] = []
    cursor = reviewed_fingerprint
    while cursor in by_from:
        record = by_from[cursor]
        walked.append(record)
        cursor = str(record["to_fingerprint"])
        if len(walked) > len(records):
            return False, "the correction records form a cycle"
    if cursor != current_fingerprint:
        return False, (
            f"the correction chain ends at {cursor[7:23]} and the tree is at "
            f"{current_fingerprint[7:23]}: the claim moved again after the last recorded "
            f"correction"
        )
    if len(walked) != len(records):
        dead = sorted(
            str(r["from_fingerprint"])[7:23] for r in records if r not in walked
        )
        return False, (
            f"{len(records) - len(walked)} correction record(s) are not on the chain "
            f"(from {dead}). A record that authorizes no live transition is a dead row."
        )
    ids = [c["id"] for r in walked for c in r["corrections"]]
    return True, (
        f"corrected under {walked[-1]['authority']} in {len(walked)} recorded step(s), "
        f"{len(ids)} correction(s): {', '.join(ids)}"
    )
