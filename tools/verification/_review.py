# SPDX-License-Identifier: Apache-2.0
"""Human review as evidence about a fingerprint — ADR-MCPRE-059 §14.7.

An approval is never a field of the object approved. It is a record that says *which
fingerprint* was reviewed, stored beside the thing it reviews and compared against the
fingerprint of the tree as it stands. Freshness of a review is therefore derived exactly as
proof freshness is derived, and there is nothing for a reviewer to remember to update:

    formal evidence          measured_fingerprint  = F   (attestation, `_evidence`)
    specification review     reviewed_fingerprint  = F   (theorem fingerprint)
    assumption review        reviewed_fingerprint  = A   (assumption entry digest)
    local security audit     audited_fingerprint   = F   (unit fingerprint)

Four axes, kept apart. A single green/red bit would let a passing prover answer for an
unreviewed specification, which is the substitution this whole layer exists to refuse.

## Why these records are source, and attestations are not

`.verification/` is gitignored: every attestation in it is re-derivable by re-running a
lane. A human approval is not re-derivable — nothing CI can run reproduces a person having
read a claim. Gitignoring it would make the axis permanently `UNREVIEWED` on every clone,
and an axis that can never be satisfied is an axis that gets routed around.

So review records live in `verification/reviews/`, in the tree, and approving is a commit.
That is the same trust model `assumptions.toml` already uses for owner ratification: the
audit trail is the history, and the record names a fingerprint, so an approval that does not
match the tree announces itself rather than passing quietly.

This module also derives the second, separate property ADR-MCPRE-059 §28.8 defines: root
completeness. Freshness asks whether the registry still describes the tree; completeness
asks whether the claims ratified as system promises are closed. Neither implies the other,
and `root_completeness` is kept out of `theorem_assurance` so the two can never be reported
as one number.

Fail-closed everywhere. Missing record, unparsable record, unknown axis, a component the
current schema cannot compare — every one is unreviewed or dirty. There is no path here
from "I could not establish that this was reviewed" to `REVIEWED`.
"""

from __future__ import annotations

import json
from pathlib import Path

#: The review axes, closed. A record naming anything else resolves to no axis and is
#: dropped — an unknown axis must not be counted as some default one.
AXES = {"specification", "assumption", "audit"}

#: What a subject id must look like on each axis, so a record cannot approve a theorem
#: under the assumption axis and have it read as either.
_SUBJECT_PREFIX = {"specification": "THM-", "assumption": "ASM-"}

#: The record schema, CLOSED. Closed rather than filtered against a list of forbidden
#: names, because an approval bit is only one of the things a record must not carry: any
#: key outside this set is a fact this schema cannot compare, and a record carrying one
#: would be read as approving something it never described. `approved`, `status` and the
#: rest are refused by this rule, not by a second list that could drift out of step with
#: it. The repository-wide named-key scan lives in `scripts/registry_approval_gate.py`,
#: where documents are arbitrary and a closed schema is not available.
_RECORD_KEYS = {"axis", "subject", "reviewed_fingerprint", "components", "reviewer", "notes"}
_RECORD_REQUIRED = {"axis", "subject", "reviewed_fingerprint", "reviewer"}

#: Which moved component produces which cause. Same shape as `_graph.COMPONENT_STATE`, and
#: for the same reason: "this review is stale" without naming what moved sends the reviewer
#: to re-read everything.
COMPONENT_CAUSE = {
    "theorem_claim": "STALE_CLAIM",
    "theorem_dependencies": "STALE_DEPENDENCY_CLAIM",
    "theorem_review_requirement": "STALE_REVIEW_REQUIREMENT",
}

#: Review states. `UNREVIEWED` and `STALE_*` are both "not reviewed as it stands now", and
#: they stay apart because the remedy differs: one has never been read, the other was read
#: at something else.
UNREVIEWED = "UNREVIEWED"
REVIEWED = "REVIEWED"
UNKNOWN = "UNKNOWN"
#: A record that is out of date and cannot say what moved, because it recorded no
#: components. Distinct from the `STALE_*` causes, which can.
STALE_REVIEW = "STALE_REVIEW"

#: Every state this module can return. Anything not `REVIEWED` withholds establishment.
REVIEW_STATES = {UNREVIEWED, REVIEWED, UNKNOWN, STALE_REVIEW, "STALE_INPUT"} | set(
    COMPONENT_CAUSE.values()
)


def review_root(repo_root: Path) -> Path:
    return repo_root / "verification" / "reviews"


def _valid(raw: object) -> dict | None:
    """One record, or None if anything about it is off. Dropped, never repaired."""
    if not isinstance(raw, dict):
        return None
    if set(raw) - _RECORD_KEYS or not _RECORD_REQUIRED <= set(raw):
        return None
    if raw["axis"] not in AXES:
        return None
    subject = raw["subject"]
    prefix = _SUBJECT_PREFIX.get(raw["axis"])
    if not isinstance(subject, str) or (prefix and not subject.startswith(prefix)):
        return None
    if not isinstance(raw["reviewed_fingerprint"], str) or not raw[
        "reviewed_fingerprint"
    ].startswith("sha256:"):
        return None
    if not isinstance(raw.get("reviewer"), str) or not raw["reviewer"].strip():
        return None
    return raw


def load_reviews(root: Path) -> dict[tuple[str, str], dict]:
    """Every review record, keyed by `(axis, subject)`.

    A malformed record is DROPPED, so its subject has no review, which derives to
    `UNREVIEWED`. Raising instead would let one bad file hide every good one; repairing
    would invent the provenance the record exists to carry.
    """
    out: dict[tuple[str, str], dict] = {}
    if not root.exists():
        return out
    for path in sorted(root.rglob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        record = _valid(raw)
        if record is None:
            continue
        out[(record["axis"], record["subject"])] = record
    return out


def derive_review_state(current: dict, record: dict | None) -> tuple[str, str]:
    """Whether a review covers the subject AS IT STANDS, and if not, what moved.

    `current` is a fingerprint mapping (`fingerprint` + `components`), the same shape
    `_fingerprint` produces for both units and theorems.
    """
    if record is None:
        return UNREVIEWED, "no review record: this has never been reviewed"

    recorded = record.get("components")
    if isinstance(recorded, dict) and recorded:
        comparable = {
            name: value
            for name, value in current["components"].items()
            if name != "encoding_version"
        }
        missing = sorted(name for name in comparable if name not in recorded)
        if missing:
            return (
                UNKNOWN,
                f"the review records no `{', '.join(missing)}`: it predates the current "
                f"encoding, so what was reviewed cannot be compared",
            )
        differing = sorted(
            name for name, value in comparable.items() if recorded[name] != value
        )
        if differing:
            cause = sorted(COMPONENT_CAUSE.get(name, "STALE_INPUT") for name in differing)[0]
            return cause, "changed since review: " + ", ".join(differing)
        if record["reviewed_fingerprint"] != current["fingerprint"]:
            # Every recorded component matches and the digest does not: the encoding itself
            # changed, so the comparison means something different from what it meant when
            # the reviewer signed. Same rule as `_graph`, and for the same reason.
            return (
                UNKNOWN,
                "every recorded component matches but the fingerprint does not: the "
                "encoding changed, so what was reviewed cannot be compared",
            )
        return REVIEWED, f"reviewed at {current['fingerprint'][7:23]}"

    # A record with no components can still say WHETHER it is current; it just cannot say
    # what moved. That is a weaker record, not an invalid one, and it must never read as
    # fresher than one that can name the cause.
    if record["reviewed_fingerprint"] != current["fingerprint"]:
        return (
            STALE_REVIEW,
            f"reviewed at {record['reviewed_fingerprint'][7:23]} but this now fingerprints "
            f"{current['fingerprint'][7:23]}; the record names no components, so what moved "
            f"cannot be derived",
        )
    return REVIEWED, f"reviewed at {current['fingerprint'][7:23]}"


def theorem_assurance(
    theorems: dict,
    theorem_fingerprints: dict[str, dict],
    reviews: dict[tuple[str, str], dict],
    unit_states: dict[str, tuple[str, str]],
) -> dict[str, dict]:
    """The conjunction — the one place the word "established" is earned.

    A theorem is ESTABLISHED only when every axis holds at once:

        structural support   some unit supports it, and it is not deprecated
        unit evidence        every supporting unit derives FRESH
        dependencies         every theorem it depends on is itself established
        specification review the owner's review covers the CURRENT theorem fingerprint

    Assumption review rides along inside the unit axis: an assumption entry that moved
    dirties its unit's `trusted_assumptions` component, so the unit is not FRESH and the
    conjunction already fails. That is composition, not omission — no second rule.

    Anything unresolvable is not established. There is deliberately no "mostly" state: the
    reason the registry reports structural support separately (T1) is so that this function
    can be the only thing entitled to say a claim holds.
    """
    entries = {row["id"]: row for row in theorems.get("theorem", [])}
    result: dict[str, dict] = {}
    for theorem_id, entry in entries.items():
        supporting = [str(t).removeprefix("unit://") for t in entry.get("supported_by", [])]
        unit_axis = [unit_states.get(unit, ("UNKNOWN", "not declared")) for unit in supporting]
        spec_state, spec_reason = derive_review_state(
            theorem_fingerprints[theorem_id],
            reviews.get(("specification", theorem_id)),
        )
        result[theorem_id] = {
            "deprecated": bool(entry.get("replaced_by")),
            "supporting_units": supporting,
            "unit_states": {unit: state for unit, (state, _) in zip(supporting, unit_axis)},
            "specification_review": (spec_state, spec_reason),
            "established": False,
        }

    # Fixpoint over `depends_on`, so a premise that loses any axis takes every claim above
    # it with it. Start optimistic on the local axes only, then subtract.
    for theorem_id, state in result.items():
        entry = entries[theorem_id]
        state["established"] = (
            not state["deprecated"]
            and bool(state["supporting_units"])
            and all(unit_state == "FRESH" for unit_state in state["unit_states"].values())
            and state["specification_review"][0] == REVIEWED
        )
    changed = True
    while changed:
        changed = False
        for theorem_id, state in result.items():
            if not state["established"]:
                continue
            for dep in entries[theorem_id].get("depends_on", []):
                if not result.get(dep, {}).get("established"):
                    state["established"] = False
                    changed = True
                    break
    return result


#: Root-completeness verdicts. `UNDECLARED` exists so that "no system promise is stated"
#: can never be printed as good news: a repository that declares no root has nothing to be
#: complete about, and reporting PASS there would make the emptiest registry the greenest.
COMPLETE = "COMPLETE"
INCOMPLETE = "INCOMPLETE"
UNDECLARED = "UNDECLARED"


def closure_satisfied(roots: dict) -> bool:
    """Whether closure mode may pass — ADR-MCPRE-059 §28.8.

    Only `COMPLETE`. `UNDECLARED` fails here as surely as `INCOMPLETE`: a release that
    states no system promise has not established one, and the emptiest registry must never
    be the greenest.
    """
    return roots["verdict"] == COMPLETE


def _blocking_cause(state: dict) -> str:
    """Why one node in a root's closure is not established, in the reviewer's vocabulary.

    `GAP` is the ADR-MCPRE-059 §28.5 terminal and it is DERIVED, never stored: a ratified
    claim with a real owner and no resolving support closure IS the gap. The other causes
    are not gaps — they are established claims whose evidence or review has gone stale, and
    sending a reviewer to look for missing architecture would waste the trip.
    """
    if state["deprecated"]:
        return "DEPRECATED: a withdrawn claim establishes nothing"
    if not state["supporting_units"]:
        return "GAP: ratified claim, real owner, no support closure — evidence does not exist"
    dirty = sorted(
        f"unit://{unit} {unit_state}"
        for unit, unit_state in state["unit_states"].items()
        if unit_state != "FRESH"
    )
    if dirty:
        return "EVIDENCE: " + ", ".join(dirty)
    review_state, reason = state["specification_review"]
    if review_state != REVIEWED:
        return f"SPECIFICATION REVIEW {review_state}: {reason}"
    return "DEPENDENCY: every local axis holds; a premise below it does not"


def root_completeness(theorems: dict, assurance: dict[str, dict]) -> dict:
    """Whether every DECLARED system root is established — ADR-MCPRE-059 §28.8.

    This is not evidence freshness and must never be reported as though it were. Freshness
    asks whether what the registry claims still describes the tree; completeness asks
    whether the claims the owner ratified as system promises are closed. A registry can be
    entirely fresh and entirely incomplete, and that combination is the normal state of a
    campaign in progress — which is precisely why an honest unresolved GAP must not fail
    ordinary CI (§28.8): a gate that punishes recording an obligation teaches people not to
    record it.

    The roots are read from the declaration, never inferred from the shape of the graph.

    For each unestablished root the whole `depends_on` closure is walked, so the report
    names the nodes that actually block it rather than only the root itself. A root three
    levels above a missing leaf is not informative on its own.
    """
    entries = {row["id"]: row for row in theorems.get("theorem", [])}
    roots = list(theorems.get("root_theorems", []))

    blocking: dict[str, list[dict]] = {}
    for root in roots:
        if assurance.get(root, {}).get("established"):
            continue
        seen: set[str] = set()
        stack = [root]
        found: list[dict] = []
        while stack:
            node = stack.pop()
            if node in seen or node not in entries:
                continue
            seen.add(node)
            state = assurance.get(node)
            if state is None or state["established"]:
                continue
            found.append({"theorem": node, "cause": _blocking_cause(state)})
            stack.extend(entries[node].get("depends_on", []))
        blocking[root] = sorted(found, key=lambda row: row["theorem"])

    if not roots:
        verdict = UNDECLARED
    elif blocking:
        verdict = INCOMPLETE
    else:
        verdict = COMPLETE
    return {
        "verdict": verdict,
        "roots": roots,
        "established_roots": [r for r in roots if r not in blocking],
        "blocking": blocking,
    }
