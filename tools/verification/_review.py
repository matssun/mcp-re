# SPDX-License-Identifier: Apache-2.0
"""Human review as evidence about a fingerprint — ADR-MCPRE-059 §14.7.

An approval is never a field of the object approved. It is a record that says *which
fingerprint* was reviewed, stored beside the thing it reviews and compared against the
fingerprint of the tree as it stands. Freshness of a review is therefore derived exactly as
proof freshness is derived, and there is nothing for a reviewer to remember to update:

    formal evidence          measured_fingerprint  = F   (attestation, `_evidence`)
    specification review     reviewed_fingerprint  = F   (theorem fingerprint)
                             review_digest         = R   (semantic evidence digest)
    assumption review        reviewed_fingerprint  = A   (assumption entry digest)
    local security audit     audited_fingerprint   = F   (unit fingerprint)

Four axes, kept apart. A single green/red bit would let a passing prover answer for an
unreviewed specification, which is the substitution this whole layer exists to refuse.

A specification review names TWO digests. `reviewed_fingerprint` is the claim surface —
statement, consequence, scope, dependency claims, review requirement — and is what the
claim-correction chain is about. `review_digest` (`_fingerprint.review_digest`) is what the
owner read the claim AGAINST: its premises, and the semantic inputs of every supporting
unit — source and specifications, the tests and probes selected, the proved and extracted
symbols. Ruling 35 §3 splits the theorem's verdict on exactly that line:

    REVIEW_CURRENT        claim, premises and semantic evidence are what the owner read
    EVIDENCE_ESTABLISHED  every supporting unit is FRESH: a run vouches for its full
                          fingerprint, toolchain, lane identities and policy included
    CURRENTLY_VERIFIED    both, and every theorem it depends on is currently verified

A toolchain or policy change makes evidence stale without asking for a re-read; an edit to
supporting source asks for both.

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
_RECORD_KEYS = {
    "axis",
    "subject",
    "reviewed_fingerprint",
    "components",
    "review_digest",
    "review_components",
    "reviewer",
    "notes",
}
_RECORD_REQUIRED = {"axis", "subject", "reviewed_fingerprint", "reviewer"}

#: Which moved component produces which cause. Same shape as `_graph.COMPONENT_STATE`, and
#: for the same reason: "this review is stale" without naming what moved sends the reviewer
#: to re-read everything.
COMPONENT_CAUSE = {
    "theorem_claim": "STALE_CLAIM",
    "theorem_dependencies": "STALE_DEPENDENCY_CLAIM",
    "theorem_review_requirement": "STALE_REVIEW_REQUIREMENT",
}

#: Precedence when SEVERAL components moved at once — the same device as
#: `_graph.STATE_PRECEDENCE`, and added for the same reason it exists there: the reviewer
#: should be told the most fundamental cause, not an incidental one.
#:
#: It was `sorted(causes)[0]`, which is alphabetical order, and alphabetical order happened
#: to put `STALE_CLAIM` first. That is correct by accident, not by construction: the next
#: cause anyone adds decides its own rank by its spelling, and a name beginning with
#: `STALE_A…` would mask a moved claim behind it. The tie-break has to be a decision.
#:
#: `STALE_INPUT` leads, mirroring `UNKNOWN` in `_graph`: it means a component moved that
#: this schema has no name for, so the named causes cannot be assumed complete, and the
#: reviewer knows least about exactly that case. The three named causes then run from the
#: claim itself, through the premises beneath it, to who must review it.
CAUSE_PRECEDENCE = (
    "STALE_INPUT",
    "STALE_CLAIM",
    "STALE_DEPENDENCY_CLAIM",
    "STALE_REVIEW_REQUIREMENT",
)

#: Review states. `UNREVIEWED` and `STALE_*` are both "not reviewed as it stands now", and
#: they stay apart because the remedy differs: one has never been read, the other was read
#: at something else.
UNREVIEWED = "UNREVIEWED"
REVIEWED = "REVIEWED"
UNKNOWN = "UNKNOWN"
#: A record that is out of date and cannot say what moved, because it recorded no
#: components. Distinct from the `STALE_*` causes, which can.
STALE_REVIEW = "STALE_REVIEW"

#: A review record that matches the tree, for a subject the owner-approval ledger does not
#: back as it stands (`_approvals.ledger_state`): a record is a file anyone can commit, and
#: the ledger is where the owner's signature over the text is checked.
UNBACKED = "UNBACKED"
#: A theorem whose own specification review holds while an assumption in its premise closure
#: is not reviewed and backed at its current digest.
PREMISE_UNREVIEWED = "PREMISE_UNREVIEWED"

#: A specification record that matches the claim but carries no `review_digest`: it was
#: written before the semantic axis existed, so nothing says which supporting code, tests
#: and proved symbols the reviewer read. No digest is reconstructed for it — the review
#: cannot be shown current, and reads this until the owner re-reviews.
NO_SEMANTIC_DIGEST = "NO_SEMANTIC_DIGEST"
#: A specification record whose `review_digest` no longer matches: a premise, a supporting
#: unit's source or specification, its test or probe selection, or its proved symbols moved
#: since the owner read it.
STALE_SEMANTICS = "STALE_SEMANTICS"

#: Every state this module can return. Anything not `REVIEWED` withholds REVIEW_CURRENT.
REVIEW_STATES = {
    UNREVIEWED,
    REVIEWED,
    UNKNOWN,
    STALE_REVIEW,
    "STALE_INPUT",
    UNBACKED,
    PREMISE_UNREVIEWED,
    NO_SEMANTIC_DIGEST,
    STALE_SEMANTICS,
} | set(COMPONENT_CAUSE.values())


def _by_precedence(causes: set[str]) -> str:
    """The most fundamental cause among those that moved.

    An unranked cause sorts LAST rather than first: a cause nobody placed must not silently
    outrank one somebody did, and `REVIEW_STATES` plus the census in `test_theorem_review`
    keep the set from growing unnoticed.
    """
    for cause in CAUSE_PRECEDENCE:
        if cause in causes:
            return cause
    return sorted(causes)[0] if causes else "STALE_INPUT"


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
    if "review_digest" in raw and (
        not isinstance(raw["review_digest"], str) or not raw["review_digest"].startswith("sha256:")
    ):
        return None
    if "review_components" in raw and not isinstance(raw["review_components"], dict):
        return None
    if ("review_digest" in raw or "review_components" in raw) and raw["axis"] != "specification":
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
            cause = _by_precedence(
                {COMPONENT_CAUSE.get(name, "STALE_INPUT") for name in differing}
            )
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


def backed_review_state(
    current: dict, record: dict | None, backing: tuple[bool, str] | None
) -> tuple[str, str]:
    """`derive_review_state`, then the ledger cross-check.

    A record that matches the tree is `REVIEWED` only if `backing` — the subject's
    `_approvals.ledger_state` — says the owner's signature covers it. No backing supplied is
    not backed: the absence of a check is not a pass.
    """
    state, reason = derive_review_state(current, record)
    if state != REVIEWED:
        return state, reason
    if backing is None:
        return UNBACKED, "no owner-approval ledger check was supplied for this subject"
    backed, why = backing
    if not backed:
        return UNBACKED, f"{reason}, but {why}"
    return REVIEWED, f"{reason}; {why}"


def assumption_review_state(
    assumption_id: str,
    digest: str,
    reviews: dict[tuple[str, str], dict],
    backing: dict[str, tuple[bool, str]],
) -> tuple[str, str]:
    """One premise on the assumption axis: its review record against the entry's current
    digest (`_fingerprint.assumption_digest`), cross-checked against the ledger."""
    return backed_review_state(
        {"fingerprint": digest, "components": {"assumption_entry": digest}},
        reviews.get(("assumption", assumption_id)),
        backing.get(assumption_id),
    )


def semantic_review_state(current: dict | None, record: dict | None) -> tuple[str, str]:
    """Whether the owner's specification review covers the semantic evidence AS IT STANDS.

    `current` is `_fingerprint.review_digest` for the theorem, or None when it could not be
    computed. The record must carry the `review_digest` the reviewer read at; a record that
    does not is `NO_SEMANTIC_DIGEST`, whatever its claim fingerprint says.
    """
    if record is None:
        return UNREVIEWED, "no review record: this has never been reviewed"
    if current is None:
        return UNKNOWN, "the semantic evidence digest could not be computed"
    reviewed = record.get("review_digest")
    if reviewed is None:
        return (
            NO_SEMANTIC_DIGEST,
            "the review names the claim but not the supporting code, tests and proved "
            "symbols it was read against",
        )
    if reviewed == current["fingerprint"]:
        return REVIEWED, f"semantic evidence reviewed at {reviewed[7:23]}"
    return STALE_SEMANTICS, "changed since review: " + _semantic_delta(
        current["components"], record.get("review_components")
    )


def _semantic_delta(current: dict, recorded: object) -> str:
    """What moved between the reviewed and the current semantic digest, as precisely as the
    record allows: each supporting unit's components by name, then the premises and claim."""
    if not isinstance(recorded, dict):
        return "the record names no components, so what moved cannot be derived"
    moved: list[str] = []
    for name in ("theorem_claim", "theorem_dependencies", "theorem_review_requirement"):
        if recorded.get(name) != current.get(name):
            moved.append(name)
    before = recorded.get("premises") if isinstance(recorded.get("premises"), dict) else {}
    after = current.get("premises", {})
    for asm in sorted(set(before) | set(after)):
        if before.get(asm) != after.get(asm):
            moved.append(f"premise {asm}")
    was = recorded.get("supporting_semantics")
    was = was if isinstance(was, dict) else {}
    now = current.get("supporting_semantics", {})
    for unit in sorted(set(was) | set(now)):
        old, new = was.get(unit), now.get(unit)
        if not isinstance(old, dict) or not isinstance(new, dict):
            moved.append(f"unit://{unit} (added or removed)")
            continue
        names = sorted(n for n in set(old) | set(new) if old.get(n) != new.get(n))
        if names:
            moved.append(f"unit://{unit} {'+'.join(names)}")
    if recorded.get("encoding_version") != current.get("encoding_version"):
        moved.append("review encoding")
    return ", ".join(moved) or "the digest differs and no recorded component does"


def _combined_review(
    spec_state: str,
    spec_reason: str,
    closure: dict[str, str] | None,
    premise_review: dict[str, tuple[str, str]],
    semantic: tuple[str, str],
) -> tuple[str, str]:
    """REVIEW_CURRENT: the current claim, its current premises, and its current supporting
    semantic evidence are what the owner reviewed. The claim leads when it fails, then the
    premises, then the semantics — the order a re-read takes."""
    if spec_state != REVIEWED:
        return spec_state, spec_reason
    if closure is None:
        return UNKNOWN, "the premise closure was not computed, so it cannot be compared"
    open_premises = sorted(
        f"{asm} {state}" for asm, (state, _) in premise_review.items() if state != REVIEWED
    )
    if open_premises:
        return PREMISE_UNREVIEWED, "premise(s) not reviewed as they stand: " + ", ".join(
            open_premises
        )
    if semantic[0] != REVIEWED:
        return semantic
    return REVIEWED, f"{spec_reason}; {len(premise_review)} premise(s) reviewed; {semantic[1]}"


def _evidence(state: dict) -> tuple[str, str]:
    """EVIDENCE_ESTABLISHED, locally: a successful run vouches for every supporting unit at
    its full current fingerprint — semantic inputs, lane identities, toolchain, generated
    model and policy revisions. `_graph.derive_unit_state` is the authority; FRESH is the
    only state that establishes."""
    if state["deprecated"]:
        return "DEPRECATED", "a withdrawn claim establishes nothing"
    if not state["supporting_units"]:
        return "NO_SUPPORT", "no supporting unit: no evidence exists"
    dirty = sorted(
        f"unit://{unit} {unit_state}"
        for unit, unit_state in state["unit_states"].items()
        if unit_state != "FRESH"
    )
    if dirty:
        return "NOT_ESTABLISHED", ", ".join(dirty)
    return "ESTABLISHED", f"{len(state['supporting_units'])} supporting unit(s) FRESH"


def theorem_assurance(
    theorems: dict,
    theorem_fingerprints: dict[str, dict],
    reviews: dict[tuple[str, str], dict],
    unit_states: dict[str, tuple[str, str]],
    premises: dict[str, dict[str, str] | None],
    backing: dict[str, tuple[bool, str]],
    review_digests: dict[str, dict | None],
) -> dict[str, dict]:
    """Two axes and their conjunction — Ruling 35 §3.

        review_current        the owner's specification review covers the CURRENT claim
                              fingerprint, the ledger backs it, every assumption in its
                              premise closure is reviewed and backed at its CURRENT digest,
                              and the record's `review_digest` equals the current semantic
                              evidence digest (`_fingerprint.review_digest`)
        evidence_established  not deprecated, supported, and every supporting unit FRESH —
                              an attestation at its full current fingerprint
        currently_verified    review_current AND evidence_established, and every theorem it
                              depends on is itself currently verified

    The two halves are reported apart so neither can stand in for the other: a fresh
    prover run over code nobody re-read is not current, and a current review over evidence
    nobody re-ran is not established. Only `currently_verified` may be read as "holds".

    `premises` maps each theorem to its premise closure (`_fingerprint.theorem_premises`);
    `review_digests` to its semantic evidence digest (`_fingerprint.theorem_review_digests`).
    A theorem missing from either is unknown there, and not current. `backing` maps subjects
    to `_approvals.ledger_state`.
    """
    entries = {row["id"]: row for row in theorems.get("theorem", [])}
    result: dict[str, dict] = {}
    for theorem_id, entry in entries.items():
        supporting = [str(t).removeprefix("unit://") for t in entry.get("supported_by", [])]
        unit_axis = [unit_states.get(unit, ("UNKNOWN", "not declared")) for unit in supporting]
        record = reviews.get(("specification", theorem_id))
        spec_state, spec_reason = backed_review_state(
            theorem_fingerprints[theorem_id], record, backing.get(theorem_id)
        )
        closure = premises.get(theorem_id)
        premise_review = {
            asm: assumption_review_state(asm, digest, reviews, backing)
            for asm, digest in sorted((closure or {}).items())
        }
        semantic = semantic_review_state(review_digests.get(theorem_id), record)
        state = {
            "deprecated": bool(entry.get("replaced_by")),
            "supporting_units": supporting,
            "unit_states": {unit: s for unit, (s, _) in zip(supporting, unit_axis)},
            "specification_review": (spec_state, spec_reason),
            "premise_review": premise_review,
            "semantic_review": semantic,
            "review": _combined_review(
                spec_state, spec_reason, closure, premise_review, semantic
            ),
        }
        state["review_current"] = state["review"][0] == REVIEWED
        state["evidence"] = _evidence(state)
        state["evidence_established"] = state["evidence"][0] == "ESTABLISHED"
        state["currently_verified"] = state["review_current"] and state["evidence_established"]
        result[theorem_id] = state

    # Fixpoint over `depends_on`: a premise theorem that is not currently verified takes
    # every claim above it with it.
    changed = True
    while changed:
        changed = False
        for theorem_id, state in result.items():
            if not state["currently_verified"]:
                continue
            for dep in entries[theorem_id].get("depends_on", []):
                if not result.get(dep, {}).get("currently_verified"):
                    state["currently_verified"] = False
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
    if not state["evidence_established"]:
        return "EVIDENCE: " + state["evidence"][1]
    review_state, reason = state["specification_review"]
    if review_state != REVIEWED:
        return f"SPECIFICATION REVIEW {review_state}: {reason}"
    review_state, reason = state["review"]
    if review_state == PREMISE_UNREVIEWED:
        return f"PREMISE REVIEW {review_state}: {reason}"
    if review_state != REVIEWED:
        return f"SEMANTIC REVIEW {review_state}: {reason}"
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
        if assurance.get(root, {}).get("currently_verified"):
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
            if state is None or state["currently_verified"]:
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
