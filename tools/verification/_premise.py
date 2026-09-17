# SPDX-License-Identifier: Apache-2.0
"""The ADR-MCPRE-068 premise ontology — why an assurance chain TERMINATES.

ONE authority over one fact, and it is deliberately not the evidence-class fact.
`_evidence_class` answers *how does MCP-RE establish this proposition?* for a unit; this
module answers *why does this chain end without MCP-RE establishing it?* for an assumption.
Owner Ruling 2 split them because a unit is never classified by the fact that it sits in
front of something external: our Redis wrapper's semantics are TESTED or PROVED, and Redis
command atomicity is an EXTERNAL BOUNDARY.

THREE CLASSES, BECAUSE THEY ANSWER THREE DIFFERENT QUESTIONS
------------------------------------------------------------

*Will this ever be discharged?*

  `assumed`             No, and that is accepted.
  `external-boundary`   Not by us — an owner outside MCP-RE guarantees it.
  `review-obligation`   Yes, at a named event.

Collapsing them — 47 records with one shape, which is where this started — makes the only
question anybody actually asks unanswerable: **which Critical or High root ultimately rests
on something we merely assume?** An external-boundary premise under a Critical root is a
supply-chain statement. An open review obligation under the same root is a DEBT. They must
not read alike.

THE DISCHARGING EVENT IS A TAGGED PREDICATE, NEVER PROSE (C3)
--------------------------------------------------------------

A `review-obligation` says a human must read this again at a named event, so the event has
to be something other than a sentence. Three kinds, and the third is the honest residue:

  `registry-fact`  observable over the policy TOMLs
  `tree-fact`      observable over the source tree at the current fingerprint
  `owner-event`    observable by NOTHING. The gate never guesses whether it happened.

AND AN OBSERVABLE EVENT THAT HAS COME TRUE IS A FAIL (C4)
----------------------------------------------------------

Not a pass, and not a silent discharge. A record that outlives the state it describes makes
the tree look measured when it is not — the same defect `_evidence.write_bundle` records for
the evidence bundle, where the file described the last run rather than the last successful
one. Discharge is a registry EDIT, owner-reviewed like every other security-sensitive
change. The gate's job is not to notice discharge; it is to make the debt impossible to stop
seeing.

WHY A WITHDRAWN RECORD CARRIES NO CLASS
----------------------------------------

`premise_class` is required of every LIVE premise and refused on a withdrawn one. A
withdrawn assumption trusts nothing — that is what withdrawing it meant — so typing it would
make a retired premise read as a live one. `_manifest._require_boundary_edge` already draws
the line in exactly that place, by exactly that argument, and liveness is the same test
there: a non-empty `scope`.

Stdlib only, like the rest of this layer.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Why a chain terminates — ADR-MCPRE-068 §4.2, owner Ruling 2.
PREMISE_CLASSES = ("assumed", "external-boundary", "review-obligation")

#: What each kind of discharging event is observable OVER.
EVENT_KINDS = ("registry-fact", "tree-fact", "owner-event")

#: The cause a stale obligation is reported under. Named once: a cause token spelled in two
#: places is a cause a reader can grep for and miss.
STALE_CAUSE = "STALE_REVIEW_OBLIGATION"

#: The predicates each observable kind may use, and the operands each takes.
#:
#: CLOSED, and small. An open predicate vocabulary would let a record state a condition the
#: gate silently cannot evaluate, which is prose again with a table around it.
PREDICATES = {
    "registry-fact": {
        # The pinned identity of a verification toolchain moved away from the version the
        # premise was written against. A ceiling attributed to "the pinned toolchain" stops
        # being a statement about THIS tree the moment the pin changes.
        "toolchain-version-differs": ("tool", "from"),
        # A unit acquired evidence of a scheme it did not have. The premise that stood in
        # for that evidence is then describing a gap the registry says is filled.
        "unit-has-evidence-scheme": ("unit", "scheme"),
    },
    "tree-fact": {
        # The seam the premise is about is no longer in the tree. Trusting the behaviour of
        # something that does not exist is not a premise; it is a leftover.
        "site-absent": ("site",),
    },
    "owner-event": {},
}

_COMMON = {"kind"}
_OWNER_EVENT_KEYS = {"statement"}


def class_problem(where: str, entry: dict, live: bool) -> str | None:
    """Why this entry's `premise_class` is not usable, or None."""
    declared = entry.get("premise_class")
    if not live:
        if declared is not None:
            return (
                f"{where}: withdrawn premise {entry['id']} declares `premise_class` "
                f"{declared!r}. A withdrawn assumption trusts nothing — that is what "
                f"withdrawing it meant — so typing it makes a retired premise read as a "
                f"live one."
            )
        return None
    if declared is None:
        return (
            f"{where}: missing `premise_class`. Every live premise says WHY the chain "
            f"terminates without MCP-RE establishing it, from {list(PREMISE_CLASSES)} "
            f"(ADR-MCPRE-068 §7, C1). The field is not `class`: that key carries the "
            f"V0/V1/V2 tier on `[[unit]]`, and one name over two closed vocabularies in "
            f"one loader is one name meaning whichever the reader assumed."
        )
    if declared not in PREMISE_CLASSES:
        return (
            f"{where}: `premise_class` is {declared!r}, not one of "
            f"{list(PREMISE_CLASSES)}. `proved`, `structural`, `tested` and `measured` are "
            f"EVIDENCE classes on `[[unit]].evidence_class`: they answer how MCP-RE "
            f"establishes a proposition, which is the question a premise exists because "
            f"nobody answered (Ruling 2)."
        )
    if declared == "external-boundary":
        return _boundary_problem(where, entry)
    if declared == "review-obligation":
        return _event_problem(where, entry)
    if entry.get("boundary_owner") or entry.get("discharging_event"):
        extra = [k for k in ("boundary_owner", "discharging_event") if entry.get(k)]
        return (
            f"{where}: `premise_class = 'assumed'` with {extra}. An assumed premise is one "
            f"nothing establishes and nothing is scheduled to discharge; a field nothing "
            f"reads is a declaration that looks like coverage. What makes it stop being "
            f"acceptable belongs in `justification`."
        )
    return None


def _boundary_problem(where: str, entry: dict) -> str | None:
    """C2: who guarantees it, and across which interface."""
    owner = entry.get("boundary_owner")
    if not owner or not str(owner).strip():
        return (
            f"{where}: `premise_class = 'external-boundary'` requires `boundary_owner`. "
            f"\"Redis\", alone, is not an owner statement: WHAT is guaranteed, across WHICH "
            f"interface, under WHICH configuration is (C2)."
        )
    if entry.get("discharging_event"):
        return (
            f"{where}: an external-boundary premise carries no `discharging_event`. It is "
            f"not discharged BY US, and scheduling an event for it would record a debt "
            f"nobody in this repository owes."
        )
    if "://" in str(owner) or len(str(owner).split()) < 3:
        return (
            f"{where}: `boundary_owner` is {owner!r}, which names a thing rather than a "
            f"guarantee. State the owner, the interface, and what is guaranteed across it."
        )
    return None


def _event_problem(where: str, entry: dict) -> str | None:
    """C3: the discharging event is a tagged record from a closed set, never a sentence."""
    event = entry.get("discharging_event")
    if not isinstance(event, dict):
        return (
            f"{where}: `premise_class = 'review-obligation'` requires a `discharging_event` "
            f"TABLE. A sentence cannot be evaluated, and a discharge condition the gate "
            f"cannot read is the prose this field replaces (C3, C5: `review_requirement` "
            f"keeps the human review rule; the gate ignores prose for discharge)."
        )
    if entry.get("boundary_owner"):
        return (
            f"{where}: a review-obligation carries no `boundary_owner`. If an owner outside "
            f"MCP-RE guarantees it, the premise is an external boundary and is not our debt."
        )
    kind = event.get("kind")
    if kind not in EVENT_KINDS:
        return f"{where}: `discharging_event.kind` is {kind!r}, not one of {list(EVENT_KINDS)}."
    if kind == "owner-event":
        allowed = _COMMON | _OWNER_EVENT_KEYS
        unknown = set(event) - allowed
        if unknown:
            return f"{where}: `discharging_event` has unknown key(s) {sorted(unknown)} for kind {kind!r}"
        if not str(event.get("statement", "")).strip():
            return (
                f"{where}: an `owner-event` states what the owner is watching for. It is the "
                f"one kind nothing observes, so the statement is the whole record of it."
            )
        return None
    predicate = event.get("predicate")
    table = PREDICATES[kind]
    if predicate not in table:
        return (
            f"{where}: `discharging_event.predicate` is {predicate!r}; kind {kind!r} admits "
            f"{sorted(table)}. The vocabulary is CLOSED: an open one would let a record "
            f"state a condition the gate silently cannot evaluate."
        )
    allowed = _COMMON | {"predicate"} | set(table[predicate])
    unknown = set(event) - allowed
    if unknown:
        return f"{where}: `discharging_event` has unknown key(s) {sorted(unknown)} for {predicate!r}"
    missing = [operand for operand in table[predicate] if not event.get(operand)]
    if missing:
        return f"{where}: `discharging_event` for {predicate!r} is missing {missing}"
    return None


def is_live(entry: dict) -> bool:
    """Whether this premise trusts anything. A withdrawn one has an empty scope."""
    return bool(entry.get("scope"))


def has_come_true(entry: dict, verification: dict, toolchains: dict) -> str | None:
    """Why this obligation's observable event has ALREADY happened, or None — C4.

    Returns a sentence naming the cause, never a verdict: the caller decides what a stale
    obligation does to the build. `owner-event` always returns None, and that is the design
    rather than a gap — the gate does not guess whether an unobservable event occurred, it
    reports the obligation as open against every root that reaches it.
    """
    event = entry.get("discharging_event")
    if not isinstance(event, dict) or event.get("kind") == "owner-event":
        return None
    predicate = event.get("predicate")
    if predicate == "toolchain-version-differs":
        pinned = _pinned_version(toolchains, str(event["tool"]))
        if pinned is not None and pinned != str(event["from"]):
            return (
                f"{STALE_CAUSE}: {entry['id']} is held open by the pinned {event['tool']} "
                f"being {event['from']}, and the tree now pins {pinned}. The ceiling it "
                f"names may be gone; re-read the premise and discharge or restate it."
            )
        return None
    if predicate == "unit-has-evidence-scheme":
        for unit in verification.get("unit", []):
            if unit["id"] != str(event["unit"]):
                continue
            if any(str(e).startswith(f"{event['scheme']}://") for e in unit.get("evidence", [])):
                return (
                    f"{STALE_CAUSE}: {entry['id']} stands in for {event['scheme']} evidence "
                    f"on unit {event['unit']}, which now declares it. The registry is "
                    f"asserting a gap the registry itself says is filled."
                )
        return None
    if predicate == "site-absent":
        path = str(event["site"]).partition("#")[0]
        if not (REPO_ROOT / path).is_file():
            return (
                f"{STALE_CAUSE}: {entry['id']} is a premise about {event['site']}, and "
                f"{path} is no longer in the tree. Trusting the behaviour of something that "
                f"does not exist is a leftover, not a premise."
            )
        return None
    return None


#: Which key carries a toolchain's version, in the order the lock uses them.
#:
#: Read in order rather than guessed per tool: `[verus]` states a `release`, `[rust]` a
#: `channel`, the extraction container a `tag`. A resolver hard-coding one of them would
#: silently return None for the others — and None here means "the lock does not pin it",
#: which `has_come_true` treats as nothing to compare. A quiet None is how an observable
#: obligation stops being observed.
_VERSION_KEYS = ("release", "channel", "version", "revision", "tag")


def _pinned_version(toolchains: dict, tool: str) -> str | None:
    """The pinned version of one toolchain, or None if the lock does not name it."""
    entry = toolchains.get(tool)
    if isinstance(entry, dict):
        for key in _VERSION_KEYS:
            if entry.get(key):
                return str(entry[key])
    return None


def open_obligations(assumptions: dict) -> list[dict]:
    """Every live review obligation, in registry order — the release view's input (N5)."""
    return [
        entry
        for entry in assumptions.get("assumption", [])
        if is_live(entry) and entry.get("premise_class") == "review-obligation"
    ]


def _closure(root: str, entries: dict) -> set[str]:
    """Every theorem the root transitively depends on, including itself."""
    seen: set[str] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node in seen or node not in entries:
            continue
        seen.add(node)
        stack.extend(entries[node].get("depends_on", []))
    return seen


def roots_reaching_premises(theorems: dict, verification: dict, assumptions: dict) -> dict:
    """Which typed premises each declared root ultimately rests on — N5.

    THE COMPOSITION, and it is the whole of what §7 found missing. Both halves already
    existed and nothing joined them: `_catalogue_views.assumption_consumers` derives
    *scope → unit → theorem* at render time, and `_review.root_completeness` walks the
    `depends_on` closure — so the registry could say which theorem an assumption reaches and
    which theorems a root stands on, and could not answer the question anybody actually
    asks, which spans both.

    Derived here, never stored. Storing the `consumed_by` direction is exactly what
    ADR-MCPRE-059 §8.2 forbids, and a second stored authority over reachability would be
    free to disagree with the two live ones.

    Returns `{root_id: {premise_class: [assumption ids]}}`, classes in vocabulary order.
    """
    entries = {row["id"]: row for row in theorems.get("theorem", [])}
    # `supported_by` carries `unit://<id>` URIs and `scope` carries the same form, so both
    # sides are reduced to the bare id here. Comparing one against the other verbatim
    # produced an empty intersection for all twelve roots and reported "no root rests on any
    # premise" — a composition that is silently EMPTY reads exactly like a clean result,
    # which is why `test_premise_class` asserts the count is non-zero rather than only that
    # the function runs.
    supports = {
        row["id"]: {str(u).removeprefix("unit://") for u in row.get("supported_by", [])}
        for row in theorems.get("theorem", [])
    }
    scoped: dict[str, set[str]] = {}
    for entry in assumptions.get("assumption", []):
        if not is_live(entry):
            continue
        for target in entry.get("scope", []):
            text = str(target)
            if text.startswith("unit://"):
                scoped.setdefault(text[len("unit://") :], set()).add(entry["id"])
    by_id = {entry["id"]: entry for entry in assumptions.get("assumption", [])}

    out: dict[str, dict[str, list[str]]] = {}
    for root in theorems.get("root_theorems", []):
        reached: set[str] = set()
        for theorem in _closure(str(root), entries):
            for unit in supports.get(theorem, set()):
                reached |= scoped.get(unit, set())
        rows = {name: [] for name in PREMISE_CLASSES}
        for asm_id in sorted(reached):
            rows[by_id[asm_id]["premise_class"]].append(asm_id)
        out[str(root)] = rows
    return out
