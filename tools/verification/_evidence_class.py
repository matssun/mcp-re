# SPDX-License-Identifier: Apache-2.0
"""The ADR-MCPRE-068 evidence-class ontology, and the adequacy its declaration owes.

ONE authority over one fact: *what kind of thing establishes this proposition, and what
would demonstrate it could fail*. `_manifest` owns the unit record and `_theorems` owns the
theorem record; both read their class and severity vocabulary from here, because a
vocabulary declared in two places is a vocabulary that will eventually name two sets.

WHY THE CLASS IS DECLARED AND THEN CHECKED, NEVER DERIVED
---------------------------------------------------------

Deriving the class from the evidence URIs would mean a unit could silently LOSE a class by
losing an evidence entry: delete a `verus://` line and a `proved` unit becomes a `tested`
one with no diagnostic, which is the silent downgrade the registry exists to prevent
(ADR-MCPRE-068 §5, A3). So the unit DECLARES, and this module refuses a declaration the
evidence does not support.

The converse also holds and is the reason the check is two-directional: a unit carrying
`measurement_scope` while classified `tested` has declared an apparatus nothing reads, and
a field nothing reads is a declaration that looks like coverage.

WHAT IS *NOT* CHECKED HERE, AND WHEN IT BECOMES CHECKABLE
---------------------------------------------------------

N1's falsifier obligation — a Medium-or-higher `tested` proposition MUST name a registered
falsifier — is absent, deliberately. It needs `effective_severity`, which is derived from
the assurance graph rather than read off a record, and that derivation is Phase 0E's. Every
rule in this module is computable from ONE record in isolation, which is what makes it
loader-stage and therefore merge-fatal (ADR-MCPRE-068 §9.3). Adding a rule here that needs
the graph would put a graph walk inside the loader and give the loader a fact it should be
handed.

Stdlib only, like the rest of this layer.
"""

from __future__ import annotations

#: How MCP-RE establishes a proposition — ADR-MCPRE-068 §4.1, owner Ruling 2.
#:
#: Four, not six. `assumed`, `external-boundary` and `review-obligation` answer a different
#: question — why a chain TERMINATES without MCP-RE establishing the proposition — and live
#: on `[[assumption]].premise_class`. A unit is never classified by the fact that it sits in
#: front of something external: our wrapper's semantics are `tested` or `proved`, and the
#: outside guarantee is a premise.
EVIDENCE_CLASSES = ("proved", "structural", "tested", "measured")

#: Consequence severity — ADR-MCPRE-068 §10, owner Ruling 1.
#:
#: Ordered, because `effective_severity = max(direct, inherited)` is a comparison. The order
#: is a scale over ONE axis (what is lost if the proposition is false) and says nothing
#: about the evidence classes, which are incomparable establishment modes rather than tiers.
SEVERITIES = ("none", "info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {name: rank for rank, name in enumerate(SEVERITIES)}

#: The bar N1 uses. Named rather than written as a literal in three places.
OBLIGATION_FLOOR = SEVERITY_ORDER["medium"]

#: What a `measured` unit must identify — ADR-MCPRE-068 §5, A4, owner Ruling 4.
#:
#: `measurement_control` is deliberately not `measurement_sensitivity`: Ruling 4 allows a
#: reproducibility control OR a sensitivity control, and the narrower name would exclude
#: half of what the ruling permits. It is not the mutation rule under another name — a
#: mutation probe falsifies the PROPOSITION, and this falsifies the APPARATUS, which is the
#: only thing a measurement can be wrong about independently of the world.
MEASUREMENT_KEYS = (
    "measurement_protocol",
    "measurement_scope",
    "measurement_artifact",
    "measurement_control",
)

#: Which evidence scheme each class's falsifier speaks — ADR-MCPRE-068 §4.1, N4.
#:
#: `measured` is absent from this map and that absence is the rule, not an omission: Ruling
#: 4 says a measured proposition does NOT inherit the mutation-falsifier obligation, and its
#: apparatus control is a declared field rather than a probe URI.
FALSIFIER_SCHEME = {
    "proved": ("verus://", "lean://"),
    "structural": ("structural://",),
    "tested": ("mutation://",),
}

#: The scheme a class's ESTABLISHING evidence must include. Distinct from the falsifier: a
#: `proved` unit's prover run and its proof-obligation probe are the same lane, while a
#: `tested` unit's battery and its mutation probe are two.
ESTABLISHING_SCHEME = {
    "proved": ("verus://", "lean://"),
    "structural": ("structural://",),
    "tested": ("test://",),
    "measured": ("measured://",),
}


def severity_problem(where: str, entry: dict, field: str = "direct_consequence_severity"):
    """Why `entry[field]` is not a severity, or None.

    ABSENT IS A PROBLEM, NOT A DEFAULT. Ruling 1 is explicit: "Do not permit missing to mean
    `none`." A proposition whose consequence nobody stated is a proposition nobody has
    thought about, and reading it as the lowest severity would make the least considered
    claims the least obligated — exactly backwards.
    """
    if field not in entry:
        return (
            f"{where}: missing `{field}`. Every assurance proposition states what is lost "
            f"if it is false, from {list(SEVERITIES)}. Absent does NOT mean 'none' "
            f"(ADR-MCPRE-068 §10, Ruling 1): an unstated consequence is an unconsidered "
            f"one, and defaulting it low would leave the least examined claims the least "
            f"obligated."
        )
    value = entry[field]
    if value not in SEVERITY_ORDER:
        return (
            f"{where}: `{field}` is {value!r}, not one of {list(SEVERITIES)}."
        )
    return None


def _schemes(unit: dict) -> set[str]:
    """The evidence schemes this unit declares, as prefixes including `://`."""
    out = set()
    for entry in unit.get("evidence", []):
        text = str(entry)
        if "://" in text:
            out.add(text.split("://", 1)[0] + "://")
    return out


def class_problems(where: str, unit: dict) -> list[str]:
    """Every way this unit's declared class disagrees with the record it sits in.

    Returns all of them rather than the first, because a unit migrated to the wrong class
    usually has several and fixing them one loader run at a time is how a migration takes a
    week. The caller decides whether to raise.
    """
    problems: list[str] = []

    declared = unit.get("evidence_class")
    if declared is None:
        problems.append(
            f"{where}: missing `evidence_class`. Every unit says what KIND of thing "
            f"establishes it, from {list(EVIDENCE_CLASSES)} (ADR-MCPRE-068 §5, A1). The "
            f"field is not `class`: that key already carries the V0/V1/V2 verification "
            f"tier, and one name holding two closed vocabularies is one name meaning "
            f"whichever the reader assumed."
        )
        return problems
    if declared not in EVIDENCE_CLASSES:
        problems.append(
            f"{where}: `evidence_class` is {declared!r}, not one of "
            f"{list(EVIDENCE_CLASSES)}. `assumed`, `external-boundary` and "
            f"`review-obligation` are PREMISE classes on `[[assumption]].premise_class`, "
            f"never a unit's: they answer why a chain terminates without MCP-RE "
            f"establishing the proposition (Ruling 2)."
        )
        return problems

    schemes = _schemes(unit)

    wanted = ESTABLISHING_SCHEME[declared]
    if not schemes & set(wanted):
        problems.append(
            f"{where}: `evidence_class = {declared!r}` but no evidence URI of "
            f"{list(wanted)}. The class is a declaration CHECKED against the evidence "
            f"(A3); a class the evidence does not support is a validation failure, not a "
            f"weaker claim (N4)."
        )

    if declared == "proved":
        # WHICH key names the proved things depends on WHICH prover, and the two are not
        # interchangeable: `proved_symbols` is the Verus lane's list of Rust items, and
        # `lean_theorems` is the set of Lean theorems the extracted-model lane asks about.
        # A unit declaring `verus://` and carrying only `lean_theorems` has named nothing
        # the Verus lane can select, and the reverse holds equally. So the requirement
        # follows the scheme the unit declared rather than the word "proved".
        wants = []
        if "verus://" in schemes:
            wants.append("proved_symbols")
        if "lean://" in schemes:
            wants.append("lean_theorems")
        missing = [key for key in wants if not unit.get(key)]
        if missing:
            problems.append(
                f"{where}: `evidence_class = 'proved'` with {sorted(schemes & {'verus://', 'lean://'})} "
                f"evidence requires {missing}. Without the selection the lane can only ask "
                f"whether this crate verified SOMETHING, and deleting one of two "
                f"specifications leaves the other to answer yes."
            )
    if declared == "tested" and not unit.get("tested_symbols"):
        problems.append(
            f"{where}: `evidence_class = 'tested'` requires `tested_symbols`. A battery "
            f"with no named members cannot be run, and an unrunnable claim is not evidence."
        )

    declared_measurement = [key for key in MEASUREMENT_KEYS if unit.get(key)]
    if declared == "measured":
        missing = [key for key in MEASUREMENT_KEYS if not unit.get(key)]
        if missing:
            problems.append(
                f"{where}: `evidence_class = 'measured'` requires {list(MEASUREMENT_KEYS)}; "
                f"missing {missing}. Ruling 4: a measured proposition identifies its "
                f"protocol, the scope that bounds it, the artifact it produced, and the "
                f"control that shows the apparatus can still MOVE. A number whose scope is "
                f"unstated is a number the reader has to guess the meaning of."
            )
    elif declared_measurement:
        problems.append(
            f"{where}: declares {declared_measurement} but `evidence_class` is "
            f"{declared!r}, so no lane reads them. A measurement apparatus nothing "
            f"consumes is a declaration that reads as coverage and measures nothing."
        )

    return problems
