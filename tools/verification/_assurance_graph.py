# SPDX-License-Identifier: Apache-2.0
"""N3's severity derivation — ADR-MCPRE-068 §9, Phase 0E.

ONE authority over one fact: *how much is lost if this proposition is false*, computed
rather than stored.

    effective_severity(P) = max(direct_consequence_severity(P), inherited_severity(P))
    inherited_severity(P) = max(effective_severity(Q)) over every Q that DIRECTLY DEPENDS
                            on P — theorem to theorem through `depends_on`, theorem to unit
                            through `supported_by`

WHY IT IS DERIVED AND NEVER STORED. A stored `inherited_severity` is a second copy of a
fact the graph already holds, and the two disagree the moment an edge moves. Worse, it is
independently editable: a unit that inherits Critical could be edited to say Medium and
would then owe less, which is the obligation deciding its own size. The owner's ratification
is explicit that these two are derived and never independently editable, so this module
computes them from the registries and nothing writes them back.

WHY IT IS ITS OWN LAYER, AND NOT `_manifest`. Registry adequacy needs `effective_severity`,
which needs a graph closure. Burying a graph walk in the loader would give the loader a fact
it should be handed, and would let the loader and `_review` compute different severities for
one proposition — which is the same class of defect as a vocabulary declared twice. Both
callers read this module.

WHY ROOT-ONLY WAS REJECTED. Ruling 1's literal text says "every declared root that
transitively depends on P", under which a unit supporting an intermediate Critical theorem
inherits nothing unless a root above is also Critical — silently dropping the intermediate
theorem's own declared consequence. The ratification broadened it (§14 item 1, "ACCEPTED,
broadened", root-only severity explicitly rejected). Ruling 1's behaviour is a CONSEQUENCE
of the general form rather than a special case: `effective(root) >= direct(root)` and the
maximum propagates through the whole closure.

THE CYCLE HAZARD DOES NOT EXIST, AND THAT IS CHECKED RATHER THAN ASSUMED. `depends_on`
cycles are already refused by `_theorems._check_acyclic`, and units are sinks. This module
still refuses a cycle it is handed, because a future edge kind added without a cycle check
would otherwise make the derivation silently non-terminating or order-dependent.

Stdlib only, like the rest of this layer.
"""

from __future__ import annotations

from _evidence_class import SEVERITIES, SEVERITY_ORDER

#: A proposition id, prefixed so a theorem and a unit can never collide in one map.
#:
#: `THM-0102` and a unit id are different namespaces in the registries and would be
#: different keys by accident here; making the namespace explicit means a typo produces a
#: missing key rather than a silent join against the wrong table.
THEOREM, UNIT = "theorem", "unit"


def key(kind: str, ident: str) -> str:
    """The graph key for a proposition."""
    return f"{kind}://{ident}"


def _strip(uri: str) -> str:
    """`unit://x` and `x` both name unit `x` — the registries use both spellings."""
    return str(uri).removeprefix("unit://")


def dependency_edges(theorems: dict, units: dict) -> dict[str, set[str]]:
    """`{dependent: {things it directly depends on}}` over both proposition kinds.

    Two edge kinds, and they are the two N3 names. A theorem depends on the theorems in its
    `depends_on` and on the units in its `supported_by`; a unit depends on nothing, so units
    are sinks and severity only ever flows INTO them.
    """
    known_units = {key(UNIT, unit["id"]) for unit in units.get("unit", [])}
    edges: dict[str, set[str]] = {u: set() for u in known_units}
    for theorem in theorems.get("theorem", []):
        source = key(THEOREM, theorem["id"])
        out = edges.setdefault(source, set())
        for other in theorem.get("depends_on", []):
            out.add(key(THEOREM, str(other)))
        for supporter in theorem.get("supported_by", []):
            out.add(key(UNIT, _strip(supporter)))
    return edges


def direct_severities(theorems: dict, units: dict) -> dict[str, str]:
    """Every proposition's DECLARED severity, by graph key.

    A proposition missing the field is absent from this map rather than defaulted: Ruling 1
    forbids reading missing as `none`, and `_evidence_class.severity_problem` is what reports
    it. Defaulting here would hide the very record that rule exists to surface.
    """
    out: dict[str, str] = {}
    for theorem in theorems.get("theorem", []):
        if theorem.get("direct_consequence_severity") in SEVERITY_ORDER:
            out[key(THEOREM, theorem["id"])] = theorem["direct_consequence_severity"]
    for unit in units.get("unit", []):
        if unit.get("direct_consequence_severity") in SEVERITY_ORDER:
            out[key(UNIT, unit["id"])] = unit["direct_consequence_severity"]
    return out


class CycleError(Exception):
    """A dependency cycle reached the severity derivation."""


def _dependents(edges: dict[str, set[str]]) -> dict[str, set[str]]:
    """Reverse the dependency edges: `{depended-on: {things that depend on it}}`."""
    reverse: dict[str, set[str]] = {node: set() for node in edges}
    for source, targets in edges.items():
        for target in targets:
            reverse.setdefault(target, set()).add(source)
    return reverse


def _order(edges: dict[str, set[str]]) -> list[str]:
    """Nodes with every DEPENDENT already emitted — the order severity propagates in.

    Kahn's algorithm over the reversed graph. A node whose dependents are all settled can be
    settled, because `inherited` is a maximum over exactly those dependents. Any node left
    unsettled is in a cycle, and this raises rather than returning a partial order: a
    severity computed from a partial order would depend on iteration order, which is the one
    thing a derived security fact may not do.
    """
    dependents = _dependents(edges)
    nodes = set(edges) | set(dependents)
    remaining = {node: len(dependents.get(node, ())) for node in nodes}
    ready = [node for node, count in remaining.items() if count == 0]
    out: list[str] = []
    while ready:
        node = ready.pop()
        out.append(node)
        for target in sorted(edges.get(node, ())):
            remaining[target] -= 1
            if remaining[target] == 0:
                ready.append(target)
    if len(out) != len(nodes):
        stuck = sorted(nodes - set(out))
        raise CycleError(
            f"the proposition graph has a cycle reaching {len(stuck)} node(s): "
            f"{stuck[:8]}{' …' if len(stuck) > 8 else ''}. Severity derivation is a maximum "
            f"over dependents and has no fixed point to report on a cycle. `depends_on` "
            f"cycles are refused by `_theorems._check_acyclic`; any edge kind added since "
            f"must be cycle-checked BEFORE severity is computed, not after."
        )
    return out


def severities(theorems: dict, units: dict) -> dict[str, dict[str, str | None]]:
    """`{graph key: {direct, inherited, effective}}` for every proposition.

    `direct` is None where the proposition declares no severity, and that absence is
    preserved rather than defaulted — `_evidence_class.severity_problem` is what reports it,
    and a default here would hide the record that rule exists to surface. `effective` still
    computes, because a maximum over an absent own-label is the inherited one.

    `inherited` is `none` where nothing depends on the proposition — which is a real answer
    and not an absence. It says the graph holds no dependent, which for a unit means no
    theorem names it in `supported_by`, and that is exactly what S5's `NOT-ROOT-REACHABLE`
    reporting is about. It does NOT lower the direct obligation: `effective` is a maximum, so
    a Critical unit nobody depends on stays Critical.
    """
    edges = dependency_edges(theorems, units)
    direct = direct_severities(theorems, units)
    dependents = _dependents(edges)
    effective: dict[str, str] = {}
    out: dict[str, dict[str, str | None]] = {}
    for node in _order(edges):
        inherited = SEVERITIES[0]
        for dependent in dependents.get(node, ()):
            candidate = effective.get(dependent, SEVERITIES[0])
            if SEVERITY_ORDER[candidate] > SEVERITY_ORDER[inherited]:
                inherited = candidate
        own = direct.get(node, SEVERITIES[0])
        best = own if SEVERITY_ORDER[own] >= SEVERITY_ORDER[inherited] else inherited
        effective[node] = best
        out[node] = {"direct": direct.get(node), "inherited": inherited, "effective": best}
    return out


def root_reachable(theorems: dict, units: dict, roots: list[str]) -> set[str]:
    """Every proposition a declared root transitively depends on, as graph keys.

    S5's fact, and ONLY S5's fact. A proposition outside this set is `NOT-ROOT-REACHABLE`,
    which means exactly "no currently declared system root transitively depends on it" — not
    low importance, not complete assurance, and not permission to omit evidence. The
    ratification is explicit on all three, and the obligation from the DIRECT label stands
    regardless, which is why this function is separate from `severities` rather than feeding
    it.
    """
    edges = dependency_edges(theorems, units)
    seen: set[str] = set()
    stack = [key(THEOREM, str(root)) for root in roots]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(edges.get(node, ()))
    return seen


def _claims_falsifier(unit: dict, scheme: str) -> bool:
    """Whether the unit names at least one evidence URI in `scheme`.

    Deliberately local rather than imported from `_manifest`: this layer is read BY the
    loader path, and importing the loader here would make the two mutually dependent. The
    check is one line, and duplicating one line is cheaper than a cycle — the vocabulary it
    reads (`FALSIFIER_SCHEME`) is still declared exactly once, in `_evidence_class`.
    """
    return any(str(entry).startswith(scheme) for entry in unit.get("evidence", []))


def unmet_obligations(theorems: dict, units: dict) -> dict[str, dict]:
    """N1's population: `tested` propositions at Medium-or-higher that name no falsifier.

    THE OBLIGATION'S EXISTENCE IS A STATIC FACT, and that is what this computes. Whether the
    falsifier has RUN, and at which fingerprint, is attestation adequacy and belongs to the
    lanes — §9.3 keeps the two apart precisely so that recording an obligation is never
    punished as harshly as declaring a class one does not satisfy.

    `measured` takes no mutation obligation at all (Ruling 4) and `proved`/`structural` owe
    their own falsifier forms, which the class-adequacy check already enforces per record.
    So this asks only about `tested`, and asks it with `FALSIFIER_SCHEME` rather than a
    literal, because a class's falsifier form is declared in one place.
    """
    from _evidence_class import FALSIFIER_SCHEME, OBLIGATION_FLOOR

    derived = severities(theorems, units)
    reachable = root_reachable(theorems, units, theorems.get("root_theorems", []))
    scheme = FALSIFIER_SCHEME["tested"][0]
    out: dict[str, dict] = {}
    for unit in units.get("unit", []):
        if unit.get("evidence_class") != "tested":
            continue
        node = key(UNIT, unit["id"])
        measured = derived[node]
        if SEVERITY_ORDER[measured["effective"] or SEVERITIES[0]] < OBLIGATION_FLOOR:
            continue
        if _claims_falsifier(unit, scheme):
            continue
        out[unit["id"]] = {
            "effective_severity": measured["effective"],
            "direct_consequence_severity": measured["direct"],
            "inherited_severity": measured["inherited"],
            "root_reachable": node in reachable,
        }
    return out
