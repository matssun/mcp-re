# SPDX-License-Identifier: Apache-2.0
"""Semantic axiom accounting for the Lean lane — ADR-MCPRE-059 §12, issue #541.

What a Lean theorem *depends on* is a question only the prover can answer. A token scan
over the source finds the word `axiom` where somebody wrote it; it does not find the axiom
a transitively imported definition introduced, and it cannot tell an axiom a theorem
actually uses from one that merely sits in the same file. So the authority here is
`#print axioms`, which reports the kernel's own closure over each named constant, and the
token scan stays where it belongs: an initial detector, upstream of this.

Three names are the declared kernel baseline — `propext`, `Classical.choice`,
`Quot.sound`. They are the axioms Lean's own standard library rests on; a theorem that
uses them is a theorem in Lean's logic, not a theorem with three extra premises. Every
OTHER name is a premise this repository is trusting, and it is registrable only as an
`ASM-NNNN` in `verification/policy/assumptions.toml`, bound to the axiom by
`tool_specific_mechanism = "lean:axiom:<lean name>"` and scoped to the units it is trusted
within.

The baseline is a NAME SET and nothing more, and this module does not hold one. It is a
property of the pinned Lean, so it is declared in `verification/policy/toolchains.lock.toml`
under `[lean].kernel_axioms`, beside the `toolchain` it is a property OF — and `verify-lean`
refuses a lock that declares none rather than falling back to a value written here. A
default here would be a second authority, and the direction it would fail in is the quiet
one: it would keep reading as correct across the exact event that could change the set.

`sorryAx` is the one name that is neither. `sorry` is not a weaker proof or a trusted
premise — it is the absence of one, and Lean will happily elaborate a file full of them
and report success. It fails closed here, and an `ASM` that names it is itself a defect
rather than a registration: allowing `sorry` to be registered would convert "nobody has
proved this" into "we have decided to trust it", which are not the same statement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Lean's constant for an incomplete proof. Never a premise, never registrable.
SORRY_AXIOM = "sorryAx"

#: `#print axioms Foo` prints one of these two forms. The list form wraps across lines for
#: a long dependency set, so the body is matched with DOTALL and split afterwards rather
#: than assumed to be on one line — a per-line regex reports a truncated axiom set, which
#: is the direction that reads as cleaner than the truth.
_DEPENDS = re.compile(r"'(?P<name>[^']+)' depends on axioms: \[(?P<axioms>.*?)\]", re.DOTALL)
_NO_AXIOMS = re.compile(r"'(?P<name>[^']+)' does not depend on any axioms")


@dataclass(frozen=True)
class AxiomReport:
    """What the prover said about one named constant."""

    theorem: str
    axioms: tuple[str, ...]


def print_axioms_source(imports: list[str], theorems: list[str]) -> str:
    """A Lean file that asks the prover for each theorem's axiom closure.

    Generated rather than checked in: the set of theorems is the manifest's to declare, and
    a checked-in query file would be a second place that decides which theorems the lane
    measures. The two would disagree the first time only one was edited, and the direction
    of that disagreement is a lane measuring fewer theorems than the unit claims.
    """
    lines = [f"import {module}" for module in imports]
    lines += [f"#print axioms {theorem}" for theorem in theorems]
    return "\n".join(lines) + "\n"


def parse_print_axioms(output: str) -> dict[str, tuple[str, ...]]:
    """`{constant: axioms}` for every constant the prover reported on.

    A constant the prover could not resolve appears in neither form and is therefore
    ABSENT from this mapping rather than present with an empty set. The distinction is the
    whole point: an unresolvable theorem name and a theorem that depends on nothing both
    produce "no axioms" to a careless reader, and only one of them is evidence.
    """
    reports: dict[str, tuple[str, ...]] = {}
    for match in _NO_AXIOMS.finditer(output):
        reports[match.group("name")] = ()
    for match in _DEPENDS.finditer(output):
        axioms = tuple(
            sorted(name.strip() for name in match.group("axioms").split(",") if name.strip())
        )
        reports[match.group("name")] = axioms
    return reports


def registered_axioms(assumptions: list[dict], unit_id: str) -> dict[str, str]:
    """`{lean axiom name: ASM id}` — the premises registered as trusted FOR THIS UNIT.

    Scoped, never global. An assumption registered against one unit does not license the
    same axiom under another: the whole content of an `ASM` is the argument for why
    trusting it *there* is acceptable, and a mechanism-level allowance would license every
    future site the axiom appears in — the failure mode
    `verification/policy/assumptions.toml` describes for its own `sites` field.
    """
    out: dict[str, str] = {}
    for entry in assumptions:
        mechanism = str(entry.get("tool_specific_mechanism", ""))
        if not mechanism.startswith("lean:axiom:"):
            continue
        if f"unit://{unit_id}" not in [str(target) for target in entry.get("scope", [])]:
            continue
        out[mechanism.removeprefix("lean:axiom:")] = str(entry["id"])
    return out


def sorry_registrations(assumptions: list[dict]) -> list[str]:
    """Every `ASM` that tries to register `sorry` as a trusted premise.

    Checked over the WHOLE registry rather than per unit, and reported wherever it is
    found. Its scope does not matter: the defect is that the registry contains a row
    asserting an unproved goal is trusted, and a row like that is wrong before anything
    consults it.
    """
    return sorted(
        str(entry["id"])
        for entry in assumptions
        if str(entry.get("tool_specific_mechanism", "")).endswith(f":{SORRY_AXIOM}")
    )


def classify(
    report: AxiomReport,
    baseline: frozenset[str],
    registered: dict[str, str],
) -> list[str]:
    """Why this theorem's axiom closure is not acceptable, one defect per entry.

    Empty means every axiom the prover reported is either the declared kernel baseline or
    a premise registered against this unit.
    """
    defects: list[str] = []
    for axiom in report.axioms:
        if axiom == SORRY_AXIOM or axiom.endswith(f".{SORRY_AXIOM}"):
            defects.append(
                f"{report.theorem} depends on {axiom}: the proof is incomplete. `sorry` "
                f"is the absence of a proof, not a trusted premise, and it is never "
                f"registrable as an assumption. It need not be in a file this repository "
                f"wrote — the pinned Aeneas Lean library carries four of its own, in "
                f"`Aeneas/Std/Slice.lean` and `Aeneas/Std/StringIter.lean`, and a theorem "
                f"reaching one is a theorem resting on an unproved goal wherever it lives."
            )
        elif axiom in baseline:
            continue
        elif axiom in registered:
            continue
        else:
            defects.append(
                f"{report.theorem} depends on the unregistered axiom {axiom}. Every axiom "
                f"outside the declared kernel baseline is a premise this repository is "
                f"trusting: register it in verification/policy/assumptions.toml with "
                f'tool_specific_mechanism = "lean:axiom:{axiom}" scoped to this unit, or '
                f"discharge it."
            )
    return defects


def unused_registrations(
    reports: list[AxiomReport], registered: dict[str, str]
) -> list[str]:
    """Registered premises no measured theorem actually depends on.

    Reported, and deliberately NOT fatal. A premise that stops being used is a registry
    that overstates the trusted computing base, which is the safe direction of wrong; a
    lane that failed on it would make discharging an assumption harder than leaving it in
    place, and that is the incentive this registry least wants.
    """
    used = {axiom for report in reports for axiom in report.axioms}
    return sorted(
        f"{asm} registers lean:axiom:{axiom}, which no measured theorem depends on"
        for axiom, asm in registered.items()
        if axiom not in used
    )
