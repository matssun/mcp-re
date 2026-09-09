# SPDX-License-Identifier: Apache-2.0
"""The Lean lane's activation probe — does the refusal still fire?

`scripts/clippy_ratchet_gate.py --activation-probe` exists because a threshold in a config
file parameterised a lint nobody had switched on, and the repository described the rule as
mechanically enforced for months. The same failure is available here and is quieter: every
refusal in this lane is conditional on `#print axioms` reporting what this code expects it
to report, and a Lean release that changed the message, a lakefile that stopped building the
theorems, or a parser that silently matched nothing would each turn every check into a
tautology. All three produce the same symptom — a clean axiom closure — and a clean axiom
closure is what a passing lane looks like.

So the probe asks the REAL prover for three propositions the lane must refuse, and fails
when it does not refuse them:

  * a theorem proved by `sorry` — `sorryAx` in the closure, never registrable;
  * a theorem resting on an axiom no `ASM` registers;
  * a constant that does not exist — absent from the reports, never "depends on nothing".

It writes nothing into the repository and names nothing the manifest declares: the
propositions are elaborated on the spot, so a probe that passes says the lane's refusals are
live in THIS environment, at this pin, right now.
"""

from __future__ import annotations

from _lean_axioms import AxiomReport, classify, parse_print_axioms
from _lean_query import elaborate

#: Deliberately unlikely to collide with anything the package defines, and deliberately
#: readable: a name in a failure message should say what it is.
NAMESPACE = "MCPREActivationProbe"

_SOURCE = """
{imports}

namespace {ns}

theorem proved_by_sorry : False := by sorry

axiom unregistered_premise : False

theorem rests_on_unregistered_premise : False := unregistered_premise

end {ns}

#print axioms {ns}.proved_by_sorry
#print axioms {ns}.rests_on_unregistered_premise
#print axioms {ns}.no_such_theorem
"""


def source(imports: list[str]) -> str:
    return _SOURCE.format(
        imports="\n".join(f"import {module}" for module in imports), ns=NAMESPACE
    )


def run(imports: list[str], baseline: frozenset[str]) -> list[str]:
    """Every way the lane's refusals failed to fire, or an empty list.

    `registered` is empty on purpose. The probe measures the lane with nothing trusted, so a
    defect here is the mechanism failing rather than a registry happening to cover it.
    """
    _code, output = elaborate(source(imports), "activation probe")
    reports = parse_print_axioms(output)
    defects: list[str] = []

    for name, must_say in (
        ("proved_by_sorry", "never registrable"),
        ("rests_on_unregistered_premise", "unregistered axiom"),
    ):
        qualified = f"{NAMESPACE}.{name}"
        if qualified not in reports:
            defects.append(
                f"the probe's {name} did not elaborate, so the refusal it exercises was "
                f"never reached. The prover said:\n{output.strip()[-2000:]}"
            )
            continue
        found = classify(AxiomReport(qualified, reports[qualified]), baseline, {})
        if not any(must_say in defect for defect in found):
            defects.append(
                f"{qualified} has axiom closure {reports[qualified]} and the lane did not "
                f"refuse it for '{must_say}'. The refusal is not firing."
            )

    absent = f"{NAMESPACE}.no_such_theorem"
    if absent in reports:
        defects.append(
            f"the prover reported on {absent}, which does not exist. A constant it cannot "
            f"resolve must be ABSENT from the reports; reporting it as depending on "
            f"nothing would make a misspelled theorem name the cleanest evidence here."
        )
    return defects
