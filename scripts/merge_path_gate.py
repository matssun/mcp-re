#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge-path gate — a control the assurance model relies on must run on the merge path.

THE FAILURE CLASS, which is the reason this file exists rather than any single instance:

    A security/assurance control relied upon by the assurance model must be mechanically
    present on the required merge path. Existence in a local-only aggregate such as
    `scripts/local_gate.sh` does not establish enforcement.

`local_gate.sh` is a convenience aggregate that a developer chooses to run. A control
reachable only from it is enforced by remembering to run it, which is the same standing as
no control at all — with the added cost that the repository, its docs and its reviewers all
believe the control is enforced. That belief is the damage: every claim above a control
reads as measured while nothing measured the change.

It has happened repeatedly and was never noticed by the thing that failed:

  * the two ADR-MCPRE-061 ratchets — a PR could grow a registered file or a lint baseline;
  * `verification_trigger_gate.py` — a PR narrowing the trigger filter also disabled the
    check that polices the filter;
  * `registry_approval_gate.py` — RED on `main`, with every CI check on every PR green;
  * the ten `tools/verification/test_*.py` suites, which are the assurance platform's own
    self-tests: nothing on the merge path established that the verdict algebra, the
    invalidation rules, the escape-hatch detector or the views generator still behave as
    the ADR says.

Each was repaired one at a time, by someone noticing. This gate is what notices.

WHAT IT PROVES: every script `local_gate.sh` invokes is named by at least one workflow
under `.github/workflows/`, or is exempt for a stated reason.

A workflow must name its controls LITERALLY. This gate reads paths, so a step that
assembles a script name at run time — a shell loop over a list of suites, say — is a
control it cannot see, and an invisible control is how the next instance of this class
gets missed. Legibility to the checker is part of the enforcement.

WHAT IT DOES NOT PROVE: that the workflow naming it is a REQUIRED check, that the job runs
on every PR, or that the control is correct. Branch protection is repository configuration
and is not readable from the tree; this gate closes the gap it can see from here, which is
the one that has actually opened five times.

Run:  python3 scripts/merge_path_gate.py
      python3 scripts/merge_path_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOCAL_GATE = REPO / "scripts" / "local_gate.sh"
WORKFLOWS = REPO / ".github" / "workflows"

#: An invocation of a repository script, in either of the two forms the gate script uses.
INVOCATION = re.compile(r"(?:^|[\s`\"'./])((?:scripts|tools)/[A-Za-z0-9_./-]+?\.(?:py|sh))")

#: Scripts that are deliberately local, each with the reason. The exemption list IS part of
#: what this gate measured, so it is printed on every run and checked for dead entries: an
#: exemption naming a script the gate no longer invokes is a claim about nothing.
EXEMPT: dict[str, str] = {
    # Measurement lanes, not controls. Both refuse to run unattended for reasons of their
    # own — one needs a quiet box, the other a live process — and neither decides whether
    # a change is admissible.
    "scripts/local_slo_lane.sh": "an SLO measurement; refuses to measure on a loaded box",
    "scripts/demo-local.sh": "a demo runner, not a control",
    # An environment shim consumed by `.` before anything runs. CI pins its toolchain in
    # the workflow instead, so there is nothing here for a job to invoke.
    "scripts/use_pinned_toolchain.sh": "sourced toolchain shim; CI pins its own",
    # Architecture ANALYSIS. These report numbers for a human to classify — ADR-MCPRE-060
    # is explicit that the workflow is measure, validate, classify, review, and never
    # "run script, refactor until the number falls". A report has no pass to enforce, and
    # only their `--selftest` runs in the gate, which is a check that the measurement still
    # measures.
    "scripts/module_map.py": "an architecture report with no verdict; --selftest only",
    "scripts/startup_backedges.py": "an architecture report with no verdict; --selftest only",
}


def invoked_by(path: Path) -> set[str]:
    return set(INVOCATION.findall(path.read_text(encoding="utf-8")))


def workflow_coverage() -> set[str]:
    covered: set[str] = set()
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        covered |= invoked_by(workflow)
    return covered


def defects(gated: set[str], covered: set[str], exempt: dict[str, str]) -> list[str]:
    """Controls the merge path does not run, and exemptions that name nothing."""
    found = [
        f"{script} runs only in scripts/local_gate.sh. A control the assurance model "
        f"relies on must be present on the merge path; add it to a workflow, or add it "
        f"to EXEMPT with the reason it is deliberately local."
        for script in sorted(gated - covered - exempt.keys())
    ]
    found.extend(
        f"EXEMPT names {script}, which scripts/local_gate.sh does not invoke. A dead "
        f"exemption is a claim about nothing and hides the next one that matters."
        for script in sorted(exempt.keys() - gated)
    )
    return found


def selftest() -> int:
    """A gate whose only evidence is that a clean tree passes has never been shown to fail."""
    cases = [
        (
            {"scripts/a.py"},
            set(),
            {},
            "runs only in scripts/local_gate.sh",
            "a control on no workflow",
        ),
        (
            {"scripts/a.py"},
            {"scripts/a.py"},
            {},
            None,
            "a control a workflow names",
        ),
        (
            {"scripts/a.py"},
            set(),
            {"scripts/a.py": "local by design"},
            None,
            "an exempt control",
        ),
        (
            set(),
            set(),
            {"scripts/gone.py": "stale"},
            "which scripts/local_gate.sh does not invoke",
            "an exemption naming nothing",
        ),
    ]
    for gated, covered, exempt, needle, label in cases:
        found = defects(gated, covered, exempt)
        if needle is None:
            if found:
                print(f"SELFTEST FAIL: refused {label}: {found}", file=sys.stderr)
                return 1
            continue
        if not any(needle in entry for entry in found):
            print(f"SELFTEST FAIL: accepted {label}", file=sys.stderr)
            return 1
    # The extractor is half the gate: a pattern that stopped matching would report an empty
    # scope as a clean tree, which is the failure this repository has already shipped once.
    if "tools/verification/verify" in INVOCATION.findall("python3 tools/verification/verify"):
        print("SELFTEST FAIL: the extractor matched an extensionless path", file=sys.stderr)
        return 1
    for line, expect in [
        ("    && python3 scripts/module_size_gate.py \\", "scripts/module_size_gate.py"),
        ("    && ./scripts/verification_runner_preflight.sh \\", "scripts/verification_runner_preflight.sh"),
        ("      run: python3 tools/verification/test_views.py", "tools/verification/test_views.py"),
    ]:
        if expect not in INVOCATION.findall(line):
            print(f"SELFTEST FAIL: the extractor missed {expect} in {line!r}", file=sys.stderr)
            return 1
    print("merge_path_gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    gated = invoked_by(LOCAL_GATE)
    if not gated:
        # An empty scope is the gate measuring nothing while printing OK.
        print(
            f"FAIL: merge-path gate found no script invocations in {LOCAL_GATE}. "
            f"The extractor has stopped matching.",
            file=sys.stderr,
        )
        return 1
    covered = workflow_coverage()
    found = defects(gated, covered, EXEMPT)
    for defect in found:
        print(f"FAIL: {defect}", file=sys.stderr)
    if found:
        return 1
    exemptions = ", ".join(f"{name} ({why})" for name, why in sorted(EXEMPT.items()))
    print(
        f"merge-path gate: OK — {len(gated)} script(s) invoked by local_gate.sh, "
        f"{len(gated - EXEMPT.keys())} of them named by a workflow. "
        f"Exempt: {exemptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
