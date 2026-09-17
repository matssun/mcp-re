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
under `.github/workflows/`, or is exempt for a stated reason — AND that every control
invoked in COMMAND POSITION is executable in the index.

The second half is the same failure class read one step earlier. A control that cannot
START is not enforced, however many workflows name it, and the failure is not subtle when
it happens — `Permission denied`, stage 1, every run. It is subtle in the INDEX:
`tools/verification/evidence-class-census` landed at mode 100644, and nothing noticed,
because the gate above it matches only `.py` and `.sh` paths and every other control in
this repository happens to have been committed with its bit set. A path invoked as
`python3 x.py` needs no bit and is not asked for one; a path invoked as itself is.

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

#: A fetch that TRUNCATES the object graph rather than extending it.
#:
#: `git fetch --depth=N` into a full clone does not add a ref beside the history; it makes
#: the repository SHALLOW at that commit, and every later step that asks an ancestry
#: question gets the wrong answer. That is not a local mistake: it took the R9 linkage
#: control down with it, reporting all 56 recorded closure commits — present in the clone —
#: as merges the tree does not contain.
#:
#: Refused only in a job that checked out at `fetch-depth: 0`, because that job asked for
#: the full history on purpose and something later reads it. A job that never had the
#: history is free to fetch what it needs.
SHALLOW_FETCH = re.compile(r"git fetch\b[^\n]*(--depth[= ]|--shallow-since|--shallow-exclude)")

#: The checkout option that says "this job needs the whole graph".
FULL_HISTORY = re.compile(r"fetch-depth:\s*0\b")

#: A path run AS A PROGRAM: at the start of a command, or after a shell operator, or as the
#: whole of a `run:` step — and NOT preceded by an interpreter.
#:
#: Extensionless too, which is the half `INVOCATION` cannot see: the verification lanes and
#: the census are executables named `verify-tests`, `evidence-class-census`, and a pattern
#: anchored on `.py`/`.sh` matches none of them.
COMMAND_POSITION = re.compile(
    r"(?:^|&&|\|\||;|\brun:|\bthen\b)\s*\.?/?((?:scripts|tools)/[A-Za-z0-9_./-]+)",
    re.M,
)

#: What an interpreter invocation looks like. A path handed to one of these is an ARGUMENT,
#: and an argument needs no execute bit — demanding one would make the gate ask for a
#: property the invocation does not use.
INTERPRETED = re.compile(r"\b(?:python3?|bash|sh|zsh|source|uv|node)\s+\S*$")

#: Scripts that are deliberately local, each with the reason. The exemption list IS part of
#: what this gate measured, so it is printed on every run and checked for dead entries: an
#: exemption naming a script the gate no longer invokes is a claim about nothing.
EXEMPT: dict[str, str] = {
    # Measurement lanes, not controls. Both refuse to run unattended for reasons of their
    # own — one needs a quiet box, the other a live process — and neither decides whether
    # a change is admissible.
    #
    # The SLO lane DOES run in CI now: `.github/workflows/slo.yml` schedules it on the
    # self-hosted runner. It stays exempt for two reasons, and both are the shape this list
    # is for rather than a way around it. That workflow is `paths:`-filtered on the declared
    # performance surface deliberately — a whole SLO run belongs where perf-relevant code was
    # touched, and `slo_evidence_identity.py` refuses a filter narrower than that surface, so
    # the filter is policed rather than trusted. And the workflow invokes the lane through
    # `scripts/local_gate.sh --from 4`, because stage 4 is a procedure (decide, refuse below
    # the disk floor, measure, attest only a PASS) with one definition; so this path is not
    # named literally there either.
    "scripts/local_slo_lane.sh": (
        "an SLO measurement, not an admissibility control; scheduled by the surface-filtered "
        ".github/workflows/slo.yml via local_gate.sh stage 4"
    ),
    # A PLUMBING rehearsal, and the only lane that needs a live kind cluster plus a 3 GB
    # bench image — neither exists on a CI runner. What keeps it wired is not this gate but
    # `rehearsal_claim_gate.py`, which IS unconditional: it fails if the runbooks' sentence
    # about this rehearsal stops being backed by a reachable invocation.
    "tools/slo/rehearse_job_spec.sh": (
        "a kind-cluster Job-spec rehearsal; its wiring is policed by rehearsal_claim_gate.py"
    ),
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
    # Named only by the `paths:`-filtered verification workflow, and correctly so: it
    # checks the self-hosted runner's environment for that workflow's jobs. Its scope IS
    # that filter — there is no other job whose environment it describes — which is the
    # one shape the filtered-only rule below is meant to admit rather than refuse.
    "scripts/verification_runner_preflight.sh": (
        "a runner-environment preflight whose scope is the verification workflow itself"
    ),
}


def invoked_by(path: Path) -> set[str]:
    return set(INVOCATION.findall(path.read_text(encoding="utf-8")))


#: A `paths:` key under `on:` — the marker of a workflow that does not run on every PR.
PATH_FILTER = re.compile(r"^\s+paths:", re.M)


def workflow_coverage() -> tuple[set[str], set[str]]:
    """`(named by an UNCONDITIONAL workflow, named only by a path-filtered one)`.

    The split is the second half of this gate's own failure class, and it was missing.
    Being NAMED by a workflow was treated as coverage, whatever that workflow's trigger —
    so a control could sit inside a `paths:`-filtered workflow, run on the PRs that touched
    those paths, and run on no others, while this gate reported it enforced. That is the
    same defect one level up: the filter and the set of changes the control must see are
    one dependency written down twice, and when they diverge nothing goes red, the job
    simply does not start.

    It was not hypothetical. `tools/verification/test_mutation_lane.py` — the self-test for
    the mutation lane's verdict semantics — was in neither `local_gate.sh` nor any
    unconditional workflow, and was invisible here because `mutation-probe.yml` mentions it.
    """
    unconditional: set[str] = set()
    filtered: set[str] = set()
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        target = filtered if PATH_FILTER.search(text) else unconditional
        target |= set(INVOCATION.findall(text))
    return unconditional, filtered - unconditional


#: The assurance platform's own self-tests. They are what establishes that a `verify`
#: verdict means what ADR-MCPRE-059 says it means, so every product claim rests on them —
#: which is why their scope here is NOT "whatever local_gate.sh happens to invoke". A suite
#: nobody wired into either aggregate would otherwise be enforced by nothing and visible to
#: nothing, and that is exactly how `test_mutation_lane.py` came to be neither.
SELFTEST_GLOB = "tools/verification/test_*.py"


def defects(
    gated: set[str],
    covered: set[str],
    exempt: dict[str, str],
    filtered_only: set[str] | None = None,
    selftests: set[str] | None = None,
) -> list[str]:
    """Controls the merge path does not run, and exemptions that name nothing."""
    filtered_only = filtered_only or set()
    found: list[str] = []
    for script in sorted(gated - covered - exempt.keys()):
        if script in filtered_only:
            found.append(
                f"{script} is named only by a `paths:`-filtered workflow. It therefore runs "
                f"on the pull requests that touch those paths and on no others, while "
                f"reading as enforced. Move it to an unconditional job, or add it to EXEMPT "
                f"with the reason its scope really is that filter."
            )
            continue
        found.append(
            f"{script} runs only in scripts/local_gate.sh. A control the assurance model "
            f"relies on must be present on the merge path; add it to a workflow, or add it "
            f"to EXEMPT with the reason it is deliberately local."
        )
    for script in sorted((selftests or set()) - covered - exempt.keys()):
        found.append(
            f"{script} is an assurance-platform self-test that no unconditional workflow "
            f"names. These suites are what establishes that a `verify` verdict means what "
            f"ADR-MCPRE-059 says it means; one that runs conditionally, or not at all, "
            f"leaves that meaning unestablished on every pull request that does not trip "
            f"its filter."
        )
    found.extend(
        f"EXEMPT names {script}, which scripts/local_gate.sh does not invoke. A dead "
        f"exemption is a claim about nothing and hides the next one that matters."
        for script in sorted(exempt.keys() - gated - (selftests or set()))
    )
    return found


def command_position_paths(text: str) -> set[str]:
    """Every repository path this text runs AS A PROGRAM.

    The preceding characters decide it: a path after `python3` is an argument, and one at
    the head of a command is a program. Matched per line and re-checked against the text
    before it, because the two forms are otherwise indistinguishable by shape alone.
    """
    found: set[str] = set()
    for match in COMMAND_POSITION.finditer(text):
        before = text[: match.start(1)].rsplit("\n", 1)[-1]
        if INTERPRETED.search(before):
            continue
        found.add(match.group(1))
    return found


def truncating_fetches(text: str) -> list[str]:
    """Shallow fetches inside a workflow whose checkout asked for the full history.

    Text-level and job-agnostic on purpose: the two facts are a `fetch-depth: 0` and a
    `--depth` fetch in the same file, and a parser that tried to attribute each to a job
    would be a YAML parser this gate does not have. A workflow with several jobs, only one
    of which is deep, is a false positive worth having — the fix is the same either way,
    and the alternative is the check nobody can be sure ran.
    """
    if not FULL_HISTORY.search(text):
        return []
    return [line.strip() for line in text.splitlines() if SHALLOW_FETCH.search(line)]


def not_executable(paths: set[str]) -> list[str]:
    """Those of `paths` that exist in the tree and are not executable.

    The FILESYSTEM bit, which is what a fresh clone and a CI checkout both get from the
    index — so a developer who ran `chmod +x` locally and never staged the mode change sees
    a green gate here and a red one in CI. A path that does not exist is not this gate's
    finding: the coverage half above already refuses a control nothing can run, and
    reporting a missing file as a permissions defect would send someone to the wrong fix.
    """
    import os

    return sorted(
        path
        for path in paths
        if (REPO / path).is_file() and not os.access(REPO / path, os.X_OK)
    )


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
    # The two rules added after the sweep, each with the case that motivated it.
    filtered = defects(
        {"scripts/a.py"}, set(), {}, filtered_only={"scripts/a.py"}
    )
    if not any("`paths:`-filtered workflow" in entry for entry in filtered):
        print("SELFTEST FAIL: accepted a control named only by a filtered workflow", file=sys.stderr)
        return 1
    if any("runs only in scripts/local_gate.sh" in entry for entry in filtered):
        print("SELFTEST FAIL: a filtered-only control reported as local-only", file=sys.stderr)
        return 1
    uncovered_suite = defects(
        set(), set(), {}, selftests={"tools/verification/test_x.py"}
    )
    if not any("assurance-platform self-test" in entry for entry in uncovered_suite):
        print("SELFTEST FAIL: accepted a self-test no unconditional workflow names", file=sys.stderr)
        return 1
    covered_suite = defects(
        set(),
        {"tools/verification/test_x.py"},
        {},
        selftests={"tools/verification/test_x.py"},
    )
    if covered_suite:
        print(f"SELFTEST FAIL: refused a covered self-test: {covered_suite}", file=sys.stderr)
        return 1
    # A filtered workflow must not count as coverage, and an unfiltered one must.
    if PATH_FILTER.search("on:\n  pull_request:\n    branches: [main]\n"):
        print("SELFTEST FAIL: PATH_FILTER matched a workflow with no paths key", file=sys.stderr)
        return 1
    if not PATH_FILTER.search("on:\n  pull_request:\n    paths:\n      - 'src/**'\n"):
        print("SELFTEST FAIL: PATH_FILTER missed a paths key", file=sys.stderr)
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
    # The command-position extractor, which is the half that found an unstageable mode.
    # Both directions, because either mistake is silent: a pattern that matched an
    # interpreted path would demand an execute bit nothing uses, and one that missed a
    # program would report a control as runnable that cannot start.
    for text, expect, why in [
        ("    && tools/verification/evidence-class-census --selftest \\", True, "a program after &&"),
        ("      run: tools/verification/verify-mutations", True, "a program as a run: step"),
        ("  scripts/run_gate.sh --selftest", True, "a program at the head of a line"),
        ("    && python3 tools/verification/test_views.py \\", False, "an argument to python3"),
        ("    . scripts/use_pinned_toolchain.sh || exit 1", False, "a sourced shim"),
        ("      run: bash scripts/demo-local.sh", False, "an argument to bash"),
    ]:
        matched = bool(command_position_paths(text))
        if matched is not expect:
            print(
                f"SELFTEST FAIL: command-position extractor {'missed' if expect else 'matched'} "
                f"{why}: {text!r}",
                file=sys.stderr,
            )
            return 1
    # And the verdict itself: a path that exists and is not executable must be reported,
    # while a missing path must not be — that is the coverage half's finding, and naming it
    # here would send someone to the wrong fix.
    if not not_executable({"scripts/local_gate.sh", "README.md"}) == ["README.md"]:
        print("SELFTEST FAIL: the executable check does not distinguish a non-executable file", file=sys.stderr)
        return 1
    if not_executable({"scripts/a-file-that-does-not-exist.sh"}):
        print("SELFTEST FAIL: a missing path was reported as a permissions defect", file=sys.stderr)
        return 1
    # The shallow-fetch rule, both directions. It exists because the defect it names was
    # introduced BY a new control and broke a different one: the fix and the breakage were
    # in the same commit, and nothing related them.
    for text, expect, why in [
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n      - run: git fetch --no-tags --depth=1 origin main\n",
         True, "a --depth fetch in a deep checkout"),
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n      - run: git fetch --no-tags origin main\n",
         False, "a full fetch in a deep checkout"),
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n      - run: git fetch --depth=1 origin main\n",
         False, "a shallow fetch where no step asked for the whole graph"),
        ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n      - run: git fetch --shallow-since=2026-01-01 origin main\n",
         True, "the other shallowing form"),
    ]:
        found = bool(truncating_fetches(text))
        if found is not expect:
            print(
                f"SELFTEST FAIL: shallow-fetch rule {'missed' if expect else 'flagged'} {why}",
                file=sys.stderr,
            )
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
    covered, filtered_only = workflow_coverage()
    selftests = {
        path.relative_to(REPO).as_posix() for path in REPO.glob(SELFTEST_GLOB)
    }
    if not selftests:
        print(
            f"FAIL: no assurance-platform self-test matched {SELFTEST_GLOB}. An empty "
            f"scope is the gate measuring nothing while printing OK.",
            file=sys.stderr,
        )
        return 1
    runnable = command_position_paths(LOCAL_GATE.read_text(encoding="utf-8"))
    truncating: list[str] = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        runnable |= command_position_paths(text)
        truncating += [
            f"{workflow.name}: `{line}` SHALLOWS a clone this workflow took at "
            f"`fetch-depth: 0`. A shallow fetch truncates the object graph rather than "
            f"extending it, so every later step that asks an ancestry question measures a "
            f"history that is no longer there. Drop the depth flag, or read the ref the "
            f"deep checkout already provides."
            for line in truncating_fetches(text)
        ]
    found = list(truncating)
    found += [
        f"{path} is invoked as a program by local_gate.sh or a workflow and is NOT "
        f"executable. A control that cannot start is not enforced — this is `Permission "
        f"denied`, stage 1, on every fresh checkout. Stage the mode: "
        f"`git update-index --chmod=+x {path}`."
        for path in not_executable(runnable)
    ]
    found += defects(gated, covered, EXEMPT, filtered_only, selftests)
    for defect in found:
        print(f"FAIL: {defect}", file=sys.stderr)
    if found:
        return 1
    exemptions = ", ".join(f"{name} ({why})" for name, why in sorted(EXEMPT.items()))
    print(
        f"merge-path gate: OK — {len(gated)} script(s) invoked by local_gate.sh and "
        f"{len(selftests)} platform self-test(s), all named by an UNCONDITIONAL workflow "
        f"except: {exemptions}; {len(runnable)} path(s) run as programs, all executable"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
