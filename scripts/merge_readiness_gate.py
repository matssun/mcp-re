#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge-readiness gate — the sole authority for whether a candidate SHA may merge.

THE FAILURE CLASS, which is why this file exists rather than any single instance:

    A merge authorized by anything weaker than "every lane the affected verification-unit
    closure requires COMPLETED SUCCESSFULLY at this exact SHA".

The instance: #945 merged while its `verification platform` lane had never executed at its
SHA. Every step of that was individually defensible — the required-check set was green, the
lane is not in `Protect main`, and a human read a status list and saw nothing red. What was
missing is that *nothing red* and *everything required, measured, here* are different
propositions, and only the second authorizes a merge. A queued lane is not a green one; an
absent check is not a passing one; a check green at a DIFFERENT commit says nothing about
this one.

WHY A CONTROL AND NOT A CONVENTION. The weaker query is always available and always easier:
`gh pr checks` prints a list a reader summarises, and summarising is where the four
distinctions below are lost. So this gate does not advise — it answers, and the answer is
tri-state with no raw material attached for a caller to re-interpret.

WHAT "REQUIRED" MEANS HERE, and where it comes from. Not a list in this file. A second list
of required evidence is the defect it would exist to prevent: it would drift from the
manifest silently and in the direction that produces a false ready. The chain is derived,
end to end, from authorities that already govern the campaign:

    changed files          git diff against the merge base
      -> affected units    `verification.toml` unit `paths`, widened by the workspace
                           build inputs and closed forward over prerequisite edges
      -> required lanes    `_evidence.required_lanes` — the lanes a unit's declared
                           `evidence` URIs claim
      -> required checks   `verify.LANES` names each lane's script; the workflows name
                           which job runs that script, or the umbrella `verify` that
                           contains it. The job's `name:` IS the check name GitHub reports.

THE FOUR CONDITIONS, per required check. All four, or the check is not satisfied:

    the check EXISTS for this SHA
    its head_sha == the candidate SHA
    its status == "completed"
    its conclusion == "success"

Everything else is NOT READY — missing, queued, pending, in_progress, a null or empty
conclusion, cancelled, skipped, timed_out, neutral. `failure` and `timed_out` are reported
as FAILED rather than NOT_READY because they are verdicts about the code and the next
action differs: NOT_READY means wait or re-run, FAILED means fix.

WHEN THE CLOSURE IS EMPTY. A change can touch no declared unit at all — a gate script, a
workflow, a document. The manifest then asks for nothing, and answering READY on that basis
would be the emptiest false green available: "no lane was required" and "every required lane
passed" are different facts. So the gate falls back to the authority that DOES govern such a
change, and reads it from where it actually lives — the repository's own branch ruleset, via
the API. That is not a second list: it is not maintained here, and a required check added or
renamed in the ruleset is picked up on the next run.

Both paths answer the same four conditions and the same three states. What differs is only
which checks are required, and the report says which authority it used.

WHAT THIS DOES NOT PROVE: that the required lanes are the right ones (that is the manifest's
claim), or that a passing lane measured what it says (that is the lane's). It proves that
what the governing authority asks for has completed successfully at this exact commit.

Run:  python3 scripts/merge_readiness_gate.py --sha <candidate>
      python3 scripts/merge_readiness_gate.py --pr 946
      python3 scripts/merge_readiness_gate.py --selftest

Exit status: 0 READY, 1 NOT_READY, 2 FAILED, 3 the gate could not decide.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"

sys.path.insert(0, str(REPO / "tools" / "verification"))

from _evidence import MALFORMED_LANE, PREREQUISITE_KINDS, required_lanes  # noqa: E402
from _fingerprint import WORKSPACE_BUILD_INPUTS  # noqa: E402
from _load_tool import load_tool  # noqa: E402
from _manifest import load_verification  # noqa: E402

#: The only three answers. A caller that wants to know whether to merge reads exactly one
#: of these; there is deliberately no fourth "green except…" state to argue with.
READY, NOT_READY, FAILED = "READY", "NOT_READY", "FAILED"

#: Conclusions that are a verdict about the code rather than an incomplete measurement.
#: `cancelled` is NOT here: a cancelled run measured nothing, so it is an absence.
FAILING_CONCLUSIONS = {"failure", "timed_out", "action_required", "startup_failure"}

#: The umbrella that runs every lane in one invocation. A job naming it satisfies every
#: lane's requirement, which is why the mapping cannot be read off lane scripts alone.
UMBRELLA = "tools/verification/verify"

#: A script invocation inside a workflow, in the forms the workflows actually use.
INVOCATION = re.compile(r"(?:^|[\s`\"'./])((?:scripts|tools)/[A-Za-z0-9_./-]+)")

#: A top-level job key (2-space indent) and a job's `name:` (4-space indent).
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
JOB_NAME = re.compile(r"^    name:\s*(.+?)\s*$", re.M)


class Undecidable(Exception):
    """The gate cannot answer. Never the same thing as NOT_READY, and never merged on."""


# --------------------------------------------------------------------------- derivation


def lane_scripts() -> dict[str, str]:
    """`{lane: script}` from the umbrella's own LANES table — the naming authority."""
    return {name: script for name, script, _is_formal in load_tool("verify").LANES}


def workflow_jobs() -> list[tuple[str, str, set[str]]]:
    """`(workflow, check name, scripts that job invokes)` for every job in every workflow.

    The check name is the job's `name:`, because that is the string GitHub reports and
    therefore the only one a readiness query can match on. A job without one would be
    reported under its key; none of the jobs this gate resolves is in that shape, and a
    lane whose job cannot be named fails loudly below rather than resolving to nothing.
    """
    jobs: list[tuple[str, str, set[str]]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        starts: list[tuple[int, str]] = []
        in_jobs = False
        for i, line in enumerate(lines):
            if line.startswith("jobs:"):
                in_jobs = True
                continue
            if in_jobs and line and not line.startswith(" ") and not line.startswith("#"):
                in_jobs = False
            if in_jobs:
                key = JOB_KEY.match(line)
                if key:
                    starts.append((i, key.group(1)))
        for n, (start, key) in enumerate(starts):
            end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
            body = "\n".join(lines[start:end])
            named = JOB_NAME.search(body)
            name = named.group(1).strip("\"'") if named else key
            jobs.append((path.name, name, set(INVOCATION.findall(body))))
    return jobs


def checks_for_lanes(lanes: set[str], scripts: dict[str, str]) -> dict[str, list[str]]:
    """`{lane: [check names]}` — every job that executes each lane, from the workflows.

    A lane is run by a job invoking its own script OR the umbrella that contains it, and
    BOTH shapes exist here: `mutation` has a dedicated path-filtered job and is also inside
    the umbrella. All of them are returned rather than one picked, because any job that
    actually measured the lane at this SHA satisfies it, and choosing between them here
    would be this file inventing a policy the workflows do not state.

    Resolving to nothing raises: a required lane no workflow runs is exactly the shape that
    lets a merge proceed on evidence that never existed, and it must not read as satisfied.
    """
    jobs = workflow_jobs()
    resolved: dict[str, list[str]] = {}
    for lane in sorted(lanes):
        if lane == MALFORMED_LANE:
            raise Undecidable(
                "a unit declares an evidence entry that is not a URI, so the lane it "
                "claims cannot be named; fix the manifest before asking about a merge"
            )
        script = scripts.get(lane)
        if script is None:
            raise Undecidable(
                f"lane '{lane}' is claimed by the manifest but is not in verify.LANES, so "
                f"no script and no job can be derived for it"
            )
        wanted = {f"tools/verification/{script}", UMBRELLA}
        found = sorted({name for _wf, name, invoked in jobs if invoked & wanted})
        if not found:
            raise Undecidable(
                f"lane '{lane}' (tools/verification/{script}) is required but no workflow "
                f"job invokes it or the umbrella; nothing would ever measure it"
            )
        resolved[lane] = found
    return resolved


def affected_units(units: list[dict], edges: list[dict], changed: set[str]) -> set[str]:
    """The unit ids whose evidence this change can invalidate.

    Three widenings, each closing a way a change reaches a unit without touching its own
    declared paths: a workspace build input changes what EVERY unit is about; the
    verification tooling and policy change what every measurement MEANS; and a prerequisite
    edge carries a producer's invalidation forward to its consumers.
    """
    if any(c in WORKSPACE_BUILD_INPUTS for c in changed):
        return {u["id"] for u in units}
    if any(c.startswith(("tools/verification/", "verification/policy/")) for c in changed):
        return {u["id"] for u in units}

    hit = set()
    for unit in units:
        for declared in unit.get("paths", []):
            if any(c == declared or c.startswith(declared.rstrip("/") + "/") for c in changed):
                hit.add(unit["id"])
                break

    changed_flag = True
    while changed_flag:
        changed_flag = False
        for edge in edges:
            if edge["kind"] in PREREQUISITE_KINDS and edge["from"] in hit and edge["to"] not in hit:
                hit.add(edge["to"])
                changed_flag = True
    return hit


# ------------------------------------------------------------------------------ verdict


def classify(check: dict | None, sha: str) -> tuple[bool, str]:
    """`(satisfied, why)` for one required check, against all four conditions."""
    if check is None:
        return False, "missing — no such check at this SHA"
    if check.get("head_sha") != sha:
        return False, f"measured at {str(check.get('head_sha'))[:12]}, not the candidate"
    status = check.get("status") or ""
    if status != "completed":
        return False, f"status {status or '(empty)'}"
    conclusion = check.get("conclusion") or ""
    if conclusion == "success":
        return True, "completed/success"
    return False, f"conclusion {conclusion or '(empty)'}"


def decide(
    required: dict[str, list[str]], runs: dict[str, dict], sha: str
) -> tuple[str, list[tuple]]:
    """The tri-state answer, plus one row per required lane for the human-readable table.

    A lane is satisfied when ANY job that runs it met all four conditions. It is FAILED
    when none did and at least one returned a verdict about the code; otherwise the
    measurement is merely incomplete, which is NOT_READY and a different next action.
    """
    rows, satisfied, failing = [], True, False
    for lane, names in sorted(required.items()):
        verdicts = [(name, *classify(runs.get(name), sha)) for name in names]
        winner = next((v for v in verdicts if v[1]), None)
        if winner is not None:
            rows.append((lane, winner[0], "OK", winner[2]))
            continue
        satisfied = False
        if any((runs.get(name) or {}).get("conclusion") in FAILING_CONCLUSIONS for name in names):
            failing = True
        name, _ok, why = verdicts[0]
        detail = why if len(verdicts) == 1 else f"{why}; none of {len(verdicts)} jobs satisfied it"
        rows.append((lane, name, "NOT SATISFIED", detail))
    if failing:
        return FAILED, rows
    return (READY if satisfied else NOT_READY), rows


# -------------------------------------------------------------------------------- input


def git(*args: str) -> str:
    done = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise Undecidable(f"git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout.strip()


def gh_json(*args: str):
    done = subprocess.run(["gh", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise Undecidable(f"gh {' '.join(args)}: {done.stderr.strip()}")
    return json.loads(done.stdout or "null")


def check_runs(repo: str, sha: str) -> dict[str, dict]:
    """The latest check run per name at `sha`. Later attempts supersede earlier ones."""
    raw = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/commits/{sha}/check-runs?per_page=100",
         "--jq", ".check_runs[]"],
        capture_output=True, text=True,
    )
    if raw.returncode != 0:
        raise Undecidable(f"gh api check-runs: {raw.stderr.strip()}")
    latest: dict[str, dict] = {}
    for line in raw.stdout.splitlines():
        if not line.strip():
            continue
        run = json.loads(line)
        prior = latest.get(run["name"])
        if prior is None or (run.get("started_at") or "") >= (prior.get("started_at") or ""):
            latest[run["name"]] = run
    return latest


def ruleset_required_checks(repo: str, base: str) -> list[str]:
    """The check contexts the repository's own ruleset requires on the target branch.

    Read from the API rather than transcribed, so this file holds no opinion about which
    checks are required and cannot drift from the ruleset. An empty or unreadable answer
    RAISES: a fallback authority that turns out to require nothing would make every
    unit-less change READY, which is the same false green the fallback exists to avoid.
    """
    branch = base.split("/")[-1]
    raw = subprocess.run(
        ["gh", "api", f"repos/{repo}/rulesets", "--jq",
         '.[] | select(.enforcement == "active") | .id'],
        capture_output=True, text=True,
    )
    if raw.returncode != 0:
        raise Undecidable(f"gh api rulesets: {raw.stderr.strip()}")
    ids = [line.strip() for line in raw.stdout.splitlines() if line.strip()]
    contexts: set[str] = set()
    for rid in ids:
        detail = subprocess.run(
            ["gh", "api", f"repos/{repo}/rulesets/{rid}", "--jq", "@json"],
            capture_output=True, text=True,
        )
        if detail.returncode != 0:
            continue
        payload = json.loads(detail.stdout or "{}")
        conditions = payload.get("conditions", {}).get("ref_name", {})
        include = conditions.get("include", [])
        if include and not any(
            token in ("~ALL", "~DEFAULT_BRANCH", f"refs/heads/{branch}") for token in include
        ):
            continue
        for rule in payload.get("rules", []):
            if rule.get("type") != "required_status_checks":
                continue
            for check in rule.get("parameters", {}).get("required_status_checks", []):
                if check.get("context"):
                    contexts.add(check["context"])
    if not contexts:
        raise Undecidable(
            f"no declared unit is affected and the ruleset for '{branch}' requires no status "
            "check, so nothing at all governs this candidate; decide it deliberately"
        )
    return sorted(contexts)


def changed_files(sha: str, base: str) -> set[str]:
    merge_base = git("merge-base", base, sha)
    return set(git("diff", "--name-only", f"{merge_base}..{sha}").splitlines())


# --------------------------------------------------------------------------------- main


def report(sha: str, units: set[str], rows: list[tuple], state: str, authority: str) -> None:
    print(f"candidate      {sha}")
    print(f"authority      {authority}")
    print(f"affected units {len(units)}")
    for lane, check, mark, why in rows:
        # Under the ruleset authority the "lane" IS the check, so printing both would be
        # the same string twice.
        label = check if lane == check else f"{lane:<16} {check}"
        print(f"  {mark:<14} {label}  [{why}]")
    print(f"MERGE-READINESS: {state}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sha", help="candidate commit; defaults to the PR head or HEAD")
    parser.add_argument("--pr", help="resolve the candidate from this PR number")
    parser.add_argument("--base", default="origin/main", help="merge base ref")
    parser.add_argument("--repo", default="matssun/mcp-re")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    try:
        sha = args.sha
        if args.pr and not sha:
            sha = gh_json("pr", "view", args.pr, "--repo", args.repo, "--json", "headRefOid")["headRefOid"]
        sha = git("rev-parse", sha or "HEAD")

        manifest = load_verification()
        units, edges = manifest["unit"], manifest.get("edge", [])
        affected = affected_units(units, edges, changed_files(sha, args.base))
        lanes: set[str] = set()
        for unit in units:
            if unit["id"] in affected:
                lanes |= required_lanes(unit)
        if lanes:
            authority = "verification-unit closure"
            required = checks_for_lanes(lanes, lane_scripts())
        else:
            # No declared unit is affected, so the manifest asks for nothing. Fall back to
            # the ruleset rather than reading "nothing required" as "everything passed".
            authority = "branch ruleset (no declared unit affected)"
            required = {name: [name] for name in ruleset_required_checks(args.repo, args.base)}
        state, rows = decide(required, check_runs(args.repo, sha), sha)
        report(sha, affected, rows, state, authority)
        return {READY: 0, NOT_READY: 1, FAILED: 2}[state]
    except Undecidable as exc:
        print(f"MERGE-READINESS: UNDECIDABLE — {exc}", file=sys.stderr)
        return 3


# ----------------------------------------------------------------------------- selftest


def selftest() -> int:
    """The false-ready catalogue: every shape that must NOT read as READY."""
    sha = "a" * 40
    req = {"test": ["verification platform"]}

    def run(check):
        return decide(req, {"verification platform": check} if check else {}, sha)[0]

    cases = [
        (None, NOT_READY, "missing check"),
        ({"name": "verification platform", "head_sha": sha, "status": "queued", "conclusion": None}, NOT_READY, "queued"),
        ({"name": "verification platform", "head_sha": sha, "status": "in_progress", "conclusion": None}, NOT_READY, "in_progress"),
        ({"name": "verification platform", "head_sha": sha, "status": "completed", "conclusion": None}, NOT_READY, "null conclusion"),
        ({"name": "verification platform", "head_sha": sha, "status": "completed", "conclusion": ""}, NOT_READY, "empty conclusion"),
        ({"name": "verification platform", "head_sha": sha, "status": "completed", "conclusion": "skipped"}, NOT_READY, "skipped while required"),
        ({"name": "verification platform", "head_sha": sha, "status": "completed", "conclusion": "cancelled"}, NOT_READY, "cancelled measured nothing"),
        ({"name": "verification platform", "head_sha": sha, "status": "completed", "conclusion": "neutral"}, NOT_READY, "neutral"),
        ({"name": "verification platform", "head_sha": "b" * 40, "status": "completed", "conclusion": "success"}, NOT_READY, "green at another SHA"),
        ({"name": "verification platform", "head_sha": sha, "status": "completed", "conclusion": "failure"}, FAILED, "failure"),
        ({"name": "verification platform", "head_sha": sha, "status": "completed", "conclusion": "timed_out"}, FAILED, "timed_out"),
        ({"name": "verification platform", "head_sha": sha, "status": "completed", "conclusion": "success"}, READY, "the only ready shape"),
    ]
    bad = 0
    for check, want, label in cases:
        got = run(check)
        if got != want:
            print(f"  FAIL {label}: wanted {want}, got {got}")
            bad += 1

    # A required lane that no job runs must refuse, not resolve to an empty requirement.
    try:
        checks_for_lanes({"nosuchlane"}, {})
        print("  FAIL an unrunnable lane resolved instead of refusing")
        bad += 1
    except Undecidable:
        pass

    # The umbrella satisfies a lane whose own script no workflow names literally.
    resolved = checks_for_lanes({"test", "mutation"}, lane_scripts())
    for lane in ("test", "mutation"):
        if lane not in resolved:
            print(f"  FAIL lane '{lane}' resolved to no check")
            bad += 1

    # The fallback authority answers the SAME four conditions. A ruleset check that is
    # queued must not read as READY just because the manifest asked for nothing.
    fallback = {c: [c] for c in ("cargo build + test (1.97.1)",)}
    queued = {"cargo build + test (1.97.1)": {
        "name": "cargo build + test (1.97.1)", "head_sha": sha,
        "status": "queued", "conclusion": None}}
    if decide(fallback, queued, sha)[0] != NOT_READY:
        print("  FAIL a queued ruleset check read as ready under the fallback authority")
        bad += 1
    if decide(fallback, {}, sha)[0] != NOT_READY:
        print("  FAIL a missing ruleset check read as ready under the fallback authority")
        bad += 1

    # A build-input change must widen to every unit, not to the units that declare it.
    manifest = load_verification()
    every = affected_units(manifest["unit"], manifest.get("edge", []), {"Cargo.lock"})
    if len(every) != len(manifest["unit"]):
        print(f"  FAIL a Cargo.lock change widened to {len(every)} of {len(manifest['unit'])} units")
        bad += 1

    print(f"merge_readiness_gate selftest: {'PASS' if bad == 0 else f'FAIL ({bad})'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
