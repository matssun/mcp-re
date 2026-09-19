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
distinctions below are lost. So this gate does not advise — it answers, and the answer
carries no raw material for a caller to re-interpret.

THE STATES ARE FOUR, AND THE RULE OVER THEM IS ONE:

    READY        every lane the governing authority requires is completed/success HERE
    NOT_READY    the measurement is incomplete — wait, or re-run
    FAILED       a lane's OWN verdict establishes that it failed — fix
    UNDECIDABLE  the gate cannot answer; it says why

    ONLY `READY` PERMITS A MERGE. Every other state refuses.

`UNDECIDABLE` is kept rather than folded into `NOT_READY` because the two call for
different actions: one is waiting, the other is a question about the gate's own inputs.
Neither permits a merge, so the distinction is diagnostic and never permissive.

ATTRIBUTION, WHICH IS WHY `FAILED` IS NARROW. One job — the umbrella `verify` — runs
several lanes. Its verdict is therefore attributable to a LANE only in one direction:

    umbrella completed/success       may satisfy every lane it actually contains
    umbrella pending or unavailable  those lanes are NOT_READY
    umbrella FAILURE                 says nothing about WHICH lane failed

A lane is `FAILED` only where a check whose verdict IS that lane's own establishes it —
which means a dedicated, single-lane job. Reporting "the V0 test lane failed" because an
unrelated Lean or extraction step went red inside the umbrella would be a fabricated
verdict, and it would send someone to fix a lane that never ran badly. The umbrella's
failure still refuses the merge; it refuses as NOT_READY, with the reason saying so.

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

Exit status: 0 READY, 1 NOT_READY, 2 FAILED, 3 UNDECIDABLE.
Only 0 permits a merge, and `scripts/merge_verified_pr.py` is the only thing that acts
on it — see that file for why the decision has to be re-bound to the head it was made about.
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
from _manifest import SCHEMA_VERSION, load_verification  # noqa: E402

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

#: A whole-line YAML comment.
#:
#: COUNT INVOCATIONS, NOT MENTIONS — and this gate was counting mentions. These workflows
#: are heavily commented, and the comments name scripts constantly, because explaining why a
#: step exists means naming what it runs. A comment in `ci.yml` reading "`tools/verification/verify
#: --manifests` fails on the same fact" made the CARGO job look like it invoked the umbrella,
#: which made every lane resolve to that job. The lane was still satisfied by a real job too,
#: so no wrong verdict shipped — but the attribution was false, and an attribution that can
#: be false by writing prose is one a job could acquire without running anything.
#:
#: The residual limit, stated rather than left to be discovered: a TRAILING comment on a
#: command line is still scanned, because distinguishing one from a `#` inside a quoted shell
#: argument needs a YAML parser this layer does not have. Whole-line comments are the shape
#: the workflows actually use for prose, and the shape that produced the defect.
COMMENT_LINE = re.compile(r"^\s*#")


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
            # Prose that NAMES a script is not a job that RUNS it. See `COMMENT_LINE`.
            runnable = "\n".join(
                line for line in lines[start:end] if not COMMENT_LINE.match(line)
            )
            jobs.append((path.name, name, set(INVOCATION.findall(runnable))))
    return jobs


def umbrella_checks() -> set[str]:
    """The check names that run the umbrella, and therefore several lanes at once.

    Kept apart from the per-lane mapping because it answers a different question: not
    "which job runs this lane" but "whose failure is attributable to one lane". Derived
    the same way, from the workflows, so a job that stops invoking the umbrella stops
    being treated as one.
    """
    return {name for _wf, name, invoked in workflow_jobs() if UMBRELLA in invoked}


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
    required: dict[str, list[str]],
    runs: dict[str, dict],
    sha: str,
    shared: set[str] | None = None,
) -> tuple[str, list[tuple]]:
    """The answer, plus one row per required lane for the human-readable table.

    A lane is satisfied when ANY job that runs it met all four conditions — including the
    umbrella, whose SUCCESS does cover every lane it contains.

    It is `FAILED` only when a check whose verdict is that lane's OWN establishes failure.
    `shared` names the jobs that run several lanes; their failure is not attributable to
    any one of them, so it refuses as NOT_READY with the reason saying which job went red.
    Inventing a per-lane verdict from a shared job's failure would send someone to fix a
    lane that never ran badly.
    """
    shared = shared or set()
    rows, satisfied, failing = [], True, False
    for lane, names in sorted(required.items()):
        verdicts = [(name, *classify(runs.get(name), sha)) for name in names]
        winner = next((v for v in verdicts if v[1]), None)
        if winner is not None:
            rows.append((lane, winner[0], "OK", winner[2]))
            continue
        satisfied = False
        own = [n for n in names if n not in shared]
        attributable = [n for n in own if (runs.get(n) or {}).get("conclusion") in FAILING_CONCLUSIONS]
        if attributable:
            failing = True
            rows.append((lane, attributable[0], "FAILED", "this lane's own job failed"))
            continue
        name, _ok, why = verdicts[0]
        red_shared = [n for n in names if n in shared
                      and (runs.get(n) or {}).get("conclusion") in FAILING_CONCLUSIONS]
        if red_shared:
            why = (f"{red_shared[0]} failed, but it runs several lanes — its verdict is not "
                   f"attributable to '{lane}'")
        elif len(verdicts) > 1:
            why = f"{why}; none of {len(verdicts)} jobs satisfied it"
        rows.append((lane, name, "NOT SATISFIED", why))
    if failing:
        return FAILED, rows
    return (READY if satisfied else NOT_READY), rows


# -------------------------------------------------------------------------------- input


def git(*args: str) -> str:
    done = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise Undecidable(f"git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout.strip()


#: The registry whose `[[unit]]` entries decide which lanes a candidate needs.
VERIFICATION_TOML = "verification/policy/verification.toml"


def manifest_at(sha: str) -> dict:
    """The verification registry AS THE CANDIDATE CARRIES IT, not as the tree carries it.

    Every other fact this gate reads is bound to the commit under review: the candidate
    sha, its check runs, their conclusions. The required-lane SET was the exception — it
    came from `verification/policy/verification.toml` in the working tree — so a verdict
    was two tree states joined, and looked exactly like a correct one.

    It is not a theoretical hazard and it was not one-directional. Both shapes were
    measured in one campaign, in one workspace with two active PRs: 192 -> 197, where the
    tree carried MORE units than the candidate, and 212 -> 206, where it carried FEWER.
    Only the first is harmless. Deriving the required set from a SMALLER estate than the
    commit being merged is the shape that returns READY for a candidate whose real
    required set is larger, which is the one thing this gate exists to prevent.

    Read raw rather than through `load_verification`: that validator resolves each unit's
    `paths` globs against the CHECKED-OUT tree, so validating the candidate's registry from
    another branch would fail on files the candidate has and the tree does not — a tree
    fact again, in the one place that must carry none. The candidate's own lanes validate
    its registry; this gate needs its unit and edge tables and the one property whose drift
    would change what a lane MEANS:

      * `git show` failing (no such commit, or a candidate carrying no registry at all)
        and unparsable TOML both raise `Undecidable` — the brief's fallback (b), which
        costs nothing once every input comes from one commit;
      * a `schema_version` this tooling does not implement is `Undecidable` for the same
        reason `load_verification` refuses it: the lane names would be read under a schema
        nobody here implements.
    """
    import tomllib

    blob = git("show", f"{sha}:{VERIFICATION_TOML}")
    try:
        doc = tomllib.loads(blob)
    except tomllib.TOMLDecodeError as exc:
        raise Undecidable(f"{VERIFICATION_TOML} at {sha[:12]} is unparsable: {exc}") from exc
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise Undecidable(
            f"{VERIFICATION_TOML} at {sha[:12]} declares schema_version "
            f"{doc.get('schema_version')!r}; this gate implements {SCHEMA_VERSION}, so the "
            f"lanes its units require would be read under a schema nobody here implements"
        )
    return doc


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


def report(
    sha: str, units: set[str], rows: list[tuple], state: str, authority: str, declared: int
) -> None:
    print(f"candidate      {sha}")
    print(f"authority      {authority}")
    # Both numbers, and the sha they came from: a reader can see that the estate the
    # required set was derived from is the candidate's own, rather than trusting it.
    print(f"registry       {VERIFICATION_TOML}@{sha[:12]} — {declared} declared unit(s)")
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

        # From the CANDIDATE, never from the tree: see `manifest_at`.
        manifest = manifest_at(sha)
        units, edges = manifest.get("unit", []), manifest.get("edge", [])
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
        state, rows = decide(required, check_runs(args.repo, sha), sha, umbrella_checks())
        report(sha, affected, rows, state, authority, len(units))
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

    # COUNT INVOCATIONS, NOT MENTIONS. A comment that NAMES the umbrella must not make its
    # job look like it RUNS the umbrella. This is not hypothetical: a comment in `ci.yml`
    # explaining that `tools/verification/verify --manifests` enforces N1 made the cargo job
    # resolve as an umbrella job, and every lane was attributed to it. Both directions,
    # because a control that only refuses prose could refuse the real invocation too.
    import tempfile as _tempfile

    prose = (
        "jobs:\n"
        "  someJob:\n"
        "    name: a job that only TALKS about the umbrella\n"
        "    steps:\n"
        "      # tools/verification/verify --manifests is what enforces this\n"
        "      - run: echo hello\n"
    )
    real = prose.replace("      - run: echo hello", "      - run: tools/verification/verify --gate")
    for label, body, expect_umbrella in (("a comment does not invoke", prose, False),
                                         ("a run: line does invoke", real, True)):
        with _tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "probe.yml"
            path.write_text(body, encoding="utf-8")
            global WORKFLOWS
            saved, WORKFLOWS = WORKFLOWS, Path(tmp)
            try:
                found = {name for _wf, name, invoked in workflow_jobs() if UMBRELLA in invoked}
            finally:
                WORKFLOWS = saved
        got = bool(found)
        if got != expect_umbrella:
            print(f"  FAIL {label}: umbrella jobs resolved to {found}")
            bad += 1

    # The umbrella satisfies a lane whose own script no workflow names literally.
    resolved = checks_for_lanes({"test", "mutation"}, lane_scripts())
    for lane in ("test", "mutation"):
        if lane not in resolved:
            print(f"  FAIL lane '{lane}' resolved to no check")
            bad += 1

    # ATTRIBUTION. A shared job's failure must never be reported as a lane's own verdict.
    UMB = "verification platform"
    DED = "V0 evidence self-test (mutation probes)"
    red_umbrella = {UMB: {"name": UMB, "head_sha": sha,
                          "status": "completed", "conclusion": "failure"}}

    # Only the umbrella runs this lane, and it went red: NOT_READY, never FAILED.
    state, rows = decide({"lean": [UMB]}, red_umbrella, sha, {UMB})
    if state != NOT_READY:
        print(f"  FAIL an umbrella failure was attributed to a single lane: {state}")
        bad += 1
    if "not attributable" not in rows[0][3]:
        print("  FAIL the row does not say the umbrella's verdict is unattributable")
        bad += 1

    # A lane with its OWN job: that job's failure IS the lane's verdict.
    state, _ = decide({"mutation": [DED]},
                      {DED: {"name": DED, "head_sha": sha,
                             "status": "completed", "conclusion": "failure"}}, sha, {UMB})
    if state != FAILED:
        print(f"  FAIL a dedicated job's failure did not read as FAILED: {state}")
        bad += 1

    # The umbrella is red, but the lane's own job passed: satisfied, because a lane is
    # satisfied by ANY job that actually measured it.
    both = dict(red_umbrella)
    both[DED] = {"name": DED, "head_sha": sha, "status": "completed", "conclusion": "success"}
    state, _ = decide({"mutation": [DED, UMB]}, both, sha, {UMB})
    if state != READY:
        print(f"  FAIL a passing dedicated job was overridden by a red umbrella: {state}")
        bad += 1

    # And the umbrella's SUCCESS does cover a lane it contains.
    state, _ = decide({"lean": [UMB]},
                      {UMB: {"name": UMB, "head_sha": sha,
                             "status": "completed", "conclusion": "success"}}, sha, {UMB})
    if state != READY:
        print(f"  FAIL a successful umbrella did not satisfy a lane it runs: {state}")
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

    # The registry the required set is derived from must come from the COMMIT, not the
    # tree. Perturbed rather than asserted: a version of `manifest_at` that read the tree
    # would return the tree's unit count for every sha, so the control compares two
    # commits that declare DIFFERENT numbers and requires the answers to differ with them.
    # `git log -1 --format=%H -- <path>` finds the last commit that CHANGED the registry,
    # so its parent is guaranteed to carry a different one wherever history has any.
    changed_at = git("log", "-1", "--format=%H", "--", VERIFICATION_TOML)
    if changed_at:
        parent = git("rev-parse", f"{changed_at}^")
        here, before = len(manifest_at(changed_at).get("unit", [])), len(
            manifest_at(parent).get("unit", [])
        )
        for sha_, read in ((changed_at, here), (parent, before)):
            declared = git("show", f"{sha_}:{VERIFICATION_TOML}").count("\n[[unit]]")
            if read != declared:
                print(f"  FAIL manifest_at({sha_[:12]}) read {read}; the blob declares {declared}")
                bad += 1
    # A candidate carrying no registry, or naming no commit, is UNDECIDABLE — never a
    # verdict. `git()` raises it; this asserts the gate does not swallow it somewhere.
    try:
        manifest_at("0000000000000000000000000000000000000000")
    except Undecidable:
        pass
    else:
        print("  FAIL a candidate with no readable registry produced a manifest anyway")
        bad += 1

    print(f"merge_readiness_gate selftest: {'PASS' if bad == 0 else f'FAIL ({bad})'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
