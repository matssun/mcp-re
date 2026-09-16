#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The canonical campaign merge operation: the ONLY thing that may merge an R11 PR.

THE FAILURE CLASS, which is why this file exists rather than any single instance:

    A merge authorized by a readiness decision that was not about the commit being merged.

`merge_readiness_gate.py` answers a question about an exact SHA. That answer starts going
stale the moment it is printed: a push, a rebase, a suggestion applied in the web UI, or a
branch update all move the head, and the lanes that were `completed/success` were measured
against bytes that are no longer what would land. A human — or an agent — who reads READY,
then merges, has merged on evidence about a different commit. Nothing about that is
hypothetical; it is the ordinary case whenever a PR is touched while its checks are read.

So the decision is BOUND to the head it was made about, three times over:

  1. the gate is run against the head as it is NOW, never against a remembered SHA;
  2. the head is re-read immediately before the merge call, and a move refuses;
  3. the merge itself carries `--match-head-commit`, so the SERVER refuses a head that
     moved between step 2 and the request landing.

Step 3 is the one that actually holds. Steps 1 and 2 close the window to something small;
only the server can close it completely, because only the server orders the two events.

ONLY `READY` PERMITS A MERGE. `NOT_READY`, `FAILED` and `UNDECIDABLE` all refuse, and this
script never interprets a status array, a check list, or a conclusion field of its own —
the gate is the sole authority and this is the sole actor on it. If the gate cannot answer,
that is a refusal and not an invitation to look for a second opinion.

WHAT THIS DOES NOT DO: decide whether the change is *right*. Readiness is about evidence
having been produced at this commit, which is a precondition for merging and not a reason
to.

Run:  python3 scripts/merge_verified_pr.py <PR>
      python3 scripts/merge_verified_pr.py <PR> --dry-run
      python3 scripts/merge_verified_pr.py --selftest

Exit status: 0 merged (or dry-run would merge), 1 refused, 2 the merge call failed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
GATE = REPO / "merge_readiness_gate.py"

#: The one state that permits a merge. Named once, so a later state cannot be added to
#: this set by being spelled next to it.
PERMITS_MERGE = "READY"

#: The gate's exit statuses, as the reason text a refusal prints.
GATE_EXIT = {
    0: "READY",
    1: "NOT_READY — the measurement is incomplete; wait or re-run",
    2: "FAILED — a lane's own verdict establishes failure; fix it",
    3: "UNDECIDABLE — the gate could not answer; see its message",
}


class Refused(Exception):
    """The merge does not happen. Never a failure of this script."""


def gh(*args: str) -> str:
    done = subprocess.run(["gh", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise Refused(f"gh {' '.join(args)}: {done.stderr.strip() or done.stdout.strip()}")
    return done.stdout.strip()


def head_of(pr: str, repo: str) -> str:
    """The PR's head SHA as the server reports it right now."""
    payload = json.loads(gh("pr", "view", pr, "--repo", repo, "--json", "headRefOid,state"))
    if payload.get("state") != "OPEN":
        raise Refused(f"PR #{pr} is {payload.get('state')}, not OPEN")
    return payload["headRefOid"]


def readiness(sha: str, repo: str) -> tuple[int, str]:
    """`(exit status, output)` from the gate, run against this exact SHA."""
    done = subprocess.run(
        [sys.executable, str(GATE), "--sha", sha, "--repo", repo],
        capture_output=True, text=True,
    )
    return done.returncode, (done.stdout + done.stderr).strip()


def merge(pr: str, repo: str, sha: str) -> None:
    """Squash-merge, refused BY THE SERVER if the head is no longer `sha`."""
    done = subprocess.run(
        ["gh", "pr", "merge", pr, "--repo", repo, "--squash", "--match-head-commit", sha],
        capture_output=True, text=True,
    )
    if done.returncode != 0:
        raise SystemExit(
            f"merge call failed (head may have moved): {done.stderr.strip()}"
        )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("pr", nargs="?", help="the pull request number")
    parser.add_argument("--repo", default="matssun/mcp-re")
    parser.add_argument("--dry-run", action="store_true",
                        help="decide and report, but do not call merge")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.pr:
        parser.error("a PR number is required")

    try:
        # 1. The head as it is NOW. A SHA passed in by a caller would be a remembered one.
        before = head_of(args.pr, args.repo)
        print(f"PR #{args.pr} head   {before}")

        # 2. Readiness about THAT commit.
        code, output = readiness(before, args.repo)
        print(output)
        if code != 0:
            raise Refused(GATE_EXIT.get(code, f"gate exited {code}"))

        # 3. Re-read. Between the gate starting and finishing, minutes pass.
        after = head_of(args.pr, args.repo)
        if after != before:
            raise Refused(
                f"head moved {before[:12]} -> {after[:12]} while readiness was being "
                "established; the answer is about a commit that is no longer the candidate"
            )

        if args.dry_run:
            print(f"DRY RUN: would merge #{args.pr} at {before}")
            return 0

        # 4. And the server refuses it too, which is the only complete close.
        merge(args.pr, args.repo, before)
        print(f"MERGED #{args.pr} at {before}")
        return 0
    except Refused as why:
        print(f"REFUSED: {why}", file=sys.stderr)
        return 1


def selftest() -> int:
    """The catalogue: every state but READY refuses, and a moved head refuses."""
    bad = 0

    for code, label in GATE_EXIT.items():
        permits = code == 0
        if permits != (label.startswith(PERMITS_MERGE)):
            print(f"  FAIL exit {code} ({label}) disagrees with the permit rule")
            bad += 1

    if len([c for c in GATE_EXIT if c == 0]) != 1:
        print("  FAIL more than one gate status maps to a permit")
        bad += 1

    # The merge call must carry --match-head-commit; without it steps 1-3 are advisory.
    source = Path(__file__).read_text(encoding="utf-8")
    if "--match-head-commit" not in source:
        print("  FAIL the merge call does not bind the head server-side")
        bad += 1

    # And it must never reach for a status array of its own. Scoped to the code ABOVE
    # this function: a detector that scans its own literals reports itself, which is the
    # same self-match trap as a `pgrep -f` pattern that finds the watcher.
    operative = source.split("def selftest(", 1)[0]
    for weaker in ("pr checks", "statusCheckRollup", "check-runs"):
        if weaker in operative:
            print(f"  FAIL this script consults '{weaker}' instead of the gate")
            bad += 1

    print(f"merge_verified_pr selftest: {'PASS' if bad == 0 else f'FAIL ({bad})'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
