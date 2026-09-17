# SPDX-License-Identifier: Apache-2.0
"""Negative controls over the R9 linkage — `merged_closure` must mean MERGED.

The defect these exist for is specific and already happened. R9-C074/C075 carried
`merged_closure = "#736 — closed canonical submitted-hop representation"` while #736 was
green and OPEN. The record read as closed, the packet rendered as closed, and nothing in
the lane could tell the difference — because the evidence for "merged" was a sentence
saying so.

So the claim is typed (`pr`, `commit`, `note`) and discharged against the local object
graph. Each control below is a way the assertion could be false while still looking well
formed:

  * a closure commit that exists and is NOT reachable from HEAD — the open-PR shape, and
    the one a spelling check would pass;
  * a closure commit this clone does not have at all, which is a MEASUREMENT FAILURE and
    not that finding. The two were one case until a CI checkout came up short and reported
    the record as false; they call for opposite actions — correct the record, or fetch the
    history — and only one of them is about the record;
  * a `merged_closure` that is prose rather than a typed record.

And the positive control, without which the other three prove nothing: a real ancestor
passes. No case consults the network. PR state is remote and mutable; the merge commit
reachable from HEAD is the durable local fact, and it is the fact that means the change is
in the tree being measured.

Run: python3 tools/verification/test_r9_linkage.py
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402

render_r9 = load_tool('render-r9-dispositions', 'render_r9')


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


class Fixture:
    """A throwaway repository with one commit on HEAD and one deliberately off it."""

    def __init__(self, tmp: Path) -> None:
        self.repo = tmp
        git(tmp, "init", "-q", "-b", "main")
        git(tmp, "config", "user.email", "control@example.invalid")
        git(tmp, "config", "user.name", "linkage control")
        (tmp / "a").write_text("a\n")
        git(tmp, "add", "a")
        git(tmp, "commit", "-qm", "reachable")
        self.reachable = git(tmp, "rev-parse", "HEAD")
        git(tmp, "checkout", "-q", "-b", "sidetrack")
        (tmp / "b").write_text("b\n")
        git(tmp, "add", "b")
        git(tmp, "commit", "-qm", "not on main")
        self.unreachable = git(tmp, "rev-parse", "HEAD")
        git(tmp, "checkout", "-q", "main")


def record(closure: object) -> dict:
    return {
        "dispositions": [
            {
                "cluster": "R9-C999",
                "severity": "medium",
                "disposition": "SURVIVES_AND_MAPPED",
                "merged_closure": closure,
            }
        ]
    }


def in_fixture(fn):
    with tempfile.TemporaryDirectory() as tmp:
        return fn(Fixture(Path(tmp)))


def test_a_real_ancestor_is_a_merged_closure():
    """The positive control. Without it the three below prove only that the check fails."""

    def check(fix: Fixture) -> None:
        defects = render_r9.unmerged_closures(
            record({"pr": 1, "commit": fix.reachable, "note": "in the tree"}), fix.repo
        )
        assert defects == [], defects

    in_fixture(check)


def test_a_commit_this_clone_DOES_NOT_HAVE_is_a_measurement_failure():
    """A FINDING and a MEASUREMENT FAILURE, told apart.

    `merge-base --is-ancestor` returns 0 reachable, 1 not reachable, and anything else for
    an error — including an object the clone does not have. Reading all of "not 0" as "this
    never merged" makes a shallow or partial checkout indistinguishable from a record that
    is lying, and the two call for opposite actions: correct the record, or fetch the
    history. Only one of them is about the record."""

    def check(fix: Fixture) -> None:
        absent = "0" * 40
        defects = render_r9.unmerged_closures(
            record({"pr": 2, "commit": absent, "note": "never existed"}), fix.repo
        )
        assert len(defects) == 1, defects
        assert "MEASUREMENT FAILURE" in defects[0], defects
        assert "this clone does not have" in defects[0], defects
        # And it must NOT be reported as the finding it is not.
        assert "does not contain" not in defects[0], defects

    in_fixture(check)


def test_a_real_commit_not_reachable_from_head_fails():
    """The open-PR shape: the work exists as commits, and is not in the measured tree."""

    def check(fix: Fixture) -> None:
        defects = render_r9.unmerged_closures(
            record({"pr": 3, "commit": fix.unreachable, "note": "green, open"}), fix.repo
        )
        assert len(defects) == 1, defects
        assert fix.unreachable[:12] in defects[0], defects
        assert "is NOT an ancestor of HEAD" in defects[0], defects
        # The object IS here, so this is a statement about the RECORD, and must not be
        # softened into one about the checkout.
        assert "MEASUREMENT FAILURE" not in defects[0], defects

    in_fixture(check)


def test_prose_is_not_a_closure_record():
    def check(fix: Fixture) -> None:
        defects = render_r9.unmerged_closures(record("#736 — merged, honestly"), fix.repo)
        assert len(defects) == 1, defects
        assert "not a typed" in defects[0], defects

    in_fixture(check)


def test_every_live_closure_commit_is_PRESENT_in_this_clone():
    """Separated from the ancestry assertion below, so a checkout that cannot answer says
    so instead of reporting the record as false. This is the control that would have named
    the cause when the CI clone came up short — the old shape failed with a bare assertion
    and no way to tell which of the two had happened."""
    import json

    live = json.loads(render_r9.RECORD.read_text(encoding="utf-8"))
    absent = [
        f"{row['cluster']} @ {row['merged_closure']['commit'][:12]}"
        for row in live["dispositions"]
        if isinstance(row.get("merged_closure"), dict)
        and render_r9._reachability(row["merged_closure"]["commit"], render_r9.REPO_ROOT)
        == render_r9.ABSENT
    ]
    assert not absent, (
        f"this checkout does not hold {len(absent)} recorded closure commit(s): {absent}. "
        f"That is a fact about the clone — fetch the full history — and NOT evidence that "
        f"the record is wrong."
    )


def test_the_live_record_carries_only_merged_closures():
    import json

    live = json.loads(render_r9.RECORD.read_text(encoding="utf-8"))
    assert render_r9.unmerged_closures(live) == [], render_r9.unmerged_closures(live)
    assert render_r9.uncovered_surviving_high(live) == [], render_r9.uncovered_surviving_high(live)


def test_a_disposition_is_never_rewritten_by_a_later_closure():
    """The historical measurement and the current ownership are separate facts.

    A row that survived the 2026-08-31 re-derivation keeps `SURVIVES_AND_MAPPED` forever;
    that later work closed it is recorded beside the disposition, never on top of it.
    """
    import json

    live = json.loads(render_r9.RECORD.read_text(encoding="utf-8"))
    closed = [r for r in live["dispositions"] if "merged_closure" in r]
    assert closed, "the control is vacuous with no closed rows"
    assert all(r["disposition"] == "SURVIVES_AND_MAPPED" for r in closed)


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
