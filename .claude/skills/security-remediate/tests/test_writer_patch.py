"""Regression: a writer's revert and commit touch that writer's hunks, nobody else's.

Batch 62, measured: the verified_response writer failed its gate and its revert returned a
shared registry (control-dispositions.toml) to HEAD, erasing the aws_sts writer's accepted
rows; finalize then refused aws_sts for undispositioned controls and, reverting it, deleted
its new module without saving it.

  1. check: a red writer B returns a shared file to where B found it — writer A's row,
     landed earlier and uncommitted, survives; B's new file is removed and kept in the patch
  2. finalize: A accepted and B rejected, sharing a file — B's hunk and new file leave the
     tree (new file saved in the patch), A's commit carries A's hunk only, tree ends clean
  3. positive control for the fallback: with no snapshot, a revert still saves a new file
     into the patch before removing it

Run:  python3 .claude/skills/security-remediate/tests/test_writer_patch.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))

import check  # noqa: E402
import finalize  # noqa: E402
import writer_patch  # noqa: E402

SHARED = "registry.toml"


def _git(root: str, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=root,
                          check=True, capture_output=True, text=True).stdout


def _repo(td: str) -> str:
    root = os.path.join(td, "ws")
    os.makedirs(root)
    with open(os.path.join(root, SHARED), "w") as fh:
        fh.write("[base]\n")
    with open(os.path.join(root, ".gitignore"), "w") as fh:
        fh.write("w/\n")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _append(path: str, text: str) -> None:
    with open(path, "a") as fh:
        fh.write(text)


def _in(root: str):
    class _Cd:
        def __enter__(self):
            self.cwd = os.getcwd()
            os.chdir(root)

        def __exit__(self, *exc):
            os.chdir(self.cwd)
    return _Cd()


def test_a_red_writer_reverts_only_its_own_hunks() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = _repo(td)
        with _in(root):
            store = "w/gates"
            writer_patch.snapshot(store, "a.rs")
            _append(SHARED, "[a]\n")
            writer_patch.capture(store, "a.rs", [SHARED])
            writer_patch.snapshot(store, "b.rs")
            _append(SHARED, "[b]\n")
            open("b_new.rs", "w").write("fn b() {}\n")
            writer_patch.capture(store, "b.rs", [SHARED, "b_new.rs"])
            patch = check._revert([SHARED, "b_new.rs"], "w", store, "b.rs")
            assert open(SHARED).read() == "[base]\n[a]\n", open(SHARED).read()
            assert not os.path.exists("b_new.rs")
            saved = open(patch).read()
            assert "+[b]" in saved and "+fn b()" in saved and "+[a]" not in saved, saved
    print("  check: a red writer leaves an earlier writer's uncommitted hunk in a shared file  OK")


def test_finalize_reverts_and_commits_per_writer() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = _repo(td)
        with _in(root):
            store = "w/gates"
            os.makedirs("w", exist_ok=True)
            writer_patch.snapshot(store, "a.rs")
            _append(SHARED, "[a]\n")
            open("a.rs", "w").write("fn a() {}\n")
            writer_patch.capture(store, "a.rs", [SHARED, "a.rs"])
            writer_patch.snapshot(store, "b.rs")
            _append(SHARED, "[b]\n")
            open("b_new.rs", "w").write("fn b() {}\n")
            writer_patch.capture(store, "b.rs", [SHARED, "b_new.rs"])
            results = {"results": [
                {"file": "a.rs", "verdict": "accept", "accepted": ["w1"],
                 "files_touched": [SHARED, "a.rs"]},
                {"file": "b.rs", "verdict": "reject", "rejected": [{"id": "w2", "cause": "wrong-fix"}],
                 "files_touched": [SHARED, "b_new.rs"]}]}
            json.dump(results, open("w/results.json", "w"))
            open("w/ledger.jsonl", "w").close()
            saved = finalize.residue_by_carrier, sys.argv
            finalize.residue_by_carrier = lambda: {}  # type: ignore[assignment]
            sys.argv = ["finalize.py", "--results", "w/results.json", "--ledger", "w/ledger.jsonl",
                        "--work-dir", "w"]
            try:
                import contextlib
                import io
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = finalize.main()
            finally:
                finalize.residue_by_carrier, sys.argv = saved  # type: ignore[assignment]
            assert rc == 0
            committed = _git(root, "show", "HEAD:" + SHARED)
            assert committed == "[base]\n[a]\n", committed
            assert _git(root, "show", "--stat", "--format=", "HEAD").count("|") == 2
            assert not os.path.exists("b_new.rs")
            assert _git(root, "status", "--porcelain").strip() == "", _git(root, "status", "--porcelain")
            rejected = open("w/review-rejected-b-rs.patch").read()
            assert "fn b()" in rejected and "[b]" in rejected, rejected
    print("  finalize: rejected writer's hunk and new file leave (saved); accepted commit is its own  OK")


def test_a_writer_that_touched_nothing_reverts_nothing() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = _repo(td)
        with _in(root):
            os.makedirs("w", exist_ok=True)
            _append(SHARED, "[other writer, uncommitted]\n")
            finalize._revert([], "w", "nothing", "w/gates", "untouched.rs")
            assert "[other writer, uncommitted]" in open(SHARED).read(), open(SHARED).read()
    print("  finalize: a rejected writer with no edits leaves everyone else's work alone  OK")


def test_a_revert_without_snapshot_still_saves_new_files() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = _repo(td)
        with _in(root):
            os.makedirs("w", exist_ok=True)
            open("new.rs", "w").write("fn n() {}\n")
            patch = finalize._revert(["new.rs"], "w", "new-rs")
            assert not os.path.exists("new.rs")
            assert "fn n()" in open(patch).read()
    print("  finalize: the HEAD fallback keeps a new file in the patch before removing it  OK")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print("%d/%d passed" % (len(tests), len(tests)))
