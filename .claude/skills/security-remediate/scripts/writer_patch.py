"""writer_patch.py — one writer's change, as a patch against the tree it started from.

Writers in a batch land on top of each other without committing, and they share files —
`control-dispositions.toml`, `verification.toml`, `BUILD.bazel`. Returning a writer's
touched paths to HEAD therefore also erases every earlier writer's hunks in those files,
and committing a writer's paths whole sweeps in every other writer's hunks. Both happened:
a red writer's revert removed an accepted writer's control dispositions, and finalize
then refused the accepted writer for undispositioned controls.

So the unit of revert and commit is the writer's own diff:

  snapshot(store, file)          `check.py pre`: the whole working tree, untracked files
                                 included, written as a git tree object, with the time
  started(store, file)           that time: finalize commits and reverts in writer order
  capture(store, file, touched)  `check.py post`: diff(pre tree, current tree) over the
                                 touched paths, saved as the writer's patch
  restore(store, file, touched)  a red gate: the touched paths go back to the pre tree —
                                 exact, because this writer is the last one to have edited
  reverse(store, file)           finalize, review rejected: reverse-apply the writer's patch
  stage(store, file)             finalize, review accepted: put exactly the writer's hunks
                                 in the index

A tree object (temporary index over the real one, `add -A`, `write-tree`) is used rather
than `git stash create`, which ignores untracked files — the new modules writers create.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time


def _git(*args: str, env: dict | None = None, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True, env=env, input=stdin)


def _key(file: str) -> str:
    return hashlib.sha1(file.encode()).hexdigest()[:12]


def _paths(store: str, file: str) -> tuple[str, str]:
    d = os.path.join(store, "snapshots")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, _key(file) + ".json"), os.path.join(d, _key(file) + ".patch")


def tree_of_worktree() -> str:
    """The working tree, tracked and untracked (ignored files excluded), as a tree sha."""
    git_dir = _git("rev-parse", "--git-dir").stdout.strip()
    with tempfile.TemporaryDirectory() as td:
        idx = os.path.join(td, "index")
        real = os.path.join(git_dir, "index")
        if os.path.exists(real):
            shutil.copyfile(real, idx)
        env = dict(os.environ, GIT_INDEX_FILE=idx)
        _git("add", "-A", "--", ".", env=env)
        return _git("write-tree", env=env).stdout.strip()


def snapshot(store: str, file: str) -> str:
    meta, _ = _paths(store, file)
    tree = tree_of_worktree()
    with open(meta, "w", encoding="utf-8") as fh:
        json.dump({"file": file, "pre_tree": tree, "started_ns": time.time_ns()}, fh)
    return tree


def started(store: str, file: str) -> int | None:
    """When this writer took its snapshot. Writers land on top of each other in the order
    they RAN, which is not the order the batch reports them in, so a later writer's patch
    applies only on top of every earlier one."""
    return _meta(store, file).get("started_ns")


def _meta(store: str, file: str) -> dict:
    meta, _ = _paths(store, file)
    try:
        return json.load(open(meta, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def capture(store: str, file: str, touched: list[str]) -> str | None:
    """Save this writer's diff over `touched`; None when no snapshot was taken."""
    meta, patch = _paths(store, file)
    m = _meta(store, file)
    if not m.get("pre_tree"):
        return None
    post = tree_of_worktree()
    diff = _git("diff", "--binary", "--full-index", m["pre_tree"], post, "--", *touched).stdout
    with open(patch, "w", encoding="utf-8") as fh:
        fh.write(diff)
    m["post_tree"] = post
    with open(meta, "w", encoding="utf-8") as fh:
        json.dump(m, fh)
    return patch


def restore(store: str, file: str, touched: list[str]) -> bool:
    """Return `touched` to the pre tree. False when there is no snapshot to return to."""
    pre = _meta(store, file).get("pre_tree")
    if not pre:
        return False
    for f in touched:
        if _git("cat-file", "-e", "%s:%s" % (pre, f)).returncode == 0:
            _git("restore", "--source=" + pre, "--worktree", "--", f)
        elif os.path.isfile(f):
            os.remove(f)
    return True


def patch_path(store: str, file: str) -> str | None:
    _, patch = _paths(store, file)
    return patch if os.path.isfile(patch) and os.path.getsize(patch) else None


def reverse(store: str, file: str) -> tuple[bool, str]:
    """Remove exactly this writer's hunks from the working tree."""
    patch = patch_path(store, file)
    if not patch:
        return False, "no writer patch recorded"
    p = _git("apply", "-R", "--binary", patch)
    return p.returncode == 0, (p.stderr or "").strip()[-300:]


def stage(store: str, file: str) -> tuple[bool, str]:
    """Put exactly this writer's hunks into the index."""
    patch = patch_path(store, file)
    if not patch:
        return False, "no writer patch recorded"
    p = _git("apply", "--cached", "--binary", patch)
    return p.returncode == 0, (p.stderr or "").strip()[-300:]
