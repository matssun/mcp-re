# SPDX-License-Identifier: Apache-2.0
"""The scratch copy of the tracked tree, which every hostile-edit lane measures inside.

ONE authority over one fact: *what a lane's working copy of this repository contains*. Two
lanes now write hostile edits — `verify-mutations` weakens a runtime check, and
`verify-structural` injects a construction the representation is supposed to refuse — and
both are only sound if the copy they edit is the tree the rest of the run fingerprinted. A
second implementation would not announce a divergence; it would quietly measure a different
tree and report a verdict about this one.

**No lane edits the working tree.** A crashed run must leave the repository untouched, so
there is no "restore" step whose own failure could be mistaken for a result.

`git ls-files --cached --others --exclude-standard` rather than a directory copy, for three
reasons that are each a measurement error avoided:

  * it takes the tree AS IT IS ON DISK, including edits not yet committed — which is what a
    developer running a lane locally means by "this tree";
  * it excludes `target/` and `.git`, whose size would make the copy the slowest part of
    a run;
  * `--others` is why a NEW, not-yet-added source file is copied too. Without it the
    mutation lane reported a probe STALE because its file "does not exist" — a true
    statement about the copy and a false one about the tree.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def copy_tracked_tree(destination: Path, repo_root: Path | None = None) -> int:
    """Copy the tracked (and untracked-but-not-ignored) tree into `destination`.

    Returns the number of files copied. A caller that receives 0 has been handed an empty
    directory rather than a copy of the repository, and every lane that runs in one would
    then be measuring nothing — which is why the count is returned rather than discarded.
    """
    root = repo_root or REPO_ROOT
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    copied = 0
    for name in listing.stdout.split("\0"):
        if not name:
            continue
        source = root / name
        if not source.is_file():
            continue
        out = destination / name
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, out)
        copied += 1
    return copied
