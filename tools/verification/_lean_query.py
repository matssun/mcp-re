# SPDX-License-Identifier: Apache-2.0
"""Asking the pinned Lean a question — the one place the lane shells out to it.

Two callers need it and must not disagree about what "asking the prover" means: the lane
itself, which asks about the theorems a unit declares, and the activation probe, which asks
about theorems it writes on the spot to check that the lane still refuses them. A second
invocation path would be a probe exercising something other than the thing it certifies.

The source is generated into the package directory and never written to the repository. A
checked-in query file would be a second place deciding which theorems the lane measures,
and the direction it drifts is a query that asks about fewer than the manifest claims.
"""

from __future__ import annotations

import subprocess
import tempfile

from _manifest import REPO_ROOT

LEAN_DIR = REPO_ROOT / "verification" / "lean"


def lake(argv: list[str], what: str) -> tuple[int, str]:
    """Run one `lake` invocation in the Lean package and return ITS OWN status.

    Streams merged, never piped: a pipeline reports its last stage, so a failed
    elaboration read through one is a failure that exits 0.
    """
    print(f"verify-lean: {what}\n  $ {' '.join(argv)}")
    proc = subprocess.run(
        argv,
        cwd=LEAN_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout


def elaborate(source: str, what: str) -> tuple[int, str]:
    """Elaborate `source` against the built package, returning the prover's own output.

    A non-zero status is NOT an error here. `#print axioms` over a constant the prover
    cannot resolve is an error AND the diagnostic the caller needs, so the status is
    returned rather than raised and the caller decides what the reports mean.
    """
    with tempfile.NamedTemporaryFile(
        "w", suffix=".lean", dir=LEAN_DIR, encoding="utf-8", delete=True
    ) as handle:
        handle.write(source)
        handle.flush()
        return lake(["lake", "env", "lean", handle.name], what)
