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

import re
import subprocess
import tempfile

from _manifest import REPO_ROOT

LEAN_DIR = REPO_ROOT / "verification" / "lean"

#: The signals that mean SOMETHING OUTSIDE stopped the prover: `SIGKILL` (the kernel OOM
#: killer, a container memory limit, or an operator) and `SIGTERM` (a job cancellation or a
#: timeout). `SIGABRT` is deliberately NOT here — an abort is the prover deciding it cannot
#: continue, which is a fact about the prover and belongs in the FAIL direction.
_EXTERNAL_SIGNALS = {9: "SIGKILL", 15: "SIGTERM"}

#: `lake` does not propagate a child's signal. It reports the death in its OUTPUT and then
#: exits 1 of its own accord, so a caller reading only the status sees an ordinary build
#: failure. This is how the 2026-09-14 OOM kill was rendered as `VERDICT: FAIL`: `lake build
#: exited 1`, and `error: Lean exited with code 137` two lines above it in the text.
_CHILD_SIGNAL = re.compile(r"exited with code (1(?:3[0-9]|4[0-3]))\b")


def external_termination(code: int, output: str) -> str | None:
    """Was this run STOPPED from outside, rather than finishing and reporting a failure?

    The distinction is the difference between two lane verdicts that must not be confused.
    A prover that elaborated the files and rejected a proof measured something: that is
    `FAIL`. A prover the OOM killer removed mid-elaboration measured NOTHING, and a lane
    that reports `FAIL` there states a fact about the theorems that no execution
    established — the strongest possible claim from the weakest possible evidence.

    Measured 2026-09-14 on this repository: `CivilFromDays` died at `[1699/1700]` under a
    colima VM holding 1.91 GiB, and `verify-lean --activation-probe` printed
    `VERDICT: FAIL`. The theorem was untouched and was re-established unchanged once the VM
    was resized, so the FAIL was about the host.

    Three shapes, because a signal reaches a caller three different ways:

    * the process WE spawned died on a signal — POSIX `Popen` reports `-N`;
    * something in the chain reported it shell-style, as `128 + N`;
    * `lake`'s own text names a child's status, which is the only trace when `lake` itself
      exits 1 having survived its child.

    Returns the reason, or `None` when the run ended on its own terms.

    **This can never manufacture a pass.** `UNAVAILABLE` holds the aggregate at
    `INCOMPLETE` exactly as `FAIL` does — both are non-measuring — so the worst outcome of
    a wrong answer here is a differently-worded refusal, never a green lane.
    """
    if code < 0 and -code in _EXTERNAL_SIGNALS:
        return f"the prover was terminated by {_EXTERNAL_SIGNALS[-code]} ({code})"
    if code >= 128 and (code - 128) in _EXTERNAL_SIGNALS:
        return (
            f"the prover exited {code}, which is 128 + "
            f"{_EXTERNAL_SIGNALS[code - 128]} — it was terminated, not a failure it reported"
        )
    match = _CHILD_SIGNAL.search(output)
    if match:
        reported = int(match.group(1))
        signal = _EXTERNAL_SIGNALS.get(reported - 128)
        if signal:
            return (
                f"`lake` reports that Lean exited with code {reported} (128 + {signal}); "
                f"lake itself then exited {code}. The build was stopped from outside"
            )
    return None


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
    # OUTSIDE the repository, deliberately. `lake env lean` takes an absolute path and sets
    # the search path itself, so the file does not need to live in the package — and two
    # things go wrong when it does. The activation probe's source contains `sorry` and an
    # `axiom` on purpose, so a file leaked by a killed process would sit in
    # `verification/lean/` where `check-assumptions` scans `.lean` for exactly those tokens,
    # reporting an unregistered seam in a file nobody wrote. And on the runner that directory
    # is a bind mount, so the write would cross it for no reason.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".lean", encoding="utf-8", delete=True
    ) as handle:
        handle.write(source)
        handle.flush()
        return lake(["lake", "env", "lean", handle.name], what)
