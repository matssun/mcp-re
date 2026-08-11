#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Runtime -> startup back-edges in mcp-re-proxy, classified.

ADR-MCPRE-060 / the module-map analysis. The architectural invariant is that
composition dependencies flow OUTWARD from the root: a runtime component may receive a
value or type produced by startup, but must not import an implementation service back
out of `app` or `cli`.

Counted from CODE ONLY. Two things are deliberately excluded because counting them
would reward the wrong behaviour:

  * doc comments — rustdoc intra-doc links (`[`crate::x::y`]`) are references for the
    reader, not dependencies; counting them rewards deleting documentation.
  * `#[cfg(test)]` modules — test wiring is not the runtime architecture.

Both forms of reference are counted: `crate::cli::Config` and a bare `use crate::cli;`
followed by `cli::Config`. Missing the second form under-reports by more than half.

Run: python3 scripts/startup_backedges.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "mcp-re-proxy" / "src"

STARTUP = {
    "main", "app", "cli", "startup_plan", "startup_posture",
    "serving_capabilities", "delegated_wiring",
}

# An edge is legitimate when what crosses is a VALUE or TYPE the composition root
# produced for the component -- that is what a composition root is for. It is a target
# when the component is reaching back for a service that startup merely happens to own.
LEGITIMATE = {
    ("replay_plane", "startup_plan"): "ReplayPlan -- a plan computed once and handed down",
    ("materialized_runtime", "app"): "serve_fleet -- composition: config to running fleet",
}


def code_only(text: str) -> str:
    """Source with the test module, block comments and line comments removed."""
    cut = text.find("#[cfg(test)]")
    if cut > 0:
        text = text[:cut]
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(re.sub(r"//.*", "", line) for line in text.split("\n"))


def edges() -> dict[tuple[str, str], set[str]]:
    found: dict[tuple[str, str], set[str]] = {}
    for path in sorted(SRC.glob("*.rs")):
        me = path.stem
        if me in STARTUP or me == "lib":
            continue
        src = code_only(path.read_text(errors="replace"))
        imported = set(re.findall(r"^\s*use\s+crate::([a-z0-9_]+)\s*;", src, re.M))
        for mod, sym in re.findall(r"crate::([a-z0-9_]+)::([A-Za-z0-9_]+)", src):
            if mod in STARTUP:
                found.setdefault((me, mod), set()).add(sym)
        for mod in imported & STARTUP:
            for sym in re.findall(rf"\b{mod}::([A-Za-z0-9_]+)", src):
                found.setdefault((me, mod), set()).add(sym)
            found.setdefault((me, mod), set())
    return found


def main() -> int:
    found = edges()
    targets = {k: v for k, v in found.items() if k not in LEGITIMATE}
    ok = {k: v for k, v in found.items() if k in LEGITIMATE}

    print(f"runtime -> startup edges: {len(found)}  "
          f"({len(targets)} misplaced-responsibility, {len(ok)} legitimate)\n")
    print("MISPLACED RESPONSIBILITY -- the reduction target")
    for (me, mod), syms in sorted(targets.items()):
        print(f"  {me:24} -> {mod:14} {', '.join(sorted(syms)) or '(module import)'}")
    print("\nLEGITIMATE -- excluded from the target, must not be optimised away")
    for (me, mod), syms in sorted(ok.items()):
        print(f"  {me:24} -> {mod:14} {LEGITIMATE[(me, mod)]}")

    by_owner: dict[str, int] = {}
    for (_, mod) in targets:
        by_owner[mod] = by_owner.get(mod, 0) + 1
    print("\nBy owner: " + ", ".join(f"{m}={c}" for m, c in sorted(by_owner.items())) or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
