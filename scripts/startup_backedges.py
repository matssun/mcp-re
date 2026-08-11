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


def strip_cfg_test_items(text: str) -> str:
    """Source with every `#[cfg(test)]`-attributed item removed.

    Removing items INDIVIDUALLY is the correctness argument. Truncating at the first
    `#[cfg(test)]` looks equivalent and is not: an inline attribute on a test-only helper
    appears at trust_plane.rs:78, signing_plane.rs:62 and tls_plane.rs:137, and truncating
    there discards 500-900 lines of production code apiece. Fifteen files in the workspace
    carry such an early attribute, and the naive form reported three real `cli`
    dependencies as test-only. The same flaw in the sibling scan under
    tools/verification/ dropped a production `SystemTime::now()` out of `boundary.clock`.
    """
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        if not lines[i].strip().startswith("#[cfg(test)]"):
            out.append(lines[i])
            i += 1
            continue
        j = i + 1
        while j < len(lines) and "{" not in lines[j] and not lines[j].rstrip().endswith(";"):
            j += 1
        if j < len(lines) and "{" not in lines[j] and lines[j].rstrip().endswith(";"):
            i = j + 1
            continue
        depth, seen = 0, False
        while j < len(lines):
            s = re.sub(r'"(?:\\.|[^"\\])*"', '""', lines[j])
            s = re.sub(r"//.*", "", s)
            for ch in s:
                if ch == "{":
                    depth += 1
                    seen = True
                elif ch == "}":
                    depth -= 1
            if seen and depth <= 0:
                break
            j += 1
        i = j + 1
    return "\n".join(out)


def code_only(text: str) -> str:
    """Source with test items, block comments and line comments removed."""
    text = strip_cfg_test_items(text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(re.sub(r"//.*", "", line) for line in text.split("\n"))


def selftest() -> int:
    """The naive truncation this scanner used to do, pinned as a refusal."""
    sample = "\n".join([
        "use crate::cli;",
        "impl Thing {",
        "    #[cfg(test)]",
        "    fn only_for_tests() -> u8 { 1 }",
        "}",
        "fn production(c: &cli::Config) {}",          # AFTER the inline attribute
        "#[cfg(test)]",
        "mod tests {",
        "    fn t(c: &cli::Config) {}",
        "}",
    ])
    kept = code_only(sample)
    if "fn production" not in kept:
        print("SELFTEST FAILED: production code after an inline #[cfg(test)] was dropped")
        return 1
    if "mod tests" in kept or "fn only_for_tests" in kept:
        print("SELFTEST FAILED: a #[cfg(test)] item survived")
        return 1
    print("startup_backedges selftest: PASS")
    return 0


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
    if "--selftest" in sys.argv:
        return selftest()
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
