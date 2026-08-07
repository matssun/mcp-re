#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned-worker gate — a long-lived thread must have an owner (ADR-MCPRE-056 §9).

No startup phase may spawn a long-lived thread whose lifetime is not represented by an
owned value. A bare `std::thread::spawn(..)` whose `JoinHandle` is dropped outlives every
value it was conceptually part of: nothing can stop it, and nothing can observe that it
stopped. Startup had four of them — trust reload, client CRL reload, delegated key
rotation, trust-epoch poll — each looping on the caller's SIGTERM flag, which no error
path sets. A `run` that failed after the first spawn returned `Err` with threads still
reading files and minting keys.

They are now owned by `managed_worker::WorkerSet`. This gate is what keeps them that way,
because the invariant does not survive as a habit: the fourth was found by accident, days
after a survey that swept one file and concluded there were three.

The rule: in library sources, `thread::spawn` may appear only in `managed_worker.rs`, in
test code, or in a file listed below with a reason. Anything else must go through
`WorkerSet::spawn`, which owns the handle and cannot hand it back.

SCOPE. This gate is about OS threads. Tokio tasks on the per-core serving runtimes are a
different lifetime question — the fleet owns its runtimes and joins them on drain — and
are deliberately not covered here.

Run:  python3 scripts/owned_worker_gate.py
      python3 scripts/owned_worker_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The one module allowed to start a thread: it is the thing that owns them.
OWNER_MODULE = "src/managed_worker.rs"

# Files permitted to spawn directly, each for a reason that is NOT "a runtime worker".
# Adding an entry is a decision; it should be as hard to justify as it looks.
ALLOWED = {
    "mcp-re-proxy/src/main.rs": (
        "the SIGTERM/SIGINT bridge thread belongs to the PROCESS, not to any runtime: it "
        "outlives `app::run` by design and exits when the signal flag flips"
    ),
    "mcp-re-proxy/src/redis_store.rs": (
        "the bounded-abandonment connect worker is a PER-OPERATION timeout thread, not a "
        "runtime worker; its permit releases the in-flight slot even when it finishes late"
    ),
    "mcp-re-proxy/src/tls.rs": (
        "the per-connection handler on the SYNC serving path lives as long as one "
        "connection and releases its `in_flight` slot on exit; it is bounded by "
        "`max_concurrent_connections` rather than by a runtime's lifetime"
    ),
    "mcp-re-client/src/main.rs": (
        "the client binary's SIGTERM bridge, the same process-lifetime signal thread as "
        "the proxy's — it belongs to the process, not to a runtime"
    ),
}

SPAWN = re.compile(r"\bthread\s*::\s*spawn\b")
CFG_TEST = re.compile(r"#!?\[\s*cfg\s*\(\s*test\s*\)\s*\]")


def code_mask(src: str) -> list[bool]:
    """True at every offset that is real code — not a comment, string or char literal.

    Written out rather than approximated with a line-based heuristic because the whole
    point is to find a `thread::spawn` someone did not mean to leave in; a scanner that
    can be fooled by the word appearing in a doc comment would be trained away rather
    than trusted.
    """
    mask = [False] * len(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        if c == "r" and i + 1 < n and src[i + 1] in '#"':
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes, j = hashes + 1, j + 1
            if j < n and src[j] == '"':
                close = '"' + "#" * hashes
                end = src.find(close, j + 1)
                i = n if end < 0 else end + len(close)
                continue
        if c == '"':
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "'":
            # A lifetime (`'a`) is code; a char literal is not. Distinguished by the
            # closing quote appearing within a couple of characters.
            j = i + 1
            if j < n and src[j] == "\\":
                j += 2
                while j < n and src[j] != "'":
                    j += 1
                i = j + 1
                continue
            if j + 1 < n and src[j + 1] == "'":
                i = j + 2
                continue
        mask[i] = True
        i += 1
    return mask


def test_regions(src: str, mask: list[bool]) -> list[tuple[int, int]]:
    """Offset ranges covered by a `#[cfg(test)]` item, by brace matching."""
    regions: list[tuple[int, int]] = []
    for m in CFG_TEST.finditer(src):
        if not mask[m.start()]:
            continue
        i, n = m.end(), len(src)
        while i < n and not (src[i] == "{" and mask[i]):
            # A `#![cfg(test)]` at file scope, or an attribute on a non-block item;
            # neither opens a region this way.
            if src[i] == ";" and mask[i]:
                i = -1
                break
            i += 1
        if i < 0 or i >= n:
            continue
        depth, j = 0, i
        while j < n:
            if mask[j]:
                if src[j] == "{":
                    depth += 1
                elif src[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
            j += 1
        regions.append((m.start(), j))
    return regions


def check(root: Path) -> list[str]:
    problems: list[str] = []
    for manifest in sorted(root.glob("*/Cargo.toml")):
        crate = manifest.parent
        for src_path in sorted((crate / "src").rglob("*.rs")):
            rel_in_crate = src_path.relative_to(crate).as_posix()
            rel = src_path.relative_to(root).as_posix()
            if rel_in_crate == OWNER_MODULE or rel in ALLOWED:
                continue
            src = src_path.read_text(encoding="utf-8")
            if not SPAWN.search(src):
                continue
            mask = code_mask(src)
            regions = test_regions(src, mask)
            for m in SPAWN.finditer(src):
                off = m.start()
                if not mask[off]:
                    continue
                if any(a <= off <= b for a, b in regions):
                    continue
                line = src.count("\n", 0, off) + 1
                problems.append(
                    f"{rel}:{line} spawns a thread directly. A runtime worker must be "
                    "started through `managed_worker::WorkerSet::spawn`, which owns the "
                    "handle; if this thread is genuinely not a runtime worker, add the "
                    "file to ALLOWED in this gate with the reason."
                )
    return problems


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        crate = root / "mcp-re-proxy"
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text('[package]\nname = "mcp-re-proxy"\n')
        owner = crate / "src" / "managed_worker.rs"
        owner.write_text("pub fn spawn() { std::thread::spawn(|| {}); }\n")
        plane = crate / "src" / "plane.rs"

        # Test code, doc comments and string literals are all fine.
        plane.write_text(
            '//! Do not use std::thread::spawn here.\n'
            'fn note() -> &\'static str { "thread::spawn is banned" }\n'
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    #[test]\n"
            "    fn t() { let h = std::thread::spawn(|| {}); h.join().unwrap(); }\n"
            "}\n"
        )
        if check(root):
            print("selftest FAIL: permitted arrangement was rejected")
            return 1

        # A production spawn is not.
        plane.write_text(
            "fn materialize() {\n"
            "    std::thread::spawn(move || loop {});\n"
            "}\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    #[test]\n"
            "    fn t() { std::thread::spawn(|| {}); }\n"
            "}\n"
        )
        found = check(root)
        if len(found) != 1 or ":2 " not in found[0]:
            print(f"selftest FAIL: production spawn not caught exactly once: {found}")
            return 1

        # ...including one placed AFTER the test module, which a "everything below
        # #[cfg(test)] is tests" heuristic would have missed.
        plane.write_text(
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    #[test]\n"
            "    fn t() { std::thread::spawn(|| {}); }\n"
            "}\n"
            "fn late() { std::thread::spawn(move || loop {}); }\n"
        )
        found = check(root)
        if len(found) != 1 or ":6 " not in found[0]:
            print(f"selftest FAIL: spawn after the test module not caught: {found}")
            return 1

        # An allowlisted file is exempt.
        plane.unlink()
        main = crate / "src" / "main.rs"
        main.write_text("fn main() { std::thread::spawn(|| {}); }\n")
        if check(root):
            print("selftest FAIL: an allowlisted file was rejected")
            return 1

    print("owned-worker gate selftest: PASS")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems = check(REPO)
    if problems:
        print("owned-worker gate: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(
        "owned-worker gate: OK — every library thread is owned by a WorkerSet, "
        f"except {len(ALLOWED)} justified non-runtime threads."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
