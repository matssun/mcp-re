#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned-worker gate — no unreviewed direct thread spawn in production code.

WHAT THIS PROVES, exactly: no library source outside `managed_worker.rs`, in any crate in
the repository (including the `sdk/python` and `sdk/typescript` native bindings), starts
an OS thread through `thread::spawn` or `thread::Builder` except in test code or at one of
the exact reviewed sites counted below. That is a syntactic check on two spellings, and
the claim stops there.

WHAT IT DOES NOT PROVE: that no detached runtime worker exists. A helper that wraps the
spawn, a type alias, a re-export, a `tokio::spawn` or `Runtime::spawn` task, or a thread
started inside a dependency all pass it untouched. Keeping the contract narrow is
deliberate — this gate is not a Rust compiler, and overstating it would be worse than
not having it, because the overstatement is what stops people looking. The real
enforcement is that runtime-owned work goes through `WorkerSet`; this gate makes the
common bypass loud.

WHY. ADR-MCPRE-056 §9: no startup phase may spawn a long-lived thread whose lifetime is
not represented by an owned value. A bare `std::thread::spawn(..)` whose `JoinHandle` is dropped outlives every
value it was conceptually part of: nothing can stop it, and nothing can observe that it
stopped. Startup had four of them — trust reload, client CRL reload, delegated key
rotation, trust-epoch poll — each looping on the caller's SIGTERM flag, which no error
path sets. A `run` that failed after the first spawn returned `Err` with threads still
reading files and minting keys.

They are now owned by `managed_worker::WorkerSet`. This gate is what keeps them that way,
because the invariant does not survive as a habit: the fourth was found by accident, days
after a survey that swept one file and concluded there were three.

Tokio tasks on the per-core serving runtimes are a different lifetime question — the
fleet owns its runtimes and joins them on drain — and are deliberately out of scope.

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

# Every thread in the system that is not started through `WorkerSet`, and why it is
# sound. Two kinds appear here and they are not equivalent:
#
#   - satisfies §9 by hand: the handle IS owned and joined, just not by `WorkerSet`
#     (the fleet, the retention writer, the anchor refresher)
#   - out of §9's scope: a per-connection, per-operation or per-process thread whose
#     lifetime is not a runtime's (the signal bridges, the connection handlers, the
#     audit writer)
#
# Adding an entry is a decision, and the asymmetry is the point: an existing entry has
# to stay explainable, a new one has to argue for itself.
#
# Each entry is (site count, reason), and the count is load-bearing: the reason justifies
# a NAMED thread, so a file-granular exemption would let the serving and evidence paths
# acquire further detached threads for free. The count is what makes a second spawn in an
# exempt file a gate failure that has to be argued rather than a silent pass.
ALLOWED = {
    "mcp-re-proxy/src/main.rs": (1, (
        "the SIGTERM/SIGINT bridge thread belongs to the PROCESS, not to any runtime: it "
        "outlives `app::run` by design and exits when the signal flag flips"
    )),
    "mcp-re-proxy/src/redis_store.rs": (1, (
        "the bounded-abandonment connect worker is a PER-OPERATION timeout thread, not a "
        "runtime worker; its permit releases the in-flight slot even when it finishes late"
    )),
    "mcp-re-proxy/src/blocking_mtls_harness/mod.rs": (1, (
        "the per-connection handler on the BLOCKING harness accept loop lives as long as "
        "one connection and releases its `in_flight` slot on exit; it is bounded by "
        "`max_concurrent_connections` rather than by a runtime's lifetime, and the harness "
        "is not the shipped serving path (MCPRE-138)"
    )),
    "mcp-re-client/src/main.rs": (1, (
        "the client binary's SIGTERM bridge, the same process-lifetime signal thread as "
        "the proxy's — it belongs to the process, not to a runtime"
    )),
    "mcp-re-proxy/src/audit_sink.rs": (1, (
        "the stderr audit writer drains a `static` OnceLock channel and is scoped to the "
        "PROCESS by construction; there is no runtime whose lifetime it could take"
    )),
    "mcp-re-proxy/src/transparency.rs": (1, (
        "the retention writer already satisfies §9 by hand: `EvidenceRetention` owns the "
        "handle, closing the job channel is its halt, and `Drop` joins it"
    )),
    "mcp-re-proxy/src/async_fleet.rs": (1, (
        "the per-core serving threads satisfy §9 by hand: their handles are `Fleet.workers` "
        "and `Fleet::shutdown_and_join` stops and joins every one of them"
    )),
    "mcp-re-client/src/anchors.rs": (1, (
        "the anchor-refresh thread's handle is owned by the refresher it belongs to, which "
        "sets its stop flag and joins on drop"
    )),
    "mcp-re-client/src/serve.rs": (1, (
        "the client's per-connection handler lives as long as one connection; its capacity "
        "slot is released by the same destructor on success, unwind, and spawn failure"
    )),
}

# Both spellings that start an OS thread. `Builder` is not a hypothetical bypass: two
# production sites already used it, and a gate that watched only `thread::spawn` would
# have reported a clean tree over them.
SPAWN = re.compile(r"\bthread\s*::\s*(?:spawn\b|Builder\b)")
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


#: Directories that hold Rust which is not this repository's production library code.
#: `node_modules` carries vendored fixture crates from an npm dependency, and build
#: outputs are copies of sources already scanned.
PRUNED = {"target", "node_modules", ".git", "bazel-out"}


def crates(root: Path) -> list[Path]:
    """Every crate directory in the repository, at any depth.

    Depth matters: `sdk/python` and `sdk/typescript` are the native bindings that ship to
    end users, and a depth-1 glob would report a clean tree having read none of them.
    """
    found: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        if (current / "Cargo.toml").is_file() and (current / "src").is_dir():
            found.append(current)
        for child in current.iterdir():
            if child.is_dir() and not child.is_symlink() and child.name not in PRUNED:
                stack.append(child)
    return sorted(found)


def production_spawns(src: str) -> list[int]:
    """The 1-based line of every `thread::spawn`/`Builder` in real, non-test code."""
    if not SPAWN.search(src):
        return []
    mask = code_mask(src)
    regions = test_regions(src, mask)
    lines = []
    for m in SPAWN.finditer(src):
        off = m.start()
        if not mask[off]:
            continue
        if any(a <= off <= b for a, b in regions):
            continue
        lines.append(src.count("\n", 0, off) + 1)
    return lines


def check(root: Path) -> list[str]:
    problems: list[str] = []
    for crate in crates(root):
        for src_path in sorted((crate / "src").rglob("*.rs")):
            rel_in_crate = src_path.relative_to(crate).as_posix()
            rel = src_path.relative_to(root).as_posix()
            if rel_in_crate == OWNER_MODULE:
                continue
            src = src_path.read_text(encoding="utf-8")
            sites = production_spawns(src)
            if rel in ALLOWED:
                # The exemption is for the reviewed sites, not for the file. A count
                # that no longer matches means a thread nobody argued for, or a reason
                # that has outlived the code it describes.
                expected, reason = ALLOWED[rel]
                if len(sites) != expected:
                    at = ", ".join(f":{line}" for line in sites) or "none"
                    problems.append(
                        f"{rel} is allowlisted for {expected} reviewed spawn site(s) "
                        f"({reason.strip()}) but has {len(sites)} ({at}). Route the new "
                        "thread through `managed_worker::WorkerSet::spawn`, or update "
                        "this gate's entry with the count and the reason the extra "
                        "thread is sound."
                    )
                continue
            for line in sites:
                problems.append(
                    f"{rel}:{line} spawns a thread directly. A runtime worker must be "
                    "started through `managed_worker::WorkerSet::spawn`, which owns the "
                    "handle; if this thread is genuinely not a runtime worker, add the "
                    "file to ALLOWED in this gate with its site count and the reason."
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

        # An allowlisted file is exempt at its reviewed site count.
        plane.unlink()
        main = crate / "src" / "main.rs"
        main.write_text("fn main() { std::thread::spawn(|| {}); }\n")
        if check(root):
            print("selftest FAIL: an allowlisted file was rejected at its reviewed count")
            return 1

        # ...and only at that count: a SECOND spawn in the same file is a new thread
        # nobody reviewed, which a file-granular exemption would have waved through.
        main.write_text(
            "fn main() { std::thread::spawn(|| {}); }\n"
            "fn extra() { std::thread::spawn(move || loop {}); }\n"
        )
        found = check(root)
        if len(found) != 1 or "allowlisted for 1 reviewed spawn site" not in found[0]:
            print(f"selftest FAIL: extra spawn in an allowlisted file not caught: {found}")
            return 1
        main.write_text("fn main() { std::thread::spawn(|| {}); }\n")

        # A crate BELOW the top level is scanned. The SDK bindings live at sdk/<lang>,
        # and a depth-1 crate walk reports a clean tree having read none of them.
        nested = root / "sdk" / "python"
        (nested / "src").mkdir(parents=True)
        (nested / "Cargo.toml").write_text('[package]\nname = "mcp-re-sdk-python"\n')
        (nested / "src" / "lib.rs").write_text("fn go() { std::thread::spawn(|| {}); }\n")
        found = check(root)
        if len(found) != 1 or not found[0].startswith("sdk/python/src/lib.rs:1"):
            print(f"selftest FAIL: nested crate not scanned: {found}")
            return 1

        # Vendored fixture crates under node_modules are not this repo's production code.
        vendored = root / "sdk" / "typescript" / "node_modules" / "pkg"
        (vendored / "src").mkdir(parents=True)
        (vendored / "Cargo.toml").write_text('[package]\nname = "vendored"\n')
        (vendored / "src" / "lib.rs").write_text("fn go() { std::thread::spawn(|| {}); }\n")
        (nested / "src" / "lib.rs").write_text("fn go() {}\n")
        if check(root):
            print("selftest FAIL: a vendored node_modules crate was scanned")
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
        f"owned-worker gate: OK — {len(crates(REPO))} crates scanned, no direct thread "
        f"spawn in production library code outside {OWNER_MODULE}, except "
        f"{sum(sites for sites, _ in ALLOWED.values())} counted sites in "
        f"{len(ALLOWED)} files that each name a reason."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
