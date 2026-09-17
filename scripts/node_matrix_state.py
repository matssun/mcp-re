#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Which pinned Node runtimes are prepared, read from the lock rather than a list here.

The TypeScript battery is measured on one prepared environment per PINNED Node version.
Those environments are build products on a persistent box and the nightly disk reclaim
removes them, after which the lane finds no runtime and measures nothing. The preflight
therefore has to ask the question *before* the lane runs — and to ask it about the exact
set the lock names, not a set spelled out a second time here, because two spellings of one
pin is how a lane comes to measure three runtimes while claiming four.

`scripts/verification_runner_preflight.sh` is the caller: absent runtimes are PREPARED
there (preparation is a different job from measurement), and this only ever reports state.

Run:  python3 scripts/node_matrix_state.py --print-missing   # newline-free, empty = ready
      python3 scripts/node_matrix_state.py --count
      python3 scripts/node_matrix_state.py --selftest
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

#: The lock entry that owns the pin. Named once.
LOCK = Path("verification/policy/toolchains.lock.toml")
ENTRY = "typescript"
#: Where a prepared runtime lives, relative to the SDK project. Mirrors
#: `tools/verification/_ecosystems.NODE_RUNTIME_DIR` — by MAJOR, because Node's support
#: lines are majors.
PROJECT = Path("sdk/typescript")
RUNTIME_DIR = ".node-v{major}"
#: What makes a directory a prepared runtime rather than an empty shell. The lane executes
#: this exact path, so its presence is the question and nothing weaker is.
NODE_BIN = "node_modules/node/bin/node"


def pinned_runtimes(lock_path: Path = LOCK) -> list[str]:
    """The exact versions the lock pins for the TypeScript battery."""
    doc = tomllib.loads(lock_path.read_text())
    entry = doc.get(ENTRY)
    if not isinstance(entry, dict):
        raise SystemExit(f"{lock_path}: no [{ENTRY}] entry — the pin has no owner")
    runtimes = entry.get("interpreters")
    if not isinstance(runtimes, list) or not runtimes:
        raise SystemExit(f"{lock_path}: [{ENTRY}].interpreters is absent or empty")
    return [str(r) for r in runtimes]


def runtime_dir(runtime: str) -> str:
    """The directory a pinned version is prepared into."""
    return RUNTIME_DIR.format(major=runtime.split(".")[0])


def missing(root: Path, runtimes: list[str]) -> list[str]:
    """The pinned runtimes with no executable prepared for them, in pin order."""
    absent = []
    for runtime in runtimes:
        if not (root / PROJECT / runtime_dir(runtime) / NODE_BIN).exists():
            absent.append(runtime)
    return absent


def _selftest() -> int:
    """Poison pills: the question must be answerable, and absence must be detected."""
    import tempfile

    ok = True

    def check(name: str, got, want) -> None:
        nonlocal ok
        if got != want:
            ok = False
            print(f"  FAIL {name}: got {got!r}, want {want!r}")
        else:
            print(f"  ok   {name}")

    runtimes = pinned_runtimes()
    check("the lock pins at least one runtime", len(runtimes) >= 1, True)
    check("versions are exact, not ranges", all(v[0].isdigit() for v in runtimes), True)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # Nothing prepared: every pinned runtime is missing.
        check("an empty tree reports every runtime missing", missing(root, runtimes), runtimes)

        # A directory that EXISTS but holds no executable is not a prepared runtime. This
        # is the case a `-d` check would pass: the reclaim can leave the shell behind.
        (root / PROJECT / runtime_dir(runtimes[0])).mkdir(parents=True)
        check(
            "an empty runtime directory is still missing",
            missing(root, runtimes),
            runtimes,
        )

        # Prepared: the executable the lane runs is there.
        binary = root / PROJECT / runtime_dir(runtimes[0]) / NODE_BIN
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\n")
        check(
            "a prepared runtime drops out of the missing set",
            missing(root, runtimes),
            runtimes[1:],
        )

        for runtime in runtimes[1:]:
            b = root / PROJECT / runtime_dir(runtime) / NODE_BIN
            b.parent.mkdir(parents=True, exist_ok=True)
            b.write_text("#!/bin/sh\n")
        check("a fully prepared tree reports nothing missing", missing(root, runtimes), [])

    print("node-matrix state: selftest " + ("passed" if ok else "FAILED"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--print-missing", action="store_true")
    ap.add_argument("--count", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()

    runtimes = pinned_runtimes()
    if args.count:
        print(len(runtimes))
        return 0
    if args.print_missing:
        # Space-separated on one line: the caller tests it for emptiness.
        print(" ".join(missing(Path("."), runtimes)), end="")
        return 0

    absent = missing(Path("."), runtimes)
    print(f"pinned: {', '.join(runtimes)}")
    print(f"missing: {', '.join(absent) if absent else '<none>'}")
    return 0 if not absent else 1


if __name__ == "__main__":
    sys.exit(main())
