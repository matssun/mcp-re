#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extraction-image gate — the image consumes pinned Aeneas/Charon prebuilts and builds neither.

WHAT THIS PROVES, exactly, about `verification/extraction/Dockerfile` against
`verification/policy/toolchains.lock.toml`:

  * the pair is Aeneas's own: the lock's `[aeneas].charon_pin` — the last line of
    `charon-pin` at the pinned Aeneas commit — equals `[charon].commit`;
  * each Aeneas/Charon build argument's default equals the lock: the commits, the release
    URLs (under each project's own `releases/download/<release_tag>/`), the archive digests,
    the digest of every binary the lane executes, and Charon's rustc nightly;
  * every instruction that downloads a release archive also checks it against its pinned
    digest, and every executed binary is checked against its own;
  * no instruction clones an Aeneas or Charon repository or invokes a tool that builds one
    (`git clone`, `make`, `dune`, `opam`, `cargo`), and the only fetch from those
    repositories outside a release is the `charon-pin` file at the pinned commit;
  * `CHARON_EXE` and `AENEAS_EXE` name the installed release binaries.

WHAT IT DOES NOT PROVE: anything about what a downloaded binary does, or what an upstream
command would run. It holds this definition to one route for the two tools — a pinned,
digest-checked download — and forbids the other. Whether the binaries that RUN are those
downloads is `tools/verification/extraction-image smoke`'s check, which re-digests them inside
the image and reads Charon's own statement of its commit.

WHY IT MATTERS. The previous definition built Charon and Aeneas from source; Charon's
`make build` runs Cargo. A scanner for the word `cargo` could not see that — it was behind
an upstream Makefile — so the invariant is stated as what the image may contain rather than
as a word it may not.

Run:  python3 scripts/extraction_image_gate.py
      python3 scripts/extraction_image_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / "verification" / "extraction" / "Dockerfile"
LOCK = REPO / "verification" / "policy" / "toolchains.lock.toml"

#: Build argument -> (lock table, lock key). Digests are recorded `sha256:<hex>` in the lock
#: and bare hex in the definition, where `sha256sum -c` reads them.
PINNED_ARGS = {
    "CHARON_COMMIT": ("charon", "commit"),
    "CHARON_URL": ("charon", "linux_arm64_url"),
    "CHARON_SHA256": ("charon", "linux_arm64_sha256"),
    "CHARON_BIN_SHA256": ("charon", "charon_sha256"),
    "CHARON_DRIVER_SHA256": ("charon", "charon_driver_sha256"),
    "RUST_NIGHTLY": ("charon", "rust_toolchain"),
    "AENEAS_COMMIT": ("aeneas", "commit"),
    "AENEAS_URL": ("aeneas", "linux_arm64_url"),
    "AENEAS_SHA256": ("aeneas", "linux_arm64_sha256"),
    "AENEAS_BIN_SHA256": ("aeneas", "aeneas_sha256"),
}
#: Each release archive, and the digest its download must be checked against.
ARCHIVES = {"CHARON_URL": "CHARON_SHA256", "AENEAS_URL": "AENEAS_SHA256"}
#: Each binary the lane executes, and the digest it must be checked against.
BINARIES = {
    "/opt/charon/bin/charon": "CHARON_BIN_SHA256",
    "/opt/charon/bin/charon-driver": "CHARON_DRIVER_SHA256",
    "/opt/aeneas/bin/aeneas": "AENEAS_BIN_SHA256",
}
EXECUTABLES = {"CHARON_EXE": "/opt/charon/bin/charon", "AENEAS_EXE": "/opt/aeneas/bin/aeneas"}
#: Tools that build a program from source. None of them may appear in an instruction.
BUILD_TOOLS = re.compile(r"(?<![\w./-])(git\s+clone|make|dune|opam|cargo)(?![\w-])")
UPSTREAM = re.compile(r"(?:github\.com|githubusercontent\.com)/AeneasVerif/(aeneas|charon)[^\s\"']*")
#: The one fetch from those repositories that is not a release: the compatibility pin.
CHARON_PIN_FETCH = "githubusercontent.com/AeneasVerif/aeneas/${AENEAS_COMMIT}/charon-pin"


def instructions(text: str) -> list[str]:
    """The definition's instructions, continuation lines joined and comments dropped."""
    out: list[str] = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not current and (not stripped or stripped.startswith("#")):
            continue
        if stripped.startswith("#"):
            continue
        current += " " + stripped.removesuffix("\\")
        if not stripped.endswith("\\"):
            out.append(current.strip())
            current = ""
    if current:
        out.append(current.strip())
    return out


def _bare(value: str) -> str:
    return value.removeprefix("sha256:")


def problems(dockerfile: str, lock: dict) -> list[str]:
    found: list[str] = []
    charon, aeneas = lock.get("charon", {}), lock.get("aeneas", {})
    if not charon.get("commit") or aeneas.get("charon_pin") != charon.get("commit"):
        found.append(
            f"[aeneas].charon_pin is {aeneas.get('charon_pin')!r} and [charon].commit is "
            f"{charon.get('commit')!r}: the pinned Charon is not the one the pinned Aeneas "
            "declares"
        )
    for table in ("charon", "aeneas"):
        tag = lock.get(table, {}).get("release_tag", "")
        url = lock.get(table, {}).get("linux_arm64_url", "")
        prefix = f"https://github.com/AeneasVerif/{table}/releases/download/{tag}/"
        if not tag or not url.startswith(prefix):
            found.append(f"[{table}].linux_arm64_url {url!r} is not a release asset of {prefix}")

    steps = instructions(dockerfile)
    args = {}
    for step in steps:
        match = re.match(r"ARG\s+(\w+)=(\S+)$", step)
        if match:
            args[match.group(1)] = match.group(2)
    for arg, (table, key) in PINNED_ARGS.items():
        pinned = _bare(str(lock.get(table, {}).get(key, "")))
        if not pinned:
            found.append(f"[{table}].{key} is not recorded, so {arg} pins nothing")
        elif args.get(arg) != pinned:
            found.append(f"ARG {arg} defaults to {args.get(arg)!r}; the lock pins {pinned!r}")

    runs = [step for step in steps if step.startswith("RUN ")]
    for url_arg, digest_arg in ARCHIVES.items():
        fetches = [run for run in runs if "${" + url_arg + "}" in run]
        if not fetches:
            found.append(f"no instruction downloads ${{{url_arg}}}")
        for run in fetches:
            if "${" + digest_arg + "}" not in run or "sha256sum -c" not in run:
                found.append(f"${{{url_arg}}} is downloaded without checking ${{{digest_arg}}}")
    for path, digest_arg in BINARIES.items():
        if not any("${" + digest_arg + "}" in run and path in run and "sha256sum -c" in run for run in runs):
            found.append(f"{path} is not checked against ${{{digest_arg}}}")

    for run in runs:
        tool = BUILD_TOOLS.search(run)
        if tool:
            found.append(f"an instruction invokes `{tool.group(1)}`: {run[:120]}")
        for reference in UPSTREAM.finditer(run):
            text = reference.group(0)
            if "/releases/download/" not in text and text != CHARON_PIN_FETCH:
                found.append(f"an instruction fetches {text} outside a pinned release")
    for step in steps:
        if step.startswith(("ARG ", "RUN ")):
            continue
        for reference in UPSTREAM.finditer(step):
            found.append(f"{step.split()[0]} references {reference.group(0)}")

    env = " ".join(step for step in steps if step.startswith("ENV "))
    for name, path in EXECUTABLES.items():
        if f"{name}={path}" not in env:
            found.append(f"{name} does not name the installed release binary {path}")
    return found


def selftest() -> int:
    good = DOCKERFILE.read_text(encoding="utf-8")
    lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    if problems(good, lock):
        print(f"extraction-image gate selftest: FAIL — the tree's own definition is refused: {problems(good, lock)}")
        return 1
    source_build = good.replace(
        "RUN curl -fsSL -o /tmp/aeneas.tar.gz",
        "RUN git clone https://github.com/AeneasVerif/aeneas /opt/src && make -C /opt/src\nRUN curl -fsSL -o /tmp/aeneas.tar.gz",
        1,
    )
    unchecked = re.sub(r'echo "\$\{CHARON_SHA256\}  /tmp/charon.tar.gz" \| sha256sum -c - \\\n\s*&& ', "", good, count=1)
    stale_pin = {**lock, "aeneas": {**lock["aeneas"], "charon_pin": "0" * 40}}
    moved_arg = re.sub(r"ARG AENEAS_SHA256=\w+", "ARG AENEAS_SHA256=" + "0" * 64, good, count=1)
    raw_source = good.replace(
        "/charon-pin\" | tail -1)",
        "/charon-pin\" | tail -1) && curl -fsSL https://raw.githubusercontent.com/AeneasVerif/charon/main/Makefile -o /tmp/M",
        1,
    )
    wrong_exe = good.replace("CHARON_EXE=/opt/charon/bin/charon", "CHARON_EXE=/usr/local/bin/charon", 1)
    cases = {
        "a source clone and make": (source_build, lock),
        "an archive downloaded without its digest check": (unchecked, lock),
        "a Charon that is not the one Aeneas pins": (good, stale_pin),
        "a build argument that disagrees with the lock": (moved_arg, lock),
        "an executable that is not the installed release": (wrong_exe, lock),
        "a source file fetched outside a release": (raw_source, lock),
    }
    for name, (text, table) in cases.items():
        if text == good and table is lock:
            print(f"extraction-image gate selftest: FAIL — the '{name}' mutation did not apply")
            return 1
        if not problems(text, table):
            print(f"extraction-image gate selftest: FAIL — {name} was not refused")
            return 1
    print(f"extraction-image gate selftest: PASS ({len(cases) + 1} cases)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    found = problems(
        DOCKERFILE.read_text(encoding="utf-8"),
        tomllib.loads(LOCK.read_text(encoding="utf-8")),
    )
    if found:
        print(f"extraction-image gate: FAIL — {len(found)} problem(s)")
        for problem in found:
            print(f"  - {problem}")
        return 1
    print(
        "extraction-image gate: OK — Aeneas and Charon enter the image only as the pinned, "
        "digest-checked release binaries, and the definition builds neither."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
