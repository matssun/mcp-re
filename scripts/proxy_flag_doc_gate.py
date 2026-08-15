#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Proxy-flag documentation gate — a guide cannot teach a flag the CLI does not have.

WHAT THIS PROVES, exactly: every `--flag` appearing in a fenced code block that invokes
`mcp_re_proxy_cli` (or `mcp-re-proxy`) is a flag `cli.rs` actually parses. That is a
syntactic check over the documentation and one source file, and the claim stops there.

WHAT IT DOES NOT PROVE: that the flag's VALUE is accepted. `--authz reference`,
`--revocation-list <path>`, `--client-ocsp require`,
`--transport-binding lb-assertion|attested-ingress` and the two sub-strict
`--replay-durability-tier` values are all
spelled with flags that exist and are then refused by configuration validation, so a
command line built entirely from flags this gate accepts can still fail to start. Value
admissibility is `unsafe_config_violations`' business and is tested there.

Nor does it read prose: only fenced blocks that invoke the proxy. A paragraph may name a
removed flag in order to say it was removed, which is exactly what several guides do.

WHY IT EXISTS. `docs/sidecar-deployment-guide.md` — the current guide for the shipped
sidecar, not a superseded one — carried a worked command line passing `--authz reference`
and `--revocation-list`, neither of which starts, plus a flag table row
for `--allow-env-keysource`, which stopped existing in `0a99957`. An operator
following it gets a proxy that refuses to start and no reason to suspect the document. A
flag that was DELETED is the case this gate catches outright; a flag whose VALUE became
inadmissible is the case it cannot, which is why the limitation is stated above rather
than implied.

Run:  python3 scripts/proxy_flag_doc_gate.py
      python3 scripts/proxy_flag_doc_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

CLI_MODULE = "mcp-re-proxy/src/cli.rs"

# Documentation roots. `docs/archive/` is history by definition and records the surface as
# it was; `docs/security/round-*/` holds captured gate logs, not instructions.
#
# Repo-root markdown is in scope too: README.md and CONTRIBUTING.md are the first
# documents an operator reads, and a scan that stops at `docs/` would never see a command
# line in either.
DOC_ROOTS = ("docs", "deploy")
SKIP_PARTS = ("archive", "grilling-seed")
SKIP_PATTERNS = (re.compile(r"docs/security/round-"),)

# Floors on what the scan actually selected. A gate whose document set collapses to zero
# reports the same green as one that examined everything, so the size of the set is part
# of what has to hold. `MIN_LAUNCH_DOCS` is the load-bearing one: markdown files exist in
# quantity, documents that actually LAUNCH the proxy are the population under test.
MIN_SCANNED_DOCS = 40
MIN_LAUNCH_DOCS = 2

# A fenced block: ```[lang]\n ... \n```
FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)

# The proxy is being LAUNCHED, as opposed to merely named. Two spellings reach it: the
# Bazel target / built binary `mcp_re_proxy_cli`, and the installed `mcp-re-proxy` binary
# at the head of a command. Everything after that token — past an optional `--` separator
# — is the proxy's own argv. Anchoring on the invocation rather than on the block keeps
# `helm --set`, `kubectl`, `gcloud` and `cargo test -- --nocapture` out, all of which
# appear in blocks that also mention the proxy.
LAUNCHES_PROXY = re.compile(
    r"(?:"
    # The Bazel target or the built CLI, wherever it appears in the command.
    r"[\w./${}-]*mcp_re_proxy_cli"
    # The installed binary, only as the command being run. Anywhere else it is a crate
    # name (`cargo test -p mcp-re-proxy`), a chart name (`helm upgrade mcp-re-proxy`) or
    # a directory, and the flags around it are some other tool's.
    r"|^\s*(?:\$\s+)?(?:[A-Z_][A-Z0-9_]*=\S+\s+)*(?:\./|/\S*/)?mcp-re-proxy"
    r")(?:\s+--(?=\s)|)(?=\s)"
)

# `--flag` but not `--` alone and not a `--flag=` fragment inside a URL.
FLAG = re.compile(r"(?<![\w=/-])(--[a-z0-9][a-z0-9-]*)")

# Every `"--flag"` string literal in cli.rs. The parser matches on these, so their
# presence is exactly the question "does this flag exist".
CLI_FLAG_LITERAL = re.compile(r'"(--[a-z0-9][a-z0-9-]*)"')

# `bazel run //target:mcp_re_proxy_cli --features x -- --bind y` puts the launcher's own
# flags AFTER the target name and before the `--`, so anchoring on the invocation is not
# enough to exclude them. Kept to flags Bazel and Cargo actually take in that position —
# every entry here is a hole in the check, so speculative ones do not belong.
LAUNCHER_FLAGS = frozenset(
    {
        "--features",
        "--release",
        "--config",
        "--compilation_mode",
        "--test_output",
    }
)


def known_cli_flags(cli_source: str) -> set[str]:
    return set(CLI_FLAG_LITERAL.findall(cli_source))


def documented_flags(markdown: str) -> set[str]:
    """Every flag on a command line that launches the proxy.

    Shell continuations are joined first, so a multi-line invocation is one command. Only
    the argv AFTER the proxy binary counts: `bazel run //t:mcp_re_proxy_cli --features x --
    --bind y` gives `--bind`, not `--features`.
    """
    found: set[str] = set()
    for block in FENCE.findall(markdown):
        for command in re.sub(r"\\\n\s*", " ", block).splitlines():
            match = LAUNCHES_PROXY.search(command)
            if not match:
                continue
            argv = command[match.end() :]
            found |= {f for f in FLAG.findall(argv) if f not in LAUNCHER_FLAGS}
    return found


# A document that opens by declaring itself superseded is describing a surface that is
# gone ON PURPOSE, and its command lines are the evidence for that claim.
#
# The banner alone does not grant the exemption. A check a document can opt out of by
# writing one line about itself is a check any live operator guide can silence, so the
# exemption is held HERE, by path, and the banner and the entry must agree:
#
#   listed + banner   -> skipped, and reported
#   banner, unlisted  -> FAIL; the document is claiming an exemption the gate did not give
#   listed, no banner -> FAIL; the entry outlived the document's own claim about itself
SUPERSEDED = re.compile(r"^>\s*\*\*[⚠!]?\s*Superseded", re.M)

SUPERSEDED_DOCS = frozenset(
    {
        "docs/dogfood-runbook.md",
        "docs/spec/v0.3-claim-matrix.md",
    }
)


def is_superseded(markdown: str) -> bool:
    return bool(SUPERSEDED.search(markdown[:4000]))


def doc_files(repo: Path) -> list[Path]:
    files: list[Path] = sorted(repo.glob("*.md"))
    for root in DOC_ROOTS:
        for path in sorted((repo / root).rglob("*.md")):
            rel = path.relative_to(repo).as_posix()
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            if any(p.search(rel) for p in SKIP_PATTERNS):
                continue
            files.append(path)
    return files


def check(repo: Path, skipped: list[str] | None = None, floors: bool = True) -> list[str]:
    """Every problem in `repo`.

    `floors` is off only for the selftest's single-document fixtures, which are about the
    per-document logic rather than the size of the real corpus; the floor itself has its
    own case.
    """
    skipped = skipped if skipped is not None else []
    cli = (repo / CLI_MODULE).read_text(encoding="utf-8")
    known = known_cli_flags(cli)
    if len(known) < 20:
        return [
            f"{CLI_MODULE}: found only {len(known)} flag literals — the parser's shape "
            f"changed and this gate is no longer reading it. Fix the gate, do not skip it."
        ]
    problems: list[str] = []
    files = doc_files(repo)
    launch_docs = 0
    for path in files:
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8")
        banner, listed = is_superseded(text), rel in SUPERSEDED_DOCS
        if banner and listed:
            skipped.append(rel)
            continue
        if banner:
            problems.append(
                f"{rel}: carries a `> **Superseded` banner but is not in this gate's "
                f"SUPERSEDED_DOCS. A document does not exempt itself from the check its "
                f"command lines exist to pass; add it here if the exemption is intended."
            )
            continue
        if listed:
            problems.append(
                f"{rel}: is in SUPERSEDED_DOCS but no longer declares itself superseded. "
                f"Remove the entry so the document is scanned again."
            )
        flags = documented_flags(text)
        if flags:
            launch_docs += 1
        for flag in sorted(flags - known):
            problems.append(
                f"{rel}: `{flag}` is used in a proxy command line but {CLI_MODULE} does "
                f"not parse it. Remove it, or say in the surrounding prose that it was "
                f"removed (prose is not scanned; command lines are)."
            )
    if floors and len(files) < MIN_SCANNED_DOCS:
        problems.append(
            f"the scan selected only {len(files)} documents (floor {MIN_SCANNED_DOCS}) — "
            f"the document set collapsed, so a green here measured nothing. Fix the "
            f"selection, do not lower the floor."
        )
    if floors and launch_docs < MIN_LAUNCH_DOCS:
        problems.append(
            f"only {launch_docs} scanned document launches the proxy (floor "
            f"{MIN_LAUNCH_DOCS}) — either the invocation pattern stopped matching or the "
            f"guides moved out of scope. Fix the selection, do not lower the floor."
        )
    return problems


SELFTEST_CLI = "\n".join(f'    "{f}" => x,' for f in [f"--flag{i}" for i in range(25)])
SELFTEST_CLI += '\n    "--bind" => x,\n    "--trust" => x,\n'


def selftest() -> int:
    """The gate must catch a removed flag, must not cry wolf, and must not report a
    green over a document set that collapsed or exempted itself."""
    cases: list[tuple[str, str, bool] | tuple[str, str, bool, str]] = [
        (
            "a proxy block using a known flag passes",
            "```sh\nmcp_re_proxy_cli --bind 127.0.0.1:8600\n```\n",
            True,
        ),
        (
            "a proxy block using an unknown flag fails",
            "```sh\nmcp_re_proxy_cli --bind 127.0.0.1:8600 --gone-flag x\n```\n",
            False,
        ),
        (
            "prose naming a removed flag is not scanned",
            "The `--gone-flag` option was removed in v0.13.\n",
            True,
        ),
        (
            "a block that does not invoke the proxy is not scanned",
            "```sh\ngcloud container clusters create c --num-nodes 3 --gone-flag x\n```\n",
            True,
        ),
        (
            "launcher flags before the `--` separator are not the proxy's",
            "```sh\nbazel run //mcp-re-proxy:mcp_re_proxy_cli --features x -- --bind y\n```\n",
            True,
        ),
        (
            "an UNLISTED document cannot exempt itself with a Superseded banner",
            "> **⚠ Superseded serving model.**\n\n"
            "```sh\nmcp_re_proxy_cli --gone-flag x\n```\n",
            False,
        ),
        (
            "the crate name in a cargo command is not an invocation",
            "```sh\ncargo test -p mcp-re-proxy --gone-flag x\n```\n",
            True,
        ),
        (
            "repo-root markdown is scanned",
            "```sh\nmcp_re_proxy_cli --gone-flag x\n```\n",
            False,
            "README.md",
        ),
    ]
    failures = 0
    for case in cases:
        name, markdown, should_pass = case[0], case[1], case[2]
        where = case[3] if len(case) > 3 else "docs/case.md"
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / CLI_MODULE).parent.mkdir(parents=True)
            (repo / CLI_MODULE).write_text(SELFTEST_CLI, encoding="utf-8")
            (repo / "docs").mkdir()
            (repo / "deploy").mkdir()
            target = repo / where
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(markdown, encoding="utf-8")
            problems = check(repo, floors=False)
        passed = not problems
        if passed != should_pass:
            failures += 1
            print(f"SELFTEST FAIL: {name}: got {problems or 'no problems'}")
        else:
            print(f"selftest ok: {name}")

    # A LISTED document with the banner is skipped; the same document without the banner
    # is scanned again and its stale entry reported.
    listed = sorted(SUPERSEDED_DOCS)[0]
    for name, markdown, should_pass in (
        (
            "a listed document declaring itself superseded is skipped",
            "> **⚠ Superseded serving model.**\n\n"
            "```sh\nmcp_re_proxy_cli --gone-flag x\n```\n",
            True,
        ),
        (
            "a listed document that dropped its banner is reported, not skipped",
            "```sh\nmcp_re_proxy_cli --bind 127.0.0.1:8600\n```\n",
            False,
        ),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / CLI_MODULE).parent.mkdir(parents=True)
            (repo / CLI_MODULE).write_text(SELFTEST_CLI, encoding="utf-8")
            (repo / "docs").mkdir()
            (repo / "deploy").mkdir()
            target = repo / listed
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(markdown, encoding="utf-8")
            problems = check(repo, floors=False)
        passed = not problems
        if passed != should_pass:
            failures += 1
            print(f"SELFTEST FAIL: {name}: got {problems or 'no problems'}")
        else:
            print(f"selftest ok: {name}")

    # The floors: an empty corpus must not read as a pass.
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / CLI_MODULE).parent.mkdir(parents=True)
        (repo / CLI_MODULE).write_text(SELFTEST_CLI, encoding="utf-8")
        (repo / "docs").mkdir()
        (repo / "deploy").mkdir()
        problems = check(repo)
        if len(problems) != 2 or not any("collapsed" in p for p in problems):
            failures += 1
            print(f"SELFTEST FAIL: an empty document set was not refused: {problems}")
        else:
            print("selftest ok: an empty document set is refused, not reported green")

    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    skipped: list[str] = []
    problems = check(REPO, skipped)
    for rel in skipped:
        print(f"skipped (declares itself superseded): {rel}")
    if problems:
        print("proxy-flag documentation gate FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(
        f"proxy-flag documentation gate: every documented proxy flag exists "
        f"({len(doc_files(REPO))} documents scanned, {len(skipped)} skipped)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
