#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Doc-path gate — current text may not name a path the repository does not contain.

    python3 scripts/doc_path_gate.py             # the verdict
    python3 scripts/doc_path_gate.py --selftest  # prove the verdict can be FAIL
    python3 scripts/doc_path_gate.py --emit-registry > config/doc-path-debt.toml

A census of current documentation found 49 statements naming something that does not
exist at the revision that ships them. A dead path in a guide is instruction: the reader
does not learn that the sentence is stale, they learn that they cannot find the file.

WHAT THIS GATE REACHES, AND WHAT IT DOES NOT. Stating the boundary is part of the
control, because a gate that covers one class and is described as covering the category
is the same defect one level up.

  * It reaches 26 of the 31 `NONEXISTENT_TARGET` hits that census recorded. The five it
    misses are a crate name in a string with no `/` in it; a pair of `tests/tls_test.rs`
    citations, which suffix resolution below deliberately admits; a dependency justified
    by a consumer that does not exist; and a chart comment naming a private type.
  * It reaches NONE of the 14 `FALSE_PRESENT_TENSE` hits. Every one of those names
    something that EXISTS, and the defect is what is said about it. No path resolver
    reaches them; they are found by asking of a claim *what edit to production code would
    make this sentence false?*, which is review, not a gate.
  * A symbol resolver would reach twelve more and is not built here: the sweep run for
    that census produced roughly 60% noise before hand-triage, which is a review
    instrument, not a merge-path control.

TWO FAILURE CLASSES, and the second is the one a resolver alone would miss:

  DEAD        the token resolves to nothing, anywhere.
  GITIGNORED  the token resolves ONLY to a path outside the repository — a path that is
              on the author's disk and on no one else's. Fifteen citations of a
              `work/`-local design document in shipped `config_state` source are the
              worked example, and nothing but this rule finds them.

WHAT IS READ. Every file the repository would offer to commit, minus the exclusions
below. In a DOCUMENT every line is read; in a code file (`.rs`, `.py`, `.sh`, `.ts`) only
comment lines are, because a path written by a gate's own `--selftest` into a temporary
tree is supposed not to exist here.

RESOLUTION, in order: repo-relative; relative to the referencing file's directory; then
ANY path suffix in the tree. The third is what makes the gate usable — it lets
`transport/mod.rs` resolve from a comment that does not spell the full path — and it is
also what costs the gate its teeth on the `tests/tls_test.rs` class, where a citation of
one crate's test file resolves against another's. That is a deliberate trade.

REPOSITORY SCOPE is `git ls-files --cached --others --exclude-standard`: what `git status`
would offer to commit. Tracked-only would leave a newly written document unchecked until
it was committed, and the COMPLEMENT of this set is exactly what the GITIGNORED class is
about. `tools/verification/_controls.py` owns this repository's definition of "a file of
this repository" for the control census; this gate must not drift from it, and neither
re-implements `.gitignore` parsing.

RATCHET, not a cliff. `config/doc-path-debt.toml` carries the population this gate lands
over, in the three-state shape of `config/module-size-debt.toml`. A registered count must
EQUAL the measurement, so a registered file may not grow by one token and a file whose
tokens are repaired cannot keep describing debt that has been paid.
"""

from __future__ import annotations

import contextlib
import fnmatch
import io
import posixpath
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REGISTRY = REPO / "config" / "doc-path-debt.toml"

# Each names a category of DATED RECORD, for which a dead path is correct — an audit is
# not falsified by a later deletion — except `.claude/**`, which is vendored third-party
# skill text and not this project's claim surface. `CLAUDE.md` is deliberately absent:
# it is this repository's normative standards document, so it is the single file whose
# dead path would be most expensive, and excluding it to absorb one `e.g.` token would
# buy one registry row at the cost of the file's coverage forever.
SCOPE_EXCLUDE = (
    "docs/archive/**",
    "**/archive/**",
    "CHANGELOG*",
    "work/**",
    "docs/security/**",
    "verification/**",
    "tools/verification/**",
    "docs/adr/**",
    "docs/releases/**",
    "*.lock",
    "MODULE.bazel.lock",
    ".claude/**",
)

# At least one `/`, and a known source extension. Anything without a `/`, and anything
# with an unknown extension, is not a token — that is what keeps prose out. The trailing
# lookahead is what makes the extension the END of the name rather than a substring of
# it: without it `scripts/test-aws-cloud.sh.example` yields a token for a `.sh` file that
# was never named, and the gate reports a dead path nobody wrote. A sentence-final `.`
# still ends a token, because the lookahead only refuses a dot that a name continues
# past.
TOKEN = re.compile(
    r"(?<![\w/.@-])((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"\.(?:rs|py|sh|toml|yaml|yml|json|md|bazel|ts|tsx))(?!\.?[A-Za-z0-9_-])"
)

FENCE = re.compile(r"^\s*(?:```|~~~)\s*([A-Za-z0-9_+-]*)")
HEADING = re.compile(r"^#{1,6}\s")
SHA_ANCHOR = re.compile(r"@\s*`[0-9a-f]{7,40}`")
STRIKE = re.compile(r"~~(.+?)~~")

# A path in EXECUTABLE code is not a claim about this repository's contents: a gate's
# `--selftest` writes a synthetic crate into a temporary tree, and those paths are
# SUPPOSED not to exist here. What a source file states about this repository it states in its
# comments — the crate header, the `//!` module doc, the `# why this pin exists` above a
# dependency — so in a code file this gate reads comment lines and nothing else. A Python
# or Rust doc STRING is therefore unread; the cost is stated here rather than discovered.
CODE_SUFFIXES = (".rs", ".py", ".sh", ".ts", ".tsx")
COMMENT = re.compile(r"^\s*(?://|#|\*|/\*)")

MAX_BYTES = 2_000_000


def repository_files(root: Path) -> set[str]:
    """Tracked plus untracked-not-ignored: what `git status` would offer to commit."""
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {p for p in out.split("\0") if p}


def in_scope(path: str) -> bool:
    return not any(fnmatch.fnmatch(path, pat) for pat in SCOPE_EXCLUDE)


def _exempt_lines(lines: list[str]) -> set[int]:
    """Line indices under a carve-out: a `text` fence in a SHA-anchored section.

    A block quoted from a named revision is a record of that revision, so its paths are
    resolved against it and not against this one. The anchor is what distinguishes a
    quotation from a claim; a fence alone is not enough.
    """
    anchored: list[bool] = []
    current = False
    section: list[int] = []
    for idx, line in enumerate(lines):
        if HEADING.match(line):
            for i in section:
                anchored[i] = current
            section, current = [], False
        if SHA_ANCHOR.search(line):
            current = True
        anchored.append(False)
        section.append(idx)
    for i in section:
        anchored[i] = current

    exempt: set[int] = set()
    fence_lang: str | None = None
    for idx, line in enumerate(lines):
        m = FENCE.match(line)
        if m:
            fence_lang = None if fence_lang is not None else (m.group(1) or "")
            continue
        if fence_lang == "text" and anchored[idx]:
            exempt.add(idx)
    return exempt


def _fence_langs(lines: list[str]) -> list[str | None]:
    langs: list[str | None] = []
    current: str | None = None
    for line in lines:
        m = FENCE.match(line)
        if m:
            current = None if current is not None else (m.group(1) or "")
            langs.append(None)
            continue
        langs.append(current)
    return langs


def _mechanically_excluded(line: str, start: int, token: str, lang: str | None) -> bool:
    """The five rules that remove a token no judgement is needed on."""
    before = line[start - 1] if start else ""
    if before in ("$", "{", "@"):
        return True
    if token.startswith("HERE/"):
        return True
    if token.startswith("./") and lang == "sh":
        return True
    return token.startswith(("target/", ".verification/", "dist/", "./dist/"))


def _candidates(token: str, source: str) -> list[str]:
    """Repo-relative, then relative to the referencing file's directory.

    Normalised textually rather than through the filesystem: `..` must be resolved
    against the repository root, and `Path.resolve()` answers about the machine the
    gate happens to run on.
    """
    parent = posixpath.dirname(source)
    forms = [posixpath.normpath(token)]
    if parent:
        forms.append(posixpath.normpath(posixpath.join(parent, token)))
    return [f for f in forms if not f.startswith("..")]


def _resolves(token: str, source: str, repo_files: set[str]) -> bool:
    forms = _candidates(token, source)
    if any(f in repo_files for f in forms):
        return True
    suffix = "/" + posixpath.normpath(token)
    return any(f.endswith(suffix) for f in repo_files)


def _on_disk(token: str, root: Path, source: str) -> bool:
    return any((root / f).exists() for f in _candidates(token, source))


def scan_file(
    source: str, text: str, root: Path, repo_files: set[str]
) -> list[tuple[int, str, str]]:
    """Return `(lineno, token, class)` for every token that does not resolve."""
    lines = text.splitlines()
    exempt = _exempt_lines(lines)
    langs = _fence_langs(lines)
    comments_only = source.endswith(CODE_SUFFIXES)
    findings: list[tuple[int, str, str]] = []
    for idx, line in enumerate(lines):
        if idx in exempt:
            continue
        if comments_only and not COMMENT.match(line):
            continue
        struck = {m.group(1) for m in STRIKE.finditer(line)}
        for match in TOKEN.finditer(line):
            token = match.group(1)
            if any(token in s for s in struck):
                continue
            if _mechanically_excluded(line, match.start(1), token, langs[idx]):
                continue
            if _resolves(token, source, repo_files):
                continue
            kind = "GITIGNORED" if _on_disk(token, root, source) else "DEAD"
            findings.append((idx + 1, token, kind))
    return findings


def measure(root: Path, repo_files: set[str] | None = None) -> dict[str, list[str]]:
    """Every in-scope file's unresolved tokens, as `line: token — class` strings."""
    files = repository_files(root) if repo_files is None else repo_files
    result: dict[str, list[str]] = {}
    for rel in sorted(files):
        if not in_scope(rel):
            continue
        path = root / rel
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        hits = scan_file(rel, text, root, files)
        if hits:
            result[rel] = [f"{n}: {tok} — {kind}" for n, tok, kind in hits]
    return result


def scanned_count(root: Path, repo_files: set[str] | None = None) -> int:
    files = repository_files(root) if repo_files is None else repo_files
    return sum(1 for rel in files if in_scope(rel) and (root / rel).is_file())


def load_registry(path: Path) -> tuple[dict[str, dict], list[str]]:
    if not path.exists():
        return {}, [f"{path} does not exist"]
    data = tomllib.loads(path.read_text())
    rows: dict[str, dict] = {}
    errors: list[str] = []
    for row in data.get("debt", []):
        rel = row.get("path", "")
        status = row.get("status", "")
        if status not in ("unreviewed", "reviewed-action-required", "reviewed-exception"):
            errors.append(f"{rel}: unknown status {status!r}")
        if status.startswith("reviewed"):
            ref = row.get("review_ref", "")
            if not ref:
                errors.append(f"{rel}: {status} without a review_ref")
            else:
                record, named = ref.split()[0], ref.split()[-1]
                doc = REPO / named
                if not doc.exists():
                    errors.append(f"{rel}: review_ref names {named}, which does not exist")
                elif record not in doc.read_text():
                    errors.append(
                        f"{rel}: review_ref names {record}, which {named} does not contain"
                    )
        elif "review_ref" in row:
            errors.append(f"{rel}: unreviewed rows carry no review_ref")
        rows[rel] = row
    return rows, errors


def emit_registry(measured: dict[str, list[str]]) -> str:
    head = (REGISTRY.read_text().split("[[debt]]")[0] if REGISTRY.exists() else "")
    body = []
    for rel, hits in sorted(measured.items()):
        body.append(
            "[[debt]]\n"
            f'path = "{rel}"\n'
            f"dead_tokens = {len(hits)}\n"
            'status = "unreviewed"\n'
        )
    return head + "\n".join(body)


def verdict(root: Path, registry: Path = REGISTRY) -> int:
    measured = measure(root)
    rows, errors = load_registry(registry)
    for rel, hits in sorted(measured.items()):
        row = rows.get(rel)
        if row is None:
            errors.append(f"{rel}: {len(hits)} unresolved token(s), and no registry entry")
            errors += [f"    {h}" for h in hits]
            continue
        baseline = row.get("dead_tokens", 0)
        if len(hits) > baseline:
            errors.append(
                f"{rel}: {len(hits)} unresolved token(s), registered at {baseline} — "
                f"a registry entry pins a file, it does not exempt one"
            )
            errors += [f"    {h}" for h in hits]
        elif len(hits) < baseline:
            errors.append(
                f"{rel}: {len(hits)} unresolved token(s), registered at {baseline} — "
                f"lower the entry to {len(hits)}"
            )
    for rel in sorted(rows):
        if rel not in measured:
            errors.append(f"{rel}: registered, but resolves cleanly — remove the entry")
    scanned = scanned_count(root)
    if errors:
        print(f"doc-path gate: FAIL ({scanned} in-scope files read)")
        for e in errors:
            print(f"  {e}")
        return 1
    print(
        f"doc-path gate: PASS ({scanned} in-scope files read, "
        f"{sum(len(v) for v in measured.values())} registered token(s), none new)"
    )
    return 0


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _fixture(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "selftest@example.invalid")
    _git(root, "config", "user.name", "selftest")
    (root / "docs").mkdir()
    (root / "src").mkdir()
    (root / "work").mkdir()
    (root / ".gitignore").write_text("/work/\n")
    (root / "src" / "real.rs").write_text("// nothing\n")
    (root / "work" / "ATLAS.md").write_text("# local only\n")
    _git(root, "add", "-A")


def _quiet_verdict(root: Path, registry: Path) -> int:
    """`verdict`'s own verdict line, swallowed.

    A self-test states ONE verdict. Letting the runs it drives print theirs would hand
    `scripts/run_gate.sh` several verdict lines for one invocation, and a wrapper that
    cannot tell which line is the answer is the failure class it exists to remove.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return verdict(root, registry)


def selftest() -> int:
    """Three cases, each asserted in BOTH directions.

    One direction is not a probe: a gate that always fails passes the failing half, and a
    gate that never fires passes the passing half.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        _fixture(root)
        guide = root / "docs" / "guide.md"

        # 1. A dead token. The gate must name it.
        guide.write_text("See `src/definitely_not_a_real_module.rs` for the details.\n")
        found = measure(root)
        if "docs/guide.md" not in found or "definitely_not_a_real_module.rs" not in str(found):
            print(f"SELFTEST FAILED: a dead token was not caught, got {found}")
            return 1
        guide.write_text("See `src/real.rs` for the details.\n")
        if measure(root):
            print("SELFTEST FAILED: a resolving token was reported")
            return 1

        # 2. The ratchet, through `verdict` and a registry — an entry PINS a file, it
        # does not exempt one. Asserted in both directions over the same registry.
        registry = root / "debt.toml"
        registry.write_text(
            'schema_version = 1\n\n[[debt]]\npath = "docs/guide.md"\n'
            'dead_tokens = 1\nstatus = "unreviewed"\n'
        )
        guide.write_text("`src/gone_a.rs`\n")
        if _quiet_verdict(root, registry) != 0:
            print("SELFTEST FAILED: a file at its registered count did not pass")
            return 1
        guide.write_text("`src/gone_a.rs` and `src/gone_b.rs`\n")
        if _quiet_verdict(root, registry) == 0:
            print("SELFTEST FAILED: a registered file grew a second token and passed")
            return 1
        guide.write_text("`src/real.rs`\n")
        if _quiet_verdict(root, registry) == 0:
            print("SELFTEST FAILED: a registry entry describing paid debt passed")
            return 1

        # 3. The gitignored token — the rule the whole class exists for. Without the
        # passing half this is indistinguishable from a substring ban on `work/`.
        guide.write_text("See `work/ATLAS.md`.\n")
        found = measure(root)
        hits = found.get("docs/guide.md", [])
        if len(hits) != 1 or "GITIGNORED" not in hits[0]:
            print(f"SELFTEST FAILED: a gitignored-only token was not caught, got {found}")
            return 1
        _git(root, "add", "-f", "work/ATLAS.md")
        if measure(root):
            print("SELFTEST FAILED: the same token failed once the path was tracked")
            return 1

    print("doc-path gate selftest: PASS")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--emit-registry" in sys.argv:
        print(emit_registry(measure(REPO)), end="")
        return 0
    return verdict(REPO)


if __name__ == "__main__":
    raise SystemExit(main())
