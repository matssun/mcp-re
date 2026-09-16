#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Module-size ratchet — a production Rust file may not cross 200 lines, and an
already-oversized one may not grow.

ADR-MCPRE-061 §5.1 sets the threshold and §6.3 specifies this gate. It exists because
**clippy has no file-length lint at all** — `clippy::module_lines` was probed against
clippy 0.1.97 and does not exist under that or any other name, so the one architectural
threshold the project states about files had no mechanical form. A rule enforced only by
an author's judgement is a rule whose enforcement cost is paid per file, by the least
reliable available party.

This is a **ratchet, not a cliff**. The debt registry (`config/module-size-debt.toml`)
records what was already oversized at a baseline SHA. From that point:

    new file over the threshold          -> FAIL
    registered file grows                -> FAIL
    registered file shrinks              -> PASS (and the entry is updated)
    registered file reaches <= threshold -> FAIL until the entry is removed
    reviewed large unit                  -> entry carries an ADR-061 §14 `review_ref`

The last two are what stop the registry rotting into a permanent allowlist: an entry that
no longer describes reality is an error, not a shrug.

# A raised baseline is a ONE-SHOT event, and it does not authorize itself

"A registered file grows -> FAIL" was enforced against `baseline_prod_loc` and nothing
enforced anything against `baseline_prod_loc`. Raising the number in the same commit as
the growth turned the whole ratchet off for that file, silently, with no reviewer seeing
anything but a larger integer in a TOML table. **A control whose input the controlled
party may edit is not a control** — it is the same defect class as a threshold
parameterising a lint nobody switched on.

So an upward baseline transition, judged against `origin/main`, is its own event with its
own authorization. It requires ALL of:

    new_baseline > old_baseline               the trigger: an upward transition
    actual production LOC == new_baseline     no headroom; exactly the growth that happened
    status == "reviewed-exception"            only a unit a §14 census kept INTACT may grow
    growth_from_prod_loc == old_baseline      the authorization names the transition it is for
    growth_ref names a §14 record that
      contains the exact literal line
      `growth-authorization: <path> <old> -> <new>`

The fourth and fifth conditions are what make it one-shot. An authorization is written for
one exact pair of integers; once merged, `old_baseline` on `origin/main` has moved to the
new value, so the spent authorization matches no future transition and a further increase
needs a fresh §14 record naming the new pair. **A previous authorization never authorizes
a later increase**, and the new ceiling is not general permission for the file to grow.

`actual == new_baseline` is the anti-headroom condition: without it, "442 -> 600" would
buy 146 lines of unexamined future growth from one review.

# Investigation status and disposition are separate facts

An entry's `status` says what is KNOWN about a unit, and there are three states because
there are three facts to tell apart:

    unreviewed                 nobody has investigated it
    reviewed-action-required   investigated; specific architectural work identified
    reviewed-exception         investigated, and deliberately kept intact

A completed census whose disposition is "decompose first" is still a completed census. If
it were recorded as `unreviewed`, the next reader would be told nobody had looked, and
would repeat the work — so `PERMITTED_TRANSITIONS` refuses every move back toward
`unreviewed`, checked against `origin/main` on every run.

# Measuring production lines

`prod` is every line NOT inside a test region. A test region opens at an attribute matching
`^#\\[cfg\\((all\\()?test` and closes at the end of the module that attribute introduces,
tracked by brace depth; a file may contain several, and counting resumes after each one.

Two details are load-bearing because each is a count this project got wrong:

- **The wide attribute pattern**, not `^#[cfg(test)]`. A census pass matching only the
  narrow form reported `mcp-re-proxy/src/app.rs` as 1680 production lines with no tests at
  all, because its module is `#[cfg(all(test, unix))]`. Its real production half is 1037.
- **Counting RESUMES after a region closes.** "Lines before the first test module" is a
  different and wrong rule: it discards every production item below the tests. Under it
  `mcp-re-proxy/src/trust_plane.rs` measures 134 lines; it is 690.
- **A region closes with the item the attribute introduces, brace-delimited or not.** Not
  every `#[cfg(test)]` introduces a module: it is also written on a `const`, a `use` or a
  type alias, which ends at `;` and opens no braces at all. Scanning on until the first
  brace closes then swallowed the NEXT item — production code — into the test region. Four
  files were undercounted this way, `mcp-re-proxy/src/trust_plane/mod.rs` by 23 lines and
  `mcp-re-proxy/src/signing_plane/mod.rs` by 17, and both were REGISTERED, so the ratchet
  was holding a ceiling below the real size and the difference was free headroom. It is
  also a bypass anyone could reach for: a `#[cfg(test)] const` placed above an item hides
  that item from the count.

A counter that silently undercounts is worse than no counter, so both details are exercised
by `--selftest`, and the rule is PRINTED on every run so prose describing it cannot drift
from it unnoticed.

# The two blindness failures this gate refuses to repeat

- **An empty scope is a failure, not an OK.** A `tests/` glob silently exempted an entire
  crate from `scripts/bazel_srcs_gate.py` for a whole campaign while it printed OK.
- **The measurement rule is printed.** A threshold whose measurement is unstated is the
  "green that measured nothing" failure applied to the gate itself.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "config" / "module-size-debt.toml"
THRESHOLD = 200

# ADR-MCPRE-061 §5.1. Both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open a test region.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")

# Directories that are not this repository's production Rust.
SKIP_DIRS = {"target", "node_modules", ".git", "bazel-out", "vendor"}

#: ADR-MCPRE-061 §14 dispositions. Investigation status and disposition are separate facts:
#: a completed census must stay distinguishable from an unperformed one EVEN WHEN its
#: disposition is "decompose before any exception". Collapsing `reviewed-action-required`
#: into `unreviewed` would tell the next agent that nobody has looked.
STATUSES = {"unreviewed", "reviewed-exception", "reviewed-action-required"}

#: Both reviewed dispositions must name the record that adjudicated them. The field is
#: `review_ref`, not `exception_ref`: EX-002 is a completed census that DECLINED an
#: exception, so the reference is to an adjudication, not to a grant.
REVIEWED = {"reviewed-exception", "reviewed-action-required"}

#: The two halves of a ONE-SHOT upward-baseline authorization. They are a pair: a
#: `growth_from_prod_loc` with no record is an unevidenced claim, and a `growth_ref` with no
#: transition does not say WHICH increase was authorized.
GROWTH_FIELDS = {"growth_from_prod_loc", "growth_ref"}

#: Anything else in a `[[debt]]` table is a typo or a stale field name, and both fail.
ENTRY_FIELDS = {
    "path",
    "baseline_prod_loc",
    "baseline_sha",
    "status",
    "review_ref",
} | GROWTH_FIELDS

#: The permitted disposition transitions, as ADR-MCPRE-061 §14 defines the lifecycle.
#: Every one of them either preserves or increases what is known about a unit; none
#: returns it to "nobody has investigated this".
PERMITTED_TRANSITIONS = {
    ("unreviewed", "unreviewed"),
    ("unreviewed", "reviewed-exception"),
    ("unreviewed", "reviewed-action-required"),
    ("reviewed-action-required", "reviewed-action-required"),
    ("reviewed-action-required", "reviewed-exception"),
    ("reviewed-exception", "reviewed-exception"),
    # A re-census of a granted exception may find new work. Refusing this would force the
    # registry to assert that no work exists, which is the defect the lifecycle exists to
    # prevent — so it is permitted, unlike any move back toward `unreviewed`.
    ("reviewed-exception", "reviewed-action-required"),
}


class _BraceScan:
    """A brace-counting scan over a sequence of Rust lines, with state carried ACROSS them.

    A per-line, literal-blind count was this gate's measurement defect and it is the same
    class as the truncation §5.1 describes: braces inside a string, a character literal or a
    comment were counted as code. A raw byte string holding JSON —
    ``br#"{"error":{"data":{...}}}"#``, which `execution_contract.rs` writes over five lines
    inside a test module — closed the region three lines early, so test code below it was
    counted as PRODUCTION and the file measured larger than it is.

    Mirrors `mcp-re-test-paths/src/rust_source.rs`, which is the same definition on the Rust
    side. The two must not drift: they decide the same fact for different gates.
    """

    CODE, STR, RAW, BLOCK = 0, 1, 2, 3

    def __init__(self) -> None:
        self.mode = self.CODE
        self.hashes = 0
        self.depth = 0

    def feed(self, line: str) -> str:
        """`line` with literals and comments blanked, continuing what `line` began inside."""
        out: list[str] = []
        i = 0
        n = len(line)
        while i < n:
            if self.mode == self.CODE:
                i = self._code(line, i, n, out)
            elif self.mode == self.STR:
                i = self._str(line, i)
            elif self.mode == self.RAW:
                i = self._raw(line, i, n)
            else:
                i = self._block(line, i)
        return "".join(out)

    def _code(self, line: str, i: int, n: int, out: list[str]) -> int:
        two = line[i : i + 2]
        if two == "//":
            return n
        if two == "/*":
            self.mode, self.depth = self.BLOCK, 1
            return i + 2
        opened = self._open_raw(line, i)
        if opened is not None:
            return opened
        c = line[i]
        if c == '"':
            self.mode = self.STR
            return i + 1
        if c == "'":
            return self._char_literal(line, i, out)
        out.append(c)
        return i + 1

    def _open_raw(self, line: str, i: int) -> int | None:
        """Enter a raw string if one opens at `i`, else None.

        The prefix must not be the tail of an identifier: `for` and `char` end in the
        letters an opener starts with.
        """
        if i > 0 and (line[i - 1].isalnum() or line[i - 1] == "_"):
            return None
        j = i
        if line[j : j + 1] == "b":
            j += 1
        if line[j : j + 1] != "r":
            return None
        j += 1
        start = j
        while line[j : j + 1] == "#":
            j += 1
        if line[j : j + 1] != '"':
            return None
        self.mode, self.hashes = self.RAW, j - start
        return j + 1

    def _str(self, line: str, i: int) -> int:
        c = line[i]
        if c == "\\":
            return i + 2
        if c == '"':
            self.mode = self.CODE
        return i + 1

    def _raw(self, line: str, i: int, n: int) -> int:
        if line[i] != '"':
            return i + 1
        if line[i + 1 : i + 1 + self.hashes] != "#" * self.hashes:
            return i + 1
        self.mode = self.CODE
        return i + 1 + self.hashes

    def _block(self, line: str, i: int) -> int:
        two = line[i : i + 2]
        if two == "/*":
            self.depth += 1
            return i + 2
        if two == "*/":
            self.depth -= 1
            if self.depth <= 0:
                self.mode = self.CODE
            return i + 2
        return i + 1

    @staticmethod
    def _char_literal(line: str, i: int, out: list[str]) -> int:
        """Skip `'x'` / `'\\n'`, or emit the tick of a lifetime and move on."""
        if line[i + 1 : i + 2] == "\\":
            j = i + 3
            while j < len(line) and line[j] != "'":
                j += 1
            return j + 1
        if line[i + 2 : i + 3] == "'":
            return i + 3
        out.append("'")
        return i + 1


def production_source(text: str) -> list[str]:
    """The lines of a Rust source that are NOT inside a test region.

    The definition `production_lines` counts and `scripts/unit_closure_gate.py` reads items
    from. Both need the same answer to "which lines are production", and a second scan
    would be a second opinion about where a test region ends.
    """
    lines = text.splitlines()
    kept: list[str] = []
    i = 0
    while i < len(lines):
        if TEST_ATTR.match(lines[i].lstrip()):
            scan = _BraceScan()
            depth = 0
            opened = False
            while i < len(lines):
                code = scan.feed(lines[i])
                depth += code.count("{") - code.count("}")
                if "{" in code:
                    opened = True
                i += 1
                if opened and depth <= 0:
                    break
                # An item with no brace-delimited body — a `const`, a `use`, a type alias —
                # ends at its own `;`. Scanning past it swallows the NEXT item, which is
                # production code, into the test region.
                if not opened and depth <= 0 and ";" in code:
                    break
            continue
        kept.append(lines[i])
        i += 1
    return kept


def production_lines(text: str) -> int:
    """Every line of a Rust source that is NOT inside a test region.

    A test region runs from its `#[cfg(test)]`-family attribute to the end of the module it
    introduces, tracked by brace depth over CODE characters only — a brace inside a string,
    a raw string, a character literal or a comment is not a brace. Counting resumes
    afterwards, and a file may contain several regions: a file that puts a helper module
    below its tests is not thereby exempt.

    This is deliberately NOT "lines before the first test module" — that rule discards every
    production item below the tests, and measured `trust_plane.rs` at 134 lines when it is
    690. This function is the definition; the prose in ADR-MCPRE-061 §5.1 describes it.
    """
    return len(production_source(text))


def rust_sources(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*.rs")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        # Tests, benches, examples and build scripts are not production modules.
        if any(part in {"tests", "benches", "examples"} for part in rel.parts):
            continue
        if p.name == "build.rs":
            continue
        out.append(p)
    return out


def load_registry(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text())
    entries = {}
    for entry in data.get("debt", []):
        entries[entry["path"]] = entry
    return entries


def check(
    root: Path, registry: dict[str, dict], out_measured: dict[str, int] | None = None
) -> tuple[list[str], int]:
    """Return (problems, files_examined), filling `out_measured` with path -> production LOC.

    `check_baseline_growth` needs the same measurement to decide whether a raised baseline
    matches the file it describes. It is handed out rather than measured again: two passes
    over the tree are two chances for the two numbers to differ.
    """
    problems: list[str] = []
    sources = rust_sources(root)
    measured: dict[str, int] = out_measured if out_measured is not None else {}

    for p in sources:
        rel = str(p.relative_to(root))
        prod = production_lines(p.read_text(encoding="utf-8", errors="replace"))
        measured[rel] = prod
        entry = registry.get(rel)

        if prod <= THRESHOLD:
            if entry is not None:
                problems.append(
                    f"{rel}: now {prod} production lines (<= {THRESHOLD}) but still in the "
                    f"debt registry — remove the entry, the debt is paid"
                )
            continue

        if entry is None:
            problems.append(
                f"{rel}: {prod} production lines exceeds {THRESHOLD} and is not in the debt "
                f"registry — decompose it, or record an ADR-MCPRE-061 §14 exception"
            )
            continue

        baseline = int(entry["baseline_prod_loc"])
        if prod > baseline:
            problems.append(
                f"{rel}: grew from {baseline} to {prod} production lines — the ratchet only "
                f"turns one way"
            )

    for rel in registry:
        if rel not in measured:
            problems.append(
                f"{rel}: in the debt registry but not found — a stale entry hides a moved "
                f"or deleted file"
            )

    return problems, len(sources)


def referenced_documents(review_ref: str) -> list[str]:
    """The repo-relative document paths a `review_ref` names.

    Free text with a path in it, so a record can be cited as "EX-001 in
    docs/architecture/review-dispositions.md" rather than as a bare filename that says nothing
    about which record.
    """
    return re.findall(r"\S+\.md", review_ref)


def permitted_transition(old: str, new: str) -> bool:
    """Whether a disposition may move from `old` to `new` (ADR-MCPRE-061 §14).

    Total, so the selftest can assert the relation rather than re-implement it. An
    unknown status is not a transition question — `validate_registry` rejects it first.
    """
    return (old, new) in PERMITTED_TRANSITIONS


def validate_registry(registry: dict[str, dict], root: Path | None = None) -> list[str]:
    problems = []
    for rel, entry in registry.items():
        for field in ("path", "baseline_prod_loc", "baseline_sha", "status"):
            if field not in entry:
                problems.append(f"{rel}: debt entry is missing `{field}`")
        status = entry.get("status")
        if status is not None and status not in STATUSES:
            problems.append(
                f"{rel}: status `{status}` is not one of {sorted(STATUSES)}"
            )
        if status in REVIEWED and not entry.get("review_ref"):
            problems.append(
                f"{rel}: status is `{status}` but no `review_ref` names the "
                f"ADR-MCPRE-061 §14 record that adjudicated it"
            )
        unknown = sorted(set(entry) - ENTRY_FIELDS)
        if unknown:
            problems.append(
                f"{rel}: unknown debt field(s) {unknown} — `exception_ref` was renamed to "
                f"`review_ref` because a §14 record may also DECLINE an exception"
            )
        # A reference to a record that is not there is the same defect as a stale entry:
        # the registry claims the review exists and nothing can be read to check it. The
        # point of `reviewed-exception` is that it points at evidence.
        ref = entry.get("review_ref")
        if ref and root is not None:
            named = referenced_documents(ref)
            if not named:
                problems.append(
                    f"{rel}: `review_ref` names no document — cite the record's file so "
                    f"the claim can be read"
                )
            for doc in named:
                if not (root / doc).exists():
                    problems.append(
                        f"{rel}: `review_ref` names {doc}, which does not exist — a "
                        f"completed review must point at a record, not at a memory of one"
                    )
    return problems


# --------------------------------------------------------------------------------------
# selftest


def selftest() -> int:
    cases: list[tuple[str, str, int]] = [
        ("no test module", "fn a() {}\nfn b() {}\n", 2),
        (
            "narrow #[cfg(test)]",
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n",
            1,
        ),
        (
            "#[cfg(all(test, unix))] — the form that broke the first census",
            "fn a() {}\nfn b() {}\n#[cfg(all(test, unix))]\nmod tests {\n    fn t() {}\n}\n",
            2,
        ),
        (
            "production code AFTER the test region is counted",
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn b() {}\nfn c() {}\n",
            3,
        ),
        (
            "nested braces inside the test module do not end it early",
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { if x { y(); } }\n    fn u() {}\n}\n",
            1,
        ),
        (
            "two test regions",
            "fn a() {}\n#[cfg(test)]\nmod t1 {\n}\nfn b() {}\n#[cfg(all(test, feature = \"x\"))]\nmod t2 {\n}\nfn c() {}\n",
            3,
        ),
        (
            "#[cfg(test)] on a const closes at its `;` — the item BELOW it is production",
            '#[cfg(test)]\nconst K: &str = "k";\nimpl Drop for T {\n    fn drop(&mut self) {}\n}\n',
            3,
        ),
        (
            "#[cfg(test)] on a `use` closes at its `;`",
            "#[cfg(test)]\nuse std::x::Y;\nfn a() {}\nfn b() {}\n",
            2,
        ),
        (
            "a multi-line #[cfg(test)] const still closes at its own `;`",
            '#[cfg(test)]\nconst K: &[&str] = &[\n    "a",\n];\nfn a() {}\n',
            1,
        ),
        (
            "an attribute followed by a comment still reaches the item it introduces",
            "#[cfg(test)]\n// a note\nmod tests {\n    fn t() {}\n}\nfn a() {}\n",
            1,
        ),
        ("empty file", "", 0),
    ]
    for name, text, expected in cases:
        got = production_lines(text)
        if got != expected:
            print(f"selftest FAIL: {name}: expected {expected} production lines, got {got}")
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # An empty scope must FAIL, never print OK.
        problems, examined = check(root, {})
        if examined != 0:
            print("selftest FAIL: empty tree reported files")
            return 1
        # main() turns examined == 0 into a failure; check that contract here.
        if not empty_scope_is_failure(examined):
            print("selftest FAIL: an empty scope was not treated as a failure")
            return 1

        crate = root / "mcp-re-probe" / "src"
        crate.mkdir(parents=True)
        big = crate / "big.rs"
        big.write_text("\n".join(f"fn f{i}() {{}}" for i in range(THRESHOLD + 5)) + "\n")
        small = crate / "small.rs"
        small.write_text("fn s() {}\n")

        rel_big = "mcp-re-probe/src/big.rs"

        # Unregistered oversized file fails.
        problems, examined = check(root, {})
        if not any("not in the debt registry" in p for p in problems):
            print(f"selftest FAIL: unregistered oversized file passed: {problems}")
            return 1
        if examined != 2:
            print(f"selftest FAIL: expected 2 files examined, got {examined}")
            return 1

        baseline = production_lines(big.read_text())
        reg = {
            rel_big: {
                "path": rel_big,
                "baseline_prod_loc": baseline,
                "baseline_sha": "0" * 7,
                "status": "unreviewed",
            }
        }

        # At baseline: passes.
        problems, _ = check(root, reg)
        if problems:
            print(f"selftest FAIL: file at its baseline reported problems: {problems}")
            return 1

        # Growth fails.
        big.write_text(big.read_text() + "fn extra() {}\n")
        problems, _ = check(root, reg)
        if not any("the ratchet only turns one way" in p for p in problems):
            print(f"selftest FAIL: growth was not caught: {problems}")
            return 1

        # Shrinking (but still oversized) passes.
        big.write_text("\n".join(f"fn f{i}() {{}}" for i in range(THRESHOLD + 2)) + "\n")
        problems, _ = check(root, reg)
        if problems:
            print(f"selftest FAIL: a shrinking file reported problems: {problems}")
            return 1

        # Dropping to the threshold requires removing the entry.
        big.write_text("fn tiny() {}\n")
        problems, _ = check(root, reg)
        if not any("the debt is paid" in p for p in problems):
            print(f"selftest FAIL: paid debt did not require entry removal: {problems}")
            return 1
        problems, _ = check(root, {})
        if problems:
            print(f"selftest FAIL: paid debt with entry removed still failed: {problems}")
            return 1

        # A stale entry naming a file that no longer exists fails.
        problems, _ = check(root, {"gone/nowhere.rs": {"path": "gone/nowhere.rs",
                                                       "baseline_prod_loc": 999,
                                                       "baseline_sha": "0" * 7,
                                                       "status": "unreviewed"}})
        if not any("stale entry" in p for p in problems):
            print(f"selftest FAIL: stale registry entry passed: {problems}")
            return 1

        # `unreviewed` -> `reviewed-exception` is the ADR-MCPRE-061 §14 transition, and it
        # changes what the entry CLAIMS, never what the ratchet ALLOWS.
        record = root / "record.md"
        record.write_text("# a §14 record\n")
        big.write_text("\n".join(f"fn f{i}() {{}}" for i in range(THRESHOLD + 2)) + "\n")
        reviewed = {rel_big: {"path": rel_big,
                              "baseline_prod_loc": THRESHOLD + 2,
                              "baseline_sha": "0" * 7,
                              "status": "reviewed-exception",
                              "review_ref": "EX-000 in record.md"}}
        if validate_registry(reviewed, root):
            print("selftest FAIL: a reviewed exception citing a real record was rejected")
            return 1
        problems, _ = check(root, reviewed)
        if problems:
            print(f"selftest FAIL: a reviewed exception at its baseline failed: {problems}")
            return 1

        # An exception is not a licence to grow.
        big.write_text(big.read_text() + "fn extra() {}\n")
        problems, _ = check(root, reviewed)
        if not any("the ratchet only turns one way" in p for p in problems):
            print(f"selftest FAIL: a reviewed exception was allowed to grow: {problems}")
            return 1

        # A completed census whose disposition is "decompose first" is still a completed
        # census, and the registry has a state for it.
        big.write_text("\n".join(f"fn f{i}() {{}}" for i in range(THRESHOLD + 2)) + "\n")
        action = {rel_big: dict(reviewed[rel_big], status="reviewed-action-required")}
        if validate_registry(action, root):
            print("selftest FAIL: a reviewed-action-required entry with a record was rejected")
            return 1
        problems, _ = check(root, action)
        if problems:
            print(f"selftest FAIL: reviewed-action-required at its baseline failed: {problems}")
            return 1

        # ...and it is not a licence to grow either.
        big.write_text(big.read_text() + "fn more() {}\n")
        problems, _ = check(root, action)
        if not any("the ratchet only turns one way" in p for p in problems):
            print(f"selftest FAIL: reviewed-action-required was allowed to grow: {problems}")
            return 1

        # A record that is not there is the same defect as a stale entry.
        record.unlink()
        if not any("does not exist" in p for p in validate_registry(reviewed, root)):
            print("selftest FAIL: a review_ref naming a missing record was accepted")
            return 1

    # Registry schema validation.
    for reviewed_status in sorted(REVIEWED):
        bad = {"a.rs": {"path": "a.rs", "baseline_prod_loc": 1, "baseline_sha": "x",
                        "status": reviewed_status}}
        if not any("review_ref" in p for p in validate_registry(bad)):
            print(f"selftest FAIL: {reviewed_status} without a reference was accepted")
            return 1

    # The renamed field does not linger: a stale `exception_ref` is an unknown field.
    stale = {"a.rs": {"path": "a.rs", "baseline_prod_loc": 1, "baseline_sha": "x",
                      "status": "unreviewed", "exception_ref": "EX-000 in record.md"}}
    if not any("unknown debt field" in p for p in validate_registry(stale)):
        print("selftest FAIL: the pre-rename `exception_ref` field was accepted")
        return 1

    # The §14 disposition lifecycle, asserted as a relation rather than restated.
    permitted = [
        ("unreviewed", "reviewed-exception"),
        ("unreviewed", "reviewed-action-required"),
        ("reviewed-action-required", "reviewed-action-required"),
        ("reviewed-action-required", "reviewed-exception"),
        ("reviewed-exception", "reviewed-action-required"),
    ]
    # Nothing returns to `unreviewed`: that would say nobody had looked.
    refused = [
        ("reviewed-exception", "unreviewed"),
        ("reviewed-action-required", "unreviewed"),
    ]
    for old_s, new_s in permitted:
        if not permitted_transition(old_s, new_s):
            print(f"selftest FAIL: `{old_s}` -> `{new_s}` should be permitted")
            return 1
    for old_s, new_s in refused:
        if permitted_transition(old_s, new_s):
            print(f"selftest FAIL: `{old_s}` -> `{new_s}` should be refused")
            return 1
    for status in sorted(STATUSES):
        if not permitted_transition(status, status):
            print(f"selftest FAIL: `{status}` -> itself should be permitted")
            return 1

    # And the relation is actually APPLIED, not merely defined.
    before = {"a.rs": {"path": "a.rs", "baseline_prod_loc": 1, "baseline_sha": "x",
                       "status": "reviewed-action-required",
                       "review_ref": "EX-000 in record.md"}}
    after = {"a.rs": dict(before["a.rs"], status="unreviewed")}
    if not any("does not permit" in p for p in check_transitions(before, after)):
        print("selftest FAIL: a completed census was allowed back to `unreviewed`")
        return 1
    if check_transitions(before, {"a.rs": dict(before["a.rs"], status="reviewed-exception")}):
        print("selftest FAIL: a permitted disposition transition was refused")
        return 1
    # A unit that is not in the baseline is a new debt, not a transition.
    if check_transitions({}, after):
        print("selftest FAIL: a newly registered file was judged as a transition")
        return 1
    bad2 = {"a.rs": {"path": "a.rs", "baseline_prod_loc": 1, "baseline_sha": "x",
                     "status": "whatever"}}
    if not any("is not one of" in p for p in validate_registry(bad2)):
        print("selftest FAIL: unknown status was accepted")
        return 1

    if selftest_baseline_growth() != 0:
        return 1

    print("module-size gate selftest: PASS (11 counter cases, ratchet in both directions, "
          "empty scope, stale + malformed registry entries, the §14 disposition lifecycle "
          "and its refusals, the pre-rename `exception_ref` field, and the one-shot upward "
          "baseline authorization, and the measurement correction that buys nothing — "
          "thirteen refusals and the three arrangements that pass)")
    return 0


def selftest_baseline_growth() -> int:
    """The one-shot upward-baseline authorization, asserted through every way it is refused.

    The hole this closes was invisible precisely because raising `baseline_prod_loc` looked
    like bookkeeping, so the positive case is asserted LAST: every refusal first, then the
    one arrangement that passes, so a rule that accepted everything could not read as green.
    """
    rel = "mcp-re-probe/src/big.rs"

    def entry(**over) -> dict[str, dict]:
        base = {"path": rel, "baseline_prod_loc": 454, "baseline_sha": "x",
                "status": "reviewed-exception", "review_ref": "EX-000 in record.md",
                "growth_from_prod_loc": 442, "growth_ref": "GR-000 in record.md"}
        base.update(over)
        return {rel: base}

    before = {rel: {"path": rel, "baseline_prod_loc": 442, "baseline_sha": "x",
                    "status": "unreviewed"}}
    at_454 = {rel: 454}

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        record = root / "record.md"
        record.write_text(
            "# a §14 record\n\n"
            f"{growth_authorization_line(rel, 442, 454)}\n"
        )

        cases: list[tuple[str, dict[str, dict], dict[str, int], str]] = [
            # Raising the number with nothing else is the whole defect, in one line.
            ("a bare raised baseline", entry(growth_from_prod_loc=None, growth_ref=None),
             at_454, "no growth authorization"),
            # Headroom: 442 -> 600 would buy 146 unreviewed lines from one review.
            ("headroom above the measured file", entry(baseline_prod_loc=600), {rel: 454},
             "never headroom"),
            # A unit already owed a decomposition may not grow while owing it.
            ("growth under reviewed-action-required",
             entry(status="reviewed-action-required"), at_454, "kept it INTACT"),
            # The one-shot property: an authorization written for an earlier transition.
            ("a spent authorization reused", entry(growth_from_prod_loc=400), at_454,
             "does not authorize the next"),
            # The record must be about THIS transition, not about growth in general.
            ("a record not naming this exact transition",
             entry(growth_ref="GR-001 in absent.md"), at_454,
             "must authorize this exact transition"),
            # Half an authorization is not one.
            ("growth_ref with no transition", entry(growth_from_prod_loc=None), at_454,
             "must appear together"),
            ("a transition with no record", entry(growth_ref=None), at_454,
             "must appear together"),
        ]
        for name, current, meas, needle in cases:
            current[rel] = {k: v for k, v in current[rel].items() if v is not None}
            got = check_baseline_growth(before, current, meas, root)
            if not any(needle in p for p in got):
                print(f"selftest FAIL: {name} was not refused ({needle!r} absent): {got}")
                return 1

        # A spent authorization must not linger once the file has shrunk back past it.
        settled = {rel: dict(entry()[rel], baseline_prod_loc=440)}
        if not any("paid back" in p for p in
                   check_baseline_growth({rel: dict(settled[rel])}, settled, {rel: 440}, root)):
            print("selftest FAIL: an authorization at or above the current baseline lingered")
            return 1

        # Fully authorized: every condition met, and it passes.
        if check_baseline_growth(before, entry(), at_454, root):
            print("selftest FAIL: a fully authorized one-shot growth was refused: "
                  f"{check_baseline_growth(before, entry(), at_454, root)}")
            return 1

        # ...and having been spent, it authorizes nothing further. `origin/main` now holds
        # 454, so the SAME entry raised again is a second transition with a stale pair.
        spent = {rel: dict(entry()[rel], baseline_prod_loc=466)}
        if not any("does not authorize the next" in p for p in
                   check_baseline_growth(entry(), spent, {rel: 466}, root)):
            print("selftest FAIL: a merged authorization authorized a second increase")
            return 1

        # The measurement correction, which is the OTHER way to a raised baseline — and the
        # narrow one. Refusals first, again, because it buys nothing and must be shown to
        # buy nothing.
        bare = {rel: {k: v for k, v in entry()[rel].items()
                      if k not in ("growth_from_prod_loc", "growth_ref")}}
        # It cannot travel with an edit to the file it re-baselines.
        if not any("no growth authorization" in p for p in
                   check_baseline_growth(before, bare, at_454, root, lambda _r: False)):
            print("selftest FAIL: a changed file was re-baselined as a measurement correction")
            return 1
        # A path git cannot answer for is not an unchanged path.
        if not any("no growth authorization" in p for p in
                   check_baseline_growth(before, bare, at_454, root, lambda _r: None)):
            print("selftest FAIL: an unanswerable path was re-baselined as a correction")
            return 1
        # It grants no headroom: the new baseline must EQUAL the measurement.
        roomy = {rel: dict(bare[rel], baseline_prod_loc=600)}
        if not any("no growth authorization" in p for p in
                   check_baseline_growth(before, roomy, at_454, root, lambda _r: True)):
            print("selftest FAIL: a measurement correction granted headroom")
            return 1
        # An unchanged file pinned at exactly its measured size: accepted, and the status is
        # NOT required to be `reviewed-exception` — correcting a number is not a review.
        plain = {rel: dict(bare[rel], status="unreviewed")}
        del plain[rel]["review_ref"]
        if check_baseline_growth(before, plain, at_454, root, lambda _r: True):
            print("selftest FAIL: a measurement correction on an unchanged file was refused: "
                  f"{check_baseline_growth(before, plain, at_454, root, lambda _r: True)}")
            return 1

        # A shrink needs no authorization at all; the ratchet already permits it.
        shrink = {rel: {"path": rel, "baseline_prod_loc": 430, "baseline_sha": "x",
                        "status": "unreviewed"}}
        if check_baseline_growth(before, shrink, {rel: 430}, root):
            print("selftest FAIL: a shrinking baseline was made to justify itself")
            return 1

    # The growth fields are part of the schema, not unknown fields.
    if validate_registry(entry()):
        print("selftest FAIL: the growth authorization fields were rejected as unknown")
        return 1
    return 0


def empty_scope_is_failure(examined: int) -> bool:
    """A gate that examined nothing must not report OK. Named so the selftest can assert
    the contract rather than re-implement it."""
    return examined == 0


def previous_registry(ref: str = "origin/main") -> tuple[dict[str, dict] | None, str]:
    """The registry as of `ref`, and a sentence saying which it is.

    Returns `(None, why)` when the ref cannot be read. The caller PRINTS that sentence: a
    transition check that quietly no-ops when it cannot find its baseline is the "green
    that measured nothing" failure applied to this gate, and a skipped check must be
    visible in the output rather than inferred from its silence.
    """
    try:
        out = subprocess.run(
            ["git", "show", f"{ref}:config/module-size-debt.toml"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout
    except Exception as e:  # noqa: BLE001 - any git failure is the same answer here
        return None, f"no baseline registry at {ref} ({type(e).__name__})"
    entries = {}
    for entry in tomllib.loads(out).get("debt", []):
        entries[entry["path"]] = entry
    return entries, f"against {ref}"


def check_transitions(previous: dict[str, dict], current: dict[str, dict]) -> list[str]:
    """Refuse a disposition change ADR-MCPRE-061 §14 does not permit.

    Only entries present in BOTH registries are transitions. An entry that appears is a
    new debt (the threshold rules judge it) and one that disappears is a paid or removed
    debt (the `debt is paid` and `not in the debt registry` rules judge that).
    """
    problems = []
    for rel, entry in current.items():
        before = previous.get(rel)
        if before is None:
            continue
        old = before.get("status")
        new = entry.get("status")
        if old not in STATUSES or new not in STATUSES:
            continue
        if not permitted_transition(old, new):
            problems.append(
                f"{rel}: disposition moved `{old}` -> `{new}`, which ADR-MCPRE-061 §14 does "
                f"not permit — a completed census may not be returned to `unreviewed`, "
                f"because that tells the next reader nobody has looked"
            )
    return problems


def growth_authorization_line(rel: str, old: int, new: int) -> str:
    """The exact literal a §14 record must contain to authorize `old -> new` for `rel`.

    Path and BOTH integers, because each one is a thing the record has to have been written
    about. A record that says only "error.rs may grow" authorizes every future increase; a
    record that says only "442 -> 454" could be cited by any file.
    """
    return f"growth-authorization: {rel} {old} -> {new}"


def file_is_unchanged(rel: str, ref: str = "origin/main") -> bool | None:
    """Whether `rel` has the same bytes here as at `ref`. `None` when `ref` cannot be read.

    The discriminator between a file that GREW and a file that was MIS-MEASURED. Growth is a
    fact about the source; a measurement correction is a fact about this script. They are
    told apart by asking whether the source moved, which no one can answer in their own
    favour: to grow a file you must change it, and a changed file gets no correction.
    """
    try:
        blob = subprocess.run(
            ["git", "show", f"{ref}:{rel}"],
            cwd=REPO, capture_output=True, check=True,
        ).stdout
    except Exception:  # noqa: BLE001 - a path absent at ref is not an unchanged path
        return None
    here = REPO / rel
    if not here.exists():
        return None
    return here.read_bytes() == blob


def check_baseline_growth(
    previous: dict[str, dict],
    current: dict[str, dict],
    measured: dict[str, int],
    root: Path,
    unchanged=file_is_unchanged,
) -> list[str]:
    """Refuse an upward `baseline_prod_loc` transition that is not separately authorized.

    `check` compares a file against its baseline. Nothing compared the BASELINE against
    anything, so raising it authorized itself — the ratchet's own input was writable by the
    party it constrains. This is the missing half, and it is deliberately the strictest rule
    in the file: a raised ceiling is the one edit that makes every other check weaker.
    """
    problems: list[str] = []
    for rel, entry in current.items():
        frm = entry.get("growth_from_prod_loc")
        ref = entry.get("growth_ref")
        if (frm is None) != (ref is None):
            problems.append(
                f"{rel}: `growth_from_prod_loc` and `growth_ref` are one authorization and "
                f"must appear together — a transition with no record is unevidenced, and a "
                f"record with no transition does not say which increase it authorized"
            )
            continue

        before = previous.get(rel)
        new = entry.get("baseline_prod_loc")
        if before is None or new is None or before.get("baseline_prod_loc") is None:
            # Not a transition. A newly registered entry is new debt (the threshold rules
            # judge it) and a malformed one is `validate_registry`'s to report.
            continue
        old, new = int(before["baseline_prod_loc"]), int(new)

        if new <= old:
            # No upward transition. A lingering authorization is the RECORD of the last one
            # and is inert — but only while it describes a transition already spent. One
            # that reaches the current baseline is stale, and a stale authorization is
            # exactly what the one-shot rule exists to refuse.
            if frm is not None and int(frm) >= new:
                problems.append(
                    f"{rel}: `growth_from_prod_loc` is {frm} and the baseline is {new} — a "
                    f"spent authorization must sit strictly below the ceiling it bought; "
                    f"remove it, the growth it recorded has been paid back"
                )
            continue

        # An upward transition. There are two, and only two, ways to reach one.
        #
        # A MEASUREMENT CORRECTION is the narrow one: this script's own counting changed, so
        # the old baseline described a size the file never had. It is strictly weaker than
        # an authorization — it buys nothing. The file's bytes must be identical to
        # `origin/main`, so it cannot travel with an edit to the file it re-baselines, and
        # the new baseline must EQUAL the measurement, so it grants no headroom: the file is
        # pinned at its true size and still cannot grow by one line. Anyone wanting room has
        # to come back through the authorization below.
        #
        # It is a separate instrument rather than a lenient reading of the authorization
        # because the authorization requires `status = "reviewed-exception"`, and a file that
        # was merely counted wrong has not thereby been reviewed. Correcting a number must
        # not launder a disposition.
        actual = measured.get(rel)
        if frm is None and actual is not None and actual == new and unchanged(rel):
            continue

        # Otherwise it is growth, and every condition below is required; they are reported
        # together rather than at the first failure, so one run names the whole gap.
        if frm is None:
            problems.append(
                f"{rel}: `baseline_prod_loc` was raised {old} -> {new} with no growth "
                f"authorization — a raised ceiling turns the ratchet off for this file, so "
                f"it needs an ADR-MCPRE-061 §14 record, not a larger integer"
            )
            continue
        if int(frm) != old:
            problems.append(
                f"{rel}: `growth_from_prod_loc` is {frm} but the baseline on origin/main is "
                f"{old} — an authorization is for one exact transition, and a spent one does "
                f"not authorize the next"
            )
        if actual is not None and actual != new:
            problems.append(
                f"{rel}: the raised baseline is {new} but the file measures {actual} "
                f"production lines — an upward baseline authorizes exactly the growth that "
                f"happened, never headroom for growth that has not been reviewed"
            )
        status = entry.get("status")
        if status != "reviewed-exception":
            problems.append(
                f"{rel}: `baseline_prod_loc` was raised {old} -> {new} while status is "
                f"`{status}` — only a unit whose §14 census deliberately kept it INTACT may "
                f"grow; anything else is growing a unit already owed a decomposition"
            )
        want = growth_authorization_line(rel, old, new)
        named = referenced_documents(str(ref))
        if not named:
            problems.append(
                f"{rel}: `growth_ref` names no document — cite the record's file so the "
                f"authorization can be read"
            )
        elif not any(
            (root / doc).exists()
            and want in (root / doc).read_text(encoding="utf-8", errors="replace")
            for doc in named
        ):
            problems.append(
                f"{rel}: no document named by `growth_ref` contains the line "
                f"`{want}` — the record must authorize this exact transition, for this "
                f"exact file, in words a reader and this gate agree on"
            )
    return problems


def baseline_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def emit_registry() -> int:
    """Print a debt registry for the current tree.

    Dispositions and their `review_ref`s are CARRIED FORWARD from the existing registry.
    Re-emitting used to stamp every entry `unreviewed`, which would silently erase every
    completed census — the same defect the disposition states exist to prevent, arriving
    through the tool that refreshes the numbers.
    """
    sha = baseline_sha()
    existing = load_registry(REGISTRY)
    rows = []
    for p in rust_sources(REPO):
        prod = production_lines(p.read_text(encoding="utf-8", errors="replace"))
        if prod > THRESHOLD:
            rows.append((str(p.relative_to(REPO)), prod))
    rows.sort(key=lambda r: (-r[1], r[0]))
    print(f"# Baselined at {sha}: {len(rows)} files over {THRESHOLD} production lines.")
    for rel, prod in rows:
        prior = existing.get(rel, {})
        status = prior.get("status", "unreviewed")
        print("\n[[debt]]")
        print(f'path = "{rel}"')
        print(f"baseline_prod_loc = {prod}")
        # A number that did not move keeps the SHA where it was established; only a
        # changed count is newly baselined.
        established = prior.get("baseline_sha") if prior.get("baseline_prod_loc") == prod else None
        print(f'baseline_sha = "{established or sha}"')
        print(f'status = "{status}"')
        if prior.get("review_ref"):
            print(f'review_ref = "{prior["review_ref"]}"')
        # Carried forward, never invented. Re-emitting must not silently mint an upward
        # authorization for a number this tool just raised on its own; if the pair no longer
        # describes a spent transition, `check_baseline_growth` says so.
        if prior.get("growth_from_prod_loc") is not None:
            print(f'growth_from_prod_loc = {prior["growth_from_prod_loc"]}')
        if prior.get("growth_ref"):
            print(f'growth_ref = "{prior["growth_ref"]}"')
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--emit-registry" in sys.argv:
        return emit_registry()

    registry = load_registry(REGISTRY)
    schema_problems = validate_registry(registry, REPO)
    measured: dict[str, int] = {}
    problems, examined = check(REPO, registry, measured)
    previous, baseline_note = previous_registry()
    if previous is None:
        # Both origin/main checks are skipped together, and the skip is PRINTED. A gate that
        # quietly stops checking the one edit that disables it is the "green that measured
        # nothing" failure aimed at the gate itself.
        baseline_problems: list[str] = []
    else:
        baseline_problems = check_transitions(previous, registry) + check_baseline_growth(
            previous, registry, measured, REPO
        )
    problems = schema_problems + problems + baseline_problems

    if empty_scope_is_failure(examined):
        print("module-size gate: FAIL — examined 0 production Rust files. A gate that "
              "measured nothing is not a pass.")
        return 1

    if problems:
        print(f"module-size gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        print(
            f"\nMeasurement: production lines = every line not inside a test region (a region opens at ^#[cfg((all()?test and closes with its module; counting resumes after it); threshold {THRESHOLD} (ADR-MCPRE-061 §5.1)."
        )
        return 1

    def with_status(name: str) -> int:
        return sum(1 for e in registry.values() if e.get("status") == name)

    unreviewed = with_status("unreviewed")
    excepted = with_status("reviewed-exception")
    action_required = with_status("reviewed-action-required")
    print(
        f"module-size gate: OK — {examined} production Rust files examined against a "
        f"{THRESHOLD}-line threshold (production lines = every line not inside a test region (a region opens at ^#[cfg((all()?test and closes with its module; counting resumes after it); ADR-MCPRE-061 §5.1). Debt registry: "
        f"{len(registry)} file(s) — {unreviewed} unreviewed, {excepted} reviewed-exception, "
        f"{action_required} reviewed-action-required. No new oversized file, no registered "
        f"file grew. Disposition transitions and upward baseline authorizations checked "
        f"{baseline_note}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
