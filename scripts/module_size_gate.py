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

#: Anything else in a `[[debt]]` table is a typo or a stale field name, and both fail.
ENTRY_FIELDS = {"path", "baseline_prod_loc", "baseline_sha", "status", "review_ref"}

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


def production_lines(text: str) -> int:
    """Every line of a Rust source that is NOT inside a test region.

    A test region runs from its `#[cfg(test)]`-family attribute to the end of the module it
    introduces, tracked by brace depth. Counting resumes afterwards, and a file may contain
    several regions: a file that puts a helper module below its tests is not thereby exempt.

    This is deliberately NOT "lines before the first test module" — that rule discards every
    production item below the tests, and measured `trust_plane.rs` at 134 lines when it is
    690. This function is the definition; the prose in ADR-MCPRE-061 §5.1 describes it.
    """
    lines = text.splitlines()
    count = 0
    i = 0
    while i < len(lines):
        if TEST_ATTR.match(lines[i].lstrip()):
            # Skip to the opening brace of the module, then past its matching close.
            depth = 0
            opened = False
            while i < len(lines):
                depth += lines[i].count("{") - lines[i].count("}")
                if "{" in lines[i]:
                    opened = True
                i += 1
                if opened and depth <= 0:
                    break
            continue
        count += 1
        i += 1
    return count


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


def check(root: Path, registry: dict[str, dict]) -> tuple[list[str], int]:
    """Return (problems, files_examined)."""
    problems: list[str] = []
    sources = rust_sources(root)
    measured: dict[str, int] = {}

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

    print("module-size gate selftest: PASS (7 counter cases, ratchet in both directions, "
          "empty scope, stale + malformed registry entries, the §14 disposition lifecycle "
          "and its refusals, and the pre-rename `exception_ref` field)")
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
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--emit-registry" in sys.argv:
        return emit_registry()

    registry = load_registry(REGISTRY)
    schema_problems = validate_registry(registry, REPO)
    problems, examined = check(REPO, registry)
    previous, baseline_note = previous_registry()
    transition_problems = check_transitions(previous, registry) if previous is not None else []
    problems = schema_problems + problems + transition_problems

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
        f"file grew. Disposition transitions checked {baseline_note}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
