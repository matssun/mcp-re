# SPDX-License-Identifier: Apache-2.0
"""Every executable verification control the tree holds — ADR-MCPRE-069 §2.

ADR-MCPRE-069 asks a question ADR-MCPRE-059's registry never asks: *which controls run and
are claimed by nothing?* Answering it needs one thing the registry cannot supply — the set
of controls that EXIST — and that set has to be measured from the tree, in the same
vocabulary the registry names its evidence in, or the join between them is a guess.

# Identity is the selector, not the function name

A control's identity here is exactly the string a unit would have to put in
`tested_symbols` to select it: `lib#module::path::fn`, `tests/<target>#module::fn`,
`bin/<name>#module::fn`, `doc#item (line N)`, `pytest#file::fn`,
`vitest#file > suite > name`. That is deliberate and it is the whole point: a census whose
identities do not join to the registry's answers a different question than the one asked,
and a name-only join — `fn` without its target — reports a control as claimed because an
unrelated crate happens to have a test of the same name.

# The Rust module path is FOLLOWED, never derived from the file path

`mcp-re-client/src/startup.rs` is not `lib#startup`; it is `bin/mcp-re-client#startup`,
because `main.rs` declares it and `lib.rs` does not. Deriving the module path from the
directory layout gets that wrong in both directions — it invents `lib#` controls that no
target runs, and it misses every control a binary owns. So each crate ROOT is walked:
`mod name;` is resolved to its file, `#[path = "..."]` is honoured, and an inline
`mod name { … }` nests in place.

A file reachable from two roots yields two controls, and that is not double counting: the
same source function compiled into the library's test target and into an integration
target are two things libtest can run and two things a unit can select, and exactly one of
them may be the claimed one.

# What counts as a control kind here

Everything with an executable carrier that a unit could name as evidence, plus the two
registries whose entries are executed by their own lanes:

  * `rust-test`      — `#[test]` / `#[tokio::test]`, per target
  * `rust-doctest`   — a rustdoc example, including the `compile_fail` ones ADR-069 §2.1
                       records as invisible to the first census
  * `pytest`         — a collected pytest function
  * `vitest`         — a registered `it(…)` / `test(…)` case
  * `structural`     — a `[[probe]]` in `structural-probes.toml`
  * `mutation`       — a `[[probe]]` in `mutation-probes.toml`
  * `measurement`    — a `[[measurement]]` in `measurements.toml`
  * `gate`           — an executable check under `scripts/` that a lane runs

The list is derived from the execution machinery that exists, and `KINDS` is its single
statement. A kind nothing can run does not belong here; a kind that runs and is absent
makes every "0 unclaimed" this module supports a false green, which is why
`test_controls.py` holds a positive-scope control per kind.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import tomllib
from pathlib import Path

from _ecosystems import REPO_ROOT

POLICY = REPO_ROOT / "verification" / "policy"

#: Every control kind this module enumerates, with the ecosystem/lane each belongs to.
#: A census reports coverage per kind, so an ecosystem that stops being discoverable shows
#: up as a zero rather than as an absence nobody counted.
KINDS: dict[str, str] = {
    "rust-test": "cargo",
    "rust-doctest": "cargo",
    "pytest": "python",
    "vitest": "typescript",
    "structural": "structural-lane",
    "mutation": "mutation-lane",
    "measurement": "measured-lane",
    "gate": "gate-lane",
}

#: Directories that are not source of this repository. Every dotted directory is skipped
#: as well — `sdk/python/.venv*/lib/.../site-packages` holds thousands of a dependency's own
#: tests, and counting them would put a census's largest population outside the repository
#: it claims to measure.
_SKIP = {"target", "node_modules", "dist", "build", "__pycache__", "site-packages"}


@dataclass(frozen=True)
class Control:
    """One executable control, identified as the registry would have to name it."""

    #: The project the selector is resolved in — the cargo PACKAGE name, the python or
    #: node project directory, or "" for a control a registry carries. A selector is only
    #: unique inside its project: `lib#error::tests::the_token_is_frozen` can exist in two
    #: crates at once, and a census joining on the bare symbol would report one of them as
    #: claimed on the strength of the other's registration.
    project: str
    identity: str
    kind: str
    carrier: str
    line: int
    #: What a reader needs in order to not misread the control — a doctest's fence modes,
    #: so that a compile refusal is never mistaken for behavioural evidence.
    note: str = ""

    def to_json(self) -> dict:
        return {
            "project": self.project,
            "identity": self.identity,
            "kind": self.kind,
            "ecosystem": KINDS[self.kind],
            "carrier": self.carrier,
            "line": self.line,
            "note": self.note,
        }


def _skipped(path: Path) -> bool:
    return any(_prune(part) for part in path.parts)


def _prune(name: str) -> bool:
    return name in _SKIP or name.startswith(".")


def walk(suffix: str, root: Path | None = None) -> list[Path]:
    """Every file whose suffix or whole NAME is `suffix`, pruning skipped directories.

    The name form is what finds manifests — `Cargo.toml`'s suffix is `.toml`, which every
    policy registry shares — and the suffix form is what finds source.

    `rglob` then filter is the obvious spelling and it is the wrong one here: it descends
    into `target/`, which holds hundreds of thousands of build artefacts, so the census
    spends minutes reading a tree it discards. Pruning at the directory makes the walk
    proportional to the repository rather than to the last build.
    """
    base = REPO_ROOT if root is None else root
    found: list[Path] = []
    stack = [base]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                # `bazel-bin` and its siblings are symlinks into the output base, which
                # holds every vendored crate's source. `rglob` never followed them;
                # `iterdir` + `is_dir` does, and following one puts 800 third-party
                # packages into a census of this repository's controls.
                continue
            if entry.is_dir():
                if not _prune(entry.name):
                    stack.append(entry)
            elif entry.suffix == suffix or entry.name == suffix:
                found.append(entry)
    return sorted(found)


# ---------------------------------------------------------------------------
# Rust: follow the module tree from each target root
# ---------------------------------------------------------------------------

_MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z0-9_]+)\s*;")
_MOD_INLINE = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z0-9_]+)\s*\{")
_PATH_ATTR = re.compile(r'^\s*#\[path\s*=\s*"([^"]+)"\]')
_TEST_ATTR = re.compile(r"^(\s*)#\[(?:tokio::)?test\]")
_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
_ATTR_LINE = re.compile(r"^\s*#\[")


def _resolve_mod(here: Path, name: str, explicit: str | None) -> Path | None:
    """The file a `mod name;` declaration in `here` refers to, or None if absent.

    `here` is the declaring file. A declaration in `foo.rs` looks in `foo/`; one in
    `mod.rs` or a crate root looks beside itself. `#[path]` overrides both and is resolved
    relative to the same directory the search would have started from.
    """
    base = here.parent if here.name in ("mod.rs", "lib.rs", "main.rs") else here.parent / here.stem
    if explicit is not None:
        candidate = (here.parent / explicit) if here.name in ("mod.rs", "lib.rs", "main.rs") else (base / explicit)
        return candidate if candidate.is_file() else None
    for candidate in (base / f"{name}.rs", base / name / "mod.rs"):
        if candidate.is_file():
            return candidate
    return None


def _walk_rust_file(
    path: Path,
    prefix: tuple[str, ...],
    package: str,
    target: str,
    seen: set[Path],
    out: list[Control],
) -> None:
    """Collect every `#[test]` reachable from `path`, and recurse into `mod name;`.

    `seen` is per target, not global: the same file reached from two targets is two
    distinct controls, and sharing the set would silently drop the second.
    """
    key = path.resolve()
    if key in seen:
        return
    seen.add(key)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return
    stack: list[tuple[int, str]] = []
    pending_test: int | None = None
    pending_path: str | None = None
    children: list[tuple[str, str | None]] = []
    for number, line in enumerate(lines, start=1):
        attr = _PATH_ATTR.match(line)
        if attr:
            pending_path = attr.group(1)
            continue
        decl = _MOD_DECL.match(line)
        if decl:
            children.append((decl.group(1), pending_path))
            pending_path = None
            continue
        inline = _MOD_INLINE.match(line)
        if inline:
            indent = len(inline.group(1))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, inline.group(2)))
            pending_path = None
            continue
        test = _TEST_ATTR.match(line)
        if test:
            pending_test = len(test.group(1))
            continue
        if pending_test is not None:
            fn = _FN.match(line)
            if fn:
                mods = tuple(name for indent, name in stack if indent < pending_test)
                segments = prefix + mods + (fn.group(1),)
                out.append(
                    Control(
                        project=package,
                        identity=f"{target}#{'::'.join(segments)}",
                        kind="rust-test",
                        carrier=path.relative_to(REPO_ROOT).as_posix(),
                        line=number,
                    )
                )
                pending_test = None
            elif not (_ATTR_LINE.match(line) or not line.strip()):
                pending_test = None
        pending_path = None
    for name, explicit in children:
        child = _resolve_mod(path, name, explicit)
        if child is not None:
            _walk_rust_file(child, prefix + (name,), package, target, seen, out)


def _cargo_packages() -> list[Path]:
    return sorted(
        manifest.parent
        for manifest in walk("Cargo.toml")
        if not _skipped(manifest.relative_to(REPO_ROOT))
    )


def _project_id(directory: Path) -> str | None:
    """A project's identity for the join — its repository-relative directory.

    The DIRECTORY and not the cargo package name, because the registry's own answer to
    "where does this unit's battery run" is `_ecosystems.test_project_for`, which returns a
    directory. Joining on anything else would compare two different keys and silently
    report every control of a mismatched project as unclaimed.
    """
    try:
        rel = directory.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return None
    return rel or "."


def _rust_targets(package: Path) -> list[tuple[str, Path]]:
    """Every runnable target of one package, as `(target name, root file)`.

    Read from the manifest where it declares paths, and from the conventional layout
    otherwise — `cargo` accepts both and a census that honoured only one would miss whole
    targets in whichever half it ignored.
    """
    targets: list[tuple[str, Path]] = []
    try:
        manifest = tomllib.loads((package / "Cargo.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return targets
    lib = manifest.get("lib", {})
    lib_path = package / lib.get("path", "src/lib.rs")
    if lib_path.is_file():
        targets.append(("lib", lib_path))
    declared_bins = manifest.get("bin", [])
    for entry in declared_bins:
        root = package / entry.get("path", f"src/bin/{entry['name']}.rs")
        if root.is_file():
            targets.append((f"bin/{entry['name']}", root))
    if not declared_bins:
        default = package / "src" / "main.rs"
        if default.is_file():
            name = manifest.get("package", {}).get("name")
            if name:
                targets.append((f"bin/{name}", default))
        for root in sorted((package / "src" / "bin").glob("*.rs")):
            targets.append((f"bin/{root.stem}", root))
    tests = package / "tests"
    if tests.is_dir():
        for root in sorted(tests.glob("*.rs")):
            targets.append((f"tests/{root.stem}", root))
        for directory in sorted(p for p in tests.iterdir() if p.is_dir()):
            root = directory / "main.rs"
            if root.is_file():
                targets.append((f"tests/{directory.name}", root))
    return targets


def rust_controls() -> list[Control]:
    """Every `#[test]` / `#[tokio::test]` reachable from a declared target root."""
    out: list[Control] = []
    for package in _cargo_packages():
        name = _project_id(package)
        if name is None:
            continue
        for target, root in _rust_targets(package):
            _walk_rust_file(root, (), name, target, set(), out)
    return out


# ---------------------------------------------------------------------------
# Rust doctests — the kind ADR-069 §2.1 records as invisible to the first census
# ---------------------------------------------------------------------------

_DOC_FENCE = re.compile(r"^\s*//(/|!)\s*```(.*)$")
_DOC_LINE = re.compile(r"^\s*//[/!]")
_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+|async\s+|const\s+|default\s+)*"
    r"(?:fn|struct|enum|trait|type|mod|impl|macro_rules!|union|static|const)\b"
)

#: The fence words rustdoc COMPILES. Anything else — `text`, `ignore`, `sh`, a language
#: name — is prose in a code font and executes nothing. A whitelist rather than a list of
#: inert words, because the failure directions are not symmetric: an unrecognised word
#: treated as inert drops a real control from the census silently, and the census would then
#: report a clean sweep over a population missing exactly the kind ADR-069 §2.1 was written
#: about.
_COMPILED_FENCE = {
    "rust",
    "compile_fail",
    "no_run",
    "should_panic",
    "edition2015",
    "edition2018",
    "edition2021",
    "edition2024",
}


def _fence_mode(words: set[str]) -> str | None:
    """How rustdoc treats this fence: `run`, `compile-only`, `compile-fail`, or None.

    None means the block is not a control at all. The three live modes are distinguished
    because ADR-MCPRE-068 §4.1 refuses to let a compile refusal count as behavioural
    evidence, and a census that flattened them would hand a registration campaign the
    means to do exactly that.
    """
    if words - _COMPILED_FENCE:
        return None
    if "compile_fail" in words:
        return "compile-fail"
    if "no_run" in words:
        return "compile-only"
    return "run"


def doctest_controls() -> list[Control]:
    """Every rustdoc example in a library's own sources, `compile_fail` ones included.

    A doctest's libtest name is `src/file.rs - item::path (line N)`, which is a shape the
    registry cannot join on without the line, so identity here is the `doc#` selector the
    test lane already uses: the ITEM the example documents. `compile_fail` is carried on
    the control so a census can refuse to count a compile refusal as behavioural evidence,
    which is ADR-MCPRE-068 §4.1's rule and not this module's to relax.
    """
    out: list[Control] = []
    for package in _cargo_packages():
        source_root = package / "src"
        if not source_root.is_dir():
            continue
        name = _project_id(package)
        if name is None or not (source_root / "lib.rs").is_file():
            continue
        for path in walk(".rs", source_root):
            rel = path.relative_to(source_root)
            if rel.parts[0] == "bin" or path.name == "main.rs" or _skipped(rel):
                continue
            out.extend(_doctests_in(path, name, _doc_module_path(path, source_root)))
    return out


def _doc_module_path(path: Path, source_root: Path) -> tuple[str, ...]:
    parts = list(path.relative_to(source_root).parts)
    last = parts[-1]
    if last in ("lib.rs", "mod.rs"):
        parts = parts[:-1]
    else:
        parts[-1] = last[: -len(".rs")]
    return tuple(parts)


def _attach(found: dict, item: str) -> tuple[int, list[str]]:
    """The `(first line, modes)` accumulator for `item`, created empty if absent."""
    return found.get(item, (1 << 30, []))


def _doctests_in(path: Path, package: str, base: tuple[str, ...]) -> list[Control]:
    """The doctest-bearing ITEMS of one file, one control each.

    The item, not the example, because that is the granularity the registry claims at: a
    `doc#` symbol selects an item's doctests as a battery (`verify-tests.doc_matches`),
    since a doctest's libtest name embeds the line it starts on and would break on any edit
    above it. An item holding three examples is therefore ONE control, and its modes travel
    with it so a reader can see that what runs there is a compile refusal.
    """
    lines = path.read_text(errors="replace").splitlines()
    found: dict[str, tuple[int, list[str]]] = {}
    block_start: int | None = None
    block_inner = False
    block_words: set[str] = set()
    pending: list[tuple[int, str]] = []
    for number, line in enumerate(lines, start=1):
        fence = _DOC_FENCE.match(line)
        if fence is not None and block_start is None:
            block_start = number
            block_inner = fence.group(1) == "!"
            block_words = {
                word.strip()
                for word in fence.group(2).replace(" ", ",").split(",")
                if word.strip()
            }
            continue
        if fence is not None:
            mode = _fence_mode(block_words)
            if mode is not None:
                # `//!` documents the enclosing module and never the item below it, so it
                # lands immediately; `///` waits for the item it is attached to.
                target = _attach(found, "::".join(base)) if block_inner else None
                if target is None:
                    pending.append((block_start or number, mode))
                else:
                    found["::".join(base)] = (min(target[0], block_start or number), target[1] + [mode])
            block_start, block_words = None, set()
            continue
        if block_start is not None or _DOC_LINE.match(line) or not line.strip():
            continue
        if not _ITEM.match(line):
            if not _ATTR_LINE.match(line):
                pending = []
            continue
        if not pending:
            continue
        name = _item_name(line)
        item = "::".join(base + ((name,) if name else ()))
        first, modes = found.get(item, (pending[0][0], []))
        found[item] = (min(first, pending[0][0]), modes + [mode for _, mode in pending])
        pending = []
    return [
        Control(
            project=package,
            identity=f"doc#{item}",
            kind="rust-doctest",
            carrier=path.relative_to(REPO_ROOT).as_posix(),
            line=first,
            note=", ".join(sorted(set(modes))) + f" ({len(modes)} example(s))",
        )
        for item, (first, modes) in sorted(found.items())
    ]


_ITEM_NAME = re.compile(
    r"\b(?:fn|struct|enum|trait|type|mod|union|static|const|macro_rules!)\s+([A-Za-z0-9_]+)"
)


def _item_name(line: str) -> str | None:
    match = _ITEM_NAME.search(line)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Python and TypeScript
# ---------------------------------------------------------------------------

_PY_TEST = re.compile(r"^(\s*)(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)")
_PY_CLASS = re.compile(r"^class\s+(Test[A-Za-z0-9_]*)")


def pytest_controls() -> list[Control]:
    """Every pytest function, named as `pytest#<path relative to its project>::<fn>`.

    Project-relative because that is what the selector is: the lane runs pytest with the
    project as its working directory, so a repo-relative path would select nothing. A file
    under no `pyproject.toml` — `tools/verification/test_*.py`, the verification suite's own
    controls — is relative to the repository root, which is where those are run from.
    """
    out: list[Control] = []
    for path in walk(".py"):
        rel_repo = path.relative_to(REPO_ROOT)
        if _skipped(rel_repo) or not _is_pytest_file(path):
            continue
        project = _nearest_project(path, "pyproject.toml")
        out.extend(
            _pytest_cases_in(
                path,
                project.relative_to(REPO_ROOT).as_posix() or ".",
                path.relative_to(project).as_posix(),
                rel_repo,
            )
        )
    return out


def _pytest_cases_in(
    path: Path, project: str, selector_base: str, rel_repo: Path
) -> list[Control]:
    out: list[Control] = []
    current_class: str | None = None
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        klass = _PY_CLASS.match(line)
        if klass:
            current_class = klass.group(1)
            continue
        match = _PY_TEST.match(line)
        if not match:
            continue
        nested = bool(match.group(1)) and current_class is not None
        owner = f"{current_class}::" if nested else ""
        out.append(
            Control(
                project=project,
                identity=f"pytest#{selector_base}::{owner}{match.group(2)}",
                kind="pytest",
                carrier=rel_repo.as_posix(),
                line=number,
            )
        )
    return out


def _nearest_project(path: Path, manifest: str) -> Path:
    """The nearest ancestor holding `manifest`, or the repository root if none does."""
    current = path.parent
    while current != REPO_ROOT:
        if (current / manifest).is_file():
            return current
        current = current.parent
    return REPO_ROOT


def _is_pytest_file(path: Path) -> bool:
    return path.name.startswith("test_") or path.name.endswith("_test.py")


_TS_CASE = re.compile(r"^\s*(?:it|test)(?:\.\w+)*\s*\(\s*(['\"`])(.+?)\1")
_TS_EACH = re.compile(r"^\s*(?:it|test)\.each\s*\(")
#: An `it.each([...])("title", …)` whose table and title share one line: the title follows
#: the table's closing `)` and a second `(`.
_TS_EACH_INLINE = re.compile(r"\)\s*\(\s*(['\"`])(.+?)\1")
#: A project-local case declarer — `const tls = (name: string, fn) => it(name, …)`. Without
#: this every case declared through the wrapper is invisible, which is not a smaller census
#: but a wrong one: those controls ARE registered, so they would read as registry selectors
#: naming nothing.
_TS_WRAPPER = re.compile(r"^\s*(?:const|let|function)\s+([A-Za-z_$][\w$]*)\s*[=(]\s*\(?\s*([A-Za-z_$][\w$]*)")
_TS_TITLE = re.compile(r"^\s*(['\"`])(.+?)\1\s*,?\s*$")
_TS_SUITE = re.compile(r"^(\s*)describe(?:\.\w+)*\s*\(\s*(['\"`])(.+?)\2")

#: How far after an `it.each([...])(` opening the case TITLE may sit. A table literal is
#: usually wrapped across lines and the title follows it, so the title is not on the
#: opening line — and a scanner that only reads that line reports zero controls for a whole
#: parametrised family while the file is full of them.
_TS_TITLE_LOOKAHEAD = 40


def vitest_controls() -> list[Control]:
    """Every vitest case, named `vitest#<file> > <suite> > … > <case>`.

    That separator is vitest's own reporter form and is what `tested_symbols` already
    carries, so the identity is the reported name rather than a path this module invents.

    A parametrised family (`it.each`) is ONE control identified by its TITLE TEMPLATE —
    `… at sign time: %s` — because that is what the source defines and what deleting would
    remove. The registry names the expanded cases, and `_census` matches them back to the
    template rather than this module inventing pytest's and vitest's id algebra, which it
    would get wrong in both.
    """
    out: list[Control] = []
    for project in _projects("package.json"):
        for path in walk(".ts", project):
            rel_repo = path.relative_to(REPO_ROOT)
            if _skipped(rel_repo) or not re.search(r"\.(test|spec)\.ts$", path.name):
                continue
            out.extend(
                _vitest_cases_in(
                    path,
                    project.relative_to(REPO_ROOT).as_posix(),
                    path.relative_to(project).as_posix(),
                    rel_repo,
                )
            )
    return out


def _vitest_cases_in(path: Path, project: str, rel: str, rel_repo: Path) -> list[Control]:
    out: list[Control] = []
    lines = path.read_text(errors="replace").splitlines()
    suites: list[tuple[int, str]] = []
    declarers = _case_declarers(lines)
    for index, line in enumerate(lines):
        suite = _TS_SUITE.match(line)
        if suite is not None:
            indent = len(suite.group(1))
            while suites and suites[-1][0] >= indent:
                suites.pop()
            suites.append((indent, suite.group(3)))
            continue
        title = _case_title(lines, index, declarers)
        if title is None:
            continue
        trail = " > ".join([name for _, name in suites] + [title])
        out.append(
            Control(
                project=project,
                identity=f"vitest#{rel} > {trail}",
                kind="vitest",
                carrier=rel_repo.as_posix(),
                line=index + 1,
            )
        )
    return out


def _case_title(lines: list[str], index: int, declarers: re.Pattern[str]) -> str | None:
    """The case title declared at `lines[index]`, or None if no case starts there."""
    case = declarers.match(lines[index])
    if case is not None:
        return case.group(2)
    if _TS_EACH.match(lines[index]) is None:
        return None
    inline = _TS_EACH_INLINE.search(lines[index])
    if inline is not None:
        return inline.group(2)
    for line in lines[index + 1 : index + 1 + _TS_TITLE_LOOKAHEAD]:
        found = _TS_TITLE.match(line)
        if found is not None:
            return found.group(2)
    return None


def _case_declarers(lines: list[str]) -> re.Pattern[str]:
    """`it`/`test` plus every project-local wrapper that delegates to one.

    A wrapper is recognised by what it DOES — it takes a name and passes that same name to
    `it(` a few lines later — rather than by being listed somewhere, because a list of
    known helper names is a thing that goes stale silently and this measurement's whole
    value is that it does not.
    """
    names = ["it", "test"]
    for index, line in enumerate(lines):
        found = _TS_WRAPPER.match(line)
        if found is None:
            continue
        wrapper, parameter = found.group(1), found.group(2)
        delegates = re.compile(rf"\b(?:it|test)\s*\(\s*{re.escape(parameter)}\s*,")
        if any(delegates.search(text) for text in lines[index : index + 6]):
            names.append(wrapper)
    alternatives = "|".join(re.escape(name) for name in dict.fromkeys(names))
    return re.compile(rf"^\s*(?:{alternatives})(?:\.\w+)*\s*\(\s*(['\"`])(.+?)\1")


def _projects(manifest: str) -> list[Path]:
    return sorted(
        found.parent
        for found in walk(manifest)
        if not _skipped(found.relative_to(REPO_ROOT))
    )


# ---------------------------------------------------------------------------
# Registry-carried controls: structural, mutation, measurement
# ---------------------------------------------------------------------------


def _registry(name: str, table: str) -> list[dict]:
    path = POLICY / name
    if not path.is_file():
        return []
    return tomllib.loads(path.read_text()).get(table, [])


def probe_controls() -> list[Control]:
    """`structural://` and `mutation://` probes, and `measured://` measurements.

    These are controls with an executable carrier — their lane runs each record — and an
    identity the registry already assigns, so they join to a unit by the probe's own
    `unit` field rather than through a symbol list.
    """
    out: list[Control] = []
    for probe in _registry("structural-probes.toml", "probe"):
        out.append(
            Control(
                project="",
                identity=f"structural#{probe['id']}",
                kind="structural",
                carrier="verification/policy/structural-probes.toml",
                line=0,
            )
        )
    for probe in _registry("mutation-probes.toml", "probe"):
        out.append(
            Control(
                project="",
                identity=f"mutation#{probe['id']}",
                kind="mutation",
                carrier="verification/policy/mutation-probes.toml",
                line=0,
            )
        )
    for measurement in _registry("measurements.toml", "measurement"):
        out.append(
            Control(
                project="",
                identity=f"measurement#{measurement['id']}",
                kind="measurement",
                carrier="verification/policy/measurements.toml",
                line=0,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Gate controls
# ---------------------------------------------------------------------------


def gate_controls() -> list[Control]:
    """Executable checks under `scripts/` — the source-text and structural gates.

    A gate is a control by every test this record applies: it executes on the merge path,
    it can fail, and what it refuses is a security-relevant property. Whether any unit
    CLAIMS one is exactly ADR-069's question, and for this kind the answer at the start of
    the campaign is uniformly no, because no evidence scheme names a gate.
    """
    out: list[Control] = []
    scripts = REPO_ROOT / "scripts"
    if not scripts.is_dir():
        return out
    for path in sorted(scripts.iterdir()):
        if not path.is_file() or path.suffix not in (".py", ".sh"):
            continue
        out.append(
            Control(
                project="",
                identity=f"gate#scripts/{path.name}",
                kind="gate",
                carrier=f"scripts/{path.name}",
                line=0,
            )
        )
    return out


# ---------------------------------------------------------------------------


def all_controls() -> list[Control]:
    """Every control of every kind, sorted by identity.

    Sorted so that two runs over the same tree produce the same report in the same order:
    a census whose output depends on filesystem iteration order cannot be diffed, and a
    report nobody can diff is a report nobody reads twice.
    """
    controls = (
        rust_controls()
        + doctest_controls()
        + pytest_controls()
        + vitest_controls()
        + probe_controls()
        + gate_controls()
    )
    return sorted(controls, key=lambda c: (c.kind, c.identity))


def main() -> int:
    controls = all_controls()
    by_kind: dict[str, int] = {}
    for control in controls:
        by_kind[control.kind] = by_kind.get(control.kind, 0) + 1
    print(json.dumps({"total": len(controls), "by_kind": by_kind}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
