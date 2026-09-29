"""prepare.py — everything an evaluator reads before it starts judging, in ONE call.

(Invoked as `python3 prepare.py …`; no shebang — see reduce.py for why.)

WHY: an agent pays for its whole context on EVERY turn, so the cost of a file is
turns x context, and turns are the lever. Measured on a lane run: a senior
evaluator averaged 31 turns at ~84K context, and most of those turns were the
same opening every time — fetch the findings, `cat` the file, locate each
evidence excerpt, grep who imports / constructs / subclasses each symbol, find
the test module and the BUILD target. None of that is judgment. This emits all
of it at once so the evaluator's turns go to the questions only it can answer.

What it prints, in order:
  1. the findings (ledger x audit packet, the `file_findings.collect` join)
  2. where each finding's evidence excerpt sits in the CURRENT source — found at
     a line, ambiguous, or absent (an absent anchor is a `superseded` candidate,
     never a verdict: the excerpt may have been paraphrased by the reviewer)
  3. the owning BUILD.bazel and candidate test modules
  4. a usage map for every top-level symbol the file defines: production
     import / construct / subclass / reference counts, test counts, and the
     first --max-sites production sites
  5. the whole source, line-numbered

The usage map is an INSTRUMENT with a stated reach: tracked files that import
the name from this file's package, read through the AST. It cannot see a
string-keyed factory, a DI registration by name, getattr, `import pkg` followed
by attribute access, or an untracked file; Rust sites are text matches only. Every section says when it was truncated, so a
cut-off list is never read as a complete one — grep further when it matters.

Usage:
  prepare.py --ledger <ledger.jsonl> --packets <dir> --file <repo-relative path>
             [--max-sites 20] [--max-symbols 25] [--max-lines 2000] [--max-note 1500]
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from file_findings import collect  # noqa: E402

_LINE_PREFIX = re.compile(r"^\s*(?:L?\d+\s*[:|]\s?|\d+\t)")
# Column-0 items only: an indented `pub fn new` is a method, not a name another file binds.
_RUST_DECL = re.compile(r"^pub(?:\([^)]*\))?\s+(?:struct|enum|trait|fn|type|const|static)\s+([A-Za-z_]\w*)", re.M)
_RUST_TEST_REGION = re.compile(r"^#\[cfg\((?:all\()?test", re.M)
_RUST_COMMENT = re.compile(r"^\s*//")


def _anchor_lines(evidence: str | None) -> list[str]:
    """The excerpt's significant lines, with any `123:` / `L123 |` prefix removed.

    Reviewers quote with line-number prefixes and elide with `...`; neither is in
    the source. Lines shorter than 8 characters (`}`, `)`, `else:`) match
    everywhere and anchor nothing, so they are dropped.
    """
    out = []
    for raw in (evidence or "").splitlines():
        line = _LINE_PREFIX.sub("", raw).strip()
        if len(line) < 8 or line.startswith(("...", "…")):
            continue
        out.append(line)
    return out


def locate(evidence: str | None, src_lines: list[str]) -> dict:
    """Where the excerpt sits now. Keyed on the FIRST significant line, then
    checked for the rest — a partial hit is reported as partial, not as found."""
    anchors = _anchor_lines(evidence)
    if not anchors:
        return {"state": "no-anchor", "detail": "the packet carries no usable excerpt"}
    stripped = [s.strip() for s in src_lines]
    first = anchors[0]
    hits = [i + 1 for i, s in enumerate(stripped) if first in s]
    rest_present = sum(1 for a in anchors[1:] if any(a in s for s in stripped))
    rest = len(anchors) - 1
    if not hits:
        # The first line may be the paraphrased one; any later line still anchors.
        later = [(a, [i + 1 for i, s in enumerate(stripped) if a in s]) for a in anchors[1:]]
        later = [(a, h) for a, h in later if h]
        if later:
            return {"state": "partial", "lines": later[0][1][:5],
                    "detail": "first excerpt line absent; %d/%d later lines present"
                              % (rest_present, rest)}
        return {"state": "absent",
                "detail": "no excerpt line is present — `superseded` CANDIDATE; confirm "
                          "the code is really gone, not paraphrased by the reviewer"}
    state = "found" if len(hits) == 1 else "ambiguous"
    detail = "" if not rest else "%d/%d further excerpt lines present" % (rest_present, rest)
    return {"state": state, "lines": hits[:5], "detail": detail}


def defined_symbols(path: str, src: str) -> list[str]:
    """Top-level public names the file defines — what other files can bind to."""
    names: list[str] = []
    if path.endswith(".py"):
        try:
            tree = ast.parse(src)
        except SyntaxError:
            return []
        for node in tree.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                # Constants and type aliases bind across files; `logger` does not.
                names += [t.id for t in targets if isinstance(t, ast.Name) and t.id[:1].isupper()]
    elif path.endswith(".rs"):
        m = _RUST_TEST_REGION.search(src)
        names = _RUST_DECL.findall(src[:m.start()] if m else src)
    seen: set[str] = set()
    return [n for n in names if not n.startswith("_") and not (n in seen or seen.add(n))]


def _prioritise(symbols: list[str], findings: list[dict]) -> list[str]:
    """Symbols a finding mentions come first: those are the ones being judged."""
    text = " ".join(" ".join(str(f.get(k) or "") for k in ("title", "claim", "evidence_anchor"))
                    for f in findings)
    named = [s for s in symbols if re.search(r"\b%s\b" % re.escape(s), text)]
    return named + [s for s in symbols if s not in named]


def _is_test(path: str) -> bool:
    base = os.path.basename(path)
    return "/tests/" in path or base.startswith("test_") or base.endswith("_test.py") \
        or "/tests.rs" in path or base == "conftest.py"


def _kind(sym: str, text: str) -> str:
    """Text classification — the Rust fallback only; Python sites are read from the AST."""
    t = text.strip()
    if t.startswith(("use ", "pub use ")):
        return "import"
    if re.search(r"\bimpl\b.*\b%s\b\s+for\b" % re.escape(sym), t):
        return "subclass"
    if re.search(r"\b%s\s*(?:\{|::new\b|\()" % re.escape(sym), t):
        return "construct"
    return "ref"


def top_package(path: str) -> str | None:
    """The importable top-level package: the path segment right after `src`."""
    parts = path.split("/")
    if "src" in parts and parts.index("src") + 1 < len(parts) - 1:
        return parts[parts.index("src") + 1]
    return None


def _py_sites(sym: str, cand: str, pkg: str, src: str) -> list[tuple[str, int]]:
    """(kind, line) for every use of `sym` in `cand` — IF `cand` binds it from `pkg`.

    A bare name match is not a use: `Scope` is also Starlette's, and `grep -w`
    counted 155 unrelated production sites for it. A file is bound only by an
    import of the name from this package (absolute, a barrel, or relative inside
    the package); only then are its Name/Attribute nodes this symbol. Mentions in
    docstrings and comments are not nodes, so they no longer count as uses.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    local = None
    imports: list[int] = []
    same_pkg = ("/src/%s/" % pkg) in cand
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            from_pkg = mod == pkg or mod.startswith(pkg + ".") or (node.level > 0 and same_pkg)
            if not from_pkg:
                continue
            for al in node.names:
                if al.name == sym:
                    local = al.asname or sym
                    imports.append(node.lineno)
    if local is None:
        return []
    out = [("import", ln) for ln in imports]
    bases: set[int] = set()
    calls: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for b in node.bases:
                for sub in ast.walk(b):
                    if isinstance(sub, ast.Name) and sub.id == local:
                        bases.add(id(sub))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == local:
            calls.add(id(node.func))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == local:
            kind = "subclass" if id(node) in bases else "construct" if id(node) in calls else "ref"
            out.append((kind, node.lineno))
    return out


def root_reexports(path: str) -> list[str]:
    """Names the crate root (`src/lib.rs` or `src/main.rs`) re-exports from `path`'s
    module: `pub use <module>::Name;` and `pub use <module>::{A, B as C};`."""
    root = component_root(path) or "."
    mod = re.escape(rust_module(path))
    out: list[str] = []
    for crate_root in ("src/lib.rs", "src/main.rs"):
        try:
            src = open(os.path.join(root, crate_root), encoding="utf-8").read()
        except OSError:
            continue
        for m in re.finditer(r"pub use (?:crate::|self::)?%s::(\{[^}]*\}|\w+)" % mod, src):
            for item in m.group(1).strip("{}").split(","):
                name = item.strip().split(" as ")[-1].strip()
                if re.fullmatch(r"[A-Za-z_]\w*", name) and name != "self":
                    out.append(name)
    return sorted(set(out))


def all_ignored(test_file: str) -> bool:
    """Whether every test in `test_file` carries `#[ignore]` (a live-infrastructure
    suite): naming its target as `--it` compiles it and runs zero tests."""
    try:
        src = open(test_file, encoding="utf-8").read()
    except OSError:
        return False
    tests = len(re.findall(r"#\[(?:tokio::)?test\b", src))
    return tests > 0 and len(re.findall(r"#\[ignore\b", src)) >= tests


def it_target(root: str, test_file: str) -> str:
    """The Bazel test target(s) a file under `<root>/tests/` is compiled into, as the
    labels `--it` takes. A shared module (`tests/<dir>/…`) can belong to several."""
    import rust_gate  # noqa: PLC0415 — only the Rust branch needs the build graph
    labels = [t for t in rust_gate.compiling_targets([test_file])
              if t in set(rust_gate.query('kind("^rust_test rule$", //%s/...)' % root))]
    return ",".join(labels) or "(no Bazel test target compiles it)"


def rust_module(path: str) -> str:
    """The module name other files write in a path to `path`'s items."""
    stem = os.path.splitext(os.path.basename(path))[0]
    return os.path.basename(os.path.dirname(path)) if stem in ("mod", "lib", "main") else stem


def _rs_binds(cand: str, own: str, src: str) -> bool:
    """Whether `cand` can name `own`'s items: it sits in the same module directory
    (`super::` / sibling access) or spells the module in a path. A heuristic, not
    name resolution — a glob re-export through a third module is missed."""
    if os.path.dirname(cand) == os.path.dirname(own):
        return True
    mod = rust_module(own)
    if re.search(r"\b%s::|::%s\b" % (re.escape(mod), re.escape(mod)), src):
        return True
    # Another crate reaching the item through the crate root's re-export.
    crate = rust_crate(own) or ""
    return bool(crate) and not cand.startswith(component_root(own) + "/src/") \
        and re.search(r"\b%s::" % re.escape(crate), src) is not None


def usages(sym: str, own: str, lang_globs: list[str], max_sites: int) -> dict:
    """Production and test uses of `sym`, with the first sites ranked by weight.

    Candidates come from `git grep -l -w` over tracked files — it cannot wander
    into `.venv`, `dist/` or a build cache, which is what made the evaluators'
    own greps need `| grep -v .venv` tails. For Python each candidate is then
    confirmed by `_py_sites`; Rust has no binding check and is text-classified,
    so a Rust count is an UPPER bound and says so.
    """
    p = subprocess.run(["git", "grep", "-l", "-I", "-w", "-e", sym, "--", *lang_globs],
                       capture_output=True, text=True)
    if p.returncode not in (0, 1):
        return {"error": (p.stderr or "git grep failed").strip()[:200]}
    pkg = top_package(own)
    prod: dict[str, int] = {"import": 0, "construct": 0, "subclass": 0, "ref": 0}
    tests = 0
    sites: list[tuple[int, str]] = []
    rank = {"subclass": 0, "construct": 1, "ref": 2, "import": 3}
    for cand in p.stdout.splitlines():
        if cand == own:
            continue
        try:
            src = open(cand, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        lines = src.splitlines()
        if cand.endswith(".py") and pkg:
            found = _py_sites(sym, cand, pkg, src)
        elif cand.endswith(".rs"):
            if not _rs_binds(cand, own, src):
                continue
            found = [(_kind(sym, lines[i]), i + 1) for i, ln in enumerate(lines)
                     if re.search(r"\b%s\b" % re.escape(sym), ln) and not _RUST_COMMENT.match(ln)]
        else:
            found = [(_kind(sym, lines[i]), i + 1) for i, ln in enumerate(lines)
                     if re.search(r"\b%s\b" % re.escape(sym), ln)]
        if not found:
            continue
        if _is_test(cand):
            tests += len(found)
            continue
        for k, ln in found:
            prod[k] += 1
            text = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
            sites.append((rank[k], "%s:%d [%s] %s" % (cand, ln, k, text[:140])))
    sites.sort(key=lambda s: s[0])
    total = len(sites)
    return {"prod": prod, "tests": tests, "bound": bool(pkg and own.endswith(".py")),
            "sites": [s for _, s in sites[:max_sites]],
            "truncated": total > max_sites, "total_prod_sites": total}


def owning_build(path: str) -> str | None:
    d = os.path.dirname(path)
    while d:
        cand = os.path.join(d, "BUILD.bazel")
        if os.path.exists(cand):
            return cand
        d = os.path.dirname(d)
    return None


def component_root(path: str) -> str:
    """The component/application directory: the parent of the `src` segment."""
    parts = path.split("/")
    if "src" in parts:
        return "/".join(parts[:parts.index("src")])
    return os.path.dirname(path)


def rust_crate(path: str) -> str | None:
    """The crate `path` belongs to, as the Bazel library targets name it."""
    from rust_resolver import RustResolver  # noqa: PLC0415
    return RustResolver(".").crate_of(path)


SIZE_GATE = "scripts/module_size_gate.py"


def module_size(path: str, src: str) -> str | None:
    """The module-size ratchet's view of this file, from the gate's own counter —
    so a fix is sized against the limit the per-file gate will enforce."""
    if not os.path.isfile(SIZE_GATE):
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("module_size_gate", SIZE_GATE)
    if spec is None or spec.loader is None:
        return None
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    loc = gate.production_lines(src)
    entry = gate.load_registry(gate.REGISTRY).get(path)
    if entry:
        base = entry.get("baseline_prod_loc")
        return ("%d production lines; registered %s at baseline %s — headroom %d, and the "
                "gate fails the file if it grows past the baseline"
                % (loc, entry.get("status"), base, (base or 0) - loc))
    return ("%d production lines; threshold %d — headroom %d%s"
            % (loc, gate.THRESHOLD, gate.THRESHOLD - loc,
               "" if loc <= gate.THRESHOLD else " (OVER: already failing?)"))


def rust_inline_tests(src: str) -> int:
    """`#[test]` functions inside the file's own test region."""
    m = _RUST_TEST_REGION.search(src)
    return len(re.findall(r"#\[(?:tokio::)?test\b", src[m.start():])) if m else 0


def test_candidates(path: str) -> list[str]:
    if path.endswith(".rs"):
        # Integration tests reach a crate's items through a module path, so a test
        # file is a candidate when it spells this file's module, whatever it is named.
        # They also reach it through the names the crate root re-exports from it
        # (`pub use aws_kms_keysource::AwsKmsEd25519Backend;` → `mcp_re_proxy::AwsKms…`),
        # which spell no module at all.
        root = component_root(path) or "."
        names = [re.escape(rust_module(path)) + "::"] + [re.escape(n) for n in root_reexports(path)]
        pattern = r"(^|[^A-Za-z0-9_])(%s)([^A-Za-z0-9_]|$)" % "|".join(names)
        p = subprocess.run(["git", "grep", "-l", "-E", pattern,
                            "--", os.path.join(root, "tests")], capture_output=True, text=True)
        hits = sorted(p.stdout.split())
        return ["%s [%s]" % (f, "every test #[ignore]d — measures nothing in a local gate"
                             if all_ignored(f) else "--it " + it_target(root, f))
                for f in hits[:10]] + \
            (["… %d more, truncated" % (len(hits) - 10)] if len(hits) > 10 else [])
    stem = os.path.splitext(os.path.basename(path))[0]
    root = component_root(path) or "."
    p = subprocess.run(["git", "ls-files", "--", root], capture_output=True, text=True)
    out = []
    for f in p.stdout.splitlines():
        if not _is_test(f) or f == path:
            continue
        b = os.path.basename(f)
        if stem in b:
            out.append(f)
    return sorted(out)[:10]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--packets", default=None)
    ap.add_argument("--file", required=True)
    ap.add_argument("--max-sites", type=int, default=20)
    ap.add_argument("--max-symbols", type=int, default=25)
    ap.add_argument("--max-lines", type=int, default=2000)
    ap.add_argument("--max-note", type=int, default=1500)
    a = ap.parse_args()

    if not os.path.exists(a.file):
        print("prepare: %s does not exist in this tree — every finding on it is a "
              "`superseded` candidate" % a.file)
        return 2
    src = open(a.file, encoding="utf-8", errors="replace").read()
    lines = src.splitlines()
    joined = collect(a.ledger, a.file, a.packets)
    findings = joined["findings"]
    out: list[str] = []
    w = out.append

    w("# PREPARE %s" % a.file)
    w("findings: %d actionable   packet_found: %s   liveness: %s"
      % (joined["n"], joined["packet_found"], joined.get("liveness")))
    w("")
    w("## 1. Findings (critical -> low)")
    for f in findings:
        w("")
        w("### %s  [%s/%s]  %s  status=%s" % (f["id"], f.get("severity"), f.get("category"),
                                             f.get("title"), f.get("status")))
        for k in ("claim", "impact", "suggested_remediation", "confidence", "lens",
                  "reported_by"):
            if f.get(k):
                w("- %s: %s" % (k, f[k]))
        if f.get("notes"):
            # A prior adjudication or ruling can run to pages and is repeated on
            # every sibling finding; the head carries the decision, the ledger
            # carries the rest.
            note = str(f["notes"])
            w("- prior notes: %s%s" % (note[:a.max_note],
                                       " … (TRUNCATED at %d of %d chars — `file_findings.py` has it all)"
                                       % (a.max_note, len(note)) if len(note) > a.max_note else ""))
        if f.get("evidence_anchor"):
            w("- evidence (verbatim, from the audit pin):")
            for ln in str(f["evidence_anchor"]).splitlines():
                w("    " + ln)

    w("")
    w("## 2. Anchors in the CURRENT source (line numbers from the audit pin drift; these do not)")
    for f in findings:
        loc = locate(f.get("evidence_anchor"), lines)
        where = (" at L" + ",".join(map(str, loc["lines"]))) if loc.get("lines") else ""
        w("- %s: %s%s%s" % (f["id"], loc["state"], where,
                           ("  — " + loc["detail"]) if loc.get("detail") else ""))

    w("")
    w("## 3. Build and tests")
    w("- owning BUILD.bazel: %s" % (owning_build(a.file) or "NONE FOUND"))
    if a.file.endswith(".rs"):
        import rust_gate  # noqa: PLC0415
        compiled_by = rust_gate.compiling_targets([a.file])
        w("- crate: %s   in-file #[test] fns: %d" % (rust_crate(a.file) or "NONE FOUND",
                                                     rust_inline_tests(src)))
        w("- Bazel targets compiling it: %s" % (", ".join(compiled_by) or "NONE FOUND"))
        w("- unit-test targets: %s" % (", ".join(rust_gate.unit_test_targets(compiled_by))
                                       or "NONE FOUND"))
        size = module_size(a.file, src)
        if size:
            w("- module size: " + size)
    w("- component root: %s   (bazel tree //%s/...)" % (component_root(a.file),
                                                        component_root(a.file)))
    tests = test_candidates(a.file)
    w("- %s: %s" % ("integration tests naming this module" if a.file.endswith(".rs")
                     else "test modules whose name contains the file stem",
                     ", ".join(tests) if tests else "NONE — a behaviour-changing fix needs one created"))

    w("")
    lang_globs = ["*.py"] if a.file.endswith(".py") else ["*.rs"] if a.file.endswith(".rs") else ["*"]
    syms = _prioritise(defined_symbols(a.file, src), findings)
    w("## 4. Usage map — tracked %s files that import each name from `%s` (reach: no "
      "string-keyed factories, no getattr, no `import pkg` + attribute access, no untracked "
      "files%s)" % ("/".join(lang_globs),
                    rust_module(a.file) if a.file.endswith(".rs") else top_package(a.file) or "?",
                    "" if a.file.endswith(".py") else
                    "; Rust: a file counts only if it sits beside this one or spells the module "
                    "in a path — text sites, an approximation of name resolution"))
    if len(syms) > a.max_symbols:
        w("(TRUNCATED: %d of %d symbols shown — finding-named symbols first)"
          % (a.max_symbols, len(syms)))
    if not syms:
        w("- no top-level public symbols")
    for s in syms[:a.max_symbols]:
        u = usages(s, a.file, lang_globs, a.max_sites)
        if "error" in u:
            w("- %s: ERROR %s" % (s, u["error"]))
            continue
        c = u["prod"]
        w("- %s: prod import=%d construct=%d subclass=%d ref=%d | tests=%d"
          % (s, c["import"], c["construct"], c["subclass"], c["ref"], u["tests"]))
        for site in u["sites"]:
            w("    " + site)
        if u["truncated"]:
            w("    (TRUNCATED: %d of %d production sites shown)" % (a.max_sites, u["total_prod_sites"]))

    w("")
    shown = lines[:a.max_lines]
    w("## 5. Source — %s (%d lines%s)" % (a.file, len(lines),
                                         ", TRUNCATED at %d: Read the rest" % a.max_lines
                                         if len(lines) > a.max_lines else ""))
    width = len(str(len(shown)))
    for i, ln in enumerate(shown, 1):
        w("%*d  %s" % (width, i, ln))

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
