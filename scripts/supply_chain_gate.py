#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Supply-chain gate — `config/supply-chain.toml` over the crates Bazel builds.

The graph is the Bazel build graph, not a manifest's view of it: the third-party crates
`bazel query 'deps(//...)'` reaches through the `crates_mcp_re` hub, for the platforms
MODULE.bazel's crate universe supports. That is every crate the proxy, the SDK native
modules and the mock PKCS#11 provider compile — build-script and proc-macro dependencies
included — and nothing a platform we never build for would pull in. Each crate's version,
source and dependency edges come from `bazel/crates.lock`; its license from the manifest
Bazel fetched (the crate repository's `cargo_toml_env_vars` target).

Checks, each over that graph:

  * SOURCES     every crate comes from an allowed registry; none from git or elsewhere.
  * LICENSES    every crate's SPDX expression is satisfiable by the allow-list.
  * BANS        a `deny-multiple-versions` crate appears at one version (outside a
                `skip-tree` subtree); a `crate.spec` is never `*`. Other duplicates are
                listed, not failed.
  * ADVISORIES  no crate version is affected by a RustSec vulnerability, unmaintained or
                unsound advisory (not withdrawn, not in `ignore`), and none is yanked
                on crates.io.

ADVISORIES needs the network: the RustSec database (`--advisory-db`, a checkout of
github.com/rustsec/advisory-db) and the crates.io sparse index. The workflow runs it
daily, because the database moves independently of this repository.

    python3 scripts/supply_chain_gate.py --advisory-db DIR   # the verdict
    python3 scripts/supply_chain_gate.py --selftest          # prove each check can FAIL
    python3 scripts/supply_chain_gate.py --list              # crate, version, license
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "config" / "supply-chain.toml"
LOCK = REPO / "bazel" / "crates.lock"
MODULE = REPO / "MODULE.bazel"
HUB = "crates_mcp_re__"
INDEX = "https://index.crates.io"
POLICY_KEYS = {
    "sources": {"allow-registry"},
    "advisories": {"ignore"},
    "licenses": {"allow"},
    "bans": {"deny-multiple-versions", "deny-wildcard-specs", "skip-tree"},
}
DENIED_CLASSES = {None, "unmaintained", "unsound"}


# --- semver ---------------------------------------------------------------------------

def parse_version(text: str) -> tuple[int, int, int, tuple]:
    core, _, pre = text.split("+", 1)[0].partition("-")
    major, minor, patch = (int(p) for p in core.split("."))
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")) if pre else ()
    return major, minor, patch, ids


def _key(v: tuple[int, int, int, tuple]) -> tuple:
    # A release outranks every pre-release of the same core.
    return v[:3] + ((1,) if not v[3] else (0, v[3]))


def _bounds(op: str, text: str) -> list[tuple[str, tuple]]:
    """One comparator as a conjunction of (op, full version) primitives."""
    parts = text.split("-", 1)[0].split(".")
    pre = text.split("-", 1)[1] if "-" in text else ""
    nums = [int(p) for p in parts if p not in ("*", "x", "X")]
    full = lambda a, b, c, p="": parse_version(f"{a}.{b}.{c}" + (f"-{p}" if p else ""))  # noqa: E731
    major, minor, patch = (nums + [0, 0, 0])[:3]
    n = len(nums)
    if op == "*" or n == 0:
        return []
    if op == "=" or (op == "~" and n < 3):
        if n == 3:
            return [("=", full(major, minor, patch, pre))]
        upper = full(major + 1, 0, 0) if n == 1 else full(major, minor + 1, 0)
        return [(">=", full(major, minor, 0)), ("<", upper)]
    if op == "~":
        return [(">=", full(major, minor, patch, pre)), ("<", full(major, minor + 1, 0))]
    if op == "^":
        lower = (">=", full(major, minor, patch, pre))
        if major > 0 or n == 1:
            return [lower, ("<", full(major + 1, 0, 0))]
        if minor > 0 or n == 2:
            return [lower, ("<", full(0, minor + 1, 0))]
        return [lower, ("<", full(0, 0, patch + 1))]
    if op == ">":
        if n == 3:
            return [(">", full(major, minor, patch, pre))]
        return [(">=", full(major + 1, 0, 0) if n == 1 else full(major, minor + 1, 0))]
    if op == ">=":
        return [(">=", full(major, minor, patch, pre))]
    if op == "<":
        return [("<", full(major, minor, patch, pre))]
    if op == "<=":
        if n == 3:
            return [("<=", full(major, minor, patch, pre))]
        return [("<", full(major + 1, 0, 0) if n == 1 else full(major, minor + 1, 0))]
    raise ValueError(f"unknown comparator {op!r}")


def matches(req: str, version: str) -> bool:
    """Cargo's requirement semantics, as RustSec's `patched`/`unaffected` lists use them."""
    v = parse_version(version)
    prims = []
    for comp in (c.strip() for c in req.split(",") if c.strip()):
        m = re.fullmatch(r"(>=|<=|>|<|=|\^|~)?\s*(\S+)", comp)
        if not m:
            raise ValueError(f"unparseable requirement {req!r}")
        text = m.group(2)
        prims += _bounds(m.group(1) or ("*" if text == "*" else "^"), text)
    for op, bound in prims:
        a, b = _key(v), _key(bound)
        if not {"=": a == b, ">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op]:
            return False
    # A pre-release matches only a comparator naming a pre-release of the same core.
    return not v[3] or any(bound[3] and bound[:3] == v[:3] for _, bound in prims)


# --- SPDX -----------------------------------------------------------------------------

def _tokens(expr: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", expr.replace("/", " OR "))


def license_allowed(expr: str, allow: set[str]) -> bool:
    """Whether some choice the expression offers is made of allowed licenses only."""
    toks = _tokens(expr)
    if not toks:
        return False
    pos = 0

    def atom() -> bool:
        nonlocal pos
        tok = toks[pos]
        pos += 1
        if tok == "(":
            value = disjunction()
            if pos >= len(toks) or toks[pos] != ")":
                raise ValueError(f"unbalanced SPDX expression {expr!r}")
            pos += 1
            return value
        ident = tok.rstrip("+")
        if pos < len(toks) and toks[pos] == "WITH":
            exception = toks[pos + 1]
            pos += 2
            return f"{ident} WITH {exception}" in allow
        return ident in allow

    def conjunction() -> bool:
        nonlocal pos
        value = atom()
        while pos < len(toks) and toks[pos] == "AND":
            pos += 1
            value = atom() and value
        return value

    def disjunction() -> bool:
        nonlocal pos
        value = conjunction()
        while pos < len(toks) and toks[pos] == "OR":
            pos += 1
            value = conjunction() or value
        return value

    result = disjunction()
    if pos != len(toks):
        raise ValueError(f"trailing tokens in SPDX expression {expr!r}")
    return result


# --- the graph ------------------------------------------------------------------------

def lock_packages(lock_text: str) -> dict[tuple[str, str], dict]:
    return {(p["name"], p["version"]): p for p in tomllib.loads(lock_text).get("package", [])}


def resolve_edges(packages: dict[tuple[str, str], dict]) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """Each package's dependencies as (name, version); a lock names the version only
    when the name alone is ambiguous."""
    by_name: dict[str, list[str]] = {}
    for name, version in packages:
        by_name.setdefault(name, []).append(version)
    edges = {}
    for key, pkg in packages.items():
        out = []
        for dep in pkg.get("dependencies", []):
            name, _, rest = dep.partition(" ")
            version = rest.split(" ", 1)[0] if rest else by_name[name][0]
            out.append((name, version))
        edges[key] = out
    return edges


def repo_key(repo: str, packages: dict[tuple[str, str], dict]) -> tuple[str, str] | None:
    """`<hub>__<name>-<version>` (build metadata's `+` spelled `-`) to its lock key."""
    for name, version in packages:
        if repo == f"{name}-{version.replace('+', '-')}":
            return name, version
    return None


def bazel(*args: str) -> str:
    proc = subprocess.run(["bazel", *args], cwd=REPO, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"supply-chain gate: `bazel {args[0]}` failed\n{proc.stderr[-2000:]}")
    return proc.stdout


def build_graph() -> dict[str, str]:
    """The hub crates the build graph reaches, as {canonical repo: '<name>-<version>'}."""
    labels = bazel("query", "--output=label", "deps(//...)").split()
    repos = {}
    for label in labels:
        repo = label.split("//", 1)[0]
        if HUB in repo:
            repos[repo] = repo.split(HUB, 1)[1]
    return repos


def crate_licenses(repos: dict[str, str]) -> dict[str, str]:
    targets = [f"{repo}//:cargo_toml_env_vars" for repo in sorted(repos)]
    bazel("build", *targets)
    exec_root = bazel("info", "execution_root").strip()
    files = bazel("cquery", "--output=files", "set(%s)" % " ".join(targets)).split()
    out = {}
    for f in files:
        env = dict(line.split("=", 1) for line in (Path(exec_root) / f).read_text().splitlines() if "=" in line)
        out[f"{env['CARGO_PKG_NAME']}-{env['CARGO_PKG_VERSION']}"] = env.get("CARGO_PKG_LICENSE", "")
    return out


# --- the checks -----------------------------------------------------------------------

def check_policy_keys(policy: dict) -> list[str]:
    problems = [f"POLICY: unknown section [{s}]" for s in policy if s not in POLICY_KEYS]
    for section, keys in POLICY_KEYS.items():
        problems += [f"POLICY: [{section}] {k} is not a key this gate enforces"
                     for k in policy.get(section, {}) if k not in keys]
    return problems


def check_sources(graph: list[tuple[str, str]], packages: dict, allowed: list[str]) -> list[str]:
    ok = {f"registry+{r}" for r in allowed}
    return [f"SOURCES: {n} {v} comes from {packages[(n, v)].get('source') or 'no recorded source'}"
            for n, v in graph if packages[(n, v)].get("source") not in ok]


def check_licenses(graph: list[tuple[str, str]], licenses: dict[str, str], allow: set[str]) -> list[str]:
    problems = []
    for n, v in graph:
        expr = licenses.get(f"{n}-{v}")
        if expr is None:
            problems.append(f"LICENSES: {n} {v}: no manifest license was read")
        elif not expr:
            problems.append(f"LICENSES: {n} {v} declares no SPDX license expression")
        elif not license_allowed(expr, allow):
            problems.append(f"LICENSES: {n} {v} is `{expr}`, which the allow-list does not satisfy")
    return problems


def skipped(skip_trees: list[dict], edges: dict, graph: set[tuple[str, str]]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for tree in skip_trees:
        roots = [k for k in graph if k[0] == tree["name"] and matches("=" + tree["version"], k[1])]
        frontier = [(r, 0) for r in roots]
        while frontier:
            node, depth = frontier.pop()
            if node in out or depth > tree["depth"]:
                continue
            out.add(node)
            frontier += [(d, depth + 1) for d in edges.get(node, [])]
    return out


def check_bans(graph: list[tuple[str, str]], edges: dict, bans: dict, module_text: str) -> tuple[list[str], list[str]]:
    exempt = skipped(bans.get("skip-tree", []), edges, set(graph))
    versions: dict[str, set[str]] = {}
    for n, v in graph:
        if (n, v) not in exempt:
            versions.setdefault(n, set()).add(v)
    problems, notes = [], []
    for name, vs in sorted(versions.items()):
        if len(vs) < 2:
            continue
        line = f"{name}: {', '.join(sorted(vs, key=lambda x: _key(parse_version(x))))}"
        (problems if name in bans.get("deny-multiple-versions", []) else notes).append(line)
    problems = [f"BANS: more than one version of a single-version crate — {p}" for p in problems]
    if bans.get("deny-wildcard-specs"):
        for body in re.findall(r"^crate\.spec\((.*?)^\)", module_text, re.M | re.S):
            if re.search(r'version = "\*"', body):
                name = re.search(r'package = "([^"]+)"', body)
                problems.append(f"BANS: crate.spec `{name.group(1) if name else body.strip()}` "
                                "requires version `*`")
    return problems, notes


def advisory(text: str) -> dict:
    body = re.search(r"```toml\n(.*?)\n```", text, re.S)
    return tomllib.loads(body.group(1)) if body else {}


def affected(adv: dict, version: str) -> bool:
    reqs = adv.get("versions", {})
    return not any(matches(r, version) for r in reqs.get("patched", []) + reqs.get("unaffected", []))


def check_advisories(graph: list[tuple[str, str]], db: Path, ignore: set[str]) -> list[str]:
    problems = []
    names = {n for n, _ in graph}
    for path in sorted((db / "crates").glob("*/*.md")):
        if path.parent.name not in names:
            continue
        adv = advisory(path.read_text(encoding="utf-8"))
        meta = adv.get("advisory", {})
        if not meta:
            problems.append(f"ADVISORIES: {path.relative_to(db)} names a crate in the graph and "
                            "holds no readable [advisory] block — an advisory not read is not cleared")
            continue
        if meta.get("withdrawn") or meta.get("id") in ignore:
            continue
        if meta.get("informational") not in DENIED_CLASSES:
            continue
        for n, v in graph:
            if n == meta.get("package") and affected(adv, v):
                kind = meta.get("informational") or "vulnerability"
                problems.append(f"ADVISORIES: {n} {v} — {meta['id']} ({kind}): {meta.get('title', '')}")
    return problems


def index_path(name: str) -> str:
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def yanked_versions(name: str) -> set[str]:
    with urllib.request.urlopen(f"{INDEX}/{index_path(name)}", timeout=30) as resp:
        entries = [json.loads(line) for line in resp.read().decode().splitlines() if line.strip()]
    return {e["vers"] for e in entries if e.get("yanked")}


def check_yanked(graph: list[tuple[str, str]]) -> list[str]:
    names = sorted({n for n, _ in graph})
    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            yanked = dict(zip(names, pool.map(yanked_versions, names)))
    except urllib.error.URLError as err:
        raise SystemExit(f"supply-chain gate: the crates.io index is unreachable ({err}); "
                         "a yanked check that could not run is not a pass")
    return [f"ADVISORIES: {n} {v} is yanked on crates.io" for n, v in graph if v in yanked[n]]


def inventory() -> int:
    """The graph as a table: every crate the build reaches, with its license."""
    packages = lock_packages(LOCK.read_text())
    repos = build_graph()
    licenses = crate_licenses(repos)
    rows = sorted(k for k in (repo_key(s, packages) for s in repos.values()) if k)
    for name, version in rows:
        print(f"{name}\t{version}\t{licenses.get(f'{name}-{version}', '')}")
    print(f"{len(rows)} crate(s)", file=sys.stderr)
    return 0 if rows else 1


def verdict(advisory_db: Path) -> int:
    policy = tomllib.loads(POLICY.read_text())
    problems = check_policy_keys(policy)
    packages = lock_packages(LOCK.read_text())
    edges = resolve_edges(packages)
    repos = build_graph()
    graph, unknown = [], []
    for spelled in sorted(repos.values()):
        key = repo_key(spelled, packages)
        (graph.append(key) if key else unknown.append(spelled))
    problems += [f"GRAPH: {u} is built but bazel/crates.lock does not pin it" for u in unknown]
    if not graph:
        problems.append("GRAPH: the build graph reached no third-party crate — assessing nothing is not a pass")

    problems += check_sources(graph, packages, policy["sources"]["allow-registry"])
    problems += check_licenses(graph, crate_licenses(repos), set(policy["licenses"]["allow"]))
    ban_problems, duplicates = check_bans(graph, edges, policy["bans"], MODULE.read_text())
    problems += ban_problems
    if not (advisory_db / "crates").is_dir():
        problems.append(f"ADVISORIES: {advisory_db} is not a RustSec advisory-db checkout")
    else:
        problems += check_advisories(graph, advisory_db, set(policy["advisories"]["ignore"]))
    problems += check_yanked(graph)

    for d in duplicates:
        print(f"supply-chain gate: note — duplicate versions (allowed): {d}")
    if problems:
        print(f"supply-chain gate: FAIL — {len(problems)} problem(s) over {len(graph)} crate(s)")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"supply-chain gate: OK — {len(graph)} crate(s) in the Bazel build graph: sources, "
          f"licenses, bans, RustSec advisories and yanked versions all pass "
          f"({len(duplicates)} allowed duplicate(s) listed above)")
    return 0


# --- selftest -------------------------------------------------------------------------

def selftest() -> int:
    """Every check asserted in BOTH directions: a check that always fails passes the
    failing half, and one that never fires passes the passing half."""
    failures = []

    def expect(what: str, got, want) -> None:
        if got != want:
            failures.append(f"{what}: got {got!r}, want {want!r}")

    for req, version, want in (
        (">= 1.2.3", "1.2.3", True), (">= 1.2.3", "1.2.2", False),
        ("^0.9.7", "0.9.9", True), ("^0.9.7", "0.10.0", False),
        ("^1.2", "1.9.0", True), ("^1.2", "2.0.0", False), ("^0.0.3", "0.0.4", False),
        ("~1.2.3", "1.2.9", True), ("~1.2.3", "1.3.0", False),
        (">= 1.0.0, < 1.4.2", "1.4.1", True), (">= 1.0.0, < 1.4.2", "1.4.2", False),
        ("> 1.2", "1.3.0", True), ("> 1.2", "1.2.9", False), ("<= 1.2", "1.2.7", True),
        ("= 0.2.1", "0.2.1", True), ("= 0.2.1", "0.2.2", False),
        (">= 1.0.0", "2.0.0-rc.1", False), (">= 2.0.0-rc.0", "2.0.0-rc.1", True),
        ("*", "7.1.0", True), ("1.2.3", "1.5.0", True),
    ):
        expect(f"matches({req!r}, {version!r})", matches(req, version), want)

    allow = {"MIT", "Apache-2.0", "ISC", "Apache-2.0 WITH LLVM-exception"}
    for expr, want in (
        ("MIT", True), ("GPL-3.0", False), ("MIT OR GPL-3.0", True), ("GPL-3.0 OR MIT", True),
        ("Apache-2.0 AND ISC", True), ("Apache-2.0 AND GPL-3.0", False),
        ("(MIT OR GPL-3.0) AND ISC", True), ("(GPL-3.0 OR LGPL-2.1) AND MIT", False),
        ("Apache-2.0 WITH LLVM-exception", True), ("MIT WITH LLVM-exception", False),
        ("MIT/Apache-2.0", True), ("Apache-2.0+", True), ("", False),
    ):
        expect(f"license_allowed({expr!r})", license_allowed(expr, allow), want)

    lock = ('version = 4\n'
            '[[package]]\nname = "ocsp"\nversion = "0.2.1"\nsource = "registry+R"\n'
            'dependencies = ["digest 0.10.7"]\n'
            '[[package]]\nname = "top"\nversion = "1.0.0"\nsource = "registry+R"\n'
            'dependencies = ["digest 0.11.0", "ocsp"]\n'
            '[[package]]\nname = "digest"\nversion = "0.10.7"\nsource = "registry+R"\n'
            '[[package]]\nname = "digest"\nversion = "0.11.0"\nsource = "registry+R"\n'
            '[[package]]\nname = "gitdep"\nversion = "0.1.0"\nsource = "git+https://x"\n')
    packages = lock_packages(lock)
    edges = resolve_edges(packages)
    expect("resolve_edges(unambiguous)", edges[("top", "1.0.0")], [("digest", "0.11.0"), ("ocsp", "0.2.1")])
    graph = [("ocsp", "0.2.1"), ("top", "1.0.0"), ("digest", "0.10.7"), ("digest", "0.11.0")]
    bans = {"deny-multiple-versions": ["digest"], "deny-wildcard-specs": True}
    expect("bans without skip-tree", len(check_bans(graph, edges, bans, "")[0]), 1)
    bans["skip-tree"] = [{"name": "ocsp", "version": "0.2.1", "depth": 1}]
    expect("bans with skip-tree", check_bans(graph, edges, bans, "")[0], [])
    bans["skip-tree"] = [{"name": "ocsp", "version": "0.2.1", "depth": 0}]
    expect("skip-tree depth is bounded", len(check_bans(graph, edges, bans, "")[0]), 1)
    wildcard = 'crate.spec(\n    package = "any",\n    version = "*",\n)\n'
    expect("wildcard spec", len(check_bans([], {}, bans, wildcard)[0]), 1)
    expect("pinned spec", check_bans([], {}, bans, wildcard.replace('"*"', '"1"'))[0], [])

    expect("sources: registry", check_sources([("top", "1.0.0")], packages, ["R"]), [])
    expect("sources: git", len(check_sources([("gitdep", "0.1.0")], packages, ["R"])), 1)
    expect("licenses: allowed", check_licenses([("top", "1.0.0")], {"top-1.0.0": "MIT"}, allow), [])
    expect("licenses: denied", len(check_licenses([("top", "1.0.0")], {"top-1.0.0": "GPL-3.0"}, allow)), 1)
    expect("licenses: none", len(check_licenses([("top", "1.0.0")], {"top-1.0.0": ""}, allow)), 1)

    doc = ('```toml\n[advisory]\nid = "RUSTSEC-0000-0001"\npackage = "top"\ntitle = "t"\n'
           '%s\n[versions]\npatched = [">= 1.0.1"]\n```\n')
    expect("advisory: affected", affected(advisory(doc % ""), "1.0.0"), True)
    expect("advisory: patched", affected(advisory(doc % ""), "1.0.1"), False)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "crates" / "top").mkdir(parents=True)
        adv = root / "crates" / "top" / "RUSTSEC-0000-0001.md"
        cases = (("", 1, set()), ("", 0, {"RUSTSEC-0000-0001"}), ('informational = "unmaintained"', 1, set()),
                 ('informational = "notice"', 0, set()), ('withdrawn = "2020-01-01"', 0, set()))
        for extra, want, ignore in cases:
            adv.write_text(doc % extra)
            expect(f"check_advisories({extra or 'vulnerability'}, ignore={sorted(ignore)})",
                   len(check_advisories([("top", "1.0.0")], root, ignore)), want)
        adv.write_text("# RUSTSEC-0000-0001\n\nNo front matter.\n")
        expect("check_advisories(unreadable)",
               [p.split(" names ")[0] for p in check_advisories([("top", "1.0.0")], root, set())],
               ["ADVISORIES: crates/top/RUSTSEC-0000-0001.md"])

    expect("index_path(a)", index_path("a"), "1/a")
    expect("index_path(abc)", index_path("abc"), "3/a/abc")
    expect("index_path(Serde)", index_path("Serde"), "se/rd/serde")
    expect("policy: unknown key", len(check_policy_keys({"bans": {"multiple-versions": "warn"}})), 1)
    expect("policy: the committed file", check_policy_keys(tomllib.loads(POLICY.read_text())), [])

    if failures:
        print("supply-chain gate selftest: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("supply-chain gate selftest: PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="supply-chain gate over the Bazel build graph")
    ap.add_argument("--advisory-db", type=Path, help="a checkout of github.com/rustsec/advisory-db")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--list", action="store_true", help="print the graph's crates and licenses")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.list:
        return inventory()
    if a.advisory_db is None:
        ap.error("--advisory-db is required: the advisory check is part of the verdict")
    return verdict(a.advisory_db)


if __name__ == "__main__":
    sys.exit(main())
