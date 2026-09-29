#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""No-Cargo-execution gate — Bazel is the Rust build and test authority, and nothing else runs.

THE INVARIANT. No CI workflow, repository script or tool, hook, verification lane,
remediation or audit skill, test harness, SLO or release path, container definition or
maintained developer command may invoke the `cargo` executable — directly, or through a
tool whose job is to drive it. Rust build and test execution is Bazel's. `Cargo.toml`,
lockfiles and prose are not violations: this gate reads INVOCATIONS, never mentions.

WHAT COUNTS AS AN INVOCATION, per context:

  * shell — workflow `run:` blocks, `*.sh`, Dockerfile `RUN`, Makefiles, hook entries,
    package.json scripts, and the fenced shell blocks of the maintained command documents:
    `cargo` or a `cargo-<tool>` binary in command position, and the wrappers that drive
    Cargo — `rustup run <toolchain> cargo`, `$CARGO`/`${CARGO}`, `napi build`,
    `maturin build|develop|publish`, `charon cargo`, `cross build|test`. Comments and
    `echo`/`printf` lines state a command without running it.
  * Python — an argv list whose first element is `cargo` or a `cargo-<tool>` (or ends in
    `/cargo`), a shell string beginning with one, and a `charon` argv followed by `cargo`.
  * Rust — `Command::new("cargo")`, or spawning `env!("CARGO")` / `var("CARGO")`.
  * JavaScript/TypeScript — `exec`/`spawn` of `cargo`, `napi build`, `maturin`.
  * TOML registries — an argv array (`protocol`, `control`, `argv`, `command`) whose first
    element is `cargo`.
  * pyproject.toml — a `maturin` build backend.

WHAT IS NOT READ: history. Archived documents, the changelog, dated review packets, rulings,
security audit records and finding ledgers describe what was run then; rewriting them would
falsify the record, and none of them is executed.

    python3 scripts/no_cargo_execution_gate.py            # the verdict
    python3 scripts/no_cargo_execution_gate.py --selftest # prove each rule can FAIL
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Directories and files that record history rather than state a command to run.
HISTORY = (
    "docs/archive/",
    "docs/security/",
    "docs/adr/",
    "docs/releases/",
    "docs/bench/",
    "verification/reviews/",
    "verification/claim-corrections/",
    "work/",
    "CHANGELOG.md",
)

#: The documents whose fenced shell blocks are maintained commands someone — or an agent —
#: is told to run.
COMMAND_DOCS = re.compile(
    r"^(?:CLAUDE\.md|AGENTS\.md|CONTRIBUTING\.md|README\.md|[^/]+/README\.md|sdk/[^/]+/README\.md"
    r"|docs/dev/.+\.md|docs/AGENT_INSTRUCTIONS\.md|tools/[^/]+/README\.md|tools/verification/README\.md"
    r"|verification/README\.md|verification/[^/]+/README\.md|\.claude/.+\.md)$"
)

_CARGO_BIN = r"cargo(?:-[a-z][a-z0-9-]*)?"
#: A shell command word position: line start, or after a separator, a subshell or a prefix
#: that runs its argument (`env`, `exec`, `time`, `timeout N`, `xargs`, `sudo`, a
#: `VAR=value` assignment).
_PREFIX = r"(?:(?:env|exec|time|nice|sudo|xargs(?:\s+-\S+)*|timeout\s+\S+|[A-Z_][A-Z0-9_]*=\S*)\s+)*"
_POSITION = r"(?:^\s*(?:RUN\s+)?|[;&|(`]|\$\(|\bthen\b|\bdo\b|\belse\b|\{)\s*" + _PREFIX
SHELL_RULES = (
    ("cargo", re.compile(_POSITION + r"(?:[^\s=]*/)?" + _CARGO_BIN + r"(?=\s|$|[;&|)`])")),
    ("rustup run … cargo", re.compile(r"\brustup\s+run\s+\S+\s+" + _CARGO_BIN + r"\b")),
    ("$CARGO", re.compile(_POSITION + r"[\"']?\$\{?CARGO(?:[:}][^\s\"']*)?[\"']?(?=\s)")),
    ("napi build", re.compile(r"\bnapi\s+build\b")),
    ("maturin", re.compile(_POSITION + r"maturin\s+(?:build|develop|publish)\b")),
    ("charon cargo", re.compile(r"\bcharon\S*\s+cargo\b")),
    ("cross", re.compile(_POSITION + r"cross\s+(?:build|test|run)\b")),
)
PRINTS = re.compile(r"^\s*(?:-\s*)?(?:echo|printf)\b")
FENCE = re.compile(r"^\s*(```|~~~)\s*([A-Za-z]*)")
SHELL_LANGS = {"", "sh", "bash", "shell", "console", "zsh"}
ARGV_KEYS = ("protocol", "control", "argv", "command")


def _is_cargo_word(text: str) -> bool:
    word = text.strip().rsplit("/", 1)[-1]
    return bool(re.fullmatch(_CARGO_BIN, word))


def shell_hits(text: str) -> list[tuple[int, str, str]]:
    """(line, rule, text) for every Cargo invocation in shell-like text."""
    out = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        if not line.strip() or PRINTS.match(line):
            continue
        for rule, pattern in SHELL_RULES:
            if pattern.search(line):
                out.append((number, rule, raw.strip()))
                break
    return out


INLINE = re.compile(r"`([^`\n]+)`")


def markdown_hits(text: str) -> list[tuple[int, str, str]]:
    """Invocations in a maintained command document: its fenced shell blocks, and inline
    code spans that are a command — "run `cargo clippy`" instructs whoever reads it."""
    out, block, start, lang = [], None, 0, ""
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        fence = FENCE.match(line)
        if fence and block is None:
            block, start, lang = [], number, fence.group(2).lower()
            continue
        if fence and block is not None:
            if lang in SHELL_LANGS:
                body = "\n".join(l.lstrip("$ ").rstrip() for l in block)
                out += [(start + n, rule, t) for n, rule, t in shell_hits(body)]
            block = None
            continue
        if block is not None:
            block.append(line)
            continue
        for span in INLINE.findall(line):
            # A lone word names a thing — a job id, a binary — rather than running it.
            if " " in span.strip() and shell_hits(span):
                out.append((number, "inline command", span))
    return out


def workflow_hits(text: str) -> list[tuple[int, str, str]]:
    """Every shell line of a workflow, and every action that drives Cargo."""
    out = shell_hits(text)
    for number, line in enumerate(text.splitlines(), start=1):
        if re.search(r"uses:\s*[\"']?(?:EmbarkStudios/cargo-deny-action|actions-rs/cargo|PyO3/maturin-action|messense/maturin-action)", line):
            out.append((number, "cargo action", line.strip()))
    return out


#: The calls that run a command line through a shell.
_SPAWNS = {"run", "call", "check_call", "check_output", "Popen", "system", "popen",
           "getoutput", "getstatusoutput"}


def _string_list(node: ast.AST) -> list[str] | None:
    """An argv-shaped literal: each element a string, or the source of a name standing
    for one. A tuple holding a call — a table of rules, say — is not an argv."""
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return None
    if any(isinstance(elt, (ast.Call, ast.Lambda, ast.Dict)) for elt in node.elts):
        return None
    return [elt.value if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            else ast.unparse(elt) for elt in node.elts]


def python_hits(text: str) -> list[tuple[int, str, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return shell_hits(text)
    out: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        values = _string_list(node)
        if values:
            if _is_cargo_word(values[0]):
                out.append((line, "cargo argv", ast.unparse(node)[:120]))
            elif len(values) > 1 and "charon" in values[0] and values[1] == "cargo":
                out.append((line, "charon cargo", ast.unparse(node)[:120]))
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            arg = node.args[0] if node.args else None
            if name in _SPAWNS and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if shell_hits(arg.value):
                    out.append((line, "cargo shell string", arg.value[:120]))
    return out


def rust_hits(text: str) -> list[tuple[int, str, str]]:
    rule = re.compile(r'Command::new\(\s*(?:"(?:\S*/)?cargo"|env!\(\s*"CARGO"\s*\)|&?(?:std::)?env::var\(\s*"CARGO"\s*\))')
    return [(n, "Command::new(cargo)", l.strip()) for n, l in enumerate(text.splitlines(), 1)
            if rule.search(l) and not l.lstrip().startswith("//")]


def js_hits(text: str) -> list[tuple[int, str, str]]:
    rule = re.compile(r"""(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\(\s*['"`](?:cargo|napi\s+build|maturin)\b""")
    return [(n, "spawn cargo", l.strip()) for n, l in enumerate(text.splitlines(), 1)
            if rule.search(l) and not l.lstrip().startswith("//")]


def toml_hits(text: str) -> list[tuple[int, str, str]]:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    out = []

    def walk(value) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ARGV_KEYS and isinstance(item, list) and item and isinstance(item[0], str) \
                        and _is_cargo_word(item[0]):
                    out.append((0, f"cargo argv in `{key}`", " ".join(map(str, item))[:120]))
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(doc)
    if re.search(r'build-backend\s*=\s*"maturin"', text):
        out.append((0, "maturin build backend", "build-backend = \"maturin\""))
    return out


def package_json_hits(text: str) -> list[tuple[int, str, str]]:
    try:
        scripts = json.loads(text).get("scripts", {})
    except (json.JSONDecodeError, AttributeError):
        return []
    return [(0, f"package script `{name}`", body) for name, body in scripts.items()
            if shell_hits(body)]


def classify(path: str):
    name = path.rsplit("/", 1)[-1]
    if path.startswith(HISTORY):
        return None
    if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
        return workflow_hits
    if name.startswith("Dockerfile") or name in ("Makefile", "justfile") or path.endswith((".sh", ".bash", ".sh.example")):
        return shell_hits
    if path.startswith("deploy/") and path.endswith((".yml", ".yaml")):
        return shell_hits
    if name in (".pre-commit-config.yaml", "lefthook.yml") or path.startswith(".githooks/"):
        return shell_hits
    if path.endswith(".py"):
        return python_hits
    if path.endswith(".rs"):
        return rust_hits
    if path.endswith((".js", ".mjs", ".cjs", ".ts", ".mts")) and not path.endswith(".d.ts"):
        return js_hits
    if name == "package.json":
        return package_json_hits
    if path.endswith(".toml") and (path.startswith(("verification/policy/", "config/")) or name == "pyproject.toml"):
        return toml_hits
    if path.endswith(".md") and COMMAND_DOCS.match(path):
        return markdown_hits
    return None


def executable_scripts(files: list[str]) -> dict:
    """Extensionless executables are read by their interpreter line."""
    out = {}
    for path in files:
        if "." in path.rsplit("/", 1)[-1] or path.startswith(HISTORY):
            continue
        try:
            first = (REPO / path).read_text(errors="replace").split("\n", 1)[0]
        except OSError:
            continue
        if first.startswith("#!"):
            out[path] = python_hits if "python" in first else shell_hits
    return out


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         cwd=REPO, capture_output=True, text=True, check=True).stdout
    names = [f for f in out.split("\0") if f]
    # `.claude/` is ignored except the files this repository deliberately tracks, and the
    # remediation and audit skills live there; read those too.
    claude = subprocess.run(["git", "ls-files", "-z", "--cached", ".claude"], cwd=REPO,
                            capture_output=True, text=True, check=True).stdout
    return sorted(set(names) | {f for f in claude.split("\0") if f})


def scan(files: list[str], read) -> list[str]:
    readers = executable_scripts(files)
    problems = []
    for path in files:
        reader = classify(path) or readers.get(path)
        if reader is None:
            continue
        try:
            text = read(path)
        except (OSError, UnicodeDecodeError):
            continue
        for line, rule, snippet in reader(text):
            where = f"{path}:{line}" if line else path
            problems.append(f"{where}: {rule} — {snippet}")
    return problems


def selftest() -> int:
    cases = [
        ("scripts/a.sh", "cargo test --workspace\n", True),
        ("scripts/a.sh", "  foo && cargo build -p x\n", True),
        ("scripts/a.sh", "timeout 60 cargo clippy\n", True),
        ("scripts/a.sh", "rustup run 1.97.1 cargo fmt\n", True),
        ("scripts/a.sh", '"${CARGO:-cargo}" build\n', True),
        ("scripts/a.sh", "/opt/v/cargo-verus verify -p x\n", True),
        ("scripts/a.sh", "RUSTFLAGS=x cargo build\n", True),
        ("scripts/a.sh", "# cargo test is gone\n", False),
        ("scripts/a.sh", 'echo "run cargo test yourself"\n', False),
        ("scripts/a.sh", "bazel test //... # not cargo test\n", False),
        ("scripts/a.sh", "CARGO_BAZEL_REPIN=1 bazel mod show_extension x\n", False),
        ("scripts/a.sh", "ls ~/.cargo/bin\n", False),
        (".github/workflows/x.yml", "      - run: rustup show && cargo --version\n", True),
        (".github/workflows/x.yml", "      - uses: EmbarkStudios/cargo-deny-action@v1\n", True),
        (".github/workflows/x.yml", "    name: cargo build + test (1.97.1)\n", False),
        ("sdk/typescript/package.json", '{"scripts": {"b": "napi build --platform"}}', True),
        ("sdk/typescript/package.json", '{"scripts": {"b": "node scripts/build-native.mjs"}}', False),
        ("sdk/python/pyproject.toml", '[build-system]\nbuild-backend = "maturin"\n', True),
        ("tools/x.py", 'subprocess.run(["cargo", "test"])\n', True),
        ("tools/x.py", 'argv = [charon, "cargo", "--preset=aeneas"]\n', True),
        ("tools/x.py", 'os.system("cargo build --release")\n', True),
        ("tools/x.py", 'RULES = (("cargo", re.compile("x")),)\n', False),
        ("verification/extraction/Dockerfile", "ENV CARGO_HOME=/opt/cargo \\\n", False),
        ("tools/x.py", 'print("cargo test-target gate: OK")\n', False),
        ("tools/x.py", 'names = ["cargo_test_target_gate.py"]\n', False),
        ("x/src/lib.rs", 'let c = Command::new("cargo").arg("build");\n', True),
        ("x/src/lib.rs", 'let c = Command::new(env!("CARGO"));\n', True),
        ("x/src/lib.rs", "// Command::new(\"cargo\") would be wrong here\n", False),
        ("verification/policy/m.toml", '[[m]]\nprotocol = ["cargo", "test"]\n', True),
        ("verification/policy/m.toml", '[[m]]\nprotocol = ["bazel", "test"]\n', False),
        ("CLAUDE.md", "text\n```sh\ncargo clippy -- -D warnings\n```\n", True),
        ("CLAUDE.md", "Run `cargo clippy -- -D warnings` after every edit.\n", True),
        ("docs/dev/x.md", "- `cargo`: the structural-gates job\n", False),
        ("CLAUDE.md", "The `Cargo.toml` manifests describe crates.\n```sh\nbazel test //x\n```\n", False),
        ("docs/security/r7.log", "cargo test\n", False),
        ("verification/reviews/p.md", "```sh\ncargo test\n```\n", False),
        ("deploy/docker/Dockerfile", "RUN cargo build --release\n", True),
    ]
    failures = []
    for path, text, expect in cases:
        found = scan([path], lambda _path, t=text: t)
        if bool(found) != expect:
            failures.append(f"{path}: {text!r} -> {found or 'nothing'}, expected {'a hit' if expect else 'none'}")
    if failures:
        print("no-cargo-execution gate selftest: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"no-cargo-execution gate selftest: PASS ({len(cases)} cases)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    files = tracked_files()
    problems = scan(files, lambda p: (REPO / p).read_text(encoding="utf-8"))
    if problems:
        print(f"no-cargo-execution gate: FAIL — {len(problems)} Cargo invocation(s)")
        for p in problems:
            print(f"  - {p}")
        print("Rust build and test execution is Bazel's. Replace each with its Bazel form.")
        return 1
    print(f"no-cargo-execution gate: OK — {len(files)} file(s) read; no workflow, script, tool, "
          f"hook, lane, container, registry or maintained command invokes Cargo")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
