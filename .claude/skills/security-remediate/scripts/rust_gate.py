"""Rust gate for one file's fix, on Bazel targets: lint every target that compiles the file,
then run the tests that exercise it — never the whole graph.

(Invoked as `python3 rust_gate.py …`, or imported by `check.py` and `batch_gate.py`.)

Bazel is the Rust build authority, so "every lane that compiles the file" is read from the
build graph rather than reconstructed: each flavor of a library is its own target with its
own `crate_features`, and the targets that list the file in their `srcs` are exactly the
configurations it is compiled in.

  lint    `bazel build --config=lint` over the targets that compile the file or any file
          the writer touched (and, at the `wide` tier, those that compile the related
          files), plus the unit-test targets built from the file's own: clippy under the
          workspace lint policy, warnings as errors.
  format  `bazel build --config=rustfmt` over the targets that compile the touched files —
          the rustfmt lane, scoped. A diff in a touched file is the writer's; a diff only in
          files nobody touched means the lane did not start on a formatted tree (`infra`).
  size    `scripts/module_size_gate.py` — seconds, whole tree.
  registry  unit closure, verification-trigger filters, mutation anchors — seconds each.
  tests   the `rust_test` targets whose `crate` is a library that compiles the file (its
          own unit tests), filtered to the file's module path, plus every integration test
          target the package named (`--it`, Bazel labels).

The verdict rests on the lane invariant, not on a stored baseline: the writer lane starts on
a tree `batch_gate.py` measured green, and every writer leaves it green or reverted.

Verdicts: `new-failures` (a lint, a compile error, a failed test), `infra` (Bazel could not
judge: analysis failed, or no test ran), `size-debt` (the only problem is size growth, which
a remediation run records and does not block on — `size_debt.py`), `ok`.

Usage:
  rust_gate.py --file F [--related a,b] [--touched a,b] [--it //pkg:target,...] --work-dir DIR
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rust_resolver import RustResolver  # noqa: E402
import size_debt  # noqa: E402

SIZE_GATE = "scripts/module_size_gate.py"
# Seconds each, whole tree, and attributable under the lane invariant: a new module that
# joins no unit, a fingerprint input no CI filter triggers on, a mutation anchor the change
# made stale. Writers kept leaving these for the batch gate.
REGISTRY_GATES = ("scripts/unit_closure_gate.py", "scripts/verification_trigger_gate.py",
                  "tools/verification/test_mutation_lane.py", "scripts/control_census_gate.py")
RUST_RULES = "rust_library|rust_binary|rust_test|rust_shared_library|rust_static_library|rust_proc_macro"
_DIAGNOSTIC = re.compile(r"^error(?:\[E\d+\])?: ", re.M)
_RUNNING = re.compile(r"^running (\d+) tests?$", re.M)
_FAILED_TEST = re.compile(r"^---- (\S+) stdout ----$", re.M)
_INLINE_TEST = re.compile(r"#\[(?:tokio::)?test\b")
_FMT_DIFF = re.compile(r"^Diff in (\S+?\.rs):\d+:$", re.M)
_FMT_PARSE = re.compile(r"^\s*--> (\S+?\.rs):\d+:\d+$", re.M)


def bazel() -> list[str]:
    """The Bazel launcher. A seam so the gate's verdict logic can be tested without one."""
    return ["bazel"]


def _slug(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]


def _run(cmd: list[str], log: str) -> tuple[int, str]:
    with open(log, "w", encoding="utf-8") as fh:
        p = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT)
    return p.returncode, open(log, encoding="utf-8", errors="replace").read()


def package_of(path: str) -> str | None:
    """The Bazel package that owns `path`: the nearest directory holding a BUILD file."""
    d = os.path.dirname(path)
    while True:
        if any(os.path.isfile(os.path.join(d or ".", b)) for b in ("BUILD.bazel", "BUILD")):
            return d
        if not d:
            return None
        d = os.path.dirname(d)


def file_label(path: str) -> str | None:
    pkg = package_of(path)
    if pkg is None:
        return None
    return "//%s:%s" % (pkg, os.path.relpath(path, pkg or "."))


def query(expr: str) -> list[str]:
    p = subprocess.run(bazel() + ["query", "--output=label", "--keep_going", expr],
                       capture_output=True, text=True)
    return sorted(line for line in p.stdout.splitlines() if line.startswith("//"))


def compiling_targets(files: list[str]) -> list[str]:
    """Every first-party Rust target that lists one of `files` in its sources."""
    labels = [lbl for lbl in (file_label(f) for f in files) if lbl]
    if not labels:
        return []
    return query('kind("^(%s) rule$", rdeps(//..., set(%s), 1))' % (RUST_RULES, " ".join(labels)))


def unit_test_targets(targets: list[str]) -> list[str]:
    """The `rust_test` targets that compile one of `targets`' crates with its unit tests,
    and any test target among `targets` itself."""
    libs = [t for t in targets]
    if not libs:
        return []
    crate_tests = query('attr(crate, "^(%s)$", kind("^rust_test rule$", //...))'
                        % "|".join(re.escape(t) for t in libs))
    own_tests = query('kind("^rust_test rule$", set(%s))' % " ".join(libs))
    manual = set(query('attr(tags, "\\bmanual\\b", set(%s))'
                       % " ".join(sorted(set(crate_tests + own_tests)) or ["//:none"])))
    return sorted(set(crate_tests + own_tests) - manual)


def _lint(targets: list[str], log: str) -> dict:
    rc, out = _run(bazel() + ["build", "--config=lint", "--keep_going", *targets], log)
    errors = [ln for ln in out.splitlines() if _DIAGNOSTIC.match(ln)][:15]
    if rc == 0:
        return {"verdict": "ok", "exit": rc, "log": log}
    if errors:
        return {"verdict": "new-failures", "exit": rc, "log": log, "errors_head": errors}
    return {"verdict": "infra", "exit": rc, "log": log,
            "why": "the lint build failed without a diagnostic — analysis, fetch or toolchain"}


def _rustfmt(targets: list[str], touched: list[str], log: str) -> dict:
    # Only the format checks: the config adds them to the default output groups, which
    # would also compile the targets and report a compile error as a format failure.
    rc, out = _run(bazel() + ["build", "--config=rustfmt", "--output_groups=rustfmt_checks",
                              "--keep_going", *targets], log)
    if rc == 0:
        return {"verdict": "ok", "exit": rc, "log": log}
    rel = lambda p: os.path.relpath(p) if os.path.isabs(p) else p  # noqa: E731
    diffs = sorted({rel(p) for p in _FMT_DIFF.findall(out)})
    unparsable = sorted({rel(p) for p in _FMT_PARSE.findall(out)} & set(touched))
    if unparsable:
        return {"verdict": "new-failures", "exit": rc, "log": log, "unformatted": unparsable,
                "why": "rustfmt cannot parse a touched file"}
    mine = [p for p in diffs if p in set(touched)]
    if mine:
        return {"verdict": "new-failures", "exit": rc, "log": log, "unformatted": mine}
    if diffs:
        return {"verdict": "infra", "exit": rc, "log": log, "unformatted": diffs,
                "why": "rustfmt diffs only in untouched files — the lane did not start formatted"}
    return {"verdict": "infra", "exit": rc, "log": log,
            "why": "the rustfmt build failed without a diff — analysis, fetch or toolchain"}


def _testlog(label: str) -> str:
    pkg, name = label[2:].split(":", 1)
    path = os.path.join("bazel-testlogs", pkg, name, "test.log")
    return open(path, encoding="utf-8", errors="replace").read() if os.path.isfile(path) else ""


def _test(targets: list[str], filt: str, log: str) -> dict:
    cmd = bazel() + ["test", "--test_output=errors", "--keep_going", *targets]
    if filt:
        cmd.append("--test_arg=" + filt)
    rc, out = _run(cmd, log)
    logs = {t: _testlog(t) for t in targets}
    ran = sum(int(n) for text in logs.values() for n in _RUNNING.findall(text))
    failed = [name for text in logs.values() for name in _FAILED_TEST.findall(text)]
    compile_error = bool(_DIAGNOSTIC.search(out))
    if rc != 0 and (failed or compile_error):
        return {"verdict": "new-failures", "exit": rc, "log": log, "failed": failed[:15],
                "compile_error": compile_error and not failed}
    if rc != 0:
        return {"verdict": "infra", "exit": rc, "log": log,
                "why": "bazel test failed before any test ran"}
    if ran == 0:
        return {"verdict": "infra", "exit": rc, "log": log,
                "why": "0 tests ran — this selection measured nothing"}
    return {"verdict": "ok", "exit": rc, "log": log, "ran": ran}


def gate(file: str, related: list[str], its: list[str], work_dir: str,
         resolver: RustResolver | None = None, touched: list[str] | None = None) -> list[dict]:
    r = resolver or RustResolver(".")
    own = compiling_targets([file])
    if not own:
        return [{"gate": "targets", "verdict": "infra",
                 "why": "%s is compiled by no Rust target in the build graph" % file}]
    edited = sorted({f for f in (touched or []) + [file] if f.endswith(".rs")})
    touched_targets = compiling_targets([f for f in edited if f != file])
    lint_scope = sorted(set(own + touched_targets + compiling_targets(related)))
    units = unit_test_targets(own)
    tag = _slug(file)
    parts: list[dict] = [dict(_lint(sorted(set(lint_scope + units)),
                                    os.path.join(work_dir, "lint-%s.log" % tag)),
                              gate="clippy", targets=lint_scope)]
    fmt_scope = sorted(set(own + touched_targets))
    parts.append(dict(_rustfmt(fmt_scope, edited, os.path.join(work_dir, "fmt-%s.log" % tag)),
                      gate="rustfmt", targets=fmt_scope))

    rc, out = _run([sys.executable, SIZE_GATE], os.path.join(work_dir, "size-%s.log" % tag))
    soft, debt = size_debt.classify("module-size", out) if rc else (False, [])
    debt = size_debt.attributable(debt, edited) if soft else []
    size_verdict = ("ok" if rc == 0 or (soft and not debt) else
                    "size-debt" if soft else "new-failures")
    record = size_debt.encountered(edited)
    # `exit` is this writer's status, so it agrees with the verdict the journal and the
    # reviewer read: growth in files the writer did not touch, and recorded size debt, are
    # not a failure of this change. The script's own status stays as `raw_exit`.
    parts.append({"gate": "module-size", "verdict": size_verdict,
                  "exit": 1 if size_verdict == "new-failures" else 0, "raw_exit": rc,
                  **({} if rc == 0 else {"head": out.strip().splitlines()[-5:]}),
                  **({"debt": debt} if debt else {}),
                  **({"record": record} if record else {}),
                  **({"note": "size growth only in files this writer did not touch"}
                     if rc and soft and not debt else {})})

    for script in REGISTRY_GATES:
        if not os.path.isfile(script):
            continue
        rc, out = _run([sys.executable, script],
                       os.path.join(work_dir, "%s-%s.log" % (os.path.basename(script), tag)))
        parts.append({"gate": "registry", "lane": os.path.basename(script),
                      "verdict": "ok" if rc == 0 else "new-failures", "exit": rc,
                      **({} if rc == 0 else {"head": [ln for ln in out.splitlines()
                                                      if "FAIL" in ln or ln.startswith("  - ")][:5]})})

    if any(p["verdict"] == "new-failures" for p in parts):
        return parts          # a tree that does not compile has no test result to add
    mod = "::".join(r.module_path(file))
    if units:
        parts.append(dict(_test(units, mod + "::" if mod else "",
                                os.path.join(work_dir, "test-unit-%s.log" % tag)),
                          gate="test", target="unit", targets=units, filter=mod))
    else:
        parts.append({"gate": "test", "target": "unit", "verdict": "infra",
                      "why": "no unit-test target compiles %s's crate" % file})
    has_own = _INLINE_TEST.search(open(file, encoding="utf-8", errors="replace").read())
    if parts[-1]["verdict"] == "infra" and not has_own and (
            "0 tests ran" in parts[-1].get("why", "") or not units):
        parts[-1]["verdict"] = "ok"
        parts[-1]["note"] = "the file has no unit tests of its own"
    if its:
        parts.append(dict(_test(its, "", os.path.join(work_dir, "test-it-%s.log" % tag)),
                          gate="test", target="integration", targets=its))
    return parts


def main() -> int:
    ap = argparse.ArgumentParser(description="Bazel Rust gate for one file's fix")
    ap.add_argument("--file", required=True)
    ap.add_argument("--related", default="")
    ap.add_argument("--touched", default="", help="comma-separated files edited (default: --file)")
    ap.add_argument("--it", default="", help="integration test targets (Bazel labels), comma-separated")
    ap.add_argument("--work-dir", required=True)
    a = ap.parse_args()
    os.makedirs(a.work_dir, exist_ok=True)
    ids = lambda s: [x.strip() for x in s.split(",") if x.strip()]  # noqa: E731
    print(json.dumps(gate(a.file, ids(a.related), ids(a.it), a.work_dir,
                          touched=ids(a.touched)), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
