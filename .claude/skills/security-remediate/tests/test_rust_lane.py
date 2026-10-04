"""Regression: the Rust half of the lane and the batch close.

What is pinned here, each refusal beside its positive control:

  rust_resolver.py
    1. `crate::` / `super::` / child-module / workspace-crate paths and `use`
       trees resolve to the defining file, THROUGH a `pub use` re-export — and a
       path into a foreign crate or a test region resolves to nothing
  rust_gate.py
    2. a lint diagnostic and a failed test are `new-failures` (naming the
       test); a Bazel failure with no diagnostic is `infra`; a selection that ran
       0 tests is `infra` when the file HAS tests and `ok` when it has none;
       a rustfmt diff in a touched file is `new-failures`, one only in an
       untouched file is `infra`
  check.py
    3. a red change is saved as a patch and reverted — tracked edits and new
       files — so the next writer starts clean
  finalize.py
    4. commit only what review accepted: `anchor`/`scope` rejections leave no
       diff and commit; `wrong-fix`, an unordered change or a reject revert
  next_file.py
    5. `--rounds` drops rows no live round reported; `--order` outranks the
       derived order
  ledger.py
    6. `ingest` fingerprints a finding that carries only `file` exactly as
       `reconcile` does — re-ingesting a round adds nothing
  prepare.py
    7. only column-0 items are symbols another file binds; a method is not

Run:  python3 .claude/skills/security-remediate/tests/test_rust_lane.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)

import rust_gate  # noqa: E402
import check  # noqa: E402
import finalize  # noqa: E402
import ledger  # noqa: E402
import next_file  # noqa: E402
from prepare import defined_symbols  # noqa: E402
from rust_resolver import RustResolver  # noqa: E402


def _write(root: str, rel: str, text: str) -> None:
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(text))


def _git_repo(root: str) -> None:
    for cmd in (["init", "-q"], ["add", "-A"],
                ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "init"]):
        subprocess.run(["git", *cmd], cwd=root, check=True, capture_output=True)


def _workspace(root: str) -> None:
    _write(root, "alpha/BUILD.bazel", ALPHA_BUILD)
    _write(root, "alpha/src/lib.rs", """\
        pub mod keys;
        pub mod plane;
        pub use keys::Signer;
        """)
    _write(root, "alpha/src/keys.rs", "pub struct Signer;\n")
    _write(root, "alpha/src/plane/mod.rs", """\
        pub mod gate;
        use gate::Gate;
        use crate::{keys::Signer, plane::gate::Verdict};
        pub fn run(_: Gate, _: Signer, _: Verdict) {}
        #[cfg(test)]
        mod tests { use crate::Ghost; }
        """)
    _write(root, "alpha/src/plane/gate.rs", """\
        pub struct Gate;
        pub struct Verdict;
        pub fn f() { let _ = super::super::keys::Signer; let _ = serde::Value; }
        """)
    _write(root, "beta/BUILD.bazel", 'nt_rust_library(\n    name = "beta",\n)\n')
    _write(root, "beta/src/lib.rs", "use alpha::Signer;\n")


def test_resolver_paths_and_reexports() -> None:
    with tempfile.TemporaryDirectory() as td:
        _workspace(td)
        _git_repo(td)
        r = RustResolver(td)
        assert r.targets("alpha/src/plane/mod.rs") == {"alpha/src/plane/gate.rs", "alpha/src/keys.rs"}, \
            r.targets("alpha/src/plane/mod.rs")
        assert r.targets("alpha/src/plane/gate.rs") == {"alpha/src/keys.rs"}, r.targets("alpha/src/plane/gate.rs")
        # through the crate root's `pub use keys::Signer`, to the defining file
        assert r.targets("beta/src/lib.rs") == {"alpha/src/keys.rs"}, r.targets("beta/src/lib.rs")
        assert r.targets("alpha/src/keys.rs") == set()
    print("  resolver: crate/super/child/workspace paths, through re-exports; test region ignored  OK")


FAKE_BAZEL = """#!/usr/bin/env python3
import json, os, sys
cfg = json.load(open(os.environ["FAKE_BAZEL_CONFIG"]))
cmd, rest = sys.argv[1], sys.argv[2:]
if cmd == "query":
    expr = rest[-1]
    for needle, labels in cfg["query"]:
        if needle in expr:
            print("\\n".join(labels))
            break
    sys.exit(0)
if cmd == "build":
    lane = cfg.get("rustfmt", {"out": "", "rc": 0}) if "--config=rustfmt" in rest else cfg["build"]
    print(lane["out"])
    sys.exit(lane["rc"])
if cmd == "test":
    for label, text in cfg["test"].get("logs", {}).items():
        pkg, name = label[2:].split(":", 1)
        os.makedirs(os.path.join("bazel-testlogs", pkg, name), exist_ok=True)
        open(os.path.join("bazel-testlogs", pkg, name, "test.log"), "w").write(text)
    print(cfg["test"]["out"])
    sys.exit(cfg["test"]["rc"])
sys.exit(2)
"""

UNIT = "//alpha:alpha_test"
ALPHA_BUILD = 'nt_rust_library(\n    name = "alpha",\n    crate_name = "alpha",\n)\n'


def _gate(td: str, src: str, lint_out: str, lint_rc: int, log: str, test_rc: int,
          fmt: tuple[str, int] = ("", 0)) -> list[dict]:
    root = os.path.join(td, "ws")
    _write(root, "alpha/BUILD.bazel", ALPHA_BUILD)
    _write(root, "alpha/src/lib.rs", "pub mod keys;\n")
    _write(root, "alpha/src/keys.rs", src)
    _write(root, "scripts/module_size_gate.py", "import sys; sys.exit(0)\n")
    if not os.path.isdir(os.path.join(root, ".git")):
        _git_repo(root)
    fake = os.path.join(td, "bazel")
    with open(fake, "w") as fh:
        fh.write(FAKE_BAZEL)
    config = os.path.join(td, "fake-bazel.json")
    with open(config, "w") as fh:
        json.dump({"query": [["rdeps(", ["//alpha:alpha"]], ["attr(crate", [UNIT]],
                             ['kind("^rust_test rule$", set(', []], ["attr(tags", []]],
                   "build": {"out": lint_out, "rc": lint_rc},
                   "rustfmt": {"out": fmt[0], "rc": fmt[1]},
                   "test": {"out": "", "rc": test_rc, "logs": {UNIT: log}}}, fh)
    orig, cwd, env = rust_gate.bazel, os.getcwd(), os.environ.get("FAKE_BAZEL_CONFIG")
    rust_gate.bazel = lambda: [sys.executable, fake]  # type: ignore[assignment]
    os.environ["FAKE_BAZEL_CONFIG"] = config
    try:
        os.chdir(root)
        os.makedirs("w", exist_ok=True)
        return rust_gate.gate("alpha/src/keys.rs", [], [], "w", RustResolver("."))
    finally:
        os.chdir(cwd)
        rust_gate.bazel = orig  # type: ignore[assignment]
        if env is None:
            os.environ.pop("FAKE_BAZEL_CONFIG", None)
        else:
            os.environ["FAKE_BAZEL_CONFIG"] = env


def _verdicts(parts: list[dict]) -> dict[str, str]:
    return {p["gate"]: p["verdict"] for p in parts}


def test_rust_gate_verdicts() -> None:
    passed = "running 3 tests\ntest result: ok. 3 passed; 0 failed; 0 ignored"
    has_tests = "pub struct S;\n#[cfg(test)]\nmod tests { #[test] fn t() {} }\n"
    with tempfile.TemporaryDirectory() as td:
        ok = _gate(td, has_tests, "", 0, passed, 0)
        assert _verdicts(ok) == {"clippy": "ok", "rustfmt": "ok", "module-size": "ok",
                                 "test": "ok"}, ok
        lint = _gate(td, "pub struct S;\n", "error: unused variable", 1, passed, 0)
        assert _verdicts(lint)["clippy"] == "new-failures" and "test" not in _verdicts(lint), lint
        red = _gate(td, has_tests, "", 0,
                    "running 1 test\n---- keys::tests::t stdout ----\n"
                    "test result: FAILED. 0 passed; 1 failed;", 3)
        t = [p for p in red if p["gate"] == "test"][0]
        assert t["verdict"] == "new-failures" and t["failed"] == ["keys::tests::t"], t
        infra = _gate(td, "pub struct S;\n", "ERROR: no such package '@@x//'", 1, passed, 0)
        assert _verdicts(infra)["clippy"] == "infra", infra
        none = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 7 filtered out"
        empty_has = _gate(td, has_tests, "", 0, none, 0)
        assert _verdicts(empty_has)["test"] == "infra", empty_has
        empty_none = _gate(td, "pub struct S;\n", "", 0, none, 0)
        assert _verdicts(empty_none)["test"] == "ok", empty_none
    print("  rust gate: lint/test failures blamed, a silent build = infra, 0 tests judged by the file  OK")


def test_rust_gate_rustfmt_blames_only_touched_files() -> None:
    passed = "running 3 tests\ntest result: ok. 3 passed; 0 failed; 0 ignored"
    has_tests = "pub struct S;\n#[cfg(test)]\nmod tests { #[test] fn t() {} }\n"
    with tempfile.TemporaryDirectory() as td:
        root = os.path.realpath(os.path.join(td, "ws"))
        mine = _gate(td, has_tests, "", 0, passed, 0,
                     ("Diff in %s/alpha/src/keys.rs:3:\n-fn  x(){}\n+fn x() {}" % root, 1))
        f = [p for p in mine if p["gate"] == "rustfmt"][0]
        assert f["verdict"] == "new-failures" and f["unformatted"] == ["alpha/src/keys.rs"], f
        assert "test" not in _verdicts(mine), mine
        other = _gate(td, has_tests, "", 0, passed, 0,
                      ("Diff in %s/alpha/src/lib.rs:1:\n" % root, 1))
        assert _verdicts(other)["rustfmt"] == "infra", other
        silent = _gate(td, has_tests, "", 0, passed, 0, ("ERROR: analysis failed", 1))
        assert _verdicts(silent)["rustfmt"] == "infra", silent
    print("  rust gate: a rustfmt diff in the touched file is blamed; elsewhere or silent = infra  OK")


def test_every_rust_gate_part_has_a_journal_line() -> None:
    """check.py journals one line per part. A part the summary does not name fell through to
    the Python-tree branch and crashed on `new_failures` — every writer's gate event was lost
    and a whole batch was rejected for missing evidence."""
    parts = [{"gate": "clippy", "verdict": "ok"},
             {"gate": "rustfmt", "verdict": "new-failures", "unformatted": ["alpha/src/keys.rs"]},
             {"gate": "module-size", "verdict": "ok"},
             {"gate": "test", "target": "unit", "verdict": "ok", "ran": 3},
             {"gate": "targets", "verdict": "infra", "why": "no target"}]
    lines = [check.gate_summary(p) for p in parts]
    assert lines[1] == "rustfmt new-failures — ['alpha/src/keys.rs']", lines
    assert check.gate_summary({"gate": "bazel", "tree": "t", "verdict": "ok"}) == "bazel t ok"
    print("  check: every Rust gate part, rustfmt included, journals a line  OK")


def test_revert_on_fail_restores_tree() -> None:
    with tempfile.TemporaryDirectory() as td:
        _write(td, "a.rs", "fn a() {}\n")
        _git_repo(td)
        _write(td, "a.rs", "fn a() { broken }\n")
        _write(td, "new.rs", "fn n() {}\n")
        cwd = os.getcwd()
        try:
            os.chdir(td)
            patch = check._revert(["a.rs", "new.rs"], td)
        finally:
            os.chdir(cwd)
        assert open(os.path.join(td, "a.rs")).read() == "fn a() {}\n"
        assert not os.path.exists(os.path.join(td, "new.rs"))
        text = open(patch).read()
        assert "broken" in text and "fn n()" in text, text
    print("  check: a red change is kept as a patch and the tree returns to HEAD  OK")


def test_finalize_commits_only_accepted_work() -> None:
    base = {"file": "f.rs", "files_touched": ["f.rs"], "accepted": ["w1"], "unordered_changes": []}
    assert finalize.decide(dict(base, verdict="accept")) == "commit"
    assert finalize.decide(dict(base, verdict="partial",
                                rejected=[{"id": "w2", "cause": "anchor"}])) == "commit"
    assert finalize.decide(dict(base, verdict="partial",
                                rejected=[{"id": "w2", "cause": "wrong-fix"}])) == "revert"
    assert finalize.decide(dict(base, verdict="accept", unordered_changes=["g.rs"])) == "revert"
    assert finalize.decide(dict(base, verdict="reject")) == "revert"
    assert finalize.decide(dict(base, verdict="gate-failed")) == "skip"
    pkg = {"work": [{"id": "w1", "finding_ids": ["a", "b"]}, {"id": "c"}, {"id": "w9"}]}
    assert finalize.finding_ids(pkg, ["w1", "c"]) == ["a", "b", "c"]
    print("  finalize: commit accept / harmless partial, revert everything else; fixed = accepted ids  OK")


def _finalize_once(td: str, residue: dict) -> list:
    """Run finalize.main over one accepted file, with the census replaced by `residue`."""
    pkg = os.path.join(td, "pkg.json")
    with open(pkg, "w") as fh:
        json.dump({"work": [{"id": "w1", "finding_ids": ["F1"]}]}, fh)
    results = os.path.join(td, "results.json")
    with open(results, "w") as fh:
        json.dump([{"file": "f.rs", "verdict": "accept", "files_touched": ["f.rs"],
                    "accepted": ["w1"], "unordered_changes": [], "package": pkg}], fh)
    ledger_path = os.path.join(td, "ledger.jsonl")
    with open(ledger_path, "w") as fh:
        fh.write(json.dumps({"id": "F1", "status": "open", "path": "f.rs"}) + "\n")
    real, argv, cwd = finalize.residue_by_carrier, sys.argv, os.getcwd()
    finalize.residue_by_carrier = lambda: residue
    sys.argv = ["finalize.py", "--results", results, "--ledger", ledger_path,
                "--work-dir", td]
    os.chdir(td)
    out = []
    try:
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            finalize.main()
        out = json.loads(buf.getvalue())
    finally:
        finalize.residue_by_carrier, sys.argv = real, argv
        os.chdir(cwd)
    return out


def test_finalize_holds_a_file_whose_new_control_is_undispositioned() -> None:
    """An accepted diff that adds a control nobody claims is not committed (ADR-MCPRE-069)."""
    for residue, want in (({"f.rs": ["lib#f::tests::new_one"]}, "revert"), ({}, "commit")):
        with tempfile.TemporaryDirectory() as td:
            _write(td, "f.rs", "fn a() {}\n")
            _git_repo(td)
            _write(td, "f.rs", "fn a() {}\n#[test]\nfn new_one() {}\n")
            report = _finalize_once(td, residue)
            row = report[0]
            assert row["action"] == want, row
            status = ledger._load(os.path.join(td, "ledger.jsonl"))["F1"]["status"]
            body = open(os.path.join(td, "f.rs")).read()
            if want == "revert":
                assert row["undispositioned"] == ["lib#f::tests::new_one"], row
                assert "new_one" not in body and os.path.isfile(row["patch"]), row
                assert status == "open", status
            else:
                assert "new_one" in body and status == "fixed", (body, status)
    print("  finalize: an undispositioned control holds the file; with none, the same diff commits  OK")


def test_next_file_rounds_and_order() -> None:
    with tempfile.TemporaryDirectory() as td:
        rows = [{"id": "1", "path": "a.rs", "severity": "low", "status": "open", "rounds": ["r12"]},
                {"id": "2", "path": "b.rs", "severity": "high", "status": "open", "rounds": ["r12"]},
                {"id": "3", "path": "c.rs", "severity": "critical", "status": "open", "rounds": ["r10"]}]
        led = os.path.join(td, "l.jsonl")
        open(led, "w").write("".join(json.dumps(r) + "\n" for r in rows))
        assert next_file.select(led, None, 3)["file"] == "c.rs"                 # positive control
        assert next_file.select(led, None, 3, {"r12"})["file"] == "b.rs"
        order = os.path.join(td, "o.json")
        json.dump([{"file": "a.rs"}], open(order, "w"))
        got = [b["file"] for b in next_file.select(led, None, 3, {"r12"}, order)["batch"]]
        assert got == ["a.rs", "b.rs"], got
    print("  next_file: --rounds drops stale rows; --order outranks severity  OK")


def test_ingest_fingerprints_file_only_findings_like_reconcile() -> None:
    with tempfile.TemporaryDirectory() as td:
        led = os.path.join(td, "l.jsonl")
        f = {"file": "crate/src/x.rs", "title": "A guard fails open", "severity": "high"}
        fid = ledger.fingerprint(ledger._file_of(f), f["title"])
        open(led, "w").write(json.dumps({"id": fid, "file": "x.rs", "status": "fixed",
                                         "title": f["title"]}) + "\n")
        pr = os.path.join(td, "p.json")
        json.dump([f], open(pr, "w"))
        out = subprocess.run([sys.executable, os.path.join(SCRIPTS, "ledger.py"), "ingest", led, pr,
                              "--round", "r"], capture_output=True, text=True).stdout
        assert "+0 new" in out, out
        row = json.loads(open(led).read().strip())
        assert row["status"] == "fixed" and row["path"] == "crate/src/x.rs", row
    print("  ledger: ingest keys a file-only finding as reconcile does; disposition kept, path backfilled  OK")


def test_prepare_rust_symbols_are_column_zero_items() -> None:
    src = "pub struct Owner;\nimpl Owner {\n    pub fn new() -> Self { Owner }\n}\npub(crate) fn helper() {}\n" \
          "#[cfg(test)]\nmod tests {\npub fn fixture() {}\n}\n"
    assert defined_symbols("x.rs", src) == ["Owner", "helper"], defined_symbols("x.rs", src)
    print("  prepare: a method and a test-region item are not bindable symbols  OK")


def test_prepare_finds_integration_tests_through_root_reexports() -> None:
    from prepare import test_candidates
    with tempfile.TemporaryDirectory() as td:
        _workspace(td)
        # reaches `keys` only as `alpha::Signer`, through the crate root's `pub use`
        _write(td, "alpha/tests/suite/main.rs", "mod signer_test;\n")
        _write(td, "alpha/tests/suite/signer_test.rs",
               "#[test]\nfn t() { let _ = alpha::Signer; }\n")
        # every test ignored: naming its target runs nothing
        _write(td, "alpha/tests/live.rs",
               "#[test]\n#[ignore]\nfn l() { let _ = alpha::Signer; }\n")
        # a name that merely CONTAINS the re-export is not a use of it
        _write(td, "alpha/tests/other.rs", "#[test]\nfn o() { let _ = alpha::SignerSet; }\n")
        _git_repo(td)
        cwd = os.getcwd()
        os.chdir(td)
        # The build graph answers which test target compiles a file; stubbed to the graph
        # this fixture would have, `tests/suite/` compiled into `//alpha:suite`.
        graph = (rust_gate.compiling_targets, rust_gate.query)
        rust_gate.compiling_targets = lambda files: (  # type: ignore[assignment]
            ["//alpha:suite"] if "/suite/" in files[0] else [])
        rust_gate.query = lambda expr: ["//alpha:live", "//alpha:suite"]  # type: ignore[assignment]
        try:
            got = test_candidates("alpha/src/keys.rs")
        finally:
            os.chdir(cwd)
            rust_gate.compiling_targets, rust_gate.query = graph  # type: ignore[assignment]
        assert got == ["alpha/tests/live.rs [every test #[ignore]d — measures nothing in a local gate]",
                       "alpha/tests/suite/signer_test.rs [--it //alpha:suite]"], got
    print("  prepare: integration tests found through root re-exports, target named, all-ignored flagged  OK")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print("%d tests passed" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
