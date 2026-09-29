# SPDX-License-Identifier: Apache-2.0
"""The first-party Rust targets of the Bazel build graph, as one table.

Bazel is the Rust build and test authority, so "which crates exist, which file is each
crate's root, which test binary runs which crate's tests under which features" is a
question the build graph answers — `bazel query` — and nothing else. Every consumer on the
assurance platform needs part of that answer: the census walks each crate root's module
tree, the manifest checks that a selector names a test target inside the unit's closure, the
fingerprint digests an integration target's own sources, the lanes run a label.

Most of those consumers run where no Bazel server does — a structural CI job, a review
packet, a unit selector — so the answer is a GENERATED, COMMITTED table,
`verification/generated/rust-targets.json`, and `tools/verification/rust-targets --check`
regenerates it from `bazel query` and fails on any difference. That is the pattern the
assurance views already follow: a derived artifact every reader can open, whose freshness
is a control rather than an assumption.

# What a row states

One row per first-party `rust_*` rule, keyed by label:

  * `kind`      — the rule class.
  * `package`   — the Bazel package, the directory a control's `project` names.
  * `root`      — the crate root, repository-relative. For a `rust_test` or
                  `rust_doc_test` with a `crate`, the crate's own root: that test binary
                  compiles the crate's module tree, which is where its `#[test]`s live.
  * `srcs`      — every source the target compiles, the crate's included.
  * `crate`     — the library a `rust_test`/`rust_doc_test` is built from, or "".
  * `features`  — the crate features the target is compiled with.
  * `manual`    — whether `bazel test //...` skips it.

The crate root is resolved the way rules_rust resolves it — the `crate_root` attribute, else
the only source, else the conventional file name — and a target none of those decides is a
generation error, not a guess.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE = REPO_ROOT / "verification" / "generated" / "rust-targets.json"
SCHEMA = 1

RULES = (
    "rust_library",
    "rust_binary",
    "rust_test",
    "rust_shared_library",
    "rust_static_library",
    "rust_proc_macro",
    "rust_doc_test",
)
TEST_RULES = ("rust_test", "rust_doc_test")
QUERY = 'kind("^(%s) rule$", //...)' % "|".join(RULES)


class TargetTableError(Exception):
    """The build graph could not be read into the table, or the table is unreadable."""


def label_path(label: str) -> str:
    """`//pkg:dir/file.rs` as the repository path `pkg/dir/file.rs`."""
    package, _, name = label[2:].partition(":")
    return f"{package}/{name}" if package else name


def label_package(label: str) -> str:
    return label[2:].partition(":")[0]


def _attrs(rule: dict) -> dict:
    return {a["name"]: a for a in rule.get("attribute", [])}


def _string(attrs: dict, name: str) -> str:
    return str(attrs.get(name, {}).get("stringValue", "") or "")


def _strings(attrs: dict, name: str) -> list[str]:
    return [str(v) for v in attrs.get(name, {}).get("stringListValue", [])]


def _own_root(label: str, kind: str, attrs: dict, srcs: list[str]) -> str:
    """The crate root rules_rust compiles for a target that names no `crate`."""
    declared = _string(attrs, "crate_root")
    if declared:
        return label_path(declared)
    files = [label_path(s) for s in srcs]
    if len(files) == 1:
        return files[0]
    conventional = "main.rs" if kind in ("rust_binary", "rust_test") else "lib.rs"
    crate_name = _string(attrs, "crate_name") or label.partition(":")[2].replace("-", "_")
    for candidate in (conventional, "lib.rs", f"{crate_name}.rs"):
        found = [f for f in files if f.rsplit("/", 1)[-1] == candidate]
        if len(found) == 1:
            return found[0]
    raise TargetTableError(
        f"{label}: no crate_root, several srcs and no conventional root file — rules_rust "
        f"would refuse it too, and a root this table guessed would send the census down a "
        f"module tree nothing compiles"
    )


def rows_from_query(lines: list[str]) -> dict[str, dict]:
    """The table's rows from `bazel query --output=streamed_jsonproto` output."""
    rules = {}
    for line in lines:
        if line.strip():
            rule = json.loads(line)["rule"]
            rules[rule["name"]] = rule
    rows: dict[str, dict] = {}
    pending: list[tuple[str, dict, str]] = []
    for label, rule in sorted(rules.items()):
        kind = rule["ruleClass"]
        attrs = _attrs(rule)
        srcs = _strings(attrs, "srcs")
        crate = _string(attrs, "crate")
        row = {
            "kind": kind,
            "package": label_package(label),
            "root": "",
            "srcs": sorted(label_path(s) for s in srcs),
            "crate": crate,
            "features": sorted(_strings(attrs, "crate_features")),
            "manual": "manual" in _strings(attrs, "tags"),
        }
        rows[label] = row
        if crate:
            pending.append((label, row, crate))
        else:
            row["root"] = _own_root(label, kind, attrs, srcs)
    for label, row, crate in pending:
        base = rows.get(crate)
        if base is None or base["crate"]:
            raise TargetTableError(f"{label}: crate {crate} is not a first-party library in the graph")
        row["root"] = base["root"]
        row["srcs"] = sorted(set(row["srcs"]) | set(base["srcs"]))
        row["features"] = sorted(set(row["features"]) | set(base["features"]))
    return rows


def generate() -> dict:
    """The table as the build graph states it now."""
    proc = subprocess.run(
        ["bazel", "query", "--output=streamed_jsonproto", QUERY],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise TargetTableError(f"bazel query failed:\n{proc.stderr[-2000:]}")
    rows = rows_from_query(proc.stdout.splitlines())
    if not rows:
        raise TargetTableError("bazel query reported no first-party Rust target")
    return {"schema": SCHEMA, "query": QUERY, "targets": rows}


def render(table: dict) -> str:
    return json.dumps(table, indent=1, sort_keys=True) + "\n"


@lru_cache(maxsize=1)
def table() -> dict[str, dict]:
    """The committed table's rows, by label."""
    try:
        data = json.loads(TABLE.read_text())
    except (OSError, json.JSONDecodeError) as err:
        raise TargetTableError(
            f"{TABLE.relative_to(REPO_ROOT)} is unreadable ({err}); regenerate it with "
            f"`tools/verification/rust-targets --write`"
        ) from err
    if data.get("schema") != SCHEMA:
        raise TargetTableError(f"{TABLE.relative_to(REPO_ROOT)} has schema {data.get('schema')}, not {SCHEMA}")
    return data["targets"]


def target(label: str) -> dict | None:
    return table().get(label)


def is_test(label: str) -> bool:
    row = target(label)
    return row is not None and row["kind"] in TEST_RULES


def crate_roots() -> dict[str, dict]:
    """Every crate root a first-party target compiles, with the targets compiling it.

    One entry per ROOT FILE, not per target: the flavors of one library — the same sources
    under different features — share a root, and a test in that module tree is one control
    however many flavors compile it.
    """
    out: dict[str, dict] = {}
    for label, row in sorted(table().items()):
        entry = out.setdefault(row["root"], {"package": row["package"], "labels": [], "kinds": set()})
        entry["labels"].append(label)
        entry["kinds"].add(row["kind"])
    return out


def root_identity(root: str, package: str) -> str:
    """A crate root as its package states it: `src/lib.rs`, `tests/integration/main.rs`."""
    prefix = f"{package}/" if package else ""
    return root[len(prefix):] if root.startswith(prefix) else root
