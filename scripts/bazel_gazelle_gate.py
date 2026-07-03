#!/usr/bin/env python3
"""ADR-MCPS-048 / MCPS-70 — Bazel BUILD semantic-drift gate.

Governance boundary (the load-bearing rule): gazelle_rust ASSISTS and DETECTS
drift, but is NOT the authoritative owner of the committed BUILD files. This gate
enforces *semantic parity* over the managed target/edge set — NOT byte-identity,
NOT gazelle's formatting, NOT gazelle's exact generated text.

It runs `bazel run //:gazelle -- -mode diff` (which never writes) and inspects the
diff gazelle WOULD apply. It FAILS only on **unmanaged semantic drift the
developer forgot to add**:

  1. a target present in the Cargo graph but MISSING from BUILD (coverage drift —
     e.g. a `tests/*.rs` cargo runs with no Bazel target), and
  2. a first-party/third-party `deps` EDGE that a `use` implies but BUILD omits
     (the exact #220 failure: a missing first-party dep edge).

It deliberately IGNORES, as managed/allowed:

  * formatting gazelle injects: explicit `visibility`, `compile_data=["Cargo.toml"]`,
    and `deps` reordering (generate_from_cargo does these unconditionally);
  * `# keep` edges — the hand-pinned feature-flavor selections (MCPS-69);
  * edge REMOVALS — gazelle can't see non-code `data`/`compile_data` deps
    (source/spec/BUILD files the traceability manifest include_str!s) or
    platform-conditional deps; demanding their deletion would make gazelle the
    authority, which the ruling forbids. Removals are informational only;
  * allowlisted exceptions: HITL/live-cloud tests, platform-specific targets,
    naming collisions, and tracked known drift (see ALLOWLIST below).

Deterministic, read-only, no BUILD rewrites. Exit 0 = parity; exit 1 = drift.

Known limitation: a `deps` list expressed as an unmergeable form gazelle cannot
read — `all_crate_deps(...)`, a `_VAR + [...]` concat, or `glob(...)` for srcs —
is emitted by gazelle as a whole-attribute replacement, which this gate skips (it
is representation, not a clean inserted edge). Edges in such targets are therefore
not edge-gated. In practice that is safe here: the only `all_crate_deps` target is
the leaf `mcps-core` (no first-party deps; `all_crate_deps` auto-covers its
crates.io deps, so a new dep is picked up with no BUILD edit). Every crate that
carries first-party edges uses an explicit `deps = [...]` list, which gazelle
merges — so a forgotten first-party edge (the #220 failure) IS caught. Missing
TARGETS are always caught regardless of deps representation.

CI: `python3 scripts/bazel_gazelle_gate.py` (pair with `bazel test //...`).
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter

# --- Allowlist: intentional generated-vs-hand-maintained exceptions ----------
#
# A gazelle-proposed NEW target whose name is here is NOT counted as drift. Every
# entry states WHY it is exempt. Keep this list tight — it is the audited seam
# between "gazelle may add this" and "a human decided this stays as-is."

# Naming collisions: gazelle names a crate's lib/bin/crate-test after the Cargo
# package name (with dashes) or `<crate>_test`; the repo already ships the SAME
# unit under a hand-chosen target name (e.g. `mcps_proxy_cli`, `proxy_unit_test`).
# Adopting gazelle's name would duplicate, not add coverage.
ALLOW_NAMING_COLLISION = {
    "mcps-client-proxy-cli",       # == :mcps_client_proxy_cli (bin)
    "mcps-client-proxy-cli_test",  # == crate unit test of the cli
    "mcps-conformance",            # == conformance lib/bin, hand-named
    "mcps-stdio-server",           # == :mcps_stdio_server (bin)
    "mcps-demo-fileserver",        # == hand-named demo bin
    "mcps-demo-server",            # == hand-named demo bin
    "mcps-proxy",                  # == :mcps_proxy_cli (bin over src/main.rs)
    "mcps_proxy_test",             # == :proxy_unit_test (crate=:mcps_proxy)
    "echo-inner",                  # == hand-named inner echo bin
    "emit_mtls_fixtures",          # == hand-named fixture-emitter bin
}

# HITL / live-cloud: `#![cfg(feature="…kms…")]` + `#[ignore]`, run ONLY in the
# manual live-infra lane against real AWS/GCP KMS. A generated Bazel target would
# compile empty (misleading) or attempt real cloud calls in CI. Cargo-only.
ALLOW_HITL_LIVE = {
    "aws_kms_live_test",
    "gcp_kms_live_test",
    "gcp_kms_draft02_live_test",
    "gcp_kms_delegated_tls_live_test",
    "t4_enterprise_kms_custody",
    "t4_python_kms_custody",
}

# Tracked known drift: genuine missing Bazel targets whose Bazel wiring needs a
# dedicated fixture/runfile bridge (they read the repo tree / drive external SDK
# drivers). Filed as issues; allowlisted so the gate is GREEN-but-honest until
# each is wired, and NEW untracked drift still fails. Remove an entry when its
# target lands.
ALLOW_TRACKED_DRIFT = {
    # name: "issue — why it is not yet a Bazel target"
    # These need a runfile/driver bridge (they read the repo tree / drive external
    # SDK driver binaries); tracked for a dedicated slice. The three directly
    # wireable drifts the gate first found (continuation_roundtrip_test,
    # continuation_driving_test, draft02_vectors_test) are now real Bazel targets.
    "no_tracked_secrets": "MCPS-77 (#256) — scans tracked repo files; needs runfiles bridge",
    "sdk_driver_matrix": "MCPS-77 (#256) — drives SDK driver binaries as runfiles",
}

ALLOWLIST = ALLOW_NAMING_COLLISION | ALLOW_HITL_LIVE | set(ALLOW_TRACKED_DRIFT)

# A quoted Bazel label at line start (first-party //, third-party @crates_mcps//:,
# or local :). Captures the bare label value so trailing commas AND inline
# comments (e.g. `"//x:y",  # #220 …`) don't defeat reorder-cancellation.
LABEL_TOKEN_RE = re.compile(r'^"((?://|@|:)[^"]+)"')
NEW_TARGET_RE = re.compile(r"^(nt_rust_\w+)\($")
NAME_RE = re.compile(r'^name = "([^"]+)",')


def run_gazelle_diff() -> str:
    """Run the generator in read-only diff mode; return its unified diff."""
    proc = subprocess.run(
        ["bazel", "run", "//:gazelle", "--", "-mode", "diff"],
        capture_output=True,
        text=True,
    )
    # gazelle exits nonzero simply because a diff exists; that is not an error
    # here. A genuine failure (missing target, bad directive) prints to stderr.
    if proc.returncode not in (0, 1, 2, 3):
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"gazelle diff failed (exit {proc.returncode})")
    return proc.stdout


def parse_per_file(diff: str) -> dict[str, list[tuple[str, str]]]:
    """Split the unified diff into {file: [(sign, trimmed_content), ...]}.

    sign is '+', '-', or ' ' (context). Order is preserved so we can tell a
    label INSERTED into an existing list (context opener) from a whole-attribute
    replacement (added opener).
    """
    files: dict[str, list[tuple[str, str]]] = {}
    cur: list[tuple[str, str]] | None = None
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].split("\t", 1)[0].strip()
            cur = files.setdefault(path, [])
            continue
        if raw.startswith("--- ") or raw.startswith("@@"):
            continue
        if cur is None:
            continue
        if raw and raw[0] in "+- ":
            cur.append((raw[0], raw[1:].strip()))
    return files


# Plain-form crate names whose `use` is satisfied by a KEPT feature-flavor dep
# (MCPS-69): gazelle's `resolve` points `use mcps_host` at `:mcps_host`, but the
# target already carries `:mcps_host_test_fixtures  # keep`, so a proposed plain
# edge is a flavor artifact, not a missing edge.
FLAVOR_PLAIN = {"mcps_host", "mcps_proxy", "mcps_transport"}
ATTR_OPEN_RE = re.compile(r"^\w+ = \[$")  # e.g. `deps = [`, `srcs = [`


def analyze_file(lines: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    """Return (new_target_names, inserted_edge_labels) for one file's diff.

    - new_target_names: gazelle-proposed NEW targets (run of `+` from
      `nt_rust_X(` to `)`).
    - inserted_edge_labels: `+` label lines INSERTED into a list whose opener is
      a context line (an existing, gazelle-mergeable deps list) — i.e. a genuine
      missing edge. Labels inside a whole added attribute block (`+deps = [` … `+]`,
      a representation/merge-conflict rewrite of an unreadable `all_crate_deps()`/
      variable/glob form) are skipped, as are `# keep` labels and flavor-plain
      forms. Removed labels of the same value cancel (reordering).
    """
    names: list[str] = []
    inserted: list[str] = []
    removed_labels: Counter = Counter()
    for s, c in lines:
        if s == "-":
            m = LABEL_TOKEN_RE.match(c)
            if m:
                removed_labels[m.group(1)] += 1

    i = 0
    n = len(lines)
    in_added_attr = 0  # >0 while inside a wholly-added `attr = [ … ]` block
    while i < n:
        sign, content = lines[i]

        # New target block: consume `+` run from `nt_rust_X(` to `)`.
        if sign == "+" and NEW_TARGET_RE.match(content):
            name = "<unnamed>"
            j = i + 1
            while j < n and lines[j][0] == "+":
                m = NAME_RE.match(lines[j][1])
                if m:
                    name = m.group(1)
                if lines[j][1] == ")":
                    break
                j += 1
            names.append(name)
            i = j + 1
            continue

        # Track whole-added attribute blocks (representation rewrites): skip
        # their label bodies.
        if sign == "+" and ATTR_OPEN_RE.match(content):
            in_added_attr += 1
            i += 1
            continue
        if in_added_attr:
            if sign == "+" and content == "],":
                in_added_attr -= 1
            i += 1
            continue

        # A label inserted into an EXISTING (context-opener) list.
        if sign == "+" and "# keep" not in content:
            m = LABEL_TOKEN_RE.match(content)
            if m:
                label = m.group(1)
                if removed_labels.get(label, 0) > 0:
                    removed_labels[label] -= 1          # reorder — cancel
                else:
                    plain = label.rsplit(":", 1)[-1]
                    if plain not in FLAVOR_PLAIN:
                        inserted.append(label)
        i += 1

    return names, inserted


def main() -> int:
    diff = run_gazelle_diff()
    files = parse_per_file(diff)

    missing_targets: list[tuple[str, str]] = []   # (file, name)
    missing_edges: list[tuple[str, str]] = []      # (file, edge label)
    tracked_hits: set[str] = set()

    for path, lines in files.items():
        new_names, inserted = analyze_file(lines)

        for name in new_names:
            if name in ALLOWLIST:
                if name in ALLOW_TRACKED_DRIFT:
                    tracked_hits.add(name)
                continue
            missing_targets.append((path, name))

        for edge in inserted:
            missing_edges.append((path, edge))

    # --- Report ---------------------------------------------------------------
    drift = bool(missing_targets or missing_edges)
    if not drift:
        print("bazel-gazelle-gate: PASS — no unmanaged semantic drift.")
        if tracked_hits:
            print("  (tracked known drift still allowlisted:)")
            for n in sorted(tracked_hits):
                print(f"    - {n}: {ALLOW_TRACKED_DRIFT[n]}")
        return 0

    print("bazel-gazelle-gate: FAIL — unmanaged semantic drift detected.\n")
    if missing_targets:
        print("Missing Bazel targets (cargo builds them; Bazel does not):")
        for path, name in sorted(missing_targets):
            print(f"    {path}: {name}")
        print()
    if missing_edges:
        print("Missing / unexpected dep edges (a `use` implies them; BUILD omits):")
        for path, edge in sorted(set(missing_edges)):
            print(f"    {path}: {edge}")
        print()
    print("Fix: add the target/edge to the crate's BUILD.bazel (see the gazelle")
    print("diff: `bazel run //:gazelle -- -mode diff`), or, if it is an intentional")
    print("exception, add it to the categorized ALLOWLIST in this script with a reason.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
