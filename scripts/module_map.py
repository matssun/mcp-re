#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The mcp-re-proxy module map: planes, production edges, and misplaced responsibilities.

This is EVIDENCE FOR an architecture model, not the model itself. Two distinct failure
modes have already occurred and they are worth keeping apart:

  * MEASUREMENT — the scan omitted edges. Truncating a file at its first `#[cfg(test)]`
    discarded 500-900 lines of production code in fifteen files, hid three real `cli`
    dependencies, and dropped a production `SystemTime::now()` out of `boundary.clock`.
  * CLASSIFICATION — the edges were right and their meaning was wrong. `config_snapshot`
    and `runtime_state` were filed under `startup` because of where they sit rather than
    what they are, inflating "back-edges into startup" by eight.

So the workflow is: measure -> validate the measurement -> classify -> review the
classification -> plan. Never: run script -> refactor until the number falls.

Both measurement failures biased the count DOWNWARD. That is the dangerous direction
here: it makes the remaining architecture look cleaner and the work smaller than it is.
No systematic cause is claimed; the bias is recorded because it is the direction to
distrust.

Run:  python3 scripts/module_map.py            # the map
      python3 scripts/module_map.py --edges    # every production edge, with symbols
      python3 scripts/module_map.py --selftest # validate the instrument
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "mcp-re-proxy" / "src"

# --- planes -------------------------------------------------------------------------
#
# `runtime-state` exists because of the classification failure above: config_snapshot is
# the ADR-MCPRE-051 §6 hot-reload snapshot the serve loop re-reads PER CONNECTION, and
# runtime_state is ADR-MCPRE-057 §3's lifecycle-as-a-value, which lifecycle_purity_gate
# verifies depends on no production module. Neither is startup machinery.

PLANES: dict[str, list[str]] = {
    "startup": [
        "main", "app", "cli", "startup_plan", "startup_posture",
        "serving_capabilities", "delegated_wiring",
    ],
    "runtime-state": ["config_snapshot", "runtime_state"],
    "serving": [
        "async_serve", "async_fleet", "async_inner", "http_inner", "http_profile_serve",
        "http_profile_dispatch", "request_stages", "exchange_state", "stage_timers",
        "managed_worker", "control_runtime", "materialized_runtime",
        "materializing_runtime",
    ],
    "replay": [
        "async_replay", "shared_replay", "replay_plane", "replay_tier",
        "async_redis_store", "async_etcd_store", "redis_store", "etcd_store",
        "continuation_store", "redis_continuation_store", "admission_source",
        "redis_admission_source",
    ],
    "trust": [
        "trust_plane", "trust_cache", "trust_epoch", "live_trust", "push_trust",
        "reloading_trust", "client_revocation", "revocation_tier", "ocsp",
        "trust_document", "revocation_resolver",
    ],
    "signing": [
        "signing_plane", "key_source", "kms_keysource", "kms_endpoint_policy",
        "aws_kms_keysource", "gcp_kms_keysource", "aws_sigv4", "aws_sts",
        "pkcs11_keysource", "pkcs11_native", "delegated_response_signer",
        "delegated_server_signer",
    ],
    "tls": ["tls", "tls_plane", "tls_auth_epoch", "delegated_tls", "transport"],
    "evidence": ["audit_sink", "log_sink", "transparency", "retained_evidence"],
    "time": ["clock"],
}
PLANE_OF = {m: p for p, ms in PLANES.items() for m in ms}

# Composition-owning planes. An edge INTO one of these from a runtime plane is the thing
# the architecture objective forbids, unless what crosses is a value or type the root
# legitimately produced.
COMPOSITION = {"startup"}

# Reviewable exclusions. Each states WHY the edge is legitimate, so the exclusion itself
# can be argued with rather than silently trusted.
LEGITIMATE: dict[tuple[str, str], str] = {
    ("replay_plane", "startup_plan"):
        "ReplayPlan is a VALUE the composition root computes once and hands down. "
        "Handing a plan to the component that executes it is what a composition root "
        "is for; driving this to zero would be metric gaming.",
    ("materialized_runtime", "app"):
        "serve_fleet is COMPOSITION: it resolves --bind, builds FleetConfig from the "
        "config, and constructs the per-core handler. Turning configuration into a "
        "running fleet is the root's job, not a service hidden inside it.",
}

# Why a target's ownership is wrong, and who should own it instead. Recorded per TARGET
# SYMBOL rather than per edge, because the same misplaced item explains several edges.
MISPLACED_OWNERSHIP: dict[str, tuple[str, str]] = {
    "load_trust": (
        "reads and assembles the trust store — a trust-plane responsibility the parser "
        "happens to host because the command line was its first caller",
        "the trust plane, with the CLI calling it like any other consumer",
    ),
    "load_trust_request_signers": (
        "same as load_trust, for the request-signer key set",
        "the trust plane",
    ),
    "build_revocation_resolver_with_channel": (
        "constructs the revocation resolver and its update channel; a revocation "
        "concern, not an argument-parsing one",
        "the trust plane",
    ),
    "load_client_crls": (
        "reads client CRLs off disk for the TLS plane; the parser owns it only because "
        "the paths arrive as flags",
        "the TLS plane, taking already-validated paths",
    ),
    "DeploymentRequest": (
        "the raw parsed-configuration type, consumed directly by runtime planes so they "
        "depend on the parser's data shape rather than on their own inputs",
        "a validated-configuration/domain type the planes own, with the parser producing it",
    ),
    "ValidatedDeployment": (
        "as DeploymentRequest; the validated form still lives in the parser module",
        "a domain configuration type outside the parser",
    ),
    "DelegatedSigningWiring": (
        "the delegated-signing wiring value, defined in a startup module and consumed by "
        "the signing plane at runtime",
        "the signing plane, if the value is its own; startup if it is genuinely composed",
    ),
    "ProdDelegatedRotor": (
        "as DelegatedSigningWiring", "the signing plane"),
    "build_delegated_signing": (
        "constructs the delegated signer; construction from validated inputs is a "
        "signing-plane responsibility",
        "the signing plane",
    ),
}


def strip_cfg_test_items(text: str) -> str:
    """Remove every `#[cfg(test)]`-attributed item, individually.

    Truncating at the first occurrence looks equivalent and is not: an inline attribute
    on a test helper sits at trust_plane.rs:78, signing_plane.rs:62, tls_plane.rs:137 and
    ocsp.rs:248, hundreds of lines above the real test module.
    """
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        if not lines[i].strip().startswith("#[cfg(test)]"):
            out.append(lines[i])
            i += 1
            continue
        j = i + 1
        while j < len(lines) and "{" not in lines[j] and not lines[j].rstrip().endswith(";"):
            j += 1
        if j < len(lines) and "{" not in lines[j] and lines[j].rstrip().endswith(";"):
            i = j + 1
            continue
        depth, seen = 0, False
        while j < len(lines):
            s = re.sub(r'"(?:\\.|[^"\\])*"', '""', lines[j])
            s = re.sub(r"//.*", "", s)
            for ch in s:
                if ch == "{":
                    depth += 1
                    seen = True
                elif ch == "}":
                    depth -= 1
            if seen and depth <= 0:
                break
            j += 1
        i = j + 1
    return "\n".join(out)


def code_only(text: str) -> str:
    """Production code with test items, comments and string literals neutralised.

    String literals are blanked because a `crate::x::Y` inside an error message is text,
    not a dependency. Comments are dropped because a rustdoc intra-doc link is a
    reference for the reader; counting one would reward deleting documentation.
    """
    text = strip_cfg_test_items(text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    kept = []
    for line in text.split("\n"):
        if line.lstrip().startswith(("///", "//!")):
            continue
        line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
        kept.append(re.sub(r"//.*", "", line))
    return "\n".join(kept)


def edges_for(name: str, src: str, known: set[str]) -> dict[str, set[str]]:
    """Production edges out of one module, as {target: {symbols}}.

    Both reference forms count: a qualified `crate::cli::DeploymentRequest`, and a bare
    `use crate::cli;` followed by `cli::DeploymentRequest`. Missing the second under-reports badly.
    """
    found: dict[str, set[str]] = defaultdict(set)
    for mod, sym in re.findall(r"crate::([a-z0-9_]+)::([A-Za-z0-9_]+)", src):
        if mod in known and mod != name:
            found[mod].add(sym)
    for mod in re.findall(r"^\s*use\s+crate::([a-z0-9_]+)\s*;", src, re.M):
        if mod in known and mod != name:
            for sym in re.findall(rf"\b{mod}::([A-Za-z0-9_]+)", src):
                found[mod].add(sym)
            found.setdefault(mod, set())
    return dict(found)


def build_map() -> tuple[dict[str, dict[str, set[str]]], set[str]]:
    modules = {p.stem for p in SRC.glob("*.rs")} - {"lib"}
    graph: dict[str, dict[str, set[str]]] = {}
    for path in sorted(SRC.glob("*.rs")):
        if path.stem == "lib":
            continue
        graph[path.stem] = edges_for(
            path.stem, code_only(path.read_text(errors="replace")), modules
        )
    return graph, modules


def selftest() -> int:
    """A miniature graph with every construct that previously confused the scanner."""
    sample = "\n".join([
        "//! Module doc mentioning [`crate::cli::DeploymentRequest`] as an intra-doc link.",
        "use crate::cli;",
        "use crate::tls::ServerLimits;",
        "impl Thing {",
        "    #[cfg(test)]",
        "    fn helper() -> u8 { 1 }",          # inline attribute, mid-file
        "}",
        "/// Doc link to [`crate::trust_plane::Thing`] — a reference, not a dependency.",
        "fn production(c: &cli::DeploymentRequest) -> &str {",
        '    let _ = "crate::evidence::AuditSink";',   # a path inside a string
        "    // crate::replay_plane::Plan in a comment",
        "    ServerLimits::NAME",
        "}",
        "#[cfg(test)]",
        "mod tests {",
        "    use crate::signing_plane;",
        "    fn t() -> signing_plane::Thing { todo!() }",
        "}",
    ])
    known = {"cli", "tls", "trust_plane", "evidence", "replay_plane", "signing_plane"}
    got = edges_for("subject", code_only(sample), known)

    checks: list[tuple[bool, str]] = [
        ("cli" in got and "DeploymentRequest" in got["cli"],
         "a bare `use crate::cli;` plus `cli::DeploymentRequest` AFTER an inline #[cfg(test)]"),
        ("tls" in got and "ServerLimits" in got["tls"],
         "a qualified `use crate::tls::ServerLimits;`"),
        ("trust_plane" not in got, "a rustdoc intra-doc link must NOT be an edge"),
        ("evidence" not in got, "a path inside a string literal must NOT be an edge"),
        ("replay_plane" not in got, "a path inside a comment must NOT be an edge"),
        ("signing_plane" not in got, "a dependency used only by #[cfg(test)] code"),
    ]
    failures = [why for ok, why in checks if not ok]
    for ok, why in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {why}")
    if failures:
        print(f"\nmodule_map selftest: FAIL ({len(failures)})")
        return 1
    print("\nmodule_map selftest: PASS")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    graph, modules = build_map()

    unclassified = sorted(m for m in modules if m not in PLANE_OF)
    if unclassified:
        print(f"UNCLASSIFIED MODULES (fix PLANES before trusting this map): {unclassified}\n")

    if "--edges" in sys.argv:
        print("EVERY PRODUCTION EDGE\n")
        for a in sorted(graph):
            for b, syms in sorted(graph[a].items()):
                print(f"  {a:26} -> {b:26} {', '.join(sorted(syms)) or '(module import)'}")
        return 1 if unclassified else 0

    total = sum(len(v) for v in graph.values())
    print(f"{len(modules)} modules, {total} production edges, {len(PLANES)} planes\n")

    cross: dict[tuple[str, str], int] = defaultdict(int)
    for a, tos in graph.items():
        for b in tos:
            pa, pb = PLANE_OF.get(a), PLANE_OF.get(b)
            if pa and pb and pa != pb:
                cross[(pa, pb)] += 1
    print("CROSS-PLANE EDGES")
    for (pa, pb), n in sorted(cross.items(), key=lambda kv: -kv[1]):
        mark = "   <-- into composition" if pb in COMPOSITION else ""
        print(f"  {n:3d}  {pa:14} -> {pb}{mark}")

    print("\nRUNTIME -> COMPOSITION EDGES")
    misplaced, legit = [], []
    for a, tos in sorted(graph.items()):
        if PLANE_OF.get(a) in COMPOSITION:
            continue
        for b, syms in sorted(tos.items()):
            if PLANE_OF.get(b) not in COMPOSITION:
                continue
            (legit if (a, b) in LEGITIMATE else misplaced).append((a, b, syms))

    print(f"\n  MISPLACED RESPONSIBILITY — the reduction target ({len(misplaced)})")
    for a, b, syms in misplaced:
        print(f"\n    {a} -> {b}")
        print(f"      symbols: {', '.join(sorted(syms)) or '(module import)'}")
        for sym in sorted(syms):
            if sym in MISPLACED_OWNERSHIP:
                why, owner = MISPLACED_OWNERSHIP[sym]
                print(f"      {sym}: {why}")
                print(f"        proposed owner: {owner}")

    print(f"\n  LEGITIMATE — excluded, with the reason reviewable ({len(legit)})")
    for a, b, syms in legit:
        print(f"\n    {a} -> {b}  [{', '.join(sorted(syms))}]")
        print(f"      {LEGITIMATE[(a, b)]}")

    by_target: dict[str, int] = defaultdict(int)
    for _, b, _ in misplaced:
        by_target[b] += 1
    print("\n\nREDUCTION TARGET BY OWNER: " +
          ", ".join(f"{k}={v}" for k, v in sorted(by_target.items())))
    return 1 if unclassified else 0


if __name__ == "__main__":
    sys.exit(main())
