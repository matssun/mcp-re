#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serving-identity provenance gate — direct TLS resolves identity from the AUTHENTICATED
peer, never by reconstructing it from certificate representation (ADR-MCPRE-064, #619).

WHAT THIS PROVES, exactly, over production Rust (test regions excluded):

  1. Neither direct-TLS serving path — the async one and the blocking one — mentions any
     raw-certificate identity route. `extract_identity`, `interpret_identity`,
     `from_leaf_der` and the retired `resolve_identity_from_leaf` may not appear in them.
  2. Each serving path resolves identity through `resolve_authenticated_identity`, and does
     so exactly once: one call site per path, so the two cannot drift into two derivations
     that currently agree.
  3. `resolve_authenticated_identity` reaches `authenticate_relationship_peer` and contains
     no raw-certificate route of its own.
  4. Its signature takes the acceptance and the options, and NOTHING else. No `leaf`, no
     `der`, no `chain`, no `certificate`, no second identity parameter.
  5. No production code outside the historical facade calls `extract_identity`.

WHY (4) IS THE ONE THAT MATTERS. The composition ADR-MCPRE-064 Slice 2 forbids is an
acceptance from relationship A paired with an identity derived from credential B, and the
enforcement mechanism is the ABSENCE OF A PARAMETER through which the second could enter.
That is a property of a signature, and a signature is exactly what a future edit widens
first — "just pass the leaf too, we already have it" reintroduces the defect without
touching a single check, and every existing control stays green because each one still
measures a true thing about a correctly-composed value.

WHAT IT DOES NOT PROVE: that the resolved identity is right. That is THM-0031 and the
controls in `tls::authenticated_identity_resolution_tests`, which drive real handshakes
against a chain carrying a rival identity. This gate is syntactic and its claim stops at
the shape of the route.

WHY A GATE AND NOT A TYPE. The historical route is still legitimate — `extract_identity` is
a published API with its own X.509 conformance suite over real DER — so it cannot be
deleted to make the wrong call unavailable. What can be held is that the SERVING PATHS do
not take it. Until the last consumer of the historical vocabulary is gone, that is a
call-site fact, and a call-site fact needs a call-site check.

Run:  python3 scripts/serving_identity_provenance_gate.py
      python3 scripts/serving_identity_provenance_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The two direct-TLS serving paths. Both reach an establishment boundary, both resolve a
#: transport identity for the request they are about to serve, and ADR-MCPRE-051 §1 makes
#: them the same security core over two I/O framings.
SERVING_PATHS = [
    "mcp-re-proxy/src/async_serve.rs",
    "mcp-re-proxy/src/blocking_mtls_harness/connection.rs",
]

#: Where the strategy dispatch lives, and the one function both serving paths call.
DISPATCH_MODULE = "mcp-re-proxy/src/tls.rs"

#: The historical facade module. It is allowed to name the historical route, because
#: converting between the vocabularies is the whole reason it exists.
FACADE = "mcp-re-proxy/src/facades/asserted_identity.rs"

#: The route this migration removed from production serving: certificate representation in,
#: identity out. Each of these names a step of it.
RAW_IDENTITY_ROUTE = (
    "extract_identity",
    "interpret_identity",
    "from_leaf_der",
    "resolve_identity_from_leaf",
)

RESOLVER = "resolve_authenticated_identity"
COMPOSITION = "authenticate_relationship_peer"

# ADR-MCPRE-061 §5.1 — both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open a test region.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")

#: `pub(crate) fn resolve_authenticated_identity( .. ) -> ..` up to the opening brace.
SIGNATURE = re.compile(
    r"fn\s+" + RESOLVER + r"\s*\((?P<params>.*?)\)\s*->[^{]*\{", re.S
)

#: A parameter naming certificate representation or a rival identity product. The check is
#: on the parameter LIST, so a local variable of any of these names is untouched — what is
#: forbidden is a caller being able to supply one.
FORBIDDEN_PARAM = re.compile(
    r"\b(leaf|leaf_der|der|chain|cert|certificate|cert_der|identity|peer_identity)\b"
)


def production_text(text: str) -> str:
    """The source with every test region removed.

    Same definition as `scripts/module_size_gate.py`: a region runs from its
    `#[cfg(test)]`-family attribute to the end of the module it introduces, tracked by
    brace depth, and counting resumes afterwards. A control that drives a real handshake
    and then asserts something about a historical extractor is evidence, not a production
    route, and a gate that could not tell them apart would forbid writing the controls.
    """
    lines = text.splitlines()
    kept: list[str] = []
    i = 0
    while i < len(lines):
        if TEST_ATTR.match(lines[i].lstrip()):
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
        kept.append(lines[i])
        i += 1
    return "\n".join(kept)


def resolver_body(text: str) -> str | None:
    """The body of `resolve_authenticated_identity`, or None if it is not defined here."""
    match = SIGNATURE.search(text)
    if match is None:
        return None
    depth = 0
    start = match.end() - 1
    for offset in range(start, len(text)):
        if text[offset] == "{":
            depth += 1
        elif text[offset] == "}":
            depth -= 1
            if depth == 0:
                return text[start : offset + 1]
    return None


def check_serving_path(path: str, text: str) -> list[str]:
    problems = []
    for name in RAW_IDENTITY_ROUTE:
        if name in text:
            problems.append(
                f"{path}: names `{name}` in production. A direct-TLS serving path must "
                f"resolve identity through `{RESOLVER}`, not by reconstructing it from "
                f"certificate representation (ADR-MCPRE-064 #619)."
            )
    calls = len(re.findall(r"\b" + RESOLVER + r"\s*\(", text))
    if calls != 1:
        problems.append(
            f"{path}: calls `{RESOLVER}` {calls} time(s); expected exactly 1. Two call "
            f"sites in one path, or none, is how the async and blocking paths stop being "
            f"one derivation and become two that happen to agree."
        )
    return problems


def check_dispatch(text: str) -> list[str]:
    problems = []
    signature = SIGNATURE.search(text)
    body = resolver_body(text)
    if signature is None or body is None:
        return [
            f"{DISPATCH_MODULE}: `{RESOLVER}` is not defined here. It is the one route "
            f"both serving paths take; moving it needs this gate moved with it."
        ]
    if COMPOSITION not in body:
        problems.append(
            f"{DISPATCH_MODULE}: `{RESOLVER}` does not reach `{COMPOSITION}`. The "
            f"identity must come from the ADR-MCPRE-064 Slice 2 authority."
        )
    for name in RAW_IDENTITY_ROUTE:
        if name in body:
            problems.append(
                f"{DISPATCH_MODULE}: `{RESOLVER}` names `{name}`. The resolver may not "
                f"carry a raw-certificate route of its own."
            )
    params = signature.group("params")
    forbidden = sorted(set(FORBIDDEN_PARAM.findall(params)))
    if forbidden:
        problems.append(
            f"{DISPATCH_MODULE}: `{RESOLVER}` takes parameter(s) named {forbidden}. The "
            f"composition takes the acceptance and the configured policy and NOTHING "
            f"else — the absence of a second-credential parameter is what makes pairing "
            f"relationship A's acceptance with credential B's identity unconstructible "
            f"(THM-0031). A parameter is how that returns."
        )
    return problems


def check_facade_containment(root: Path) -> list[str]:
    """No production caller of the historical extractor outside the facade it belongs to."""
    problems = []
    for path in sorted(root.glob("mcp-re-*/src/**/*.rs")):
        rel = path.relative_to(root).as_posix()
        if rel in (FACADE, DISPATCH_MODULE):
            continue
        text = production_text(path.read_text(encoding="utf-8"))
        if re.search(r"\bextract_identity\s*\(", text):
            problems.append(
                f"{rel}: calls `extract_identity` in production. The historical extractor "
                f"survives for its published X.509 suite; production identity comes from "
                f"the authenticated peer."
            )
    return problems


def check(root: Path) -> tuple[list[str], int]:
    problems: list[str] = []
    examined = 0
    for rel in SERVING_PATHS:
        path = root / rel
        if not path.exists():
            problems.append(f"{rel}: missing — the gate cannot examine what is not there.")
            continue
        examined += 1
        problems += check_serving_path(rel, production_text(path.read_text(encoding="utf-8")))

    dispatch = root / DISPATCH_MODULE
    if not dispatch.exists():
        problems.append(f"{DISPATCH_MODULE}: missing.")
    else:
        examined += 1
        problems += check_dispatch(production_text(dispatch.read_text(encoding="utf-8")))

    problems += check_facade_containment(root)
    return problems, examined


def selftest() -> int:
    """Each case is a way the migration could be undone. A gate that passed them all would
    be reporting on a file set rather than on a property."""
    cases = [
        (
            "clean",
            f"let identity = {RESOLVER}(credential.as_ref(), options);",
            f"pub(crate) fn {RESOLVER}(accepted: Option<&Mvc>, options: &ServerOptions) "
            f"-> Option<TransportIdentity> {{ {COMPOSITION}(accepted?.clone(), p).ok() }}",
            0,
        ),
        (
            "serving path reconstructs from the leaf",
            "let identity = extract_identity(leaf, policy);\n"
            f"let other = {RESOLVER}(c, o);",
            f"pub(crate) fn {RESOLVER}(accepted: Option<&Mvc>, options: &ServerOptions) "
            f"-> Option<TransportIdentity> {{ {COMPOSITION}(accepted?.clone(), p).ok() }}",
            1,
        ),
        (
            "serving path stopped resolving at all",
            "let identity = None;",
            f"pub(crate) fn {RESOLVER}(accepted: Option<&Mvc>, options: &ServerOptions) "
            f"-> Option<TransportIdentity> {{ {COMPOSITION}(accepted?.clone(), p).ok() }}",
            1,
        ),
        (
            "resolver widened to accept a leaf",
            f"let identity = {RESOLVER}(credential.as_ref(), options);",
            f"pub(crate) fn {RESOLVER}(accepted: Option<&Mvc>, leaf: Option<&[u8]>, "
            f"options: &ServerOptions) -> Option<TransportIdentity> "
            f"{{ {COMPOSITION}(accepted?.clone(), p).ok() }}",
            1,
        ),
        (
            "resolver stopped reaching the authority",
            f"let identity = {RESOLVER}(credential.as_ref(), options);",
            f"pub(crate) fn {RESOLVER}(accepted: Option<&Mvc>, options: &ServerOptions) "
            f"-> Option<TransportIdentity> {{ extract_identity(x, p) }}",
            2,
        ),
        (
            "the route is named only inside a test region",
            "#[cfg(test)]\nmod tests {\n    fn t() { extract_identity(leaf, p); }\n}\n"
            f"let identity = {RESOLVER}(credential.as_ref(), options);",
            f"pub(crate) fn {RESOLVER}(accepted: Option<&Mvc>, options: &ServerOptions) "
            f"-> Option<TransportIdentity> {{ {COMPOSITION}(accepted?.clone(), p).ok() }}",
            0,
        ),
    ]
    failures = 0
    for name, serving, dispatch, expected in cases:
        found = check_serving_path("probe.rs", production_text(serving))
        found += check_dispatch(production_text(dispatch))
        status = "ok " if len(found) == expected else "FAIL"
        if len(found) != expected:
            failures += 1
        print(f"  {status} {name}: {len(found)} problem(s), expected {expected}")
        for problem in found:
            print(f"        {problem}")
    print(
        f"\nserving-identity-provenance selftest: "
        f"{'PASS' if failures == 0 else 'FAIL'} — {len(cases)} case(s)"
    )
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems, examined = check(REPO)
    if examined == 0:
        print(
            "serving-identity provenance gate: FAIL — examined nothing. An empty scope is "
            "a broken gate, not a clean tree.",
            file=sys.stderr,
        )
        return 1
    if problems:
        print(f"serving-identity provenance gate: FAIL — {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"serving-identity provenance gate: OK — {examined} production module(s) examined; "
        f"both direct-TLS serving paths resolve identity through `{RESOLVER}` -> "
        f"`{COMPOSITION}`, and no production caller reconstructs it from certificate "
        f"representation."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
