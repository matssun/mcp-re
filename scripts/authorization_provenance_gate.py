#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authorization-provenance gate — ADR-MCPRE-065 Slice 1 (#630).

WHAT THIS PROVES, exactly, over production Rust (test regions excluded):

  1. The authorization authority names no certificate, TLS or transport-identity route.
     `TransportIdentity`, `extract_identity`, `peer_certificates`, `x509`, `rustls`,
     `from_leaf_der` and friends may not appear in it. Peer identity reaches authorization
     as the ADR-MCPRE-064 product or not at all.
  2. **Law A-1.** The authorization authority names no MCP transport header and never asks
     whether a transport contract is enforced. `Mcp-Method`, `Mcp-Name`,
     `MCP_METHOD_HEADER`, `MCP_NAME_HEADER` and `mcp_transport` are absent from it.
  3. The action coordinate proves its own pairing: `interpret_authorization_action` asks
     the verified request itself (`covers_body`), so a body that is not the signed body
     cannot produce an inhabitant — and the comparison is not re-derived here from parts.
  4. The serving path decides exactly once: `handle` calls `authorization_stage` once,
     `authorization_stage` reaches `decide`, and `decide` reaches `authorize`.
  5. `authorize` admits its predecessors and NOTHING else. No `header`, no `leaf`, no
     `chain`, no `certificate`, no `cert`, no rival identity parameter.
  6. Both sealed products keep their representation private: no `pub` field in
     `VerifiedAuthorizationActor`, `VerifiedAuthorizationAction`, `AuthorizationRequest` or
     `AuthorizedRequestFacts`.
  7. **Dispatch is gated by the type, not by source order.** `ReadyForDispatch::new` takes
     an `AuthorizedRequestBody`; that type has exactly ONE producer, `release`, defined once
     on `AuthorizationPosture`; and the serving assembly calls `release` exactly once. A
     pipeline that dropped the decision would not compile at the dispatch.
  8. No configuration promotes a conformance evaluator to production authority:
     `--authz reference` is still refused by Layer-A validation.
 10. **The posture that claims nothing has one producer.** `AuthorizationPosture`'s variants
     are named in production only in `decide.rs`, which builds them, and `posture.rs`, which
     projects them. Nowhere else in the authority, and nowhere in the serving path. This is
     what closes the gap the sealed body type leaves open: `NoPolicyConfigured` is a public
     variant, so possession of an `AuthorizedRequestBody` proves a decision was TAKEN and
     not that a configured policy produced it — unless nothing else can synthesize the
     posture that claims nothing.

  9. **The Mode-1 linkage form can never become Mode-2 evidence.** The candidate filter in
     `bound_decision_evidence` selects on `BindingType::OpaqueDigest`, so a
     `pdp-decision` / `reference-digest` entry — which names an external decision MCP-RE
     authenticates nothing about — is not a candidate at all, rather than a candidate that
     is rejected later.

WHY (5) IS THE ONE THAT MATTERS. Law A-1 is not enforced by a check that could be deleted;
it is enforced by the ABSENCE OF A PARAMETER through which a header could enter. That is a
property of a signature, and a signature is what a future edit widens first — "just pass the
headers too, we already have them" reintroduces the defect without touching a single check,
and every behavioural control stays green because each still measures a true thing about a
correctly-composed value.

WHAT IT DOES NOT PROVE: that the decision is right. That is the controls in
`tests/integration_async/authorization_serving_test.rs`, which drive real signed requests
whose covered routing header disagrees with the body they also signed. This gate is
syntactic and its claim stops at the shape of the route.

Run:  python3 scripts/authorization_provenance_gate.py
      python3 scripts/authorization_provenance_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The authorization authority. Every file of it, because the claim is about the AUTHORITY,
#: not about one module of it — a route added next door would otherwise be invisible.
AUTHORITY_DIR = "mcp-re-proxy/src/authorization"

#: The serving path that consults it, and the machine that orders the decision.
#:
#: A DIRECTORY, read whole. MCPRE-175 split the assembly into one module per region of the
#: exchange, so `authorization_stage` and the function that orders it moved out of
#: `mod.rs`; a gate still reading that one file counted zero calls, which is the shape this
#: gate exists to refuse. The claim is about the serving PATH, and its closure follows the
#: owner subtree.
SERVING = "mcp-re-proxy/src/http_profile_serve"

#: The function that orders the pre-admission region, and therefore the one place the
#: authorization decision is sequenced. `handle` orders the REGIONS; this orders the
#: decisions inside the free one. The chain the gate checks is
#: `handle` -> `REGION_ASSEMBLY` -> `authorization_stage` -> `decide`, each exactly once.
REGION_ASSEMBLY = "admit_request"
VALIDATION = "mcp-re-proxy/src/config_state/validation/residue.rs"

#: Certificate / TLS / transport-identity vocabulary. Peer identity reaches authorization as
#: `RequestPeerBindingFacts` or not at all (ADR-MCPRE-065 §3).
RAW_PEER_ROUTE = (
    "TransportIdentity",
    "extract_identity",
    "interpret_identity",
    "from_leaf_der",
    "resolve_identity_from_leaf",
    "peer_certificates",
    "x509",
    "rustls",
)

#: Transport routing hints, and the contract that would make them agree with the body.
#: Law A-1: none of these is authorization authority, and correctness must not depend on
#: whether the contract is enforced.
TRANSPORT_HINTS = (
    "Mcp-Method",
    "Mcp-Name",
    "MCP_METHOD_HEADER",
    "MCP_NAME_HEADER",
    "mcp_transport",
)

#: `(function, what its body must reach)`.
#: `(file, function, what its body must reach)`. FILE-SCOPED on purpose: the authority now
#: has more than one `decide`, and a gate that searched the concatenated source would measure
#: whichever it found first — reporting a true fact about the wrong function.
LINKS = (
    ("verified_action.rs", "interpret_authorization_action", "covers_body"),
    ("serving.rs", "decide", "authorize"),
    ("relation.rs", "decide", "verify_authorization_decision"),
    ("evidence.rs", "bound_decision_evidence", "verify_pdp_decision_binding"),
    # The Mode-1 / Mode-2 split, structurally. The candidate filter must name the EVIDENCE
    # form: a `reference-digest` entry names an external decision MCP-RE authenticates
    # nothing about, and it must not be selectable and then rejected — it must never enter.
    ("evidence.rs", "bound_decision_evidence", "BindingType::OpaqueDigest"),
)

#: Every sealed product of this authority, and the rule: a private representation.
SEALED = (
    "VerifiedAuthorizationActor",
    "VerifiedAuthorizationAction",
    "AuthorizationRequest",
    "AuthorizedRequestFacts",
)

#: The type that gates the dispatch, its single producer, and where the ready state lives.
#:
#: This is the enforcement, and it is stronger than an ordering check: the inner dispatch
#: consumes a `ReadyForDispatch`, that state carries an `AuthorizedRequestBody`, and the
#: only way to obtain one is an authorization decision releasing it. A pipeline that dropped
#: the stage does not become a subtly weaker proxy that still compiles.
#: The posture and where its variants may be named in production.
#:
#: `decide.rs` BUILDS them and is the only operation entitled to; `posture.rs` OWNS them and
#: projects them. A third file naming a variant is either a second producer — which would let
#: a serving path release a body under the posture that claims nothing, on a deployment where
#: a policy is configured — or a consumer destructuring what it should be asking for.
POSTURE = "AuthorizationPosture"
POSTURE_VARIANTS = ("NoPolicyConfigured", "Authorized")
POSTURE_SITES = ("decide.rs", "posture.rs")

DISPATCH_BODY = "AuthorizedRequestBody"
RELEASE = "release"
STAGES = "mcp-re-proxy/src/request_stages.rs"

#: A parameter through which a header, a certificate or a rival identity could enter.
FORBIDDEN_PARAM = re.compile(
    r"\b(header|headers|leaf|leaf_der|der|chain|cert|certificate|cert_der|identity|"
    r"peer_identity|transport)\b"
)

# ADR-MCPRE-061 §5.1 — both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open a test region.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")


#: A line comment, including a doc comment. Stripped before the vocabulary scan: a module
#: whose documentation explains why it does NOT read `Mcp-Name` is exactly what these
#: modules should carry, and a gate that forbade saying so would forbid the explanation
#: while leaving the route open.
LINE_COMMENT = re.compile(r"^\s*(///|//!|//).*$", re.M)


def code_only(text: str) -> str:
    """`text` with line comments removed. The claim is about the ROUTE, not the prose."""
    return LINE_COMMENT.sub("", text)


def production_text(text: str) -> str:
    """The source with every test region removed.

    Same definition as `scripts/module_size_gate.py`: a region runs from its
    `#[cfg(test)]`-family attribute to the end of the module it introduces, tracked by brace
    depth, and counting resumes afterwards. A control that drives a real handshake and then
    names a certificate is evidence, not a production route, and a gate that could not tell
    them apart would forbid writing the controls.
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


def signature_re(name: str) -> re.Pattern:
    """`fn <name>( .. ) -> ..` up to the opening brace."""
    return re.compile(r"fn\s+" + name + r"\s*\((?P<params>.*?)\)\s*->[^{]*\{", re.S)


def body_of(text: str, name: str) -> str | None:
    """The body of `name`, or None if it is not defined here."""
    match = signature_re(name).search(text)
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


def struct_body(text: str, name: str) -> str | None:
    """The field block of `struct <name> { .. }`, or None."""
    match = re.search(r"\bstruct\s+" + name + r"\b[^{;]*\{", text)
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


def check_authority(sources: dict[str, str]) -> list[str]:
    """(1), (2), (3), (5), (6) over the authorization authority."""
    problems: list[str] = []
    joined = code_only("\n".join(sources.values()))
    for path, text in sources.items():
        code = code_only(text)
        for name in RAW_PEER_ROUTE:
            if name in code:
                problems.append(
                    f"{path}: names `{name}` in production. Peer identity reaches "
                    f"authorization as the ADR-MCPRE-064 binding or not at all; "
                    f"reconstructing it here is what ADR-MCPRE-065 §3 forbids."
                )
        for name in TRANSPORT_HINTS:
            if name in code:
                problems.append(
                    f"{path}: names `{name}` in production. LAW A-1: the action coordinate "
                    f"comes from the SIGNED BODY, and authorization correctness must not "
                    f"depend on the MCP transport contract being enforced."
                )
    for filename, fn, must_reach in LINKS:
        source = next(
            (code_only(t) for path, t in sources.items() if path.endswith("/" + filename)),
            None,
        )
        if source is None:
            problems.append(
                f"{filename}: no longer part of the authorization authority. A link this "
                f"gate cannot locate is a link it is not measuring."
            )
            continue
        body = body_of(source, fn)
        if body is None:
            problems.append(f"{filename}: `{fn}` not found.")
        elif must_reach not in body:
            problems.append(
                f"{filename}::{fn}: no longer reaches `{must_reach}`. The link is the "
                f"proof; without it the function answers from somewhere this gate cannot see."
            )
    match = signature_re("authorize").search(joined)
    if match is None:
        problems.append(
            "authorize: not found in the authorization authority. The decision has one "
            "operation, and a gate that cannot find it is measuring nothing."
        )
    else:
        offending = sorted(set(FORBIDDEN_PARAM.findall(match.group("params"))))
        if offending:
            problems.append(
                f"authorize: parameter list admits {offending}. The enforcement mechanism "
                f"for Law A-1 and for §3 is the ABSENCE of a parameter through which a "
                f"header, a certificate or a rival identity could enter."
            )
    for name in SEALED:
        fields = struct_body(joined, name)
        if fields is None:
            problems.append(
                f"{name}: no longer defined in the authorization authority. A sealed "
                f"product that moved out from under its gate is unsealed."
            )
            continue
        if re.search(r"^\s*pub(\s|\()", fields, re.M):
            problems.append(
                f"{name}: has a `pub` field. The representation is private to its module, "
                f"which is the only in-crate seal there is: a public field lets a caller "
                f"assemble the product from parts nobody verified."
            )
    problems += check_posture_producers(sources)
    return problems


def check_posture_producers(sources: dict[str, str]) -> list[str]:
    """(10) — the posture that claims nothing has one producer."""
    problems: list[str] = []
    for path, text in sources.items():
        if path.endswith(POSTURE_SITES):
            continue
        code = code_only(text)
        for variant in POSTURE_VARIANTS:
            if f"{POSTURE}::{variant}" in code:
                problems.append(
                    f"{path}: names `{POSTURE}::{variant}` in production. The posture is "
                    f"built in `decide.rs` and projected by `posture.rs`; a third site is "
                    f"either a second producer — and `NoPolicyConfigured` released at the "
                    f"dispatch is a configured policy bypassed — or a consumer "
                    f"destructuring what it should be asking for."
                )
    return problems


def check_serving(text: str) -> list[str]:
    """(4) — the serving path decides exactly once.

    Three links, each exactly once, so no one of them can be satisfied by a second route:
    the assembly orders the pre-admission region once, that region asks for the decision
    once, and the stage reaches the authority that owns what a decision means.

    The call count is taken over the WHOLE serving path, not only inside the ordering
    function. Before the split it was scoped to `handle`'s body, so a second call elsewhere
    in the file was invisible; reading the path whole is what the region modules require and
    is strictly the stronger question.
    """
    problems: list[str] = []
    handle = body_of(text, "handle")
    if handle is None:
        problems.append(
            f"{SERVING}: `handle` not found. The assembly is where the regions are ordered."
        )
    else:
        ordered = len(re.findall(r"\b" + REGION_ASSEMBLY + r"\s*\(", handle))
        if ordered != 1:
            problems.append(
                f"{SERVING}: `handle` calls `{REGION_ASSEMBLY}` {ordered} time(s); expected "
                f"exactly 1. The pre-admission region is where the decision is sequenced, "
                f"and an assembly that entered it twice would decide twice."
            )
    region = body_of(text, REGION_ASSEMBLY)
    if region is None:
        problems.append(
            f"{SERVING}: `{REGION_ASSEMBLY}` not found. The region assembly is where the "
            f"decision is ordered against its predecessors."
        )
    else:
        asked = len(re.findall(r"\bauthorization_stage\s*\(", region))
        if asked != 1:
            problems.append(
                f"{SERVING}: `{REGION_ASSEMBLY}` calls `authorization_stage` {asked} "
                f"time(s); expected exactly 1. The decision is ordered against its "
                f"predecessors HERE — a call from anywhere else is a second one that has "
                f"not been sequenced behind admission."
            )
    calls = len(re.findall(r"\bauthorization_stage\s*\(", text))
    # One definition plus one call site.
    if calls != 2:
        problems.append(
            f"{SERVING}: names `authorization_stage` {calls} time(s); expected exactly 2 "
            f"(its definition and one call). None is a serving path that dispatches "
            f"without deciding; more is two decisions that happen to agree."
        )
    stage = body_of(text, "authorization_stage")
    if stage is None:
        problems.append(f"{SERVING}: `authorization_stage` not found.")
    elif ".decide(" not in stage:
        problems.append(
            f"{SERVING}: `authorization_stage` no longer reaches `AuthorizationStage::"
            f"decide`. The serving file owns the ORDERING; a stage that decided here would "
            f"be a second authority over what a decision means."
        )
    for variant in POSTURE_VARIANTS:
        if f"{POSTURE}::{variant}" in text:
            problems.append(
                f"{SERVING}: names `{POSTURE}::{variant}` in production. The serving path "
                f"CARRIES the posture the stage returned and never states one. A synthesized "
                f"`NoPolicyConfigured` at the dispatch is a configured policy bypassed, and "
                f"no type can refuse it — the body it releases is indistinguishable."
            )
    return problems


def check_dispatch(stages: str, authority: str, serving: str) -> list[str]:
    """(7) — dispatch is gated by the type, not by source order."""
    problems = []
    ready = signature_re("new").search(stages)
    if ready is None or DISPATCH_BODY not in ready.group("params"):
        problems.append(
            f"{STAGES}: `ReadyForDispatch::new` no longer takes an `{DISPATCH_BODY}`. That "
            f"parameter IS the gate: a body typed `Vec<u8>` can be produced by any path, "
            f"including one that never asked a policy."
        )
    producers = len(re.findall(r"\bfn\s+" + RELEASE + r"\s*\(", authority))
    if producers != 1:
        problems.append(
            f"the authorization authority defines `{RELEASE}` {producers} time(s); expected "
            f"exactly 1. A second producer of `{DISPATCH_BODY}` is a second way to reach "
            f"the backend, and the type stops proving anything."
        )
    calls = len(re.findall(r"\." + RELEASE + r"\s*\(", serving))
    if calls != 1:
        problems.append(
            f"{SERVING}: calls `.{RELEASE}(` {calls} time(s); expected exactly 1. One "
            f"decision releases one body."
        )
    return problems


def check_validation(text: str) -> list[str]:
    """(8) — no configuration promotes a conformance evaluator to production authority."""
    if "AuthzKind::Reference" not in text:
        return [
            f"{VALIDATION}: no longer refuses `--authz reference`. ADR-MCPRE-065 §7.2: a "
            f"reference/conformance evaluator may prove the boundary and must never become "
            f"the accepted production authorization authority."
        ]
    return []


def authority_sources(directory: Path) -> dict[str, str]:
    """Every production `.rs` file of the authority, keyed by its RELATIVE PATH.

    Keyed by path, not by file name: `authorization/mod.rs` and `authorization/pdp/mod.rs`
    share a name, and a name-keyed dict silently drops one of them — a gate that examines
    less than it claims to, which is the failure mode that matters most in a gate.
    """
    return {
        str(p.relative_to(REPO)): production_text(p.read_text(encoding="utf-8"))
        for p in sorted(directory.rglob("*.rs"))
    }


def read(repo: Path, rel: str) -> str:
    """One unit's production source: a file, or an owner subtree read whole.

    Each member's production half is taken SEPARATELY before joining — concatenating first
    would let one file's unterminated test region swallow the next file's production code,
    and the exactly-once counts are precisely what that would corrupt.
    """
    target = repo / rel
    if target.is_file():
        return code_only(production_text(target.read_text(encoding="utf-8")))
    members = sorted(m for m in target.rglob("*.rs") if m.is_file())
    if not members:
        raise SystemExit(f"{rel}: a serving path with no Rust source is not measurable")
    return "\n".join(
        code_only(production_text(m.read_text(encoding="utf-8"))) for m in members
    )


def check(repo: Path) -> tuple[list[str], int]:
    directory = repo / AUTHORITY_DIR
    sources = authority_sources(directory)
    serving = read(repo, SERVING)
    problems = check_authority(sources)
    problems += check_serving(serving)
    problems += check_dispatch(
        read(repo, STAGES), code_only("\n".join(sources.values())), serving
    )
    problems += check_validation(read(repo, VALIDATION))
    return problems, len(sources)


# --------------------------------------------------------------------------------------
# Selftest: every claim, undone, must be caught.
# --------------------------------------------------------------------------------------

def selftest() -> int:
    cases: list[tuple[str, callable, int]] = [
        # (10), the authority half: a second producer of the posture.
        (
            "a second producer of the posture in the authority",
            lambda s: {**s, f"{AUTHORITY_DIR}/serving.rs": s[f"{AUTHORITY_DIR}/serving.rs"]
                       + "\nfn shortcut() -> AuthorizationPosture "
                       "{ AuthorizationPosture::NoPolicyConfigured }\n"},
            1,
        ),
        (
            "a certificate route in the authority",
            lambda s: {**s, f"{AUTHORITY_DIR}/request.rs": s[f"{AUTHORITY_DIR}/request.rs"]
                       + "\nfn back_door(l: &[u8]) { let _ = extract_identity(l); }\n"},
            1,
        ),
        (
            "a transport hint in the authority",
            lambda s: {**s, f"{AUTHORITY_DIR}/verified_action.rs":
                       s[f"{AUTHORITY_DIR}/verified_action.rs"].replace(
                           "let Ok(body) =", "let _ = MCP_NAME_HEADER; let Ok(body) =")},
            1,
        ),
        (
            "the digest pairing deleted",
            lambda s: {**s, f"{AUTHORITY_DIR}/verified_action.rs":
                       s[f"{AUTHORITY_DIR}/verified_action.rs"].replace(
                           "!verified.covers_body(body)", "false")},
            1,
        ),
        (
            "a header parameter widened into `authorize`",
            lambda s: {**s, f"{AUTHORITY_DIR}/decide.rs":
                       s[f"{AUTHORITY_DIR}/decide.rs"].replace(
                           "    body: &[u8],", "    body: &[u8],\n    headers: &[(String, String)],")},
            1,
        ),
        (
            "the Mode-1 linkage form made selectable as evidence",
            lambda s: {**s, f"{AUTHORITY_DIR}/pdp/evidence.rs":
                       s[f"{AUTHORITY_DIR}/pdp/evidence.rs"].replace(
                           "&& b.binding_type == BindingType::OpaqueDigest", "")},
            1,
        ),
        (
            "the decision digest check deleted",
            lambda s: {**s, f"{AUTHORITY_DIR}/pdp/evidence.rs":
                       s[f"{AUTHORITY_DIR}/pdp/evidence.rs"].replace(
                           "match verify_pdp_decision_binding(binding, document) {",
                           "match Ok::<(), PdpBindingRefusal>(()) {")},
            1,
        ),
        (
            "a sealed representation made public",
            lambda s: {**s, f"{AUTHORITY_DIR}/verified_actor.rs":
                       s[f"{AUTHORITY_DIR}/verified_actor.rs"].replace(
                           "    identity: ActorIdentity,", "    pub identity: ActorIdentity,")},
            1,
        ),
    ]
    sources = authority_sources(REPO / AUTHORITY_DIR)
    failures = 0
    print("authorization-provenance selftest")

    # THE GATE'S OWN DEFECT, pinned. Keying the source map by BASENAME silently collapsed
    # `authorization/mod.rs` and `authorization/pdp/mod.rs` into one entry, so the gate
    # examined a strict subset of the authority it claimed to cover — and said nothing. The
    # extension that exposed it is exactly the kind that will happen again.
    by_name: dict[str, list[str]] = {}
    for path in sources:
        by_name.setdefault(path.rsplit("/", 1)[-1], []).append(path)
    collisions = {n: p for n, p in by_name.items() if len(p) > 1}
    if not collisions:
        print(
            "  FAIL basename collision: the authority no longer contains two same-named "
            "modules, so this control is measuring nothing. Point it at a real pair."
        )
        failures += 1
    else:
        for name, paths in sorted(collisions.items()):
            missing = [p for p in paths if p not in sources]
            status = "ok " if not missing else "FAIL"
            failures += 0 if not missing else 1
            print(
                f"  {status} basename collision: all {len(paths)} `{name}` files are "
                f"examined ({', '.join(sorted(paths))})"
            )

    clean = check_authority(sources)
    if clean:
        print("  FAIL baseline: the live tree already has problems")
        for problem in clean:
            print(f"        {problem}")
        failures += 1
    else:
        print("  ok  baseline: the live authority is clean")
    for name, mutate, expected in cases:
        found = check_authority(mutate(sources))
        ok = len(found) == expected
        failures += 0 if ok else 1
        print(f"  {'ok ' if ok else 'FAIL'} {name}: {len(found)} problem(s), expected {expected}")
        if not ok:
            for problem in found:
                print(f"        {problem}")

    # The serving, machine and validation claims, undone against their own text.
    text_cases = [
        # Deleting the call breaks TWO links at once and is reported as two: the region
        # assembly no longer asks, and the path no longer names the stage twice (its
        # definition and its one call site). Collapsing that to one report would hide which
        # of the two the next reader has to restore.
        ("the serving stage removed", check_serving,
         read(REPO, SERVING).replace(
             ".authorization_stage(ex, decided_over.as_ref())", ".no_decision()"), 2),
        # The region assembly is a link of its own: an assembly that stopped entering the
        # pre-admission region would dispatch without ever reaching the decision.
        ("the pre-admission region no longer ordered", check_serving,
         read(REPO, SERVING).replace(
             ".admit_request(&ex, req.peer.as_ref(), &mut progress)", ".no_region()"), 1),
        ("a second producer of the dispatchable body",
         lambda t: check_dispatch(read(REPO, STAGES), t, read(REPO, SERVING)),
         code_only("\n".join(sources.values())) + "\n    fn release(self, b: Vec<u8>) -> AuthorizedRequestBody { todo!() }\n", 1),
        ("the dispatch gate widened back to `Vec<u8>`",
         lambda t: check_dispatch(
             t.replace("forwarded: AuthorizedRequestBody,", "forwarded: Vec<u8>,"),
             code_only("\n".join(sources.values())), read(REPO, SERVING)),
         read(REPO, STAGES), 1),
        ("the reference-profile refusal removed", check_validation,
         read(REPO, VALIDATION).replace("AuthzKind::Reference", "AuthzKind::Off"), 1),
        # (10), the serving half. The bypass this refuses is the one no type can catch:
        # a body released under a synthesized `NoPolicyConfigured` is byte-for-byte the
        # body a real decision would have released.
        ("the serving path synthesizing the posture that claims nothing", check_serving,
         read(REPO, SERVING) + "\nfn back_door() -> AuthorizedRequestBody { "
         "AuthorizationPosture::NoPolicyConfigured.release(Vec::new()) }\n", 1),
    ]
    for name, fn, text, expected in text_cases:
        found = fn(text)
        ok = len(found) == expected
        failures += 0 if ok else 1
        print(f"  {'ok ' if ok else 'FAIL'} {name}: {len(found)} problem(s), expected {expected}")
        if not ok:
            for problem in found:
                print(f"        {problem}")

    print(
        f"\nauthorization-provenance selftest: "
        f"{'PASS' if failures == 0 else 'FAIL'} — {len(cases) + len(text_cases) + 2} case(s)"
    )
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems, examined = check(REPO)
    if examined == 0:
        print(
            "authorization-provenance gate: FAIL — examined nothing. An empty scope is a "
            "broken gate, not a clean tree.",
            file=sys.stderr,
        )
        return 1
    if problems:
        print(f"authorization-provenance gate: FAIL — {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"authorization-provenance gate: OK — {examined} production module(s) examined; the "
        f"authorization authority reads its action from the signed body, takes the "
        f"ADR-MCPRE-064 binding whole, keeps every product sealed, and the dispatch "
        f"consumes a body only a decision can release."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
