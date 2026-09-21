#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serving-provenance gate — direct TLS derives identity AND currency from semantic
products, never by reconstructing them from certificate representation (ADR-MCPRE-064,
#619 and #621).

WHAT THIS PROVES, exactly, over production Rust (test regions excluded):

  1. Neither direct-TLS serving path — the async one and the blocking one — mentions any
     raw-certificate route, for identity or for currency. `extract_identity`,
     `interpret_identity`, `from_leaf_der`, `resolve_identity_from_leaf`, `leaf_facts`,
     `chain_issuers_` and `cert_lifetime_rejection_for_chain` may not appear in them.
  2. Each serving path calls `resolve_authenticated_identity` and
     `credential_currency_rejection` exactly once apiece: one call site per path per
     question, so the two paths cannot drift into two derivations that currently agree.
  3. Each resolver reaches its authority — `authenticate_relationship_peer` and
     `evaluate_credential_currency` — and carries no raw-certificate route of its own.
  4. Each resolver's signature takes its predecessor and the options, and NOTHING else. No
     `leaf`, no `der`, no `chain`, no `certificate`, no second identity parameter.
  5. No production code outside the historical facade and the extractor's own module
     calls `extract_identity`.
  6. The async path never names `accepted_chain_der`. The blocking path may, and ONLY while
     the file also carries the `online_ocsp` feature gate that is its last consumer.

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
#:
#: An entry may name a FILE or a DIRECTORY, and the async path is the latter since
#: MCPRE-175 split the listener into owner modules: the establishment boundary is in
#: `connection.rs` and the resolver call in `request.rs`. The proposition is about the
#: PATH, so a directory is read whole — a gate that kept reading `async_serve.rs` alone
#: would have reported on a file that no longer holds the derivation, and one pointed at
#: `mod.rs` would count zero resolver calls and pass for the wrong reason.
ASYNC_PATH = "mcp-re-proxy/src/async_serve"
BLOCKING_PATH = "mcp-re-proxy/src/blocking_mtls_harness/connection.rs"
SERVING_PATHS = [ASYNC_PATH, BLOCKING_PATH]

#: Where the strategy dispatch lives, and the one function both serving paths call.
DISPATCH_MODULE = "mcp-re-proxy/src/tls.rs"

#: Where the channel-peer product is CONSTRUCTED. The dispatch module reaches the currency
#: authority through this owner rather than calling it directly, because the product's
#: representation is private and this is its only producer — so the authority is now
#: unavoidable rather than merely called. The hop is checked on both sides: the dispatch
#: module must reach the constructor (RESOLVERS), and the constructor must reach the
#: authority (CONSTRUCTOR_REACHES). Checking only the first would let the constructor
#: answer the currency question itself.
PEER_OWNER_MODULE = "mcp-re-proxy/src/communication_assurance/authenticated_channel_peer.rs"

#: `(function in PEER_OWNER_MODULE, authority it must reach)`.
CONSTRUCTOR = "resolve"
CONSTRUCTOR_REACHES = ("current_authenticated_peer",)

#: The historical facade module. It is allowed to name the historical route, because
#: converting between the vocabularies is the whole reason it exists.
FACADE = "mcp-re-proxy/src/facades/asserted_identity.rs"

#: Where the historical extractor itself lives. MCPRE-156 moved it out of the dispatch
#: module and into the transport identity owner, so that `TransportIdentity`'s private
#: constructor and its one certificate producer are in the same module — a `pub(crate)`
#: constructor beside a sibling producer is not a boundary in this crate. The gate follows
#: the extractor rather than continuing to exempt the file it used to live in: an
#: exemption left pointing at a module that no longer calls it would exempt that module for
#: the next author who added a call.
EXTRACTOR_HOME = "mcp-re-proxy/src/transport/identity.rs"

#: The route this migration removed from production serving: certificate representation in,
#: identity out. Each of these names a step of it.
RAW_IDENTITY_ROUTE = (
    "extract_identity",
    "interpret_identity",
    "from_leaf_der",
    "resolve_identity_from_leaf",
)

#: The route Slice 3 removed from production serving: certificates in, a currency verdict
#: out. Each of these names a step of the authority that moved.
RAW_CURRENCY_ROUTE = (
    "cert_lifetime_rejection_for_chain",
    "connection_rejection_for_chain",
    "leaf_facts",
    "chain_issuers_",
)

#: The last raw-chain projection in the serving path. Its ONE remaining consumer is the
#: online-OCSP guard, which ADR-MCPRE-064 Slice 3 deliberately did not migrate.
OCSP_RESIDUE = "accepted_chain_der"
OCSP_GATE = 'feature = "online_ocsp"'

#: The ONE function each direct-TLS serving path calls about its relationship. Since
#: ADR-MCPRE-064 Slice 4 the identity question and the currency question are one question —
#: who authenticated, and what the deployment's controls concluded about their credential —
#: so there is one call site per path rather than two that must stay in step.
RESOLVER = "served_channel_peer"

#: `(function, authority or route it must reach)`. Each link of the chain from the serving
#: path to the ADR-MCPRE-064 authorities, so a resolver that stopped reaching one of them
#: fails here rather than silently answering from somewhere else.
RESOLVERS = (
    ("served_channel_peer", "resolve_channel_peer"),
    ("resolve_channel_peer", "AuthenticatedChannelPeer::resolve"),
    ("resolve_channel_peer", "evaluate_credential_currency"),
    ("authenticated_peer", "authenticate_relationship_peer"),
)

COMPOSITION = "authenticate_relationship_peer"

# ADR-MCPRE-061 §5.1 — both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open a test region.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")

def signature_re(name: str) -> re.Pattern:
    """`pub(crate) fn <name>( .. ) -> ..` up to the opening brace."""
    return re.compile(r"fn\s+" + name + r"\s*\((?P<params>.*?)\)\s*->[^{]*\{", re.S)


SIGNATURE = signature_re(RESOLVER)

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


def resolver_body(text: str, name: str = RESOLVER) -> str | None:
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


def check_serving_path(path: str, text: str) -> list[str]:
    problems = []
    for name in RAW_IDENTITY_ROUTE + RAW_CURRENCY_ROUTE:
        if name in text:
            problems.append(
                f"{path}: names `{name}` in production. A direct-TLS serving path derives "
                f"identity and currency from semantic products, not by reconstructing them "
                f"from certificate representation (ADR-MCPRE-064 #619/#621)."
            )
    calls = len(re.findall(r"\b" + RESOLVER + r"\s*\(", text))
    if calls != 1:
        problems.append(
            f"{path}: calls `{RESOLVER}` {calls} time(s); expected exactly 1. Two call "
            f"sites in one path, or none, is how the async and blocking paths stop being "
            f"one derivation and become two that happen to agree."
        )
    if OCSP_RESIDUE in text:
        if path == ASYNC_PATH:
            problems.append(
                f"{path}: names `{OCSP_RESIDUE}`. The async path has no raw-chain consumer "
                f"left — online OCSP is not wired on it — so a chain projection here is a "
                f"currency or identity route being rebuilt."
            )
        elif OCSP_GATE not in text:
            problems.append(
                f"{path}: names `{OCSP_RESIDUE}` without the `{OCSP_GATE}` gate. The one "
                f"legitimate raw-chain consumer left in the serving path is the "
                f"unmigrated online-OCSP guard; an ungated projection is a new one."
            )
    return problems


def serving_path_text(path: Path) -> str:
    """One serving path's production source, whether it is a file or an owner subtree.

    Each member's production half is taken SEPARATELY and then joined: concatenating first
    would let one file's unterminated test region swallow the next file's production code,
    and the resolver-called-exactly-once count is precisely what that would corrupt.
    """
    if path.is_file():
        return production_text(path.read_text(encoding="utf-8"))
    members = sorted(p for p in path.rglob("*.rs") if p.is_file())
    if not members:
        raise SystemExit(f"{path}: a serving path with no Rust source is not measurable")
    return "\n".join(production_text(m.read_text(encoding="utf-8")) for m in members)


def check_dispatch(text: str) -> list[str]:
    problems = []
    # Signatures are checked ONCE per function. A function that must reach two authorities
    # appears twice in RESOLVERS, and reporting its parameter list twice would count one
    # defect as two.
    for name in dict.fromkeys(fn for fn, _ in RESOLVERS):
        signature = signature_re(name).search(text)
        if signature is None or resolver_body(text, name) is None:
            problems.append(
                f"{DISPATCH_MODULE}: `{name}` is not defined here. It is a link in the one "
                f"route both serving paths take; moving it needs this gate moved with it."
            )
            continue
        forbidden = sorted(set(FORBIDDEN_PARAM.findall(signature.group("params"))))
        if forbidden:
            problems.append(
                f"{DISPATCH_MODULE}: `{name}` takes parameter(s) named {forbidden}. Each "
                f"link takes its predecessor product and the deployment's own policies and "
                f"NOTHING else — the absence of a second-credential parameter is what makes "
                f"pairing relationship A's facts with relationship B's certificates "
                f"unconstructible (THM-0031, THM-0032, THM-0034). A parameter is how that "
                f"returns."
            )
    for name, authority in RESOLVERS:
        body = resolver_body(text, name)
        if body is None:
            continue
        if authority not in body:
            problems.append(
                f"{DISPATCH_MODULE}: `{name}` does not reach `{authority}`. The fact must "
                f"come from the ADR-MCPRE-064 authority that owns it."
            )
        for raw in RAW_IDENTITY_ROUTE + RAW_CURRENCY_ROUTE:
            if raw in body:
                problems.append(
                    f"{DISPATCH_MODULE}: `{name}` names `{raw}`. A link in this route may "
                    f"not carry a raw-certificate route of its own."
                )
    return problems


def check_constructor(text: str) -> list[str]:
    """The far half of the hop the dispatch module takes to reach the currency authority.

    `resolve_channel_peer` no longer names `current_authenticated_peer`; it names the
    constructor of the product, which names the authority. That is a longer chain and a
    stronger one — the product's representation is private, so the constructor is the only
    producer and the authority cannot be skipped by a second construction site. It is
    stronger only while BOTH halves hold: a constructor that stopped reaching the authority
    would answer the currency question itself, with the dispatch module's edge still green.
    """
    problems = []
    body = resolver_body(text, CONSTRUCTOR)
    if body is None:
        problems.append(
            f"{PEER_OWNER_MODULE}: `{CONSTRUCTOR}` is not defined here. It is the far half "
            f"of the route the dispatch module takes to the ADR-MCPRE-064 currency "
            f"authority; moving it needs this gate moved with it."
        )
        return problems
    for authority in CONSTRUCTOR_REACHES:
        if authority not in body:
            problems.append(
                f"{PEER_OWNER_MODULE}: `{CONSTRUCTOR}` does not reach `{authority}`. The "
                f"product's only producer must obtain the currency verdict from the "
                f"authority that owns it, not decide it here."
            )
    for raw in RAW_IDENTITY_ROUTE + RAW_CURRENCY_ROUTE:
        if raw in body:
            problems.append(
                f"{PEER_OWNER_MODULE}: `{CONSTRUCTOR}` names `{raw}`. The one producer of "
                f"the channel-peer product may not carry a raw-certificate route of its own."
            )
    return problems


def check_facade_containment(root: Path) -> list[str]:
    """No production caller of the historical extractor outside the facade it belongs to."""
    problems = []
    for path in sorted(root.glob("mcp-re-*/src/**/*.rs")):
        rel = path.relative_to(root).as_posix()
        if rel in (FACADE, EXTRACTOR_HOME):
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
        problems += check_serving_path(rel, serving_path_text(path))

    dispatch = root / DISPATCH_MODULE
    if not dispatch.exists():
        problems.append(f"{DISPATCH_MODULE}: missing.")
    else:
        examined += 1
        problems += check_dispatch(production_text(dispatch.read_text(encoding="utf-8")))

    owner = root / PEER_OWNER_MODULE
    if not owner.exists():
        problems.append(f"{PEER_OWNER_MODULE}: missing.")
    else:
        examined += 1
        problems += check_constructor(production_text(owner.read_text(encoding="utf-8")))

    problems += check_facade_containment(root)
    return problems, examined


def selftest() -> int:
    """Each case is a way the migration could be undone. A gate that passed them all would
    be reporting on a file set rather than on a property."""
    cases = [
        ("clean", "let peer = served_channel_peer(c, o, b, n);", "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }", 0),
        (
            "serving path reconstructs identity from the leaf",
            "let identity = extract_identity(leaf, policy);\nlet peer = served_channel_peer(c, o, b, n);",
            "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }",
            1,
        ),
        (
            "serving path rebuilds the currency decision from a chain",
            "let r = cert_lifetime_rejection_for_chain(&chain, o, b, n);\nlet peer = served_channel_peer(c, o, b, n);",
            "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }",
            1,
        ),
        ("serving path stopped asking at all", "let peer = None;", "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }", 1),
        (
            "serving path asks twice",
            "let peer = served_channel_peer(c, o, b, n);\nlet again = served_channel_peer(c, o, b, n);",
            "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }",
            1,
        ),
        (
            "resolver widened to accept a leaf",
            "let peer = served_channel_peer(c, o, b, n);",
            "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }".replace(
                "fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64)",
                "fn resolve_channel_peer(accepted: Option<&Mvc>, leaf: Option<&[u8]>, options: &ServerOptions, now: i64)",
            ),
            1,
        ),
        (
            "resolver stopped reaching the currency evaluation",
            "let peer = served_channel_peer(c, o, b, n);",
            "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }".replace("evaluate_credential_currency(accepted, &q, now); ", ""),
            1,
        ),
        (
            "resolver stopped reaching the authentication authority",
            "let peer = served_channel_peer(c, o, b, n);",
            "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }".replace("authenticate_relationship_peer(accepted?.clone(), p).ok()", "None"),
            1,
        ),
        (
            "the route is named only inside a test region",
            "#[cfg(test)]\nmod tests {\n    fn t() { extract_identity(leaf, p); }\n}\nlet peer = served_channel_peer(c, o, b, n);",
            "pub(crate) fn served_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, request: &[u8], now: i64) -> Result<Option<Peer>, Vec<u8>> { resolve_channel_peer(accepted, options, now) }\npub(crate) fn resolve_channel_peer(accepted: Option<&Mvc>, options: &ServerOptions, now: i64) -> Result<Option<Peer>, R> { let p = authenticated_peer(accepted, options); evaluate_credential_currency(accepted, &q, now); AuthenticatedChannelPeer::resolve(p, &q, now) }\nfn authenticated_peer(accepted: Option<&Mvc>, options: &ServerOptions) -> Option<Facts> { authenticate_relationship_peer(accepted?.clone(), p).ok() }",
            0,
        ),
    ]
    #: The far half of the hop. `resolve` is the product's only producer, so these are the
    #: ways the constructor could stop being a route to the authority and start being a
    #: second opinion — each invisible to every case above, because the dispatch module's
    #: edge stays green through all of them.
    constructor = (
        "pub fn resolve(peer: Facts, policy: &CredentialCurrencyPolicy, now: i64) -> "
        "Result<Self, CredentialCurrencyRefusal> { match current_authenticated_peer(peer, "
        "policy, now) { Ok(c) => Ok(Self(A::Current(c))), Err(e) => Err(e) } }"
    )
    constructor_cases = [
        ("constructor clean", constructor, 0),
        (
            "constructor stopped reaching the currency authority",
            constructor.replace("current_authenticated_peer(peer, policy, now)", "Ok(peer)"),
            1,
        ),
        (
            "constructor rebuilt the currency decision from a chain",
            constructor.replace(
                "current_authenticated_peer(peer, policy, now)",
                "cert_lifetime_rejection_for_chain(&chain, policy, now)",
            ),
            2,
        ),
        ("constructor moved away", "pub fn other(x: u8) -> u8 { x }", 1),
        (
            "the constructor exists only inside a test region",
            "#[cfg(test)]\nmod tests {\n" + constructor + "\n}",
            1,
        ),
    ]

    failures = 0
    for name, text, expected in constructor_cases:
        found = check_constructor(production_text(text))
        status = "ok " if len(found) == expected else "FAIL"
        if len(found) != expected:
            failures += 1
        print(f"  {status} {name}: {len(found)} problem(s), expected {expected}")
        for problem in found:
            print(f"        {problem}")

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
        f"{'PASS' if failures == 0 else 'FAIL'} — "
        f"{len(cases) + len(constructor_cases)} case(s)"
    )
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems, examined = check(REPO)
    if examined == 0:
        print(
            "serving-provenance gate: FAIL — examined nothing. An empty scope is "
            "a broken gate, not a clean tree.",
            file=sys.stderr,
        )
        return 1
    if problems:
        print(f"serving-provenance gate: FAIL — {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    routes = ", ".join(f"`{r}` -> `{a}`" for r, a in RESOLVERS)
    print(
        f"serving-provenance gate: OK — {examined} production module(s) examined; both "
        f"direct-TLS serving paths take {routes}, and no production caller reconstructs "
        f"identity or currency from certificate representation."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
