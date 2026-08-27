#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refusal-provenance gate — ADR-MCPRE-066 Slice 0 (#642).

WHAT THIS PROVES, over production Rust (test regions excluded):

  1. **A refusal carries a cause, not a token.** `Refusal` has a `cause: RefusalCause`
     field and no `wire_code` FIELD. A struct that stores a rendered token has already
     thrown away which authority produced it, and no downstream check can recover that.
  2. **`RefusalCause` is closed over exactly the two authorities on this path** — `Core`
     and `Authorization`. A third arm is a design decision, not a variant.
  3. **The authorization stage hands its refusal over WHOLE.** `authorization_stage` does
     not call `.wire_code()`. This is poison pill 1: re-render there and the gate fails
     alongside the unit control that measures the same thing behaviourally.
  4. **No production site renders a token INTO a `Refusal` constructor.** The three
     constructors take `impl Into<RefusalCause>`, and no call site passes a `&'static str`
     or a `.wire_code()` result.
  5. **`PolicyError` has no route into the Core taxonomy.** No `impl From<PolicyError>`
     for `McpReError` or for `RefusalCause::Core` exists anywhere in the workspace. This is
     poison pill 2: the authorization branch must arrive at the audit boundary still
     recognizably authorization provenance, and a conversion is what would silently end
     that.
  6. **The cause algebra is exhaustive by construction.** `refusal/` carries no wildcard arm
     (`_ =>`), so a new authority or a new Core producer is a COMPILE error until it names
     its verdict, rather than silently inheriting one.

ADDED BY SLICE 1 (#644) — the provenance now has to survive one step further, into the
record itself:

  7. **A request record always states an authorization outcome.** The `Request` arm carries
     an `authorization: AuthorizationFacet`, never an `Option` and never a `NotApplicable`.
     ADR-MCPRE-066 R3: absence must have exactly one meaning — a record from before this
     slice — and an `Option` gives it two.
  8. **A response record carries none.** Authorization is request-side (R5). A response
     record does not represent a second authorization decision and must not be able to
     claim one.
  9. **The facet is PROJECTED, never assembled at the audit site.** The serving path does
     not construct an `AuthorizationFacet` variant or an `AuthorizationAttribution` literal;
     it asks the owner (`audit_facet` / `authorization_facet`). Invariant 5 / R-COMPOSE: a
     composition root that builds the facet out of parts has re-derived what an owner
     already decided.

ADDED BY SLICE 2 (#648) — the containment stops being a rule and becomes a type:

 10. **No audit rejection constructor takes a string.** `mcp-re-core/src/audit.rs` declares
     no `fn *_rejected_code(reason: &'static str)`. That was the join where two authorities'
     tokens became indistinguishable (#637); with it gone, `PolicyError -> AuditEvent.reason`
     does not typecheck, and invariant 9's producer graph is decided by the compiler rather
     than discovered by a scanner over a hand-maintained file list.
 11. **The serving path never renders a token into an audit event.** `rejection` and
     `response_rejection` take a typed `RefusalCause` and ask it for a Core verdict; neither
     passes a `wire_code()` result to an `AuditEvent` constructor.

WHY (5) IS THE ONE THAT MATTERS. Every other check here constrains a shape that a reviewer
would notice changing. A `From<PolicyError> for McpReError` would look like a convenience,
would compile, would make every existing test pass, and would re-create the exact defect
ADR-MCPRE-066 was opened for — one taxonomy quietly absorbing another's semantics. It is
the only one of the six that a well-intentioned edit is likely to introduce.

WHAT (10) REPLACED. Slice 1 could not assert that Core's `reason` was free of foreign
tokens, because it was not: an authorization refusal's `wire_code()` still reached
`request_rejected_code`. Slice 2 deleted the constructor rather than adding a scanner for
its callers, which is why the check is the absence of a SHAPE rather than a survey of
producers. The companion claim — that no carrier mints an `mcp-re.*` token of its own — is
`//mcp-re-conformance:audit_vocabulary_guard_test`.

WHAT IT DOES NOT PROVE: that the right cause is chosen at any given site. That is the unit
controls in `refusal/cause.rs`, and the wire-compatibility controls that show Slice 0 is
observably a no-op. This gate is syntactic and its claim stops at the shape of the route.

Run:  python3 scripts/refusal_provenance_gate.py
      python3 scripts/refusal_provenance_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

REFUSAL = ["mcp-re-proxy/src/refusal/mod.rs", "mcp-re-proxy/src/refusal/cause.rs"]
SERVING = "mcp-re-proxy/src/http_profile_serve/mod.rs"
RECORD = "mcp-re-proxy/src/audit_record.rs"
CORE_AUDIT = "mcp-re-core/src/audit.rs"

#: Where a `From<PolicyError>` conversion could plausibly be introduced. Every Rust file in
#: the workspace, because the whole point is that it must exist NOWHERE — restricting the
#: scan to the files that look relevant is how a gate stops covering its subject.
WORKSPACE_GLOB = "**/*.rs"

TEST_REGION = re.compile(r"^#\[cfg\((all\()?test")


def production(src: str) -> str:
    """Drop `#[cfg(test)]` regions, brace-counting so code below a test module survives."""
    out, lines, i = [], src.split("\n"), 0
    while i < len(lines):
        if TEST_REGION.match(lines[i].strip()):
            depth, seen = 0, False
            while i < len(lines):
                depth += lines[i].count("{") - lines[i].count("}")
                seen = seen or "{" in lines[i]
                i += 1
                if seen and depth <= 0:
                    break
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def read(rel: str, overrides: dict[str, str] | None = None) -> str:
    """The production half of `rel`, or a loud failure.

    A gate whose input has moved must say so rather than traceback or, worse, quietly examine
    nothing: an empty scope printing OK is how a control stops covering its subject.
    """
    if overrides and rel in overrides:
        return production(overrides[rel])
    path = REPO / rel
    if not path.is_file():
        raise SystemExit(
            f"refusal-provenance gate: FAIL — {rel} is not there. The gate's scope has moved; "
            f"fix the scope rather than the symptom."
        )
    return production(path.read_text())


def body_of(src: str, fn: str) -> str:
    """The body of `fn`, brace-matched from its signature."""
    m = re.search(rf"fn\s+{re.escape(fn)}\s*[(<]", src)
    if not m:
        return ""
    start = src.index("{", m.start())
    depth, i = 0, start
    while i < len(src):
        depth += 1 if src[i] == "{" else -1 if src[i] == "}" else 0
        if depth == 0:
            return src[start : i + 1]
        i += 1
    return src[start:]


def body_of_variant(src: str, variant: str) -> str:
    """The brace-matched body of enum variant `variant`, or `""`."""
    m = re.search(rf"^\s{{4}}{re.escape(variant)}\s*\{{", src, re.M)
    if not m:
        return ""
    start = src.index("{", m.start())
    depth, i = 0, start
    while i < len(src):
        depth += 1 if src[i] == "{" else -1 if src[i] == "}" else 0
        if depth == 0:
            return src[start : i + 1]
        i += 1
    return src[start:]


def check(overrides: dict[str, str] | None = None) -> list[str]:
    problems: list[str] = []
    refusal = "\n".join(read(r, overrides) for r in REFUSAL)
    serving = read(SERVING, overrides)

    # 1. a cause, not a token
    if not re.search(r"cause:\s*RefusalCause", refusal):
        problems.append("`Refusal` must carry a `cause: RefusalCause`")
    if re.search(r"^\s*(pub\(crate\)\s+)?wire_code:\s*&'static str", refusal, re.M):
        problems.append(
            "`Refusal` carries a rendered `wire_code` FIELD — that is the Slice 0 defect"
        )

    # 2. closed over exactly two authorities
    arms = set(re.findall(r"^\s{4}(Core|Authorization)\(", refusal, re.M))
    if arms != {"Core", "Authorization"}:
        problems.append(f"`RefusalCause` arms must be exactly Core+Authorization, found {arms}")

    # 3. POISON PILL 1 — the authorization stage hands its refusal over whole
    stage = body_of(serving, "authorization_stage")
    if not stage:
        problems.append("`authorization_stage` not found in the serving path")
    elif ".wire_code()" in stage:
        problems.append(
            "`authorization_stage` renders its refusal — the typed provenance dies at the "
            "stage boundary (ADR-MCPRE-066 Slice 0 poison pill 1)"
        )

    # 4. no token rendered into a Refusal constructor
    for m in re.finditer(r"Refusal::(preflight|before_admission|after_admission)\(", serving):
        tail = serving[m.end() : m.end() + 200]
        head = tail.split(")")[0]
        if ".wire_code()" in head or re.search(r'"\s*mcp-re\.', head):
            problems.append(
                f"a `Refusal::{m.group(1)}` call site renders a token instead of passing a cause"
            )

    # 5. POISON PILL 2 — PolicyError may never reach the Core taxonomy
    for path in sorted(REPO.glob(WORKSPACE_GLOB)):
        if "target/" in str(path) or "/node_modules/" in str(path):
            continue
        rel = str(path.relative_to(REPO))
        try:
            src = read(rel, overrides)
        except (OSError, UnicodeDecodeError):
            continue
        if re.search(r"impl\s+From<&?\s*(mcp_re_policy::)?PolicyError>\s+for\s+McpReError", src):
            problems.append(f"{rel}: a PolicyError -> McpReError conversion exists")
        if re.search(r"RefusalCause::Core\(\s*[A-Za-z_:]*[Pp]olicy", src):
            problems.append(f"{rel}: a PolicyError is being placed in the Core arm")

    # 7/8. the record kind decides what each authority may say (R3, R5)
    record = read(RECORD, overrides)
    if "Option<AuthorizationFacet>" in record:
        problems.append(
            f"{RECORD}: the authorization facet is optional — an absent facet then means both "
            f"'no policy' and 'legacy record' (ADR-MCPRE-066 R3)"
        )
    request_arm = body_of_variant(record, "Request")
    if "authorization: AuthorizationFacet" not in request_arm:
        problems.append(
            f"{RECORD}: the Request record does not state an authorization outcome (R3)"
        )
    response_arm = body_of_variant(record, "Response")
    if "AuthorizationFacet" in response_arm:
        problems.append(
            f"{RECORD}: a Response record carries an authorization coordinate — authorization "
            f"is request-side (ADR-MCPRE-066 R5)"
        )

    # 9. the facet is projected from an owner, never assembled at the audit site
    for bad in ("AuthorizationFacet::Authorized(", "AuthorizationFacet::Refused(",
                "AuthorizationAttribution {"):
        if bad in serving:
            problems.append(
                f"the serving path builds `{bad}` itself instead of asking the owner for its "
                f"projection (ADR-MCPRE-066 invariant 5 / R-COMPOSE)"
            )

    # 10. no audit rejection constructor takes a string
    core_audit = read(CORE_AUDIT, overrides)
    if re.search(r"fn\s+\w*rejected\w*\s*\(\s*\w+\s*:\s*&'static str", core_audit):
        problems.append(
            f"{CORE_AUDIT}: an audit rejection constructor takes a `&'static str` — that is "
            f"the join where two authorities' tokens become one (ADR-MCPRE-066 invariant 8/9)"
        )

    # 11. the serving path never renders a token into an audit event
    for m in re.finditer(r"AuditEvent::\w+\(", serving):
        head = serving[m.end() : m.end() + 160].split(";")[0]
        if ".wire_code()" in head:
            problems.append(
                "the serving path renders a token into an `AuditEvent` constructor instead "
                "of passing a typed Core verdict (ADR-MCPRE-066 invariant 9)"
            )

    # 6. the cause algebra is exhaustive by construction
    if re.search(r"^\s*_\s*=>", refusal, re.M):
        problems.append(
            "`refusal/` has a wildcard arm — a new authority or Core producer would inherit a "
            "verdict instead of naming one"
        )
    return problems


SELFTEST = [
    (
        "the Refusal keeps a rendered token field",
        {REFUSAL[0]: "pub(crate) struct Refusal {\n    wire_code: &'static str,\n}\n"},
        1,
    ),
    (
        "the authorization stage renders its refusal again (poison pill 1)",
        {
            SERVING: "fn authorization_stage(&self) -> u8 {\n"
            "    self.authorization.decide().map_err(|r| Refusal::before_admission(r.wire_code(), 403))\n}\n"
        },
        1,
    ),
    (
        "a PolicyError conversion into the Core taxonomy appears (poison pill 2)",
        {REFUSAL[1]: "impl From<PolicyError> for McpReError {\n    fn from(_e: PolicyError) -> McpReError { todo!() }\n}\n"},
        1,
    ),
    (
        "a PolicyError is placed in the Core arm",
        {REFUSAL[1]: "fn f() { RefusalCause::Core(PolicyError::AuthorizationScopeDenied) }\n"},
        1,
    ),
    (
        "the cause algebra grows a wildcard arm",
        {REFUSAL[1]: "fn wire_code(&self) -> &'static str {\n    match self {\n        _ => \"mcp-re.missing_envelope\",\n    }\n}\n"},
        1,
    ),
    (
        "a call site renders a token into a constructor",
        {SERVING: 'fn f() { Refusal::preflight("mcp-re.missing_envelope", 400) }\n'},
        1,
    ),
    (
        "the request record's facet becomes optional (R3)",
        {RECORD: "pub enum AuditSubject {\n"
                 "    Request {\n        event: AuditEvent,\n"
                 "        authorization: Option<AuthorizationFacet>,\n    },\n"
                 "    Response {\n        event: AuditEvent,\n    },\n}\n"},
        1,
    ),
    (
        "a response record acquires an authorization coordinate (R5)",
        {RECORD: "pub enum AuditSubject {\n"
                 "    Request {\n        event: AuditEvent,\n"
                 "        authorization: AuthorizationFacet,\n    },\n"
                 "    Response {\n        event: AuditEvent,\n"
                 "        authorization: AuthorizationFacet,\n    },\n}\n"},
        1,
    ),
    (
        "the serving path assembles the facet instead of projecting it",
        {SERVING: "fn f() { self.audit(AuditSubject::request(e, "
                  "AuthorizationFacet::Refused(x))) }\n"},
        1,
    ),
    (
        "a string-taking audit rejection constructor comes back (invariant 8)",
        {CORE_AUDIT: "impl AuditEvent {\n"
                     "    pub fn request_rejected_code(reason: &'static str) -> Self { todo!() }\n"
                     "}\n"},
        1,
    ),
    (
        "the serving path renders a token into an audit event (invariant 9)",
        {SERVING: "fn f() { self.audit(AuditEvent::request_rejected_code(cause.wire_code())) }\n"},
        1,
    ),
]


def selftest() -> int:
    failures = 0
    for name, override, expected in SELFTEST:
        base = {r: (REPO / r).read_text() for r in REFUSAL + [SERVING, RECORD, CORE_AUDIT]}
        base.update(override)
        got = len(check(base))
        ok = got >= expected
        print(f"  {'ok ' if ok else 'FAIL'} {name}: {got} problem(s), expected >= {expected}")
        failures += 0 if ok else 1
    # And the tree as it stands must be clean, or the pills prove nothing.
    live = check()
    if live:
        print(f"  FAIL the working tree itself: {live}")
        failures += 1
    else:
        print("  ok  the working tree is clean")
    print(f"\nrefusal-provenance selftest: {'PASS' if not failures else 'FAIL'} — "
          f"{len(SELFTEST) + 1} case(s)")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems = check()
    if problems:
        print("refusal-provenance gate: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(
        "refusal-provenance gate: OK — a refusal carries its authority rather than a rendered "
        "token, the authorization branch survives the stage boundary intact, PolicyError has "
        "no route into the Core taxonomy, the cause algebra is exhaustive, the record states "
        "each authority's outcome in its own coordinate, and no rejection reason can be "
        "built from a string."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
