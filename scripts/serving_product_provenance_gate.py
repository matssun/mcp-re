#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serving-product provenance gate — the ratified theorem architecture, THM-0051.

WHAT THIS PROVES, exactly, over production Rust (test regions excluded):

  1. **The serving assembly verifies once.** `handle` calls `verify_stage` exactly once and
     builds exactly one `Exchange`. Two verifications would put two products in scope and
     make "the one the pipeline holds" a question about source order.
  2. **The serving path has one verification stage.** `verify_stage` is named exactly twice
     across the subtree — its definition and that one call. None is a path that dispatches
     without verifying; more is a second product nothing sequenced.
  3. **The stage hands its product to the machine.** `verify_stage` reaches
     `progress.establish`, so the exchange learns that verification ran by the value being
     CONSUMED rather than by anyone remembering to say so.
  4. **Nothing in the proxy fabricates a verified request.** No production module of
     `mcp-re-proxy` constructs a `VerifiedMcpRequest` literal. The product enters this crate
     from `Verifier::verify_request` or not at all.
  5. **The exchange carries the product; it does not restate it.** `Exchange` has no `pub`
     field, so no consumer can be handed one assembled from parts.

WHY THIS GATE AND NOT A TYPE. `VerifiedMcpRequest` has PUBLIC fields, so any crate can
construct one from parts — which is exactly why every verifier theorem's `scope` says it
characterizes values the operation RETURNED and not values that happen to have the type.
The obvious fix is to seal the representation, and it is not available: the Verus obligation
on `prepare_http_dispatch` reads `verified.request_block` as a FIELD so the prover can relate
the obligation to the value, and `#[verifier::external_type_specification]` refuses a
non-public field. A proved postcondition outranks a seal (`docs/dev/sealed-owners.md`), so
the seam stays open and this gate is what stands in the gap — as EVIDENCE, never as
unconstructibility. Delete it and a second product compiles.

WHAT IT DOES NOT PROVE: that the verification was correct (THM-0014/THM-0015), that the
product is not substitutable for a weaker one (THM-0047), or that a crate outside this
workspace cannot fabricate one. Its claim stops at the shape of the serving route.

Run:  python3 scripts/serving_product_provenance_gate.py
      python3 scripts/serving_product_provenance_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The serving path, read as an owner subtree: MCPRE-175 split the assembly into one module
#: per region, so a gate reading only `mod.rs` would count zero.
SERVING = "mcp-re-proxy/src/http_profile_serve"

#: The crate whose production half may not fabricate the product.
PROXY = "mcp-re-proxy/src"

PRODUCT = "VerifiedMcpRequest"
STAGE = "verify_stage"
CARRIER = "Exchange"

# ADR-MCPRE-061 §5.1 — both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open a test region.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")

#: A module declared under `#[cfg(test)]` in its PARENT. The file itself carries no test
#: attribute, so a per-file scan reads all of it as production — which is how a harness that
#: fabricates evidence for controls looks like a production route. The parent is the
#: authority on whether the module exists in a shipped binary, so the parent is what is read.
TEST_MOD_DECL = re.compile(r"#\[cfg\((?:all\()?test\b[^\]]*\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")

LINE_COMMENT = re.compile(r"^\s*(///|//!|//).*$", re.M)


def code_only(text: str) -> str:
    """`text` with line comments removed. The claim is about the ROUTE, not the prose."""
    return LINE_COMMENT.sub("", text)


def production_text(text: str) -> str:
    """The source with every test region removed, by brace depth from the attribute."""
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
    return re.compile(r"fn\s+" + name + r"\s*\((?P<params>.*?)\)\s*->[^{]*\{", re.S)


def body_of(text: str, name: str) -> str | None:
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


def test_only_modules(root: Path) -> set[Path]:
    """Every file whose `mod` declaration is `#[cfg(test)]` in its parent.

    Measured rather than listed. `authorization/action_harness.rs` fabricates verified
    requests for controls and carries no attribute of its own — the gate that missed this
    would report three production fabrications that do not exist in any shipped binary, and
    the fix for a false report is always to loosen the rule.
    """
    excluded: set[Path] = set()
    for parent in root.rglob("*.rs"):
        text = parent.read_text(encoding="utf-8")
        for name in TEST_MOD_DECL.findall(text):
            for candidate in (
                parent.parent / f"{name}.rs",
                parent.parent / name / "mod.rs",
                parent.with_suffix("") / f"{name}.rs",
                parent.with_suffix("") / name / "mod.rs",
            ):
                if candidate.is_file():
                    excluded.add(candidate.resolve())
    return excluded


def production_sources(root: Path) -> dict[str, str]:
    """Every shipped `.rs` under `root`, keyed by relative path, test regions removed."""
    excluded = test_only_modules(root)
    return {
        str(p.relative_to(REPO)): code_only(production_text(p.read_text(encoding="utf-8")))
        for p in sorted(root.rglob("*.rs"))
        if p.resolve() not in excluded
    }


def read_subtree(sources: dict[str, str], prefix: str) -> str:
    """One subtree's production source. Each member is reduced SEPARATELY before joining —
    concatenating first would let one file's unterminated region swallow the next file's
    code, and the exactly-once counts are precisely what that would corrupt."""
    return "\n".join(t for p, t in sources.items() if p.startswith(prefix))


def check_serving(serving: str) -> list[str]:
    """(1), (2), (3), (5)."""
    problems: list[str] = []
    handle = body_of(serving, "handle")
    if handle is None:
        problems.append(f"{SERVING}: `handle` not found. The assembly is where the regions are ordered.")
    else:
        verified = len(re.findall(r"\b" + STAGE + r"\s*\(", handle))
        if verified != 1:
            problems.append(
                f"{SERVING}: `handle` calls `{STAGE}` {verified} time(s); expected exactly 1. "
                f"Two verifications put two products in scope, and which one the dispatch "
                f"holds becomes a question about source order."
            )
        carriers = len(re.findall(r"\b" + CARRIER + r"\s*\{", handle))
        if carriers != 1:
            problems.append(
                f"{SERVING}: `handle` builds {carriers} `{CARRIER}`; expected exactly 1. The "
                f"exchange is what carries the product to every stage after verification."
            )
    named = len(re.findall(r"\b" + STAGE + r"\s*\(", serving))
    if named != 2:
        problems.append(
            f"{SERVING}: names `{STAGE}` {named} time(s); expected exactly 2 (its definition "
            f"and one call). None is a serving path that dispatches without verifying; more "
            f"is a second product nothing sequenced."
        )
    stage = body_of(serving, STAGE)
    if stage is None:
        problems.append(f"{SERVING}: `{STAGE}` not found.")
    elif "progress.establish" not in stage:
        problems.append(
            f"{SERVING}: `{STAGE}` no longer hands its product to `progress.establish`. The "
            f"machine learns verification ran by the value being CONSUMED; a stage that "
            f"returned the product plainly would let the pipeline advance without it."
        )
    fields = struct_body(serving, CARRIER)
    if fields is None:
        problems.append(f"{SERVING}: `{CARRIER}` not found.")
    elif re.search(r"^\s*pub(\s|\()", fields, re.M):
        problems.append(
            f"{SERVING}: `{CARRIER}` has a `pub` field. The carrier holds borrowed products; "
            f"a public field lets a consumer be handed one assembled from parts."
        )
    return problems


def check_no_fabrication(sources: dict[str, str]) -> list[str]:
    """(4) — nothing in the proxy's production half constructs the product."""
    problems: list[str] = []
    for path, text in sources.items():
        count = len(re.findall(r"\b" + PRODUCT + r"\s*\{", text))
        if count:
            problems.append(
                f"{path}: constructs `{PRODUCT}` {count} time(s) in production. The product's "
                f"fields are public, so possession proves nothing on its own — the serving "
                f"path's claim is that it holds the one `Verifier::verify_request` returned, "
                f"and a literal built here is exactly the counterexample."
            )
    return problems


def check(repo: Path) -> tuple[list[str], int]:
    sources = production_sources(repo / PROXY)
    serving = read_subtree(sources, SERVING)
    if not serving.strip():
        raise SystemExit(f"{SERVING}: no production source found — a gate with an empty scope measures nothing")
    return check_serving(serving) + check_no_fabrication(sources), len(sources)


# --------------------------------------------------------------------------------------
# Selftest: every claim, undone, must be caught.
# --------------------------------------------------------------------------------------

def selftest() -> int:
    sources = production_sources(REPO / PROXY)
    serving = read_subtree(sources, SERVING)
    failures = 0
    cases = [
        (
            "a second verification in the assembly",
            check_serving,
            serving.replace(
                "let verified = match self.verify_stage(&http_req, now, &mut progress) {",
                "let _second = self.verify_stage(&http_req, now, &mut progress);\n"
                "        let verified = match self.verify_stage(&http_req, now, &mut progress) {",
            ),
            # The assembly count AND the subtree count both move: one edit, two claims.
            2,
        ),
        (
            "the stage no longer handing its product to the machine",
            check_serving,
            serving.replace("Ok(verified) => Ok(progress.establish(verified)),", "Ok(verified) => Ok(verified),"),
            1,
        ),
        (
            "a public field on the carrier",
            check_serving,
            serving.replace("    verified: &'a VerifiedMcpRequest,", "    pub verified: &'a VerifiedMcpRequest,"),
            1,
        ),
        (
            "a fabricated product in the production tree",
            check_no_fabrication,
            {**sources, "fake.rs": "fn back_door() -> VerifiedMcpRequest { VerifiedMcpRequest { floor } }"},
            1,
        ),
    ]
    for name, fn, argument, expected in cases:
        found = fn(argument)
        ok = len(found) == expected
        failures += 0 if ok else 1
        print(f"  {'ok ' if ok else 'FAIL'} {name}: {len(found)} problem(s), expected {expected}")
        if not ok:
            for problem in found:
                print(f"        {problem}")
    print()
    if failures:
        print(f"serving-product provenance selftest: FAIL — {failures} case(s) not caught")
        return 1
    print(f"serving-product provenance selftest: PASS — {len(cases)} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    problems, examined = check(REPO)
    if problems:
        print("serving-product provenance gate: FAILED")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"serving-product provenance gate: OK — {examined} production module(s) examined; "
        f"the serving path verifies once, hands the product to the exchange machine, and "
        f"nothing in this crate fabricates one."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
