# SPDX-License-Identifier: Apache-2.0
"""What a TRUSTED SEAM is — the single authority, shared by every consumer.

A seam is a place where a proof stops proving and starts trusting: an `uninterp` spec
function, an `external_body`, an `assume_specification`. Two questions in this repository
depend on recognising one, and they used to be answerable only inside `check-assumptions`:

  * IS EVERY SEAM REGISTERED?  — `check-assumptions`, the escape-hatch gate.
  * WHICH TRUST BOUNDARIES DOES A PROOF ACTUALLY CROSS? — `_manifest.boundary_class_violations`.

The second is why this module exists. R9-C022 asked whether six V1 units crossed
`boundary.crypto_primitives`, and the answer turns on the difference between a proof that
CONSUMES an unproved proposition beyond that boundary and one that merely COMPILES
alongside it. Only a seam distinguishes them, so the boundary rule needs the same notion of
"seam" the escape-hatch gate uses — and a second copy of these patterns would be a second
answer to what a seam is, diverging the first time one was updated.

Stdlib only, and it imports nothing from this package: `_manifest` imports it.
"""

from __future__ import annotations

import re
from pathlib import Path

#: Mechanisms that move a proof obligation out of the proof and into the trusted computing
#: base. Word-bounded so `assumed_state` or `external_id` do not trip the gate.
MECHANISMS = {
    "assume": r"\bassume\b",
    "assume_specification": r"\bassume_specification\b",
    "admit": r"\badmit\b",
    "axiom": r"\baxiom\b",
    "external_body": r"\bexternal_body\b",
    "external_type_specification": r"\bexternal_type_specification\b",
    "external_fn_specification": r"\bexternal_fn_specification\b",
    "external": r"\bexternal\b",
    "uninterp": r"\buninterp\b",
    "opaque": r"\bopaque\b",
    "sorry": r"\bsorry\b",
}

#: The same question, asked of production Rust, where the bare words are ordinary English.
#: "admit only the closed set" in a comment is not a proof escape hatch, and a gate that
#: said it was would be teaching people to ignore it within a week. So the mechanisms are
#: matched in their code forms: the verus-specific spellings, and `assume`/`admit` only as
#: calls.
PRODUCTION_MECHANISMS = {
    "assume_specification": r"\bassume_specification\b",
    "external_body": r"\bexternal_body\b",
    "external_type_specification": r"\bexternal_type_specification\b",
    "external_fn_specification": r"\bexternal_fn_specification\b",
    # `external` REMOVES a function from verification entirely, which is a stronger escape
    # than `external_body`. Matched only in its two code spellings, because the bare word
    # is ordinary English and ordinary Rust.
    "external": r"verifier::external\b(?!_)|verus_verify\s*\(\s*external\s*\)",
    # An uninterpreted spec function is a trusted seam by construction: every theorem that
    # mentions it says nothing about what it computes.
    "uninterp": r"\buninterp\b",
    "opaque": r"verifier::opaque\b",
    "axiom": r"\baxiom\b",
    "sorry": r"\bsorry\b",
    # A METHOD call is not a proof escape hatch, and neither is a method DEFINITION.
    # `self.inner_async.admit()` asks the inner plane whether it will accept a request, and
    # `fn admit(&self)` is where that question is answered; Verus' `admit()` deletes a proof
    # obligation. They share a name and nothing else, and a gate that conflated them would
    # fire on ordinary serving code — the same failure the code-forms rule above exists to
    # avoid, and one that arrived twice: once when the caller entered a unit's paths, and
    # again when the definition did.
    # Path-qualified spellings (`vstd::pervasive::admit()`) are still matched: `::` is not
    # `.`, and `fn ` does not precede them.
    "assume": r"(?<!\.)(?<!fn )\bassume\s*[(!]",
    "admit": r"(?<!\.)(?<!fn )\badmit\s*[(!]",
}


TEST_REGION = re.compile(r"^#\[cfg\((all\()?test\b")


def production_lines(text: str) -> list[tuple[int, str]]:
    """`(1-based line number, line)` for every line OUTSIDE a test region.

    A region runs from its `#[cfg(test)]`-family attribute to the end of the module it
    introduces, tracked by brace depth, and scanning resumes afterwards — not "everything
    above the first one", which would discard production items below a test module.

    Why the PRODUCTION scan needs this at all: its mechanism list exists because the bare
    words are ordinary English and ordinary Rust, and a test region is where ordinary Rust
    is densest. `mcp-re-http-profile/src/replay.rs` has a test helper `fn admit(..)`; Verus'
    `admit()` deletes a proof obligation, and the two share a name and nothing else. A
    region that ships in no binary cannot weaken a proof about one, so the honest scope for
    "which escape hatches does this shipped code use" is the shipped code.
    """
    lines = text.splitlines()
    kept: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        if TEST_REGION.match(lines[i].lstrip()):
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
        kept.append((i + 1, lines[i]))
        i += 1
    return kept




def seam_lines(path: Path) -> list[tuple[int, str]]:
    """Every PRODUCTION line of `path` that carries a trusted seam, with its line number.

    Production lines only, for the reason `production_lines` gives: a region that ships in
    no binary cannot weaken a proof about one.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out: list[tuple[int, str]] = []
    for lineno, line in production_lines(text):
        if any(re.search(pattern, line) for pattern in PRODUCTION_MECHANISMS.values()):
            out.append((lineno, line.strip()))
    return out


def files_with_seams(repo_root: Path, relative_paths) -> set[str]:
    """Which of `relative_paths` contain at least one trusted seam."""
    return {
        rel
        for rel in relative_paths
        if rel.endswith(".rs") and seam_lines(repo_root / rel)
    }
