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
from bisect import bisect_left
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




#: A line comment's tail, and a whole-line block-comment body. Removed before a line is
#: searched for a mechanism.
_COMMENT_TAIL = re.compile(r"//.*$")


def code_of(line: str) -> str:
    """`line` with its comment removed — what the compiler would see.

    R9-C037 / R9-C067 / R9-C068 surfaced this: the production mechanism list matches
    `\bexternal_body\b` against whole lines, so PROSE mentioning a mechanism counted as an
    escape hatch. Two real examples on `main`:

        // Class B, and it matters most here: `external_body` means Verus checks this
        //! seal is `external_body`, which makes the type OPAQUE and its postconditions …

    Under kind-level registration this was invisible — the kind was registered, so a comment
    and a real seam both read `[registered]` and were indistinguishable. It matters twice
    over now: a site census that counts comments is not a census of seams, and
    `semantic_boundary_crossings` would read a boundary file that merely DISCUSSES a
    mechanism as one the proof trusts.

    `_definition_sites` in `check-assumptions` has stripped comments for exactly this reason
    since the deleted-specification repair — *"a comment cannot supply an escape-hatch
    mechanism either"*. That reasoning was applied to attribute blocks and not to the line
    scan; this is the same rule in the one place both consumers read.

    Leading `*` continuation lines of a block comment are dropped too. A `/* */` opening on
    its own line leaves nothing to match, and a mechanism written inside a multi-line block
    comment beside code on the same line is not a construction the language admits.
    """
    stripped = _COMMENT_TAIL.sub("", line)
    body = stripped.strip()
    if body.startswith(("*", "/*")):
        return ""
    return stripped


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
        code = code_of(line)
        if any(re.search(pattern, code) for pattern in PRODUCTION_MECHANISMS.values()):
            out.append((lineno, line.strip()))
    return out


def files_with_seams(repo_root: Path, relative_paths) -> set[str]:
    """Which of `relative_paths` contain at least one trusted seam."""
    return {
        rel
        for rel in relative_paths
        if rel.endswith(".rs") and seam_lines(repo_root / rel)
    }


#: `assume_specification[ <path> ]` names its item INSIDE the brackets, so the seam and the
#: item it trusts sit on one line. Bracket-balanced rather than non-greedy: `<[T]>::split_last`
#: contains a `]` of its own, and a non-greedy match truncates it to `<[T` — a site key that
#: silently merges two different standard-library seams.
_ASSUME_SPEC = re.compile(r"\bassume_specification\b")

#: An item declaration, in the forms Verus and Rust both use. `uninterp`, `spec`, `proof`,
#: `open`, `closed`, `tracked` and `ghost` are Verus modifiers; the rest are Rust's.
_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+|const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+"
    r"|uninterp\s+|spec\s+|proof\s+|exec\s+|open\s+|closed\s+|tracked\s+|ghost\s+)*"
    r"(?:fn|struct|enum|union|trait|type|mod)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)

#: The block forms that QUALIFY the items inside them. `impl Trait for Type` and `impl Type`
#: both qualify by the TYPE: two `actor_id` methods in two impl blocks of one file are two
#: seams, and a key that could not tell them apart would let one registration license both.
_IMPL = re.compile(r"^\s*(?:unsafe\s+)?impl\b(?P<head>[^{]*)")
_MOD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")

#: String and char literals, removed before braces are counted. A `{` inside a literal does
#: not open a block, and a qualifier stack that believed it would mis-attribute every item
#: after it.
_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])'")


def _impl_type(head: str) -> str | None:
    """The TYPE an `impl` block qualifies, from the text between `impl` and `{`."""
    text = head.split(" for ")[-1] if " for " in head else head
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<.*)?$", text.strip().rstrip("<"))
    if match:
        return match.group(1)
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)", text)
    return match.group(1) if match else None


def _brackets(text: str) -> tuple[int, int]:
    """`(square balance, brace balance)` of `text`, literals removed."""
    bare = _LITERAL.sub("", text)
    return (
        bare.count("[") - bare.count("]"),
        bare.count("{") - bare.count("}"),
    )


def declared_items(lines: list[str]) -> list[tuple[int, str]]:
    """Every item declaration in `lines`, as `(1-based line, qualified name)`, in order.

    ONE forward pass per file, and that is a correctness property rather than a speed one:
    the qualifier of an item is decided by the blocks open above it, so a per-seam walk from
    the top of the file re-derives the same stack once per seam. Over the whole scan — every
    `.rs`, `.lean` and `.v` file a unit declares plus the whole `verification/` tree — that
    is quadratic in the size of the files with the most seams, which are exactly the
    specification files.

    Braces are counted over code with comments and literals removed, and only `impl`/`mod`
    heads contribute a qualifier; every other block adds depth without a name, so
    `verus!{ ... }` and ordinary function bodies do not qualify what they contain.
    """
    items: list[tuple[int, str]] = []
    stack: list[tuple[int, str | None]] = []
    depth = 0
    for index, line in enumerate(lines):
        code = code_of(line)
        match = _ITEM.match(code)
        if match:
            qualifiers = [name for _, name in stack if name]
            items.append((index + 1, "::".join([*qualifiers, match.group("name")])))
        opened = _brackets(code)[1]
        name: str | None = None
        impl_match = _IMPL.match(code)
        mod_match = _MOD.match(code)
        if impl_match:
            name = _impl_type(impl_match.group("head"))
        elif mod_match:
            name = mod_match.group("name")
        if opened > 0:
            stack.append((depth, name))
        depth += opened
        while stack and depth <= stack[-1][0]:
            stack.pop()
    return items


def item_at(lines: list[str], lineno: int, items: list[tuple[int, str]] | None = None) -> str | None:
    """The ITEM a seam on `lineno` (1-based) sits on, qualified by its enclosing block.

    Two shapes, because Verus writes the seam two ways. `assume_specification[ X ]` names
    the trusted symbol in its own brackets and is answered from that line. Every other
    mechanism is an attribute or a modifier on a following item, so the answer is the FIRST
    declaration at or after the seam — never backwards from the item, and never a line
    number.

    A line number is what a registry must not be keyed on: adding a comment above a seam
    would move every key below it, and a registry that goes stale on formatting is one people
    regenerate without reading. The item's NAME is what the trust decision was about.

    The qualifier matters as much as the name. `mcp-re-http-profile/src/block.rs` declares
    `actor_id` twice, in `impl ActorIdentity` and in `impl ResolvedActor`; an unqualified key
    would make them one site, and registering either would license both.

    `items` is `declared_items(lines)`, passed in by a caller answering for several seams in
    one file so the pass is performed once.

    `None` where no declaration follows — a seam that cannot be named cannot be registered,
    and the gate says so rather than inventing a key.
    """
    line = code_of(lines[lineno - 1]) if 0 < lineno <= len(lines) else ""
    if _ASSUME_SPEC.search(line):
        return _assume_spec_item(lines, lineno)
    if items is None:
        items = declared_items(lines)
    index = bisect_left(items, (lineno, ""))
    return items[index][1] if index < len(items) else None


def _assume_spec_item(lines: list[str], lineno: int) -> str | None:
    """The symbol inside `assume_specification[ ... ]`, across line breaks if it wraps."""
    text = ""
    for index in range(lineno - 1, min(lineno + 8, len(lines))):
        text += code_of(lines[index])
        start = text.find("[", text.find("assume_specification"))
        if start < 0:
            continue
        depth = 0
        for offset, char in enumerate(text[start:], start=start):
            depth += (char == "[") - (char == "]")
            if depth == 0:
                return text[start + 1 : offset].strip() or None
    return None


def site_key(
    relative_path: str,
    lines: list[str],
    lineno: int,
    items: list[tuple[int, str]] | None = None,
) -> str | None:
    """`<path>#<qualified item>` — the stable identity of one trusted seam."""
    item = item_at(lines, lineno, items)
    return f"{relative_path}#{item}" if item else None
