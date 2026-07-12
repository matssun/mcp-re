#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""JCS / object-profile vocabulary firewall (CI gate).

Enforces decision D1 of
`docs/design/active-profile-and-legacy-quarantine.md`: the Native JCS / object
profile is DEPRECATED — not a security mechanism, not an alternative carrier —
and forward-design docs MUST NOT frame a live "two-profile (object + HTTP)"
world.

This is a *vocabulary* gate: it enforces the exact forbidden framings D1 names,
not a semantic JCS detector (semantic intent lives in the deprecation banners and
`docs/AGENT_INSTRUCTIONS.md`). It scans the forward-design doc surface and fails
CI if any forbidden framing appears as a LIVE (non-repudiated) phrase.

Scanned surface (forward-design + spec/guide docs that must not frame a live
two-profile world):
  - docs/adr/adr-mcpre-*.md
  - docs/design/*.md
  - docs/spec/*.md
  - docs/*.md   (top-level guides: conformance, transport-hardening, architecture)

Allowlisted (these docs must NAME the framings in order to forbid them):
  - docs/design/active-profile-and-legacy-quarantine.md

Excluded (frozen pre-ADR-MCPRE-050 history — SUPPOSED to contain JCS/object
material, never scanned as live design):
  - docs/archive/**

A line is a violation only if a forbidden framing appears on it AND no
repudiation marker (deprecated, legacy, forbidden, "not", "never", rejected,
off-target, superseded, "must not") is present on the same line, AND the line is
not inside a fenced code block.

Run:  python3 scripts/jcs_vocabulary_gate.py         # scan the repo
      python3 scripts/jcs_vocabulary_gate.py --selftest   # prove the detector
"""

from __future__ import annotations

import glob
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The exact D1 forbidden framings (normalized: lowercased, whitespace collapsed).
FORBIDDEN_FRAMINGS = (
    "object profile + http profile",
    "object-profile + http profile",
    "native jcs profile + http profile",
    "jcs carrier + http carrier",
    "http profile + object profile",
    "http profile + jcs carrier",
)

# If one of these appears on the same line, the framing is being repudiated
# (named as a non-goal), not asserted as a live option.
REPUDIATION_MARKERS = (
    "deprecated",
    "legacy",
    "forbidden",
    "must not",
    "not ",
    "never",
    "no ",
    "rejected",
    "off-target",
    "off target",
    "superseded",
    "obsolete",
    "instead of",
)

# Doc globs (repo-relative) that make up the forward-design surface.
SCAN_GLOBS = (
    "docs/adr/adr-mcpre-*.md",
    "docs/design/*.md",
    "docs/spec/*.md",
    "docs/*.md",
)

# Basenames exempt from the ban: they must name the framings to forbid them.
ALLOWLIST_BASENAMES = frozenset(
    {
        "active-profile-and-legacy-quarantine.md",
    }
)

ERROR_MESSAGE = (
    "Native JCS/object-profile is DEPRECATED — not a security mechanism, not an\n"
    "alternative carrier. Use RFC 9421 + RFC 9530 HTTP profile language for active design.\n"
    "(enforces D1 of docs/design/active-profile-and-legacy-quarantine.md)"
)


def _normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line.replace("`", "").lower())


def scan_text(text: str):
    """Yield (line_no, framing) for each live forbidden framing in `text`."""
    in_fence = False
    for idx, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        norm = _normalize(raw)
        for framing in FORBIDDEN_FRAMINGS:
            if framing in norm and not any(m in norm for m in REPUDIATION_MARKERS):
                yield idx, framing


def scan_repo() -> int:
    files: list[str] = []
    for pattern in SCAN_GLOBS:
        files.extend(sorted(glob.glob(os.path.join(REPO_ROOT, pattern))))
    if not files:
        print("jcs_vocabulary_gate: no docs matched the scan globs — wiring is broken", file=sys.stderr)
        return 2

    violations: list[str] = []
    for path in files:
        rel = os.path.relpath(path, REPO_ROOT)
        # docs/archive/ is frozen pre-ADR-MCPRE-050 history — it is SUPPOSED to
        # contain JCS/object material and must never be scanned as live design.
        if rel.startswith("docs/archive/") or os.sep + "archive" + os.sep in path:
            continue
        if os.path.basename(path) in ALLOWLIST_BASENAMES:
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for line_no, framing in scan_text(text):
            violations.append(f"{rel}:{line_no}: forbidden framing {framing!r}")

    if violations:
        print("JCS vocabulary firewall FAILED:\n", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        print("\n" + ERROR_MESSAGE, file=sys.stderr)
        return 1

    print(f"jcs_vocabulary_gate: OK — {len(files)} forward-design docs clean of forbidden JCS framings")
    return 0


def selftest() -> int:
    """Prove the detector catches an asserted framing and allows repudiation."""
    asserted = "The design keeps an object profile + HTTP profile split."
    assert len(list(scan_text(asserted))) == 1, "must catch an asserted framing"

    repudiated = "A two-carrier object profile + HTTP profile design is forbidden."
    assert list(scan_text(repudiated)) == [], "must allow a repudiated framing"

    negated = "This is not an object profile + HTTP profile world; there is one carrier."
    assert list(scan_text(negated)) == [], "must allow a negated framing"

    fenced = "```\nobject profile + HTTP profile\n```"
    assert list(scan_text(fenced)) == [], "must ignore fenced code"

    print("jcs_vocabulary_gate: selftest OK")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        sys.exit(selftest())
    sys.exit(scan_repo())
