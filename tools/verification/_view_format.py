# SPDX-License-Identifier: Apache-2.0
"""The format contract every generated view obeys — ADR-MCPRE-059 §9, Phase T3.

One responsibility: what a generated file looks like, independent of what it says. The
banner is the security-relevant half — a reader who finds a wrong line in a generated file
must be sent to the source that decides it, and an editor who ignores the banner is caught
by `check-generated`, which regenerates and compares.

Separated from the renderers because the banner and the source list are the one thing every
view must agree on, and a contract stated once in a small file cannot drift between five
callers.
"""

from __future__ import annotations

#: Where generated views live. Everything in this directory is derived; a file here that
#: no renderer produces is a drift failure, because nothing can establish it is current.
GENERATED_ROOT = "verification/generated"

#: The authoritative inputs, named on every page. A view derived from anything else — the
#: attestation store above all — could not be committed, because it would not reproduce.
SOURCES = (
    "verification/policy/theorems.toml",
    "verification/policy/verification.toml",
    "verification/policy/assumptions.toml",
    # Added with the derived boundary view. A page that named three sources while reading
    # four would understate what can invalidate it, and the banner is the only place a
    # reader is told what a regeneration depends on.
    "verification/policy/trust-boundaries.toml",
)


def header(title: str, what: str) -> str:
    """The do-not-edit banner every generated file carries, naming generator and sources."""
    sources = "\n".join(f"       {path}" for path in SOURCES)
    return (
        f"<!-- SPDX-License-Identifier: Apache-2.0 -->\n"
        f"<!-- GENERATED FILE — DO NOT EDIT.\n"
        f"     Regenerate with: tools/verification/generate-views\n"
        f"     Gated by:        tools/verification/check-generated\n"
        f"     Derived from:\n{sources}\n"
        f"-->\n\n"
        f"# {title}\n\n"
        f"{what}\n"
    )


def table(rows: list[tuple[str, ...]], headers: tuple[str, ...]) -> str:
    """A Markdown table, or an explicit `_None._` — never an empty table that reads as
    a table nobody filled in."""
    if not rows:
        return "_None._\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    out.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(out) + "\n"


def one_line(text: str) -> str:
    """Collapse a TOML multi-line string for a table cell, escaping the delimiter.

    Collapses whitespace only. It never shortens: a truncated description in a table reads
    as the whole of what is claimed or trusted.
    """
    return " ".join(str(text).split()).replace("|", "\\|")
