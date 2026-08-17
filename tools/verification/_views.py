# SPDX-License-Identifier: Apache-2.0
"""The generated human assurance views — ADR-MCPRE-059 §9, §15, Phase T3.

**Nothing this module produces is authoritative.** Every view is a pure function of the
three catalogues, and every file it writes says so at the top. The catalogues are source;
these are a reading of them.

Two rules decide what may be generated here at all, and they are the reason the live
blast-radius and frontier views are NOT in this file's output:

  * A generated file is checked in and gated by `check-generated`, so it must be
    **byte-reproducible from the catalogues alone**. Anything that reads the attestation
    store depends on local machine state, so committing it would make the gate fail for
    everyone whose `.verification/` differs — which is everyone.
  * The STRUCTURAL blast radius ("if this moves, what is invalidated") *is* catalogue-pure
    and is generated here. The LIVE one ("what is dirty right now, and why") belongs to
    `review-frontier`, which already owns derived state and the two closures.

No reverse edge is stored to make rendering easier (§8.2). Where a view shows one — an
assumption's consumers, a unit's theorems — it is computed at render time from the forward
edges the catalogues declare.

Nothing here truncates. Every view shows its whole input, so there is no top-N or depth
limit to disclose; if one is ever added, the view must say so on the page, because silent
truncation reads as coverage.

**This file owns one fact: which views exist.** The renderers live beside it, split by what
they read — `_theorem_views` for the registry alone, `_catalogue_views` for the derivations
that cross all three. `render_all` is the single place that names the set, because the
generator and the drift gate must not be able to disagree about it: a gate that checked a
subset would leave the rest editable by hand.
"""

from __future__ import annotations

from _catalogue_views import assumption_consumers, owner_view, structural_blast_radius
from _theorem_views import theorem_dependencies, theorem_index
from _view_format import GENERATED_ROOT

__all__ = [
    "GENERATED_ROOT",
    "assumption_consumers",
    "owner_view",
    "render_all",
    "structural_blast_radius",
    "theorem_dependencies",
    "theorem_index",
]


def render_all(theorems: dict, verification: dict, assumptions: dict) -> dict[str, str]:
    """Every generated view, keyed by repo-relative path."""
    return {
        f"{GENERATED_ROOT}/theorem-index.md": theorem_index(theorems),
        f"{GENERATED_ROOT}/theorem-dependencies.md": theorem_dependencies(theorems),
        f"{GENERATED_ROOT}/assumption-consumers.md": assumption_consumers(
            theorems, verification, assumptions
        ),
        f"{GENERATED_ROOT}/owners.md": owner_view(theorems, verification),
        f"{GENERATED_ROOT}/blast-radius.md": structural_blast_radius(
            theorems, verification, assumptions
        ),
    }
