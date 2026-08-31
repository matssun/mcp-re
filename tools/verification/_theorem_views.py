# SPDX-License-Identifier: Apache-2.0
"""The views derived from `theorems.toml` alone — ADR-MCPRE-059 §9, Phase T3.

Grouped by what they read, not by what they look like. Everything here is a function of the
theorem registry and nothing else, so a change to `verification.toml` or `assumptions.toml`
cannot alter a byte of it. That is the same invalidation boundary the theorem fingerprint
draws (§14.7), stated once more in the module layout.

Neither view reports whether a claim is ESTABLISHED. They cannot: establishment is a
conjunction over attestations, and these files are committed. Each says so on the page
rather than leaving a reader to assume a table of claims is a table of guarantees.
"""

from __future__ import annotations

from _view_format import header, one_line, table


def theorem_index(theorems: dict) -> str:
    entries = sorted(theorems.get("theorem", []), key=lambda row: row["id"])
    body = header(
        "Security theorem index",
        "Every claim MCP-RE states, with its owner and the review units that support it.\n"
        "Support is STRUCTURAL — that a unit exists and is named, not that its evidence is\n"
        "fresh. Whether a claim is established is the conjunction `tools/verification/review`\n"
        "derives, and it is not shown here because this view cannot see the attestations.",
    )
    rows = [
        (
            row["id"],
            one_line(row["title"]),
            row["owner"],
            ", ".join(sorted(row.get("supported_by", []))) or "_none_",
            "deprecated → " + row["replaced_by"] if row.get("replaced_by") else "live",
        )
        for row in entries
    ]
    body += _roots_section(theorems)
    body += "\n" + table(rows, ("id", "title", "owner", "supported by", "lifecycle"))
    if not entries:
        body += (
            "\nThe registry declares no theorem. That is a statement about the registry,\n"
            "not about the code: no claim is made, so no claim is established.\n"
        )
        return body
    body += "\n## Claims in full\n"
    for row in entries:
        body += (
            f"\n### {row['id']} — {row['title']}\n\n"
            f"**Statement.** {one_line(row['statement'])}\n\n"
            f"**Security consequence.** {one_line(row['security_consequence'])}\n\n"
            f"**Scope — what this does NOT establish.** {one_line(row['scope'])}\n\n"
            f"**Review requirement.** {one_line(row['review_requirement'])}\n"
        )
        deps = sorted(row.get("depends_on", []))
        if deps:
            body += f"\n**Depends on.** {', '.join(deps)}\n"
    return body


def _roots_section(theorems: dict) -> str:
    """The declared system roots — ADR-MCPRE-059 §28.1.

    Rendered from the declaration, never from graph shape: this view must not be the place
    a reader learns a different root set from the one the owner ratified.

    Like the rest of this module it reports no establishment. Whether a root is CLOSED is
    root completeness, which is a conjunction over attestations and belongs to
    `tools/verification/review`.
    """
    roots = list(theorems.get("root_theorems", []))
    entries = {row["id"]: row for row in theorems.get("theorem", [])}
    out = "\n## System roots\n\n"
    if not roots:
        return out + (
            "_No system root is declared._ Nothing here is claimed at the MCP-RE boundary,\n"
            "so no root is complete — an empty root set is never a pass. Roots are declared\n"
            "in `theorems.toml` `root_theorems` after theorem-architecture ratification.\n"
        )
    out += (
        "The claims MCP-RE makes at its boundary. Proof-tree completeness is derived over\n"
        "these and reported by `tools/verification/review`; this view cannot see whether\n"
        "any of them is closed.\n\n"
    )
    return out + table(
        [(root, one_line(entries[root]["title"])) for root in roots],
        ("root", "claim"),
    )


def theorem_dependencies(theorems: dict) -> str:
    """The `depends_on` graph, as Mermaid.

    One diagram per connected component rather than one global picture: a single diagram
    over every theorem becomes unreadable at exactly the size where a reader needs it, and
    an unreadable diagram is a view nobody consults.
    """
    entries = {row["id"]: row for row in theorems.get("theorem", [])}
    roots = set(theorems.get("root_theorems", []))
    body = header(
        "Theorem dependency graph",
        "Which claims rest on which — `depends_on` is logical implication, never a call\n"
        "or a build edge. Rendered as one diagram per connected component: a single global\n"
        "diagram is unreadable at the size where it would matter. Declared system roots are\n"
        "marked; a component containing none is not yet attached to a system promise.",
    )
    if not entries:
        return body + "\n_No theorem is declared, so there is no dependency graph._\n"
    for index, group in enumerate(_components(entries), start=1):
        body += f"\n## Component {index}\n\n```mermaid\ngraph BT\n"
        for tid in group:
            label = one_line(entries[tid]["title"]).replace('"', "'")
            prefix = "ROOT — " if tid in roots else ""
            body += f'    {tid.replace("-", "_")}["{prefix}{tid}<br/>{label}"]\n'
        for tid in group:
            for dep in sorted(entries[tid].get("depends_on", [])):
                # Bottom-to-top: the premise is below the claim that rests on it, matching
                # how invalidation travels.
                body += f'    {dep.replace("-", "_")} --> {tid.replace("-", "_")}\n'
        marked = [tid for tid in group if tid in roots]
        if marked:
            body += "    classDef root stroke-width:3px;\n"
            body += f'    class {",".join(tid.replace("-", "_") for tid in marked)} root;\n'
        body += "```\n"
    return body


def _components(entries: dict[str, dict]) -> list[list[str]]:
    """Connected components over the UNDIRECTED `depends_on` edges.

    Undirected so a premise and its consumers are drawn together regardless of which way
    the arrow runs — a reader asking "what else moves with this claim" needs both
    directions, and the arrows inside the diagram still show which is which.
    """
    neighbours: dict[str, set[str]] = {tid: set() for tid in entries}
    for tid, row in entries.items():
        for dep in row.get("depends_on", []):
            neighbours[tid].add(dep)
            neighbours.setdefault(dep, set()).add(tid)
    seen: set[str] = set()
    components: list[list[str]] = []
    for tid in sorted(entries):
        if tid in seen:
            continue
        stack, group = [tid], []
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            group.append(node)
            stack.extend(sorted(neighbours.get(node, ())))
        components.append(sorted(group))
    return components
