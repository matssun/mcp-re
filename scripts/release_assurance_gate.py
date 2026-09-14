#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release-assurance gate — the canonical command has a caller, and the document has a record.

THE FAILURE CLASS THIS EXISTS FOR, measured on 2026-09-14:
`tools/verification/review --require-root-complete` is the BINDING closure mode named by
#542 as a done criterion, and it had **zero invokers** — zero shell scripts, zero
workflows. Every occurrence in the tree was prose about the flag. It had been run by hand
for v0.16 and v0.17 and its verdict typed into a provenance document.

A tool with no caller is the false-green class this repository has now recorded three
times: `too-many-lines-threshold` parameterising a lint nobody switched on, a documented
SLO-Job rehearsal with no caller, and this. So the repair is not only to write the command
— it is to make its absence fail.

WHAT THIS PROVES, exactly, in two halves:

1. **INVOCATION.** The release workflow calls `tools/verification/release-assurance` in
   COMMAND POSITION. A mention in a comment or a `name:` is not a call, and this gate's own
   docstring names the path — so a mention-based reading would let the gate satisfy its own
   requirement by describing it.

2. **CORRESPONDENCE.** A release provenance document does not get to state the assurance
   verdict on its own authority. Every document under `docs/releases/` is registered here
   with how its assurance claim is backed, and an UNREGISTERED document is refused: a claim
   this gate has not been taught to check is a claim nobody checks.

WHAT IT DOES NOT PROVE. That the release workflow was ever RUN, or that it passed. That is
what the record the workflow uploads is for, and reachability is the half that had actually
come loose.

Run:  python3 scripts/release_assurance_gate.py
      python3 scripts/release_assurance_gate.py --selftest
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The one authority a release procedure may call. Not a family, not a prefix.
CANONICAL = "tools/verification/release-assurance"

#: The workflow that must call it.
WORKFLOW = Path(".github/workflows/release-assurance.yml")

#: Where release provenance documents live.
RELEASES = Path("docs/releases")

#: How each provenance document's assurance claim is backed. The registry may only shrink
#: in the `pre-mechanism` direction: a historical document is a DATED measurement and is not
#: retroactively falsified by a mechanism that did not exist when it was written — but a new
#: one may not join that class, and an unregistered document is refused outright.
#:
#: `mechanized` — the document carries a `release-assurance` marker block whose commit and
#:               verdict must equal the record COMMITTED beside it, at
#:               `docs/releases/<version>-release-assurance.json`. The record is tracked
#:               rather than left as a CI artifact on purpose: a document checked against a
#:               file that expires in 90 days is a document that stops being checked, and
#:               `.verification/` is gitignored, so a gate reading there would pass on every
#:               fresh checkout by finding nothing.
#: `pre-mechanism` — written before the command existed; the reason is recorded and the
#:               document is not checked for correspondence.
BACKING: dict[str, str] = {
    "v0.16.0-provenance.md": "pre-mechanism",
    "v0.17.0-provenance.md": "pre-mechanism",
}

#: The block a `mechanized` document carries, rendered from the record and never typed.
MARKER_BEGIN = "<!-- release-assurance:begin -->"
MARKER_END = "<!-- release-assurance:end -->"

#: A reference in COMMAND POSITION inside a workflow's `run:` text: first word of a command,
#: after any leading environment assignments and any interpreter that runs it.
RUNNERS = {"python3", "python", "bash", "sh", "exec", "time", "."}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

#: YAML scaffolding in front of a command: the sequence dash, and `run:` — the ONLY key
#: whose value is a shell command. Stripped rather than ignored, because the alternative is
#: a gate that reads `- run: <command>` as a command named `-`.
#:
#: No other key is stripped, and that is the load-bearing half. `- name:` and `- uses:` take
#: VALUES, not commands: a step named after the tool, or an action whose input happens to be
#: the path, must read as a mention. Stripping every `key:` made `- name: <path>` a caller.
YAML_LEAD = re.compile(r"^-$|^run:$")


def invoked(text: str, target: str) -> bool:
    """Does this text CALL `target`, rather than mention it?

    Comment lines are dropped first. In YAML that is load-bearing in both directions: a
    `# ...` line inside a `run:` block is a shell comment, and a `#` line outside one is a
    YAML comment. Neither runs anything.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for segment in re.split(r"&&|\|\||[;|]", line):
            words = segment.strip().split()
            while words and (
                ASSIGNMENT.match(words[0])
                or words[0] in RUNNERS
                or YAML_LEAD.match(words[0])
                or words[0] in {"|", ">"}
            ):
                words.pop(0)
            if not words:
                continue
            candidate = words[0].lstrip("./") if words[0].startswith("./") else words[0]
            if candidate == target:
                return True
    return False


def render(record: dict) -> str:
    """The document's assurance block, DERIVED from the record.

    Deliberately small: commit, tree, verdict, root completeness. A document may explain a
    result at any length it likes; what it may not do is be the authority for what the
    command returned.
    """
    target = record["target"]
    return "\n".join(
        [
            MARKER_BEGIN,
            f"| release assurance | `{record['verdict']}` |",
            f"| commit | `{target['commit']}` |",
            f"| tree | `{target['tree']}` |",
            f"| root completeness | `{record['root_completeness']}` |",
            f"| recorded at | `{record['recorded_at']}` |",
            MARKER_END,
        ]
    )


def block_of(text: str) -> str | None:
    """The document's marker block, or None when it carries none."""
    start = text.find(MARKER_BEGIN)
    end = text.find(MARKER_END)
    if start < 0 or end < 0 or end < start:
        return None
    return text[start : end + len(MARKER_END)]


def invocation_problems(read: dict[str, str]) -> list[str]:
    """The release workflow calls the canonical command."""
    text = read.get(str(WORKFLOW))
    if text is None:
        return [
            f"{WORKFLOW} does not exist. The canonical command `{CANONICAL}` would then "
            "have no caller, which is the state this gate exists to make impossible."
        ]
    if not invoked(text, CANONICAL):
        return [
            f"{WORKFLOW} does not invoke `{CANONICAL}` in command position. It may name it "
            "in a comment or a step name; a mention is not a caller, and this gate's own "
            "docstring names the same path."
        ]
    return []


def record_name(document: str) -> str:
    """The record that backs `vX.Y.Z-provenance.md`: `vX.Y.Z-release-assurance.json`."""
    return document.replace("-provenance.md", "-release-assurance.json")


def correspondence_problems(documents: dict[str, str], records: dict[str, dict]) -> list[str]:
    """Every provenance document is registered, and a mechanized one matches its record."""
    problems = []
    for name in sorted(documents):
        backing = BACKING.get(name)
        if backing is None:
            problems.append(
                f"{RELEASES / name} is not registered in BACKING. A release provenance "
                "document states an assurance verdict; one this gate has not been taught "
                "to check is a verdict nobody checks. Register it as `mechanized`."
            )
            continue
        if backing == "pre-mechanism":
            continue
        block = block_of(documents[name])
        if block is None:
            problems.append(
                f"{RELEASES / name} is registered `mechanized` but carries no "
                f"`{MARKER_BEGIN}` block, so its assurance line is typed rather than derived."
            )
            continue
        record = records.get(record_name(name))
        if record is None:
            problems.append(
                f"{RELEASES / name} is `mechanized` and {RELEASES / record_name(name)} is "
                "absent, unreadable, or not a schema-1 release-assurance record. A missing "
                "record is a refusal, never a pass."
            )
            continue
        expected = render(record)
        if block.strip() != expected.strip():
            problems.append(
                f"{RELEASES / name}'s assurance block disagrees with the record.\n"
                f"  document says:\n    " + "\n    ".join(block.strip().splitlines()) + "\n"
                f"  record says:\n    " + "\n    ".join(expected.strip().splitlines())
            )
    return problems


def load_record_obj(record: object) -> dict | None:
    """A parsed object, if it is a release-assurance record this gate can read."""
    if not isinstance(record, dict) or record.get("kind") != "release-assurance":
        return None
    if record.get("schema_version") != 1:
        return None
    return record


def load_record(path: Path) -> dict | None:
    """The record, or None — where None is 'absent, unreadable or unknown', all refusals."""
    if not path.is_file():
        return None
    try:
        return load_record_obj(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return None


def selftest() -> int:
    """The mutation probe. Each control is shown to FAIL on the thing it forbids."""
    good = "      - run: python3 tools/verification/release-assurance\n"
    assert not invocation_problems({str(WORKFLOW): good})
    assert invocation_problems({}), "an absent workflow must fail"
    assert invocation_problems(
        {str(WORKFLOW): "      # runs tools/verification/release-assurance\n"}
    ), "a comment naming the command is not a caller"
    assert invocation_problems(
        {str(WORKFLOW): "      - name: tools/verification/release-assurance\n"}
    ), "a step NAME is not a caller"
    assert not invocation_problems(
        {str(WORKFLOW): "      - run: FOO=1 python3 ./tools/verification/release-assurance --out x\n"}
    ), "assignments and an interpreter may precede the command"

    record = {
        "kind": "release-assurance",
        "schema_version": 1,
        "verdict": "PASS",
        "root_completeness": "PASS",
        "recorded_at": "2026-01-01T00:00:00Z",
        "target": {"repository": "r", "commit": "c" * 40, "tree": "t" * 40},
    }
    records = {"v9.9.9-release-assurance.json": record}
    assert not correspondence_problems({"v0.16.0-provenance.md": "anything"}, records)
    assert correspondence_problems({"v9.9.9-provenance.md": "x"}, records), "unregistered refuses"

    BACKING["v9.9.9-provenance.md"] = "mechanized"
    try:
        assert correspondence_problems({"v9.9.9-provenance.md": "no block"}, records)
        matching = "intro\n" + render(record) + "\noutro"
        assert not correspondence_problems({"v9.9.9-provenance.md": matching}, records)
        assert correspondence_problems({"v9.9.9-provenance.md": matching}, {}), (
            "a missing record must refuse a mechanized document, never pass it"
        )
        lying = matching.replace("`PASS`", "`FAIL`", 1)
        assert correspondence_problems({"v9.9.9-provenance.md": lying}, records), (
            "a document claiming a verdict the record does not carry must fail"
        )
        wrong_sha = matching.replace("c" * 40, "d" * 40)
        assert correspondence_problems({"v9.9.9-provenance.md": wrong_sha}, records), (
            "a document naming a different target than the record must fail"
        )
        malformed = dict(record, schema_version=99)
        assert load_record_obj(malformed) is None, (
            "an unknown schema version is refused rather than read optimistically"
        )
    finally:
        del BACKING["v9.9.9-provenance.md"]

    assert load_record(Path("/nonexistent/x.json")) is None
    print("release-assurance gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    read = {}
    if (REPO / WORKFLOW).is_file():
        read[str(WORKFLOW)] = (REPO / WORKFLOW).read_text(encoding="utf-8")
    documents = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((REPO / RELEASES).glob("*-provenance.md"))
    }
    records = {}
    for path in sorted((REPO / RELEASES).glob("*-release-assurance.json")):
        loaded = load_record(path)
        if loaded is not None:
            records[path.name] = loaded
    problems = invocation_problems(read) + correspondence_problems(documents, records)
    if problems:
        print("release-assurance gate: FAIL", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    mechanized = sum(1 for name in documents if BACKING.get(name) == "mechanized")
    print(
        f"release-assurance gate: OK — {WORKFLOW.name} invokes `{CANONICAL}`; "
        f"{len(documents)} provenance document(s), {mechanized} mechanized, "
        f"{len(documents) - mechanized} pre-mechanism and recorded as such."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
