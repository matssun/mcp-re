#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Documented-rehearsal gate — a runbook sentence is a claim, and a claim needs a caller.

THE FAILURE CLASS. Both cloud SLO runbooks stated that local-gate stage 5 "additionally
rehearses the **exact** SLO Job spec this runbook schedules". `tools/slo/run_slo_job.sh`
was invoked by `scripts/local_gate.sh`, by `docs/security/gke-multi-replica-validation.sh`
and by nothing else in the tree — zero callers. The sentence had been false since it was
written, and every reader of those runbooks believed the Job manifest, the Redis sidecars,
the bench image and the marker-based report extraction had all been exercised locally
before an EC2 or GKE node existed.

This is `merge_path_gate.py`'s class one layer up: there, a control existed but nothing
required ran it; here, a control is DESCRIBED but nothing invokes it. Prose is a claim, and
a claim whose mechanism nobody calls is worth less than no claim at all, because it stops
anyone looking.

WHAT IT PROVES. For each registered claim: the document still makes it, AND the invocation
it asserts is reachable from `scripts/local_gate.sh` through the transitive closure of
script-to-script invocations.

The absent-claim direction fails too, on purpose. If the sentence is deleted, this gate's
premise is gone and the entry must be removed in the same change — otherwise the registry
slowly fills with checks about text nobody has, which is the same rot in the other
direction.

WHAT IT DOES NOT PROVE. That stage 5 is ever run (it is opt-in, `--with-kind`), or that the
rehearsal passes. Reachability is what a text gate can establish, and it is the half that
had actually come loose.

Run:  python3 scripts/rehearsal_claim_gate.py
      python3 scripts/rehearsal_claim_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from collections import deque
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENTRY = "scripts/local_gate.sh"

#: A repository script or harness reference, in the forms these files use. `docs/` is in
#: the set because the fleet harness lives there and is invoked like any other script.
INVOCATION = re.compile(r"(?:^|[\s`\"'./])((?:scripts|tools|docs)/[A-Za-z0-9_./-]+?\.(?:py|sh))")

#: document -> (the literal claim it makes, the invocation that claim asserts)
#:
#: The marker is a literal substring rather than a regex: a claim this gate can only match
#: approximately is a claim it cannot report precisely, and the whole point is that the
#: reader of the document and the reader of this table are looking at the same words.
CLAIMS: dict[str, tuple[str, str]] = {
    "docs/security/eks-slo-baseline-runbook.md": (
        "rehearses the **exact** SLO Job spec",
        "tools/slo/run_slo_job.sh",
    ),
    "docs/security/gke-slo-baseline-runbook.md": (
        "rehearses the **exact** SLO Job spec",
        "tools/slo/run_slo_job.sh",
    ),
    "docs/dev/local-gate-order.md": (
        "rehearses the **exact** SLO Job spec",
        "tools/slo/run_slo_job.sh",
    ),
}


def closure(read: dict[str, str], entry: str) -> set[str]:
    """Every script reachable from `entry` by invocation, `entry` included.

    Reachability, not a call graph: a name inside a comment counts. That is deliberate and
    conservative in the safe direction for THIS question — a commented-out invocation would
    make the gate pass while the rehearsal is dead, so the registry entry and the wiring are
    reviewed together in the same diff rather than trusted to a parser.
    """
    seen = {entry}
    queue = deque([entry])
    while queue:
        current = queue.popleft()
        for found in INVOCATION.findall(read.get(current, "")):
            if found not in seen:
                seen.add(found)
                queue.append(found)
    return seen


def adjudicate(claims: dict[str, tuple[str, str]], docs: dict[str, str], reachable: set[str]) -> list[str]:
    findings: list[str] = []
    for document, (marker, required) in sorted(claims.items()):
        text = docs.get(document)
        if text is None:
            findings.append(f"{document}: registered here but the file does not exist")
            continue
        if marker not in text:
            findings.append(
                f"{document}: no longer contains the claim {marker!r}. "
                "Remove this entry in the same change that removed the sentence — a check "
                "about text nobody has is not a check."
            )
            continue
        if required not in reachable:
            findings.append(
                f"{document} claims {marker!r}, but {required} is NOT reachable from "
                f"{ENTRY}. The sentence is currently false."
            )
    return findings


def _read_repo() -> tuple[dict[str, str], dict[str, str]]:
    scripts: dict[str, str] = {}
    for pattern in ("scripts/*.sh", "scripts/*.py", "tools/**/*.sh", "docs/**/*.sh"):
        for path in REPO.glob(pattern):
            scripts[str(path.relative_to(REPO))] = path.read_text(encoding="utf-8", errors="replace")
    docs = {
        name: (REPO / name).read_text(encoding="utf-8", errors="replace")
        for name in CLAIMS
        if (REPO / name).is_file()
    }
    return scripts, docs


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    scripts, docs = _read_repo()
    reachable = closure(scripts, ENTRY)
    findings = adjudicate(CLAIMS, docs, reachable)
    for finding in findings:
        print(f"  ✗ {finding}")
    if findings:
        print(f"rehearsal-claim gate: FAILED ({len(findings)} claim(s) not backed by a caller)")
        return 1
    print(
        f"rehearsal-claim gate: OK — {len(CLAIMS)} documented rehearsal claim(s), "
        f"each backed by an invocation reachable from {ENTRY} "
        f"({len(reachable)} script(s) in the closure)"
    )
    return 0


def selftest() -> int:
    scripts = {
        "scripts/local_gate.sh": "runs docs/h.sh and scripts/other.py",
        "docs/h.sh": "calls tools/slo/run_slo_job.sh",
        "scripts/other.py": "",
    }
    reachable = closure(scripts, "scripts/local_gate.sh")
    assert reachable == {"scripts/local_gate.sh", "docs/h.sh", "scripts/other.py", "tools/slo/run_slo_job.sh"}, reachable

    claim = {"d.md": ("CLAIM", "tools/slo/run_slo_job.sh")}
    assert adjudicate(claim, {"d.md": "we CLAIM it"}, reachable) == []
    unreachable = adjudicate(claim, {"d.md": "we CLAIM it"}, {"scripts/local_gate.sh"})
    assert len(unreachable) == 1 and "currently false" in unreachable[0], unreachable
    gone = adjudicate(claim, {"d.md": "we say nothing"}, reachable)
    assert len(gone) == 1 and "no longer contains" in gone[0], gone
    missing = adjudicate(claim, {}, reachable)
    assert len(missing) == 1 and "does not exist" in missing[0], missing

    # A one-hop closure must not be mistaken for a transitive one: the invocation this gate
    # exists for is two hops away, and a direct-reference-only check would have passed the
    # whole time the sentence was false.
    assert "tools/slo/run_slo_job.sh" not in closure(scripts, "scripts/other.py")

    print("rehearsal_claim_gate selftest: OK — 4 adjudication cases, 2 closure cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
