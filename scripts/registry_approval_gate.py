#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Registry approval gate — no policy registry may carry a mutable approval string.

WHAT THIS PROVES, exactly: no file under `verification/policy/` declares a key that
represents review or approval STATE, and no review record under `verification/reviews/`
carries one either.

WHAT IT DOES NOT PROVE: that any approval is genuine, that a reviewer read anything, or
that the fingerprint a record names was ever computed honestly. It proves only that
approval is expressed as evidence ABOUT a fingerprint and not as a bit on the object
approved.

WHY IT MATTERS (ADR-MCPRE-059 §14.7). A stored `review = "approved"` answers the wrong
question: it does not say WHICH proposition was approved, so it survives every edit to the
proposition. It also makes a self-approving change a single-file operation, and — where the
record is itself fingerprinted — it is either inside its own fingerprint, so flipping it
dirties the evidence it approves, or it is silently excluded, so the fingerprint means
"some subset". Both are incoherent.

The theorem loader already rejects these keys inside `theorems.toml`. This gate is the
repository-wide statement of the same rule: it covers the sibling registries, catches a key
smuggled into a nested table the loader's flat key check would not reach, and keeps working
if a fourth registry is added tomorrow.

Run:  python3 scripts/registry_approval_gate.py
      python3 scripts/registry_approval_gate.py --selftest
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
POLICY_DIR = REPO / "verification" / "policy"
REVIEWS_DIR = REPO / "verification" / "reviews"

#: Keys that express review/approval STATE. Deliberately not "any key containing the word
#: review": `review_requirement` (who must review) and `reviewed_fingerprint` (which
#: fingerprint was reviewed) are both legitimate and both must keep working, so the set is
#: enumerated rather than pattern-matched.
FORBIDDEN = {
    "approved",
    "approval",
    "review_status",
    "reviewed_by_status",
    "signed_off",
    "sign_off",
    "verdict",
    "audited",
    "attested",
    "clean",
    "status",
    "state",
}

#: Keys that LOOK like the forbidden ones and are the mechanism itself. Listed so a future
#: reader does not "tighten" the gate into refusing the thing it exists to require.
PERMITTED = {"review_requirement", "reviewed_fingerprint", "reviewer", "subject", "axis"}

#: The one exemption, named rather than implied, because a gate's exemption is part of what
#: it measured. `toolchains.lock.toml` uses `state = "resolved" | "unresolved"` to say
#: whether a TOOL'S IDENTITY is pinned — a fact about the lock file, not a review verdict
#: about code — and `_manifest.load_toolchains` already validates it as a closed enum and
#: refuses anything else. Every other file, including any future registry, is covered.
EXEMPT_KEYS: dict[str, set[str]] = {"toolchains.lock.toml": {"state"}}


def offending_keys(value, path: str = "", exempt: set[str] | None = None) -> list[str]:
    """Every forbidden key in a parsed document, as dotted paths."""
    exempt = exempt or set()
    found: list[str] = []
    if isinstance(value, dict):
        for key, sub in value.items():
            where = f"{path}.{key}" if path else str(key)
            if key in PERMITTED or key in exempt:
                continue
            if key in FORBIDDEN:
                found.append(where)
            found.extend(offending_keys(sub, where, exempt))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(offending_keys(item, f"{path}[{index}]", exempt))
    return found


def scan() -> tuple[list[str], int]:
    """(failures, files examined). An empty scope is a failure, not a pass."""
    failures: list[str] = []
    examined = 0
    for path in sorted(POLICY_DIR.glob("*.toml")):
        examined += 1
        try:
            with path.open("rb") as handle:
                doc = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            failures.append(f"{path.relative_to(REPO)}: unparsable: {exc}")
            continue
        exempt = EXEMPT_KEYS.get(path.name, set())
        for key in offending_keys(doc, exempt=exempt):
            failures.append(
                f"{path.relative_to(REPO)}: `{key}` is a stored approval/status field. "
                f"An approval is evidence ABOUT a fingerprint (ADR-MCPRE-059 §14.7); "
                f"record it in verification/reviews/ keyed by reviewed_fingerprint."
            )
    for path in sorted(REVIEWS_DIR.rglob("*.json")) if REVIEWS_DIR.exists() else []:
        examined += 1
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"{path.relative_to(REPO)}: unparsable: {exc}")
            continue
        for key in offending_keys(doc):
            failures.append(
                f"{path.relative_to(REPO)}: `{key}` is a stored approval bit. A review "
                f"record says which fingerprint was reviewed and nothing else."
            )
        if "reviewed_fingerprint" not in doc:
            failures.append(
                f"{path.relative_to(REPO)}: no `reviewed_fingerprint`. A review that does "
                f"not name what it reviewed approves nothing in particular."
            )
    return failures, examined


def selftest() -> int:
    """The gate must refuse a document that carries the thing it forbids.

    A gate whose only evidence is that a clean tree passes has never been shown to fail.
    """
    cases = [
        ({"theorem": [{"id": "THM-0001", "approved": True}]}, "theorem[0].approved"),
        ({"assumption": [{"id": "ASM-0001", "review_status": "ok"}]}, "review_status"),
        ({"unit": [{"id": "u", "nested": {"clean": True}}]}, "clean"),
    ]
    for doc, needle in cases:
        found = offending_keys(doc)
        if not any(needle in entry for entry in found):
            print(f"SELFTEST FAIL: {needle} not caught in {doc}", file=sys.stderr)
            return 1
    permitted = {
        "theorem": [
            {
                "id": "THM-0001",
                "review_requirement": "Owner security-specification review",
            }
        ]
    }
    if offending_keys(permitted):
        print(
            "SELFTEST FAIL: the gate refused `review_requirement`, which is the "
            "mechanism, not a violation",
            file=sys.stderr,
        )
        return 1
    record = {"reviewed_fingerprint": "sha256:abc", "reviewer": "x", "axis": "specification"}
    if offending_keys(record):
        print("SELFTEST FAIL: the gate refused a well-formed review record", file=sys.stderr)
        return 1
    print("registry_approval_gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    failures, examined = scan()
    if examined == 0:
        # An empty scope is the gate measuring nothing while printing OK — the failure
        # mode a glob that stopped matching produces, and one this repository has shipped.
        print(
            "FAIL: registry approval gate examined 0 files. Expected the policy "
            "registries under verification/policy/.",
            file=sys.stderr,
        )
        return 1
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    exempted = ", ".join(
        f"{name}:{'/'.join(sorted(keys))}" for name, keys in sorted(EXEMPT_KEYS.items())
    )
    # What was examined AND what was exempted, on the pass line. A gate that prints only
    # OK cannot be distinguished from one whose scope quietly went empty.
    print(
        f"registry approval gate: OK ({examined} file(s) examined, no stored approvals; "
        f"exempt: {exempted})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
