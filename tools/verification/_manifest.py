# SPDX-License-Identifier: Apache-2.0
"""Shared loading and validation for the ADR-MCPRE-059 verification manifests.

Strict by construction: an unknown key is a validation FAILURE, not a field that is
silently ignored (ADR-MCPRE-059, "Authoritative manifest"). A typo in a security
declaration must not read as an absent declaration.

Stdlib only. This is analysis tooling, not production code, and it must run before any
verification toolchain exists.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "verification" / "policy"

VERIFICATION_TOML = POLICY_DIR / "verification.toml"
ASSUMPTIONS_TOML = POLICY_DIR / "assumptions.toml"
TRUST_BOUNDARIES_TOML = POLICY_DIR / "trust-boundaries.toml"
TOOLCHAINS_LOCK_TOML = POLICY_DIR / "toolchains.lock.toml"

SCHEMA_VERSION = 1

#: Verification classes, ADR-MCPRE-059 §9.
CLASSES = {"V0", "V1", "V2", "V3"}

#: The classes as an ordered scale, so "past the class this boundary permits" is a
#: comparison rather than a reading of the manifest by a human.
CLASS_ORDER = {"V0": 0, "V1": 1, "V2": 2, "V3": 3}

#: The URI forms an assumption's `scope` may take. A scope entry that matches neither is a
#: typo that scopes the assumption to nothing while looking like a registration, which is
#: the same failure as a mistyped key: it must not read as an absent declaration.
_SCOPE_PREFIXES = ("unit://", "boundary://")

#: Typed edge kinds, ADR-MCPRE-059 §4. Collapsing these into one "depends on" relation is
#: forbidden once invalidation is enforced, so the set is closed here.
EDGE_KINDS = {
    "COMPILE_DEPENDENCY",
    "CONTRACT_CONSUMES",
    "PROOF_DEPENDENCY",
    "TEST_EVIDENCE",
    "TRUSTS_ASSUMPTION",
    "GENERATED_FROM",
    "REVIEW_CONTEXT",
}

#: Freshness states, ADR-MCPRE-059 §5.
STATES = {
    "FRESH",
    "DIRTY_SELF",
    "DIRTY_CONTRACT",
    "DIRTY_DEPENDENCY",
    "DIRTY_ASSUMPTION",
    "DIRTY_POLICY",
    "DIRTY_TOOLCHAIN",
    "DIRTY_EVIDENCE",
    "UNKNOWN",
    "BLOCKED",
}

_VERIFICATION_TOP = {
    "schema_version",
    "policy_revision",
    "unknown_is_dirty",
    "formal_model_revision",
    "threat_model_revision",
    "unit",
    "edge",
}
_UNIT_KEYS = {
    "id",
    "class",
    "description",
    "paths",
    "exported_contracts",
    "consumed_contracts",
    "evidence",
    "assumptions",
    "features",
    "pilot",
    "proved_symbols",
    "tested_symbols",
    "test_package",
}
_EDGE_KEYS = {"kind", "from", "to", "contract", "sealed", "sealed_by", "rationale"}

def _unit_packages(unit: dict) -> list[str]:
    """The Cargo packages the unit's declared paths live in, sorted.

    Shared by the schema check and by `verify-tests`, because "which packages does this
    unit name" must not have two answers.
    """
    heads = {
        path.split("/", 1)[0]
        for path in unit["paths"]
        if "/" in path and (REPO_ROOT / path.split("/", 1)[0] / "Cargo.toml").is_file()
    }
    return sorted(heads)


def claims_test_evidence(unit: dict) -> bool:
    """Whether any `test://` URI claims this unit's battery.

    Defined once here rather than in the lane, because the FINGERPRINT and the lane must
    agree about which units have test evidence: a unit the fingerprint treats as untested
    and the lane runs would have its battery measured by nobody.
    """
    return any(str(entry).startswith("test://") for entry in unit.get("evidence", []))


def test_package_for(unit: dict) -> str | None:
    """The single Cargo package this unit's battery runs in, or None if there is none.

    One answer, shared by the lane (which runs the battery) and the fingerprint (which
    records which package was measured). Two implementations of "where do these tests live"
    would let the recorded package and the executed package disagree.

    Fail-closed on a path outside every Cargo package: such a unit has no package the lane
    could run, and answering with one of the others would name a package that does not
    cover its source.
    """
    for path in unit["paths"]:
        head = path.split("/", 1)[0]
        if "/" not in path or not (REPO_ROOT / head / "Cargo.toml").is_file():
            return None
    packages = _unit_packages(unit)
    if len(packages) == 1:
        return packages[0]
    declared = unit.get("test_package")
    return declared if declared in packages else None


def _module_candidates(package: str, symbol_path: str) -> list[str]:
    """The source files a `lib#`/`doc#` selector's module path could name, longest first.

    `lib#rejection::tests::x` can only execute code in `<pkg>/src/rejection.rs`;
    `doc#verified_response::bound::X` in `<pkg>/src/verified_response/bound.rs`. Every
    prefix is offered because the selector names an item, not a file, and the file boundary
    can be anywhere above it.
    """
    segments = [s for s in symbol_path.split("::") if s]
    out: list[str] = []
    for depth in range(len(segments), 0, -1):
        stem = "/".join(segments[:depth])
        out.append(f"{package}/src/{stem}.rs")
        out.append(f"{package}/src/{stem}/mod.rs")
    return out


def _validate_in_crate_selectors(uwhere: str, unit: dict) -> None:
    """A `lib#`/`doc#` selector must execute code the unit's own `paths` measure.

    Integration-test sources enter the fingerprint as their own component; in-crate tests
    do not, because they live inside the source files the unit already declares. That is
    only true if it IS true, so it is checked rather than assumed: a `lib#` selector whose
    module is not in `paths` would be a battery member whose body could be rewritten with
    no fingerprint moving — the same false-freshness shape as an unmeasured implementation.
    """
    package = test_package_for(unit)
    if package is None:
        return
    declared = set(unit["paths"])
    for symbol in unit.get("tested_symbols", []):
        target, _, path = str(symbol).partition("#")
        if target not in ("lib", "doc"):
            continue
        candidates = _module_candidates(package, path)
        if not any(c in declared for c in candidates):
            raise ManifestError(
                f"{uwhere}: tested_symbol {symbol!r} executes code in {package}/src, but no "
                f"prefix of its module path is among this unit's `paths`. An in-crate test "
                f"whose source the unit does not measure can be rewritten under the same "
                f"name without moving the fingerprint. Declare the module's file."
            )


def _validate_test_package(uwhere: str, unit: dict) -> None:
    """`test_package` is required exactly when the source closure spans several packages.

    The test lane derives the package to run from the declared paths so that a unit whose
    source moves cannot keep testing the package it left. A unit whose SOURCE CLOSURE
    legitimately spans packages — the verifier's results reach `mcp-re-core`'s Ed25519
    primitive — has no single answer, and the lane refused to run at all.

    Naming the package is the fix, and it is constrained rather than free: it must be one
    of the packages the unit already declares, so it can select a package inside the
    measured closure and nothing else. Where the paths name ONE package the field is
    REFUSED, not merely unnecessary — an optional restatement of a derived fact is a second
    place for it to be wrong.
    """
    packages = _unit_packages(unit)
    declared = unit.get("test_package")
    if declared is None:
        if len(packages) > 1 and unit.get("tested_symbols"):
            raise ManifestError(
                f"{uwhere}: paths span {len(packages)} Cargo packages "
                f"({', '.join(packages)}) and the unit declares a test battery, so the "
                f"lane cannot derive which package to run it in. Name it in "
                f"`test_package`."
            )
        return
    if len(packages) <= 1:
        raise ManifestError(
            f"{uwhere}: `test_package` is set but the paths name a single package; the "
            f"lane derives it, and a restatement is a second place for it to be wrong."
        )
    if declared not in packages:
        raise ManifestError(
            f"{uwhere}: test_package {declared!r} is not one of the packages this unit's "
            f"paths name ({', '.join(packages)}). The battery must run inside the "
            f"measured source closure."
        )


_ASSUMPTION_KEYS = {
    "id",
    "description",
    "justification",
    "scope",
    "owner",
    "introduced_by",
    "review_requirement",
    "affected_contracts",
    "tool_specific_mechanism",
}
_ASSUMPTION_REQUIRED = set(_ASSUMPTION_KEYS)

_BOUNDARY_KEYS = {
    "id",
    "description",
    "kind",
    "paths",
    "beyond",
    "max_class_without_assumption",
}


#: What a single lane may declare on its `VERDICT:` line.
#:
#: Five states, because three conflated two pairs of genuinely different situations and
#: the difference is exactly where a false PASS gets in:
#:
#:   NOT_REQUIRED  the manifest asks nothing of this lane — no unit of its class exists.
#:                 Legitimate, and does NOT hold the aggregate back.
#:   PASS          executed and satisfied.
#:   FAIL          executed and not satisfied.
#:   UNAVAILABLE   required, but could not execute — tools unpinned, lane absent on this
#:                 host, container unreachable.
#:   SKIPPED       required, could have executed, deliberately not executed.
#:
#: UNAVAILABLE and SKIPPED are both "required and missing", so both force INCOMPLETE. They
#: are kept apart because the remedy differs: one is an environment to fix, the other a
#: decision to justify. Neither may ever read as success — that is the whole point of the
#: split.
LANE_VERDICTS = {"NOT_REQUIRED", "PASS", "FAIL", "UNAVAILABLE", "SKIPPED"}

#: The aggregate a run reports, derived from the lane verdicts.
AGGREGATE_VERDICTS = {"PASS", "FAIL", "INCOMPLETE"}


def aggregate_verdict(formal_verdicts, hygiene_verdicts=()) -> str:
    """Merge lane verdicts into the repository's formal verdict.

        every required formal lane PASSed            -> PASS
        any required lane FAILed                     -> FAIL
        any required formal lane absent/unavailable  -> INCOMPLETE
        no formal lane required at all               -> INCOMPLETE

    Two kinds of lane, and conflating them produces the exact false success this whole
    design exists to prevent:

      * **formal** lanes (Verus, Lean, generated-model) produce evidence. Only these can
        constitute a PASS.
      * **hygiene** lanes (manifest validation, the assumption/TCB gate) can *withhold* a
        pass by failing, but passing them proves nothing about the code. They are
        preconditions for trusting evidence, not evidence.

    So a repository with green hygiene gates and no proofs is `INCOMPLETE`. Letting the
    assumption gate's PASS carry the aggregate would mean an empty manifest reads as a
    verified repository — "exits 0 having measured nothing", one level up again.

    `NOT_REQUIRED` is excluded from the requirement set rather than counted as a pass:
    "the manifest asked nothing of Lean" and "Lean proved something" are different claims,
    and only the second is evidence. A run in which every formal lane is `NOT_REQUIRED`
    has produced no evidence and is therefore `INCOMPLETE`.

    An unrecognized verdict is INCOMPLETE — unknown is dirty (ADR-MCPRE-059 §2).
    """
    formal = list(formal_verdicts)
    hygiene = list(hygiene_verdicts)
    if any(v not in LANE_VERDICTS for v in formal + hygiene):
        return "INCOMPLETE"
    # A failing precondition outranks everything: evidence gathered beside a broken
    # assumption gate is not evidence we may rely on.
    if any(v == "FAIL" for v in hygiene) or any(v == "FAIL" for v in formal):
        return "FAIL"
    required = [v for v in formal if v != "NOT_REQUIRED"]
    if not required:
        return "INCOMPLETE"
    if any(v in {"UNAVAILABLE", "SKIPPED"} for v in required):
        return "INCOMPLETE"
    if any(v in {"UNAVAILABLE", "SKIPPED"} for v in hygiene):
        return "INCOMPLETE"
    return "PASS"


class ManifestError(Exception):
    """A manifest is malformed. Always fatal — unknown provenance is never freshness."""


def _load(path: Path) -> dict:
    if not path.exists():
        raise ManifestError(f"{path.relative_to(REPO_ROOT)}: missing")
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{path.relative_to(REPO_ROOT)}: unparsable: {exc}") from exc


def _reject_unknown(where: str, got, allowed: set[str]) -> None:
    unknown = sorted(set(got) - allowed)
    if unknown:
        raise ManifestError(
            f"{where}: unknown key(s) {unknown}. "
            f"Unknown keys fail validation rather than being ignored — a mistyped "
            f"security declaration must not read as an absent one."
        )


def _require(where: str, got: dict, required: set[str]) -> None:
    missing = sorted(required - set(got))
    if missing:
        raise ManifestError(f"{where}: missing required key(s) {missing}")


def load_verification() -> dict:
    """Load and validate `verification/policy/verification.toml`."""
    doc = _load(VERIFICATION_TOML)
    where = "verification.toml"
    _reject_unknown(where, doc, _VERIFICATION_TOP)
    _require(
        where,
        doc,
        {"schema_version", "policy_revision", "unknown_is_dirty"},
    )
    if doc["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(
            f"{where}: schema_version {doc['schema_version']} but this tooling "
            f"implements {SCHEMA_VERSION}. A schema change alters what a fingerprint "
            f"means, so it invalidates every attestation and must be handled, not "
            f"tolerated."
        )
    if doc["unknown_is_dirty"] is not True:
        raise ManifestError(
            f"{where}: unknown_is_dirty must be true. Turning it off is a policy change "
            f"that removes the fail-closed property the whole graph rests on; it cannot "
            f"be done by editing this field alone."
        )

    seen_ids: set[str] = set()
    contracts: set[str] = set()
    for index, unit in enumerate(doc.get("unit", [])):
        uwhere = f"{where} [[unit]] #{index}"
        _reject_unknown(uwhere, unit, _UNIT_KEYS)
        _require(uwhere, unit, {"id", "class", "paths"})
        if unit["class"] not in CLASSES:
            raise ManifestError(
                f"{uwhere}: class {unit['class']!r} not one of {sorted(CLASSES)}"
            )
        if unit["id"] in seen_ids:
            raise ManifestError(f"{uwhere}: duplicate unit id {unit['id']!r}")
        seen_ids.add(unit["id"])
        for declared in unit["paths"]:
            if not list(REPO_ROOT.glob(declared)):
                raise ManifestError(
                    f"{uwhere}: path {declared!r} matches nothing. A unit whose source "
                    f"cannot be located has unknown provenance, which is dirty, not empty."
                )
        # A V1/V3 unit must name the symbols its proof is about. Without that the lane can
        # only ask "did this crate verify something", and deleting one of two
        # specifications leaves the other to answer yes — coverage silently halves while
        # the gate stays green. Naming them turns a deleted theorem into a lane failure.
        if unit["class"] in {"V1", "V3"} and not unit.get("proved_symbols"):
            raise ManifestError(
                f"{uwhere}: class {unit['class']} requires `proved_symbols`. A unit that "
                f"claims formal evidence must name the symbols proved, or nothing "
                f"distinguishes a deleted specification from a passing one."
            )
        # The same argument one class down. A `test://` URI names a battery, and a battery
        # with no declared members is a description: the lane would have nothing to select,
        # and "the tests passed" would mean "no test was asked for".
        if any(str(entry).startswith("test://") for entry in unit.get("evidence", [])):
            if not unit.get("tested_symbols"):
                raise ManifestError(
                    f"{uwhere}: declares test:// evidence but no `tested_symbols`. A "
                    f"battery with no named members cannot be run, and an unrunnable "
                    f"claim is not evidence."
                )
            for symbol in unit["tested_symbols"]:
                target, _, path = str(symbol).partition("#")
                # The target is required, not defaulted: a defaulted target lets a test
                # that moved between the lib and an integration target keep reporting under
                # the one it left.
                # `doc` names the crate's doctest target. A doctest's reported name
                # embeds the line it starts on, so the symbol names the ITEM and the lane
                # matches that item's doctests — an edit above a control must not break the
                # declaration, a rename or deletion must.
                if not path or not (
                    target in ("lib", "doc")
                    or (target.startswith("tests/") and target[6:])
                ):
                    raise ManifestError(
                        f"{uwhere}: tested_symbol {symbol!r} names no runnable target; "
                        f"expected `lib#path::to::test`, `doc#module::Item`, or "
                        f"`tests/<name>#path::to::test`"
                    )
        elif unit.get("tested_symbols"):
            # Declared members with no `test://` URI claiming them would run a battery
            # whose result no evidence entry reads — measurement nothing consumes.
            raise ManifestError(
                f"{uwhere}: declares `tested_symbols` but no test:// evidence entry "
                f"claims them, so nothing consumes what the lane would measure."
            )
        _validate_test_package(uwhere, unit)
        _validate_in_crate_selectors(uwhere, unit)
        contracts.update(unit.get("exported_contracts", []))

    for index, edge in enumerate(doc.get("edge", [])):
        ewhere = f"{where} [[edge]] #{index}"
        _reject_unknown(ewhere, edge, _EDGE_KEYS)
        _require(ewhere, edge, {"kind", "from", "to"})
        if edge["kind"] not in EDGE_KINDS:
            raise ManifestError(
                f"{ewhere}: kind {edge['kind']!r} not one of {sorted(EDGE_KINDS)}"
            )
        for endpoint in ("from", "to"):
            if edge[endpoint] not in seen_ids:
                raise ManifestError(
                    f"{ewhere}: {endpoint} {edge[endpoint]!r} is not a declared unit"
                )
        if edge.get("sealed"):
            if edge["kind"] != "CONTRACT_CONSUMES":
                raise ManifestError(
                    f"{ewhere}: only a CONTRACT_CONSUMES edge may be sealed. Sealing "
                    f"means source-only dirtiness stops at a proved unchanged contract, "
                    f"which is meaningless without a contract."
                )
            _require(ewhere, edge, {"contract", "sealed_by", "rationale"})
            if edge["contract"] not in contracts:
                raise ManifestError(
                    f"{ewhere}: sealed on contract {edge['contract']!r}, which no unit "
                    f"exports"
                )
    return doc


def load_assumptions() -> dict:
    """Load and validate the trusted-assumption registry."""
    doc = _load(ASSUMPTIONS_TOML)
    where = "assumptions.toml"
    _reject_unknown(where, doc, {"schema_version", "assumption"})
    _require(where, doc, {"schema_version"})
    seen: set[str] = set()
    for index, entry in enumerate(doc.get("assumption", [])):
        awhere = f"{where} [[assumption]] #{index}"
        _reject_unknown(awhere, entry, _ASSUMPTION_KEYS)
        _require(awhere, entry, _ASSUMPTION_REQUIRED)
        if entry["id"] in seen:
            raise ManifestError(
                f"{awhere}: duplicate assumption id {entry['id']!r}. Ids are never reused "
                f"— a reused id makes two different trusted claims indistinguishable in "
                f"the review history."
            )
        seen.add(entry["id"])
        for target in entry.get("scope", []):
            if not str(target).startswith(_SCOPE_PREFIXES):
                raise ManifestError(
                    f"{awhere}: scope entry {target!r} is neither `unit://<id>` nor "
                    f"`boundary://<id>`. A scope the tooling cannot resolve trusts the "
                    f"assumption nowhere while reading as a registration."
                )
    return doc


def load_trust_boundaries() -> dict:
    """Load and validate the declared trust boundaries."""
    doc = _load(TRUST_BOUNDARIES_TOML)
    where = "trust-boundaries.toml"
    _reject_unknown(where, doc, {"schema_version", "boundary"})
    _require(where, doc, {"schema_version"})
    for index, entry in enumerate(doc.get("boundary", [])):
        bwhere = f"{where} [[boundary]] #{index}"
        _reject_unknown(bwhere, entry, _BOUNDARY_KEYS)
        _require(bwhere, entry, {"id", "description", "kind", "paths", "beyond"})
        cls = entry.get("max_class_without_assumption")
        if cls is not None and cls not in CLASSES:
            raise ManifestError(f"{bwhere}: max_class_without_assumption {cls!r} invalid")
    return doc


def expand_paths(patterns) -> set[str]:
    """The repo-relative files a `paths` list names, with its globs expanded."""
    out: set[str] = set()
    for pattern in patterns:
        for path in REPO_ROOT.glob(pattern):
            if path.is_file():
                out.add(path.relative_to(REPO_ROOT).as_posix())
    return out


def boundary_class_violations(
    verification: dict, boundaries: dict, assumptions: dict
) -> list[str]:
    """Units promoted past the class a boundary they cross permits.

    `max_class_without_assumption` is the rule that keeps a proof's meaning honest across a
    trust boundary: a theorem about code on this side says nothing about the other side, so
    claiming V1/V2/V3 over an FFI, crypto, KMS or clock boundary is an over-read unless a
    registered assumption states what is being trusted there.

    A crossing is COVERED when some assumption's `scope` names both the unit and the
    boundary. Naming only the unit is not enough — that is the assumption's ordinary scope,
    and it says nothing about which boundary it discharges.
    """
    covered: set[tuple[str, str]] = set()
    for entry in assumptions.get("assumption", []):
        scope = [str(target) for target in entry.get("scope", [])]
        units = [t.removeprefix("unit://") for t in scope if t.startswith("unit://")]
        crossed = [
            t.removeprefix("boundary://") for t in scope if t.startswith("boundary://")
        ]
        for unit_id in units:
            for boundary_id in crossed:
                covered.add((unit_id, boundary_id))

    violations: list[str] = []
    for boundary in boundaries.get("boundary", []):
        cap = boundary.get("max_class_without_assumption")
        if cap is None:
            continue
        boundary_files = expand_paths(boundary["paths"])
        for unit in verification.get("unit", []):
            if CLASS_ORDER[unit["class"]] <= CLASS_ORDER[cap]:
                continue
            crossing = sorted(expand_paths(unit["paths"]) & boundary_files)
            if not crossing:
                continue
            if (unit["id"], boundary["id"]) in covered:
                continue
            violations.append(
                f"unit {unit['id']} is class {unit['class']} but its paths cross "
                f"{boundary['id']} ({', '.join(crossing)}), which permits at most "
                f"{cap} without a registered assumption covering the crossing. Register "
                f"one in assumptions.toml with `boundary://{boundary['id']}` in its "
                f"scope, or lower the unit's class."
            )
    return violations


def load_toolchains() -> dict:
    """Load and validate the toolchain lock."""
    doc = _load(TOOLCHAINS_LOCK_TOML)
    where = "toolchains.lock.toml"
    _require(where, doc, {"schema_version"})
    for name, entry in doc.items():
        if name == "schema_version":
            continue
        if not isinstance(entry, dict):
            raise ManifestError(f"{where}: [{name}] must be a table")
        state = entry.get("state")
        if state not in {"resolved", "unresolved"}:
            raise ManifestError(
                f"{where}: [{name}] state must be 'resolved' or 'unresolved', got "
                f"{state!r}. A tool with no state is a tool of unknown identity."
            )
        for sub_name, sub in entry.items():
            if isinstance(sub, dict) and sub.get("state") not in {
                "resolved",
                "unresolved",
            }:
                raise ManifestError(
                    f"{where}: [{name}.{sub_name}] state must be 'resolved' or "
                    f"'unresolved'"
                )
    return doc


def unresolved_pins(toolchains: dict) -> list[str]:
    """Every toolchain identity that is not pinned, as dotted names.

    An unresolved pin means the tool's identity is unknown, and unknown is dirty. The
    lanes that depend on it refuse to run rather than running against whatever is on
    PATH — a proof checked by an unknown prover is not evidence.
    """
    out: list[str] = []
    for name, entry in toolchains.items():
        if name == "schema_version" or not isinstance(entry, dict):
            continue
        if entry.get("state") == "unresolved":
            out.append(name)
        for sub_name, sub in entry.items():
            if isinstance(sub, dict) and sub.get("state") == "unresolved":
                out.append(f"{name}.{sub_name}")
    return sorted(out)


def fail(message: str) -> None:
    """Print a fatal manifest/lane error and exit non-zero."""
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)
