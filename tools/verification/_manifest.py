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
from collections.abc import Iterable
from pathlib import Path

from _extraction_artifact import record_problems as artifact_record_problems
from _extraction_identity import identity_problems
from _seams import files_with_seams
from _ecosystems import CARGO
from _ecosystems import test_project_for
from _ecosystems import valid_target
from _ecosystems import unit_ecosystem
from _ecosystems import unit_projects

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
    "features",
    "pilot",
    "proved_symbols",
    "tested_symbols",
    "test_package",
    "test_features",
    "extracted_symbols",
    "lean_theorems",
}
_EDGE_KEYS = {"kind", "from", "to", "contract", "sealed", "sealed_by", "rationale"}

def _unit_packages(unit: dict) -> list[str]:
    """The projects the unit's declared paths live in, sorted.

    Shared by the schema check and by `verify-tests`, because "which projects does this unit
    name" must not have two answers. Which BUILD SYSTEM answers it is `_ecosystems`' —
    Cargo is one adapter beneath this concept rather than the shape of it (issue #745).
    """
    return unit_projects(unit)


def claims_mutation_evidence(unit: dict) -> bool:
    """Whether a `mutation://` URI claims this unit's probe battery.

    Declaring it is what puts the probes inside the ATTESTATION closure: `required_lanes`
    reads every scheme, so the unit refuses attestation without a mutation record at its
    exact fingerprint.
    """
    return any(str(entry).startswith("mutation://") for entry in unit.get("evidence", []))


def claims_test_evidence(unit: dict) -> bool:
    """Whether any `test://` URI claims this unit's battery.

    Defined once here rather than in the lane, because the FINGERPRINT and the lane must
    agree about which units have test evidence: a unit the fingerprint treats as untested
    and the lane runs would have its battery measured by nobody.
    """
    return any(str(entry).startswith("test://") for entry in unit.get("evidence", []))


def test_package_for(unit: dict) -> str | None:
    """The single project this unit's battery runs in, or None if there is none.

    Delegates to `_ecosystems.test_project_for`, which is where the fail-closed cases live:
    a closure spanning two ecosystems, a source path outside every project of its own
    ecosystem, and several projects with no `test_package` naming one of them.

    The name is kept because the schema field is `test_package` and the two must read as
    one concept; what changed is that a package is no longer necessarily a Cargo one.
    """
    return test_project_for(unit)


def _module_candidates(package: str, symbol_path: str) -> list[str]:
    """The source files an IN-CRATE selector's module path could name, longest first.

    `lib#rejection::tests::x` can only execute code in `<pkg>/src/rejection.rs`;
    `doc#verified_response::bound::X` in `<pkg>/src/verified_response/bound.rs`;
    `bin/mcp-re-client#startup::tests::x` in `<pkg>/src/startup.rs`. Every prefix is
    offered because the selector names an item, not a file, and the file boundary can be
    anywhere above it.
    """
    segments = [s for s in symbol_path.split("::") if s]
    out: list[str] = []
    for depth in range(len(segments), 0, -1):
        stem = "/".join(segments[:depth])
        out.append(f"{package}/src/{stem}.rs")
        out.append(f"{package}/src/{stem}/mod.rs")
    return out


def _validate_test_features(uwhere: str, unit: dict) -> None:
    """`test_features` names the build configuration the unit's battery is measured under.

    Three refusals, and each is a way the field could state something it does not mean.

    A unit with no `test://` evidence has no battery, so a feature set for one measures
    nothing. A non-Cargo ecosystem has no such concept and the adapter would DROP the
    value — a declaration nothing applies is worse than none, because the fingerprint would
    carry it while the runner ignored it. And the specification feature is excluded by
    construction: `features` carries the prover's text, is off in every production build,
    and running the battery under it would measure a crate that does not ship. That
    exclusion was a sentence in the lane's docstring; it is a check here.
    """
    declared = unit.get("test_features")
    if declared is None:
        return
    if not isinstance(declared, list) or not all(isinstance(f, str) and f for f in declared):
        raise ManifestError(f"{uwhere}: test_features must be a list of feature names")
    if not claims_test_evidence(unit):
        raise ManifestError(
            f"{uwhere}: declares `test_features` but no test:// evidence, so the feature "
            f"set configures a battery that does not exist."
        )
    if unit_ecosystem(unit) is not CARGO:
        raise ManifestError(
            f"{uwhere}: `test_features` is a Cargo concept and this unit's battery does "
            f"not run under Cargo; a feature set the runner cannot apply would enter the "
            f"fingerprint while measuring nothing."
        )
    overlap = sorted(set(declared) & set(unit.get("features", [])))
    if overlap:
        raise ManifestError(
            f"{uwhere}: {overlap} appear in both `features` and `test_features`. The "
            f"specification feature carries the prover's text and is off in every "
            f"production build; a battery run under it measures a different crate than "
            f"the one that ships."
        )


def _validate_in_crate_selectors(uwhere: str, unit: dict) -> None:
    """A `lib#`/`doc#`/`bin/<name>#` selector must execute code the unit's own `paths` measure.

    Integration-test sources enter the fingerprint as their own component; in-crate tests
    do not, because they live inside the source files the unit already declares. That is
    only true if it IS true, so it is checked rather than assumed: a `lib#` selector whose
    module is not in `paths` would be a battery member whose body could be rewritten with
    no fingerprint moving — the same false-freshness shape as an unmeasured implementation.

    A binary crate's modules live under the same `<pkg>/src` tree, so `bin/<name>#` carries
    the identical obligation and is checked by the identical rule. Exempting it would let a
    deployable's own controls sit outside every fingerprint component.
    """
    package = test_package_for(unit)
    if package is None or unit_ecosystem(unit) is not CARGO:
        return
    declared = set(unit["paths"])
    for symbol in unit.get("tested_symbols", []):
        target, _, path = str(symbol).partition("#")
        if target not in ("lib", "doc") and not target.startswith("bin/"):
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
    "sites",
}
#: `sites` is the one OPTIONAL key, and its absence is not a default — it is the
#: fail-closed direction. An assumption with no `sites` registers no seam, so a premise
#: whose sites nobody has decided reads as trusting nothing rather than as trusting
#: whatever the mechanism kind happens to appear in next. It is therefore excluded from
#: the required set: making it required would force an entry to name a seam before the
#: decision about which seams it covers has been taken, which is how the kind-level rule
#: it replaces came to license every future site.
_ASSUMPTION_REQUIRED = set(_ASSUMPTION_KEYS) - {"sites"}

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
        # The extracted-model lane's two halves of the same argument, and they are separate
        # keys because they name different things in different languages: which RUST items
        # Charon starts from, and which LEAN theorems the prover is asked about. Deriving
        # either from the other would be a guess about a name mangling that Aeneas owns.
        #
        # Kept apart from `proved_symbols` deliberately. That key is the Verus lane's, and a
        # V3 unit claims BOTH lanes — one key read by two provers with two naming schemes is
        # a key that means whichever the reader assumed.
        if unit["class"] in {"V2", "V3"}:
            for key, what in (
                ("extracted_symbols", "the Rust items the model is extracted from"),
                ("lean_theorems", "the Lean theorems the prover is asked about"),
            ):
                if not unit.get(key):
                    raise ManifestError(
                        f"{uwhere}: class {unit['class']} requires `{key}` — {what}. A "
                        f"unit claiming extracted-model evidence with an empty selection "
                        f"asks the lane to measure nothing, and nothing measured passes."
                    )
            # AND IT MUST SAY SO IN ITS EVIDENCE. Two authorities read "what does this unit
            # require": `_evidence.required_lanes` derives it from the declared URIs, and the
            # aggregate's requirement set derives it from the class. They agree only while
            # every V2/V3 unit declares `lean://` — and nothing made it. A unit with the
            # selection keys above and no `lean://` entry would be ISSUED an attestation on
            # its test battery alone while claiming extracted-model evidence, because the
            # issuer would see no lean lane to check.
            if not any(
                str(entry).startswith("lean://") for entry in unit.get("evidence", [])
            ):
                raise ManifestError(
                    f"{uwhere}: class {unit['class']} declares an extraction selection but "
                    f"no `lean://` evidence entry. The class says the Lean lane must "
                    f"measure this unit and the evidence list is where a unit says which "
                    f"lanes are asked about it, so the two must agree — otherwise the "
                    f"issuer checks a lane the class requires and the manifest never named."
                )
        elif unit.get("extracted_symbols") or unit.get("lean_theorems"):
            raise ManifestError(
                f"{uwhere}: declares extraction selection but is class {unit['class']}, so "
                f"no lane reads it. A selection nothing consumes is a declaration that "
                f"reads as coverage and measures nothing."
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
            eco = unit_ecosystem(unit)
            for symbol in unit["tested_symbols"]:
                target, _, path = str(symbol).partition("#")
                # The target is required, not defaulted: a defaulted target lets a test
                # that moved between the lib and an integration target keep reporting under
                # the one it left.
                # WHICH targets exist is the ecosystem's answer (issue #745): Cargo has
                # `lib`, `doc` and an open-ended `tests/<name>` family, while a pytest or
                # vitest battery has the one target that says which runner reads the
                # selector. A unit whose paths name no single ecosystem has no runnable
                # target at all, which is the same refusal for a different reason.
                if not path or eco is None or not valid_target(eco, target):
                    raise ManifestError(
                        f"{uwhere}: tested_symbol {symbol!r} names no runnable "
                        f"{eco.name if eco else '<unresolved ecosystem>'} target; "
                        f"cargo takes `lib#path::to::test`, `doc#module::Item` or "
                        f"`tests/<name>#path::to::test`; python takes "
                        f"`pytest#tests/file.py::name`; typescript takes "
                        f"`vitest#test/file.test.ts > suite > name`"
                    )
        elif unit.get("tested_symbols"):
            # Declared members with no `test://` URI claiming them would run a battery
            # whose result no evidence entry reads — measurement nothing consumes.
            raise ManifestError(
                f"{uwhere}: declares `tested_symbols` but no test:// evidence entry "
                f"claims them, so nothing consumes what the lane would measure."
            )
        _validate_test_features(uwhere, unit)
        _validate_test_package(uwhere, unit)
        _validate_in_crate_selectors(uwhere, unit)
        # `mutation://` is a claim about a NEGATIVE battery, which only exists on top of a
        # positive one: the probes' `expect_red` names members of `tested_symbols`. A unit
        # claiming mutation evidence without test evidence would declare controls that are
        # not evidence for anything.
        if claims_mutation_evidence(unit) and not claims_test_evidence(unit):
            raise ManifestError(
                f"{uwhere}: declares mutation:// evidence without test:// evidence. A "
                f"mutation probe asserts that a DECLARED control goes red; with no "
                f"declared battery there is nothing for it to name."
            )
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
        _validate_sites(awhere, entry)
        _require_boundary_edge(awhere, entry)
    return doc


def _validate_sites(where: str, entry: dict) -> None:
    """`sites` names SEAMS, as `<repo-relative path>#<item>`.

    The path half is checked to exist, because a registration against a file that is not
    there registers nothing while reading as a registration — and the escape-hatch gate,
    which refuses a site key that resolves to no seam, cannot distinguish "the file moved"
    from "the entry was always wrong" once it is only reporting a missing key.

    A duplicate inside one entry is refused too: two identical rows say one thing, and the
    count of registered seams is read.
    """
    declared = entry.get("sites")
    if declared is None:
        return
    if not isinstance(declared, list) or not declared:
        raise ManifestError(
            f"{where}: `sites` must be a non-empty list. Omit the key entirely to register "
            f"nothing — an EMPTY list and an absent one would be the same fact written two "
            f"ways."
        )
    seen: set[str] = set()
    for site in declared:
        site = str(site)
        path, separator, item = site.partition("#")
        if not separator or not path or not item:
            raise ManifestError(
                f"{where}: site {site!r} is not `<path>#<item>`. A seam is identified by "
                f"the item it sits on, never by a line number: a line number moves when a "
                f"comment is added above it, and a registry that goes stale on formatting "
                f"is one people regenerate without reading."
            )
        if site in seen:
            raise ManifestError(f"{where}: site {site!r} is registered twice in one entry.")
        seen.add(site)
        if not (REPO_ROOT / path).is_file():
            raise ManifestError(
                f"{where}: site {site!r} names {path}, which does not exist. A registration "
                f"against a missing file registers nothing while reading as a registration."
            )


def _require_boundary_edge(where: str, entry: dict) -> None:
    """Every live assumption names the boundary it crosses — the v0.17 TCB slice.

    `scope` is the ONE canonical direction of this relation, and it always accepted a
    `boundary://` target. What it did not do was require one, and the consequence was
    measured rather than supposed: of forty-one registered premises, exactly ONE named a
    boundary. `boundary_class_violations` therefore consulted a relation that was almost
    entirely unpopulated, so the cap could not fire for any boundary nobody had happened to
    write down — an enforcement that was live, correct, and reaching almost nothing.

    An unpopulated relation is worse than an absent one. Absent, a reader asks where the
    trust inventory is; unpopulated, the tooling answers the question with silence that
    reads like a clean result.

    A TOMBSTONE is the one exemption, and it is exempt by having an EMPTY scope rather than
    by being named in a list here. A withdrawn assumption trusts nothing — that is what
    withdrawing it meant — so giving it a boundary edge would make a retired premise read as
    a live one, which is the same defect pointed the other way.
    """
    scope = [str(target) for target in entry.get("scope", [])]
    if not scope:
        return
    if any(target.startswith("boundary://") for target in scope):
        return
    raise ManifestError(
        f"{where}: assumption {entry['id']} names no `boundary://<id>` in its scope. Every "
        f"live premise crosses something — foreign code, a service, the language runtime, "
        f"or this repository's own behaviour where the lane stops at it — and the boundary "
        f"is what tells a reader how far the claim above it reaches. Name the boundary it "
        f"crosses, or empty the scope if the premise is withdrawn."
    )


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
        for pattern in entry.get("paths", []):
            # A boundary path that matches nothing SILENTLY NARROWS the boundary. Unlike a
            # unit path, `expand_paths` globs these, so a stale entry raises nothing and the
            # code it used to name simply stops being inside the boundary — and
            # `boundary_class_violations` stops seeing units that cross it. That is an
            # over-read produced by a rename, which is exactly what happened when MCPRE-175
            # turned `pkcs11_keysource.rs` and `async_replay.rs` into owner subtrees.
            if not any(REPO_ROOT.glob(str(pattern))):
                raise ManifestError(
                    f"{bwhere}: path {pattern!r} matches nothing. A boundary that names no "
                    f"file bounds no unit's class, so a stale entry reads as a registered "
                    f"boundary while trusting the code it used to cover nowhere."
                )
    return doc


def expand_paths(patterns) -> set[str]:
    """The repo-relative files a `paths` list names, with its globs expanded."""
    out: set[str] = set()
    for pattern in patterns:
        for path in REPO_ROOT.glob(pattern):
            if path.is_file():
                out.add(path.relative_to(REPO_ROOT).as_posix())
    return out


#: The classes whose evidence comes from a whole-crate run rather than from a battery over
#: declared symbols. Defined here rather than in the fingerprint because the fingerprint and
#: the boundary rule must agree about what a unit's evidence covers.
#:
#: V2 is here for the reason V1 is, one tool along. `cargo verus verify -p <crate>` checks
#: the whole crate; `charon cargo --start-from <item>` compiles the whole crate and follows
#: the named item into whatever it calls, so the extracted model's cone is decided inside
#: the tool and is not reported by it. Both are wider than the declared paths, and a
#: fingerprint narrower than the measured cone lets source a proof stands on change while
#: the graph still answers FRESH.
FORMAL_CLASSES = {"V1", "V2", "V3"}

#: The classes whose proof lane can CONSUME a seam `_seams` recognises. Those mechanisms are
#: Verus', written in Rust and read by the Verus lane; a Lean theorem over an extracted model
#: cannot consume one, because the spec items carrying them are behind the `verify` feature
#: and are never compiled into the extraction. See `boundary_class_violations`, which is the
#: one place this distinction decides anything.
RUST_SEAM_CONSUMERS = {"V1", "V3"}


def path_dependency_closure(project: str, seen: set[str]) -> set[str]:
    """Workspace projects reachable from `project` by path dependency, transitively.

    The `verify` feature travels down this closure — `mcp-re-http-profile/verify` turns on
    `mcp-re-core/verify` — so the prover compiles and checks these projects as part of the
    run whose result the unit claims.
    """
    manifest = REPO_ROOT / project / "Cargo.toml"
    if project in seen or not manifest.is_file():
        return seen
    seen.add(project)
    with manifest.open("rb") as handle:
        doc = tomllib.load(handle)
    for spec in doc.get("dependencies", {}).values():
        if not isinstance(spec, dict) or "path" not in spec:
            continue
        resolved = (manifest.parent / spec["path"]).resolve()
        try:
            path_dependency_closure(resolved.relative_to(REPO_ROOT).as_posix(), seen)
        except ValueError:
            continue
    return seen


def evidence_cone(unit: dict) -> set[str]:
    """INVALIDATION REACHABILITY: every source file whose change must stale this evidence.

    For a formal unit that is the whole crate plus the projects the `verify` feature reaches
    through, because `verify-verus` runs `cargo verus verify -p <crate>` and the prover
    checks all of it. For a V0 unit it is the declared paths, which is what its battery
    measures.

    This is the FIRST of the two graphs R9-C022 turned out to be about, and it is
    deliberately generous: a file in here changing invalidates the evidence even if it
    contributes no premise to any proof. Over-invalidation is safe. It is NOT a statement
    that the proof depends on anything in here semantically — see `semantic_boundary_crossings`.
    """
    declared = expand_paths(unit["paths"])
    if unit["class"] not in FORMAL_CLASSES:
        return declared
    projects: set[str] = set()
    for project in unit_projects(unit):
        path_dependency_closure(project, projects)
    cone = set(declared)
    for project in sorted(projects):
        cone |= expand_paths([f"{project}/src/**/*.rs"])
    return cone


def semantic_boundary_crossings(unit: dict, boundaries: dict) -> dict[str, list[str]]:
    """TRUSTED-PREMISE REACHABILITY: boundaries whose files this proof actually TRUSTS.

    The second graph, and the one the class cap belongs to. A boundary is crossed
    SEMANTICALLY when a file it declares carries a TRUSTED SEAM — an `uninterp`, an
    `external_body`, an `assume_specification` — that lies inside this unit's evidence cone.
    A seam is the only place a proof stops proving and starts trusting, so it is the only
    place an unproved proposition can enter one.

    R9-C022, and the owner ruling of 2026-09-03 that closed it. The rule compared a
    boundary's files against the unit's DECLARED paths, which was too narrow; widening it to
    the evidence cone made all six V1 units "cross" `boundary.crypto_primitives`, which is
    too wide in a way that is worse. Neither `mcp-re-core/src/crypto.rs` nor `hash.rs`
    contains a single seam: the six proofs are COMPILED alongside the primitives and consume
    no proposition from them. Requiring six crypto assumptions there would have invented
    premises to satisfy a source-level overlap — assumptions nobody could justify, in a
    registry whose value is that every entry names something real.

        proof consumes an unproved proposition beyond the boundary
            -> explicit registered assumption required

        proof merely shares the compilation/invalidation cone
            -> fingerprint is conservatively invalidated, and NO premise is invented

    Returns `{boundary id: [seam file, ...]}` so a refusal can name the seam it found rather
    than the overlap it computed.

    WHAT THIS DOES NOT CATCH, stated because a control's blind spot is part of what it
    establishes. A seam is attributed to a boundary by LOCATION: it must sit in a file the
    boundary declares. A premise that MODELS a boundary's semantics from somewhere else is
    invisible here — `verus_std_specs.rs` holds `uninterp spec fn labeled_digest`, which is
    the digest as an uninterpreted function, while `boundary.crypto_primitives` declares
    only `crypto.rs` and `hash.rs`. ASM-0037 bridges exactly that gap by naming
    `boundary://boundary.crypto_primitives` in its own scope, which is the declared half of
    the relation and is why `scope` accepts a boundary at all.

    So the mechanism is a FLOOR with a declared complement, not a decision procedure:
    `check-assumptions` already refuses any unregistered seam, so no seam goes unaccounted
    for; what is not forced is that a seam's assumption also names the boundary it crosses.
    Closing that would mean requiring a boundary's `paths` to cover the files where its
    premises are modelled, which is a change to what a boundary declaration MEANS and is not
    made here.
    """
    cone = evidence_cone(unit)
    crossings: dict[str, list[str]] = {}
    for boundary in boundaries.get("boundary", []):
        seams = sorted(files_with_seams(REPO_ROOT, expand_paths(boundary["paths"]) & cone))
        if seams:
            crossings[boundary["id"]] = seams
    return crossings


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

    THE CAP IS ASKED OF THE LANE THAT CAN CONSUME THE SEAM. `_seams` recognises VERUS
    mechanisms written in Rust — `uninterp`, `assume_specification`, `external_body` — and
    those are propositions the Verus lane trusts. A V2 unit's proof is a Lean theorem over a
    model Charon extracted from compiled Rust: the spec items carrying those mechanisms are
    behind the `verify` feature, are not compiled into the extraction, and do not appear in
    the model at all. Reading them as premises of a Lean theorem would be R9-C022 one lane
    over — a premise invented out of a source-level overlap, in a registry whose whole value
    is that every entry names something real.

    That is a decision about a case that has never arisen rather than a relaxation of one
    that has: the cap can only fire above `max_class_without_assumption`, every declared cap
    is V0, and until now every unit above V0 was a Verus unit. What it must not become is an
    unguarded lane, and it is not one. The extracted model's premises are its AXIOM CLOSURE,
    `verify-lean` discovers that closure with `#print axioms` rather than by location, and
    every axiom outside the declared kernel baseline must be an `ASM-NNNN` scoped to the
    unit or the lane refuses. An assumption there names its boundary in its own `scope`, the
    way ASM-0037 names `boundary://boundary.crypto_primitives` — which is the declared half
    of the relation this function's own docstring calls a floor with a declared complement.
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

    caps = {
        boundary["id"]: boundary["max_class_without_assumption"]
        for boundary in boundaries.get("boundary", [])
        if boundary.get("max_class_without_assumption") is not None
    }
    violations: list[str] = []
    # Once per unit: the crossings are a property of the unit's proof, not of the boundary
    # being asked about, and computing them inside the boundary loop rescanned every seam
    # file once per boundary.
    for unit in verification.get("unit", []):
        if unit["class"] not in RUST_SEAM_CONSUMERS:
            continue
        for boundary_id, seams in semantic_boundary_crossings(unit, boundaries).items():
            cap = caps.get(boundary_id)
            if cap is None or CLASS_ORDER[unit["class"]] <= CLASS_ORDER[cap]:
                continue
            if (unit["id"], boundary_id) in covered:
                continue
            violations.append(
                f"unit {unit['id']} is class {unit['class']} and its proof TRUSTS a seam "
                f"beyond {boundary_id} ({', '.join(seams)}), which permits at most {cap} "
                f"without a registered assumption covering the crossing. The seam is an "
                f"unproved proposition the proof consumes, not a file it is compiled "
                f"beside. Register an assumption in assumptions.toml with "
                f"`boundary://{boundary_id}` in its scope, or lower the unit's class."
            )
    return sorted(violations)


def unit_assumptions(unit_id: str, assumptions: dict) -> list[str]:
    """The assumptions a unit trusts, derived from `[[assumption]].scope`.

    ADR-MCPRE-059 §8 has one authoritative direction, and this is the only place the
    inverse is computed. `scope` is the authoritative side because the assumption owns its
    own trust blast radius and can name a boundary as readily as a unit; every consumer —
    the review packet, the owner and blast-radius views, the evidence graph — derives the
    unit→assumption direction here.

    A second authored declaration on the unit is not a convenience, it is a second source:
    the two halves feed different machinery, `scope` reaching the fingerprint and
    `check-assumptions` while a unit-side field would reach only the human-facing artefacts.
    A premise no scope names is absent from the unit's fingerprint, so the assumption can be
    rewritten and every claim over that unit still reads as fresh.
    """
    prefix = f"unit://{unit_id}"
    return sorted(
        entry["id"]
        for entry in assumptions.get("assumption", [])
        if prefix in [str(target) for target in entry.get("scope", [])]
    )


def assumption_scope_defects(verification: dict, assumptions: dict) -> list[str]:
    """Scopes that name a unit no `[[unit]]` declares.

    What remains checkable once the relation has one source. A scope entry naming a unit
    that does not exist reads as a registration and trusts the assumption nowhere: the
    premise reaches no fingerprint, no view and no packet, while the registry shows the
    assumption as scoped. Misspelling a unit id is exactly how a premise silently stops
    being carried.

    The disagreement control this replaces had a second job — catching a unit that
    declared an unregistered assumption — and the schema now does that one: `assumptions`
    is no longer an admissible `[[unit]]` key, so there is no unit-side declaration left to
    be wrong.
    """
    known_units = {unit["id"] for unit in verification.get("unit", [])}
    defects: list[str] = []
    for entry in assumptions.get("assumption", []):
        for target in entry.get("scope", []):
            target = str(target)
            if not target.startswith("unit://"):
                continue
            unit_id = target.removeprefix("unit://")
            if unit_id not in known_units:
                defects.append(
                    f"assumption {entry['id']} is scoped to unit://{unit_id}, which no "
                    f"[[unit]] declares. A scope naming a unit that does not exist trusts "
                    f"the assumption nowhere while reading as a registration."
                )
    return defects


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
    # The extraction container's identity is COMPUTABLE from the inputs recorded beside it,
    # so it is computed here rather than trusted. Validating in the loader binds every
    # consumer at once — the gate, the Lean lane, the graph — instead of one script
    # remembering to ask.
    for problem in identity_problems(doc):
        raise ManifestError(problem)
    # The same class of question one level down: not *which* environment the pin names, but
    # whether the record says which preserved BYTES carry it. A lock that omits that cannot
    # be checked against the store at all, so it is refused here rather than at whichever
    # consumer happens to look first.
    for problem in artifact_record_problems(doc):
        raise ManifestError(problem)
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


def unpinned_identities(toolchains: dict, required: Iterable[str]) -> dict[str, str]:
    """Each required identity that is not resolved, mapped to WHY it is not.

    R9-C069. `unresolved_pins` answers over the tables the lock CONTAINS, so it can only
    report an identity someone wrote down and marked `unresolved`. Deleting the table
    instead removed the identity from its answer entirely, and a lane computing
    `REQUIRED & unresolved_pins(...)` then found nothing missing and ran — with `[rust]` or
    `[verus.z3]` gone from the lock, against whatever the environment supplied. The
    strongest way to unpin a tool was to stop mentioning it.

    Absence and `state = "unresolved"` are the same fact about the tool — its identity is
    unknown, and unknown is dirty — so both are returned and both are disqualifying. They
    are returned with their reason rather than as one list because the REMEDY differs and
    naming the wrong one sends the reader nowhere: an unresolved pin is resolved by
    installing the tool and recording what was installed, while an absent one is a lock
    that does not know the tool exists and is repaired by declaring it. Collapsing them
    would trade one unreadable message for another.

    `required` names dotted paths exactly as `unresolved_pins` reports them, so
    `verus.z3` asks about the sub-table and `verus` about its parent.
    """
    out: dict[str, str] = {}
    unresolved = set(unresolved_pins(toolchains))
    for name in required:
        head, _, tail = name.partition(".")
        entry = toolchains.get(head)
        if not isinstance(entry, dict) or (tail and not isinstance(entry.get(tail), dict)):
            out[name] = "absent"
        elif name in unresolved:
            out[name] = "unresolved"
    return dict(sorted(out.items()))


def fail(message: str) -> None:
    """Print a fatal manifest/lane error and exit non-zero."""
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)
