# SPDX-License-Identifier: Apache-2.0
"""Deterministic ReviewFingerprint over a review unit — ADR-MCPRE-059 §2.

    ReviewFingerprint(U) = H(
        source_inputs, generated_inputs, build_configuration, enabled_features,
        exported_contracts, consumed_contracts, proof_dependencies,
        test_evidence_definition, test_selection, test_sources, test_lane_identity,
        mutation_probes, mutation_lane_identity, trusted_assumptions, toolchain_identity,
        formal_model_revision, threat_model_revision, review_policy_revision
    )

Freshness is DERIVED by comparing this against the inputs recorded in a successful
attestation. There is no mutable `clean = true` anywhere, because a mutable marker is easy
to stale and easy to manipulate.

Two properties the encoding must have, and does:

  * Deterministic. Sorted keys, explicit separators, UTF-8, no timestamps, no run ids.
    Provenance may be attached to an attestation; it may not enter the semantic fingerprint.
  * Versioned. `encoding_version` participates in the hash, so changing how inputs are
    encoded changes every fingerprint — which is correct, since the meaning changed.

Every component is MEASURED. There is no sentinel value standing in for an input nobody
computes: a constant compares equal on every run, so a component recorded as one is inert
and the freshness derivation silently establishes nothing over it. A component with no
matching inputs is an empty mapping — measured, and empty — which is a different claim from
"not accounted for" and the only one this encoding can make.

Encoding v4 measures the EFFECTIVE TEST EVIDENCE, not merely its label. Until v3 the only
test component was `test_evidence_definition` — the sorted `test://` URIs — so a battery
could fall from 67 declared controls to 5, or move to a different Cargo package, with the
URI and therefore the fingerprint unchanged. Four components now answer "what did the test
lane actually measure":

  * `test_evidence_definition`  the `test://` URIs, as before — WHAT is claimed
  * `test_selection`            the resolved package and the exact sorted symbols — WHICH
                                tests were selected
  * `test_sources`              the bytes of the integration-test targets those selectors
                                run. In-crate (`lib#`, `doc#`) selectors are NOT here: they
                                execute code inside the unit's declared `paths`, which
                                `source_inputs` already digests, and the manifest loader
                                REFUSES a `lib#`/`doc#` selector whose module is not
                                declared, so that is a checked fact rather than a hope.
  * `test_lane_identity`        the selector mechanism itself — `verify-tests` and the
                                manifest logic it reads. The meaning of `doc#…`, and of
                                `test_package`, is decided by that code; if the measuring
                                instrument changes, what the measurement MEANS changed.

Encoding v5 extends the same rule to the MUTATION evidence. A `mutation://` URI puts the
probe suite inside the attestation closure — `attest` refuses a unit with no mutation PASS
at its exact fingerprint — but a closure over a suite that can silently SHRINK proves as
little as the v3 test component did. So:

  * `mutation_probes`        each in-scope probe's id mapped to a digest of its whole
                             registry entry. Deleting a probe, widening its `expect_red`,
                             or softening its weakening all move the fingerprint, which
                             invalidates the standing mutation PASS.
  * `mutation_lane_identity` `verify-mutations`, for the reason `test_lane_identity`
                             carries `verify-tests`: this lane decides what "the control
                             went red" MEANS, and it has already been wrong about it once —
                             the first version counted a control that never executed as
                             red.

An integration-test target is digested as a whole file (plus any module directory beside
it), not as the subset of it the selectors name. That over-approximates — an unrelated test
in the same file invalidates the unit — and over-approximation is the safe direction: it
causes extra review, never false freshness. It narrows once there is an executable
dependency boundary to narrow to.

`_fingerprint.py` is deliberately NOT in `test_lane_identity`. Its identity is carried by
`ENCODING_VERSION`, which is what a change of MEANING here must move; hashing the file
would additionally invalidate every unit for a comment.

The measured cone is the cone the LANE measures, not the paths the unit lists. `cargo verus
verify -p <crate>` verifies the whole crate and compiles its `verify`-feature dependency
closure, so a formal unit's `source_inputs` covers every `.rs` file in the crate its paths
name and its `proof_dependencies` covers the workspace crates that crate depends on. A
fingerprint narrower than the verified cone lets source the proof stands on change while
the graph still answers FRESH.

Importable as a module — `_graph` and `review-frontier` both need `fingerprint_unit`, and
the `fingerprint` command is a thin CLI over it. It lives here rather than in the
extensionless script because an extensionless file cannot be imported.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from functools import lru_cache

from _ecosystems import build_configuration_patterns
from _ecosystems import formal_source_patterns
from _ecosystems import unit_projects
from _manifest import (
    claims_mutation_evidence,
    claims_test_evidence,
    test_package_for,
    expand_paths,
    load_trust_boundaries,
    REPO_ROOT,
)

# Every attestation carrying an earlier version is UNKNOWN from the moment this moves, which
# is the intended cost: an attestation computed over a narrower set of inputs cannot answer
# whether one of the inputs it never saw has since changed.
ENCODING_VERSION = 6

#: The classes whose evidence comes from a whole-crate prover run.
FORMAL_CLASSES = {"V1", "V3"}

#: Build inputs that decide what the verified crate IS, for every unit. A dependency swap,
#: a lockfile bump or a toolchain channel change alters what a theorem is about without
#: touching a line of the source the unit declares.
WORKSPACE_BUILD_INPUTS = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")

#: Where extraction deposits machine-generated proof input.
GENERATED_ROOT = "verification/lean/generated"


def _digest_paths(patterns: list[str]) -> dict[str, str]:
    """SHA-256 per file, keyed by repo-relative path, sorted.

    Content-addressed rather than mtime-based: a file restored to identical content is
    identical evidence, and a file whose bytes changed is not, regardless of timestamps.
    """
    out: dict[str, str] = {}
    for pattern in sorted(patterns):
        for path in sorted(REPO_ROOT.glob(pattern)):
            if path.is_file():
                rel = path.relative_to(REPO_ROOT).as_posix()
                out[rel] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def _unit_crates(unit: dict) -> list[str]:
    """The projects the unit's declared paths live in.

    Derived from the paths rather than configured, for the reason `verify-verus` derives
    its `-p` argument the same way: a unit whose source moves to another project must not
    keep fingerprinting the one it left. Which build system decides what a project IS is
    `_ecosystems`' (issue #745), so this is no longer a Cargo-only answer.
    """
    return unit_projects(unit)


def _path_dependencies(crate: str, seen: set[str]) -> set[str]:
    """Workspace crates reachable from `crate` by path dependency, transitively.

    The `verify` feature travels down this closure — `mcp-re-http-profile/verify` turns on
    `mcp-re-core/verify` — so the prover compiles and checks these crates as part of the
    run whose result the unit claims.
    """
    manifest = REPO_ROOT / crate / "Cargo.toml"
    if crate in seen or not manifest.is_file():
        return seen
    seen.add(crate)
    with manifest.open("rb") as handle:
        doc = tomllib.load(handle)
    for spec in doc.get("dependencies", {}).values():
        if not isinstance(spec, dict) or "path" not in spec:
            continue
        resolved = (manifest.parent / spec["path"]).resolve()
        try:
            _path_dependencies(resolved.relative_to(REPO_ROOT).as_posix(), seen)
        except ValueError:
            continue
    return seen


def _crate_sources(crates: list[str]) -> dict[str, str]:
    return _digest_paths([f"{crate}/src/**/*.rs" for crate in crates])


def _formal_sources(unit: dict) -> dict[str, str]:
    """Whole-project sources for a unit whose evidence comes from a prover run.

    Empty where the ecosystem has no prover lane, which is what keeps a V1/V3 declaration
    over Python or TypeScript source from deriving a fingerprint that pretends a whole-
    project measurement happened. The class check that refuses such a unit outright is the
    schema's; this is the half that would otherwise measure it as if it had one.
    """
    return _digest_paths(formal_source_patterns(unit))


def _build_configuration(unit: dict) -> dict[str, str]:
    """The dependency and configuration inputs that decide what this unit's source IS.

    Ecosystem-supplied (`build_configuration_patterns`), because a Python project's
    `pyproject.toml` and `uv.lock` bear exactly the weight a crate's `Cargo.toml` and the
    workspace `Cargo.lock` bear: a dependency swap or a lockfile bump alters what a claim is
    about without touching a declared source line. Absent alternatives — `poetry.lock` where
    a project uses `uv` — contribute nothing rather than an error.
    """
    return _digest_paths(build_configuration_patterns(unit))


def _toolchain_identity(toolchains: dict) -> dict:
    """Every pinned identity, plus every unresolved one named as such."""
    identity: dict[str, object] = {}
    for name, entry in sorted(toolchains.items()):
        if name == "schema_version" or not isinstance(entry, dict):
            continue
        scalars = {
            key: value
            for key, value in sorted(entry.items())
            if not isinstance(value, dict) and key != "note"
        }
        identity[name] = scalars
        for sub_name, sub in sorted(entry.items()):
            if isinstance(sub, dict):
                identity[f"{name}.{sub_name}"] = {
                    key: value
                    for key, value in sorted(sub.items())
                    if key != "note"
                }
    return identity


def canonical_digest(value) -> str:
    """The one encoding every fingerprint in this module uses.

    Single function rather than an inlined `json.dumps` per call site, because "how a
    fingerprint is encoded" is exactly the fact that must not have two implementations: two
    encoders that agree today and diverge later would make two records incomparable while
    both look well-formed.
    """
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assumption_digest(entry: dict) -> str:
    """A digest of WHAT AN ASSUMPTION TRUSTS — its whole registry entry.

    Exposed because two axes read it: a unit's `trusted_assumptions` component, and the
    assumption review axis, which is fresh only while the entry a reviewer ratified still
    hashes the same.
    """
    return canonical_digest(entry)


def _trusted_assumptions(unit_id: str, assumptions: dict) -> dict[str, str]:
    """Each in-scope assumption's id, mapped to a digest of WHAT IT TRUSTS.

    Ids alone would let an assumption be rewritten — its description widened, its scope
    extended, its mechanism swapped — without any unit deriving DIRTY_ASSUMPTION. The
    registry entry is the trusted claim, so the entry's content is what participates.
    """
    out: dict[str, str] = {}
    for entry in assumptions.get("assumption", []):
        if f"unit://{unit_id}" not in entry.get("scope", []):
            continue
        out[entry["id"]] = assumption_digest(entry)
    return out


def _test_selection(unit: dict) -> dict:
    """WHICH tests were selected: the resolved package and the exact symbols.

    Empty for a unit with no `test://` evidence — measured, and empty, which is a different
    claim from "not accounted for".
    """
    if not claims_test_evidence(unit):
        return {}
    return {
        "package": test_package_for(unit),
        "symbols": sorted(str(s) for s in unit.get("tested_symbols", [])),
    }


def test_source_patterns(unit: dict) -> list[str]:
    """The globs naming the integration-test targets this unit's selectors run.

    Exposed because two things read it: this module, which digests them, and
    `scripts/verification_trigger_gate.py`, which checks the workflow re-runs the lane when
    one of them changes. A path-filtered workflow and a content-addressed fingerprint are
    one dependency set stated twice, and they drift in the direction that produces a false
    green — so they are derived from one function.
    """
    if not claims_test_evidence(unit):
        return []
    package = test_package_for(unit)
    if package is None:
        return []
    patterns: set[str] = set()
    for symbol in unit.get("tested_symbols", []):
        target, _, _ = str(symbol).partition("#")
        if not target.startswith("tests/") or not target[6:]:
            continue
        name = target[6:]
        patterns.add(f"{package}/tests/{name}.rs")
        patterns.add(f"{package}/tests/{name}/**/*.rs")
    return sorted(patterns)


def _test_sources(unit: dict) -> dict[str, str]:
    """The bytes of the integration-test targets this unit's selectors run.

    Without this, a control could keep its declared name and lose its body: the selector
    still resolves, the lane still reports a pass, and the fingerprint never moves. The
    name is the label; the file is the evidence.
    """
    return _digest_paths(test_source_patterns(unit))


#: The code that decides WHICH tests a selector names and WHERE they run. Not a build
#: input — a measurement instrument, and evidence whose instrument changed is evidence
#: whose meaning changed.
TEST_LANE_INPUTS = (
    "tools/verification/verify-tests",
    "tools/verification/_manifest.py",
    # The adapter registry: which ecosystem a path belongs to, which project runs the
    # battery, and how a selected result is read. It decides what a symbol NAMES, so a
    # change to it changes what the recorded evidence means — the same argument that put
    # the lane itself here (issue #745).
    "tools/verification/_ecosystems.py",
)


def _test_lane_identity(unit: dict) -> dict[str, str]:
    if not claims_test_evidence(unit):
        return {}
    return _digest_paths(list(TEST_LANE_INPUTS))


def _mutation_probes(unit_id: str) -> dict[str, str]:
    """Each probe scoped to this unit, mapped to a digest of WHAT IT PROVES.

    Ids alone would let a probe be hollowed out — its weakening softened, its `expect_red`
    widened to a control that fails for another reason — with no unit deriving DIRTY. The
    registry entry is the claim, so the entry's content is what participates. Same argument,
    and same shape, as `_trusted_assumptions`.
    """
    registry = REPO_ROOT / "verification" / "policy" / "mutation-probes.toml"
    if not registry.is_file():
        return {}
    with registry.open("rb") as handle:
        doc = tomllib.load(handle)
    return {
        probe["id"]: canonical_digest(probe)
        for probe in doc.get("probe", [])
        if probe.get("unit") == unit_id
    }


#: The lane that decides what "a declared control went red" means.
MUTATION_LANE_INPUTS = ("tools/verification/verify-mutations",)


def _mutation_lane_identity(unit: dict) -> dict[str, str]:
    if not claims_mutation_evidence(unit):
        return {}
    return _digest_paths(list(MUTATION_LANE_INPUTS))


@lru_cache(maxsize=None)
def _boundary_files(patterns: tuple[str, ...]) -> frozenset[str]:
    """The files a boundary's patterns name. Cached: the globs are walked once per run."""
    return frozenset(expand_paths(list(patterns)))


def _governing_boundaries(unit: dict, boundaries: dict) -> dict[str, str]:
    """The declared trust boundaries this unit's paths cross, by id and content digest.

    `trust-boundaries.toml` decides how far a unit may be promoted: a theorem about code on
    this side of a boundary says nothing about the other side, so
    `max_class_without_assumption` is what keeps a proof's meaning honest across it. That
    cap participated in NO fingerprint. Widening it — or deleting the boundary, or narrowing
    its `paths` so it stops covering a unit — relaxed the rule and invalidated nothing, so
    every claim above it kept deriving FRESH while the argument beneath it had changed.

    The digest covers the whole entry, not the cap alone, because each field can weaken the
    reading on its own: `paths` decides WHICH units the cap binds, `beyond` states what is
    being trusted, and `kind` is how a reader classifies the trust. Only the boundaries a
    unit actually crosses are included, so a change to an unrelated boundary does not dirty
    the whole tree — the same relation `boundary_class_violations` uses to decide the rule.
    """
    unit_files = expand_paths(unit["paths"])
    crossed: dict[str, str] = {}
    for boundary in boundaries.get("boundary", []):
        if not unit_files & _boundary_files(tuple(boundary["paths"])):
            continue
        crossed[boundary["id"]] = canonical_digest(
            {
                "kind": boundary.get("kind"),
                "beyond": boundary.get("beyond"),
                "max_class_without_assumption": boundary.get(
                    "max_class_without_assumption"
                ),
                "paths": sorted(boundary["paths"]),
            }
        )
    return dict(sorted(crossed.items()))


def fingerprint_unit(
    unit: dict,
    doc: dict,
    toolchains: dict,
    assumptions: dict,
    boundaries: dict | None = None,
) -> dict:
    crates = _unit_crates(unit)
    formal = unit["class"] in FORMAL_CLASSES
    # A formal unit's evidence comes from a whole-crate prover run, so the crate is the
    # measured object. Digesting only the declared paths would leave every other file the
    # theorem reads — the types it quantifies over, the helpers it calls — free to change
    # under an attestation that still derives FRESH.
    source_inputs = _digest_paths(unit["paths"])
    if formal:
        source_inputs |= _formal_sources(unit)
    proof_dependencies: dict[str, str] = {}
    if formal:
        closure: set[str] = set()
        for crate in crates:
            _path_dependencies(crate, closure)
        proof_dependencies = _crate_sources(sorted(closure - set(crates)))
    components = {
        "encoding_version": ENCODING_VERSION,
        "unit_id": unit["id"],
        "class": unit["class"],
        "source_inputs": source_inputs,
        "generated_inputs": _digest_paths(
            [p for p in unit["paths"] if p.startswith(GENERATED_ROOT)]
        ),
        "build_configuration": _build_configuration(unit),
        "enabled_features": sorted(unit.get("features", [])),
        # The theorems the unit claims, by prover-reported name. In the fingerprint
        # because deleting one is a reduction in evidence: the source digest would move
        # too, but the contract digest would not, and this is the component that says the
        # CLAIM changed rather than its implementation.
        "proved_symbols": sorted(unit.get("proved_symbols", [])),
        "exported_contracts": sorted(unit.get("exported_contracts", [])),
        "consumed_contracts": sorted(unit.get("consumed_contracts", [])),
        "proof_dependencies": proof_dependencies,
        "test_evidence_definition": sorted(unit.get("evidence", [])),
        "test_selection": _test_selection(unit),
        "test_sources": _test_sources(unit),
        "test_lane_identity": _test_lane_identity(unit),
        "mutation_probes": (
            _mutation_probes(unit["id"]) if claims_mutation_evidence(unit) else {}
        ),
        "mutation_lane_identity": _mutation_lane_identity(unit),
        "trusted_assumptions": _trusted_assumptions(unit["id"], assumptions),
        # The boundaries whose cap binds this unit's class. See `_governing_boundaries`:
        # the cap was a gate that participated in no fingerprint, so relaxing it left every
        # claim above it reading as fresh.
        "governing_boundaries": _governing_boundaries(
            unit, load_trust_boundaries() if boundaries is None else boundaries
        ),
        "toolchain_identity": _toolchain_identity(toolchains),
        "formal_model_revision": doc.get("formal_model_revision"),
        "threat_model_revision": doc.get("threat_model_revision"),
        "review_policy_revision": doc["policy_revision"],
    }
    return {
        "unit_id": unit["id"],
        "fingerprint": canonical_digest(components),
        "components": components,
    }


# ---------------------------------------------------------------------------
# The theorem axis — ADR-MCPRE-059 §14.1, §14.3, §14.7
# ---------------------------------------------------------------------------
#
# A theorem fingerprint is SEPARATE from the fingerprint of the units that support it, and
# the separation is the whole mechanism §14.3 asks for:
#
#   * A theorem's supporting unit fingerprints are NOT components here. If they were,
#     editing a line of Rust would invalidate the owner's approval of the specification —
#     collapsing the proof axis and the specification-review axis into the single bit
#     §14.7 exists to prevent.
#   * Conversely a unit fingerprint carries no theorem component, so restating a claim
#     leaves the prover green. That is exactly the situation the mutation test pins: the
#     theorem moves from F1 to F2 while the review record still names F1, so specification
#     review derives DIRTY with no legislative rule and no stored status string.
#
# Whether the two axes are BOTH fresh is a conjunction, computed in `_review`, and it is
# the only place the word "established" is allowed to appear.

#: Versioned independently of the unit encoding. Bumping one must not invalidate the other:
#: they certify different things and are compared separately.
THEOREM_ENCODING_VERSION = 1


def _claim_digest(entry: dict) -> str:
    """The canonical digest of the human claim — §14.1's `theorem_claim`.

    Exactly `statement + security_consequence + scope`, as the ADR names them. `title` is
    excluded because it is a label for humans, not part of the proposition; renaming a
    theorem must not invalidate a review of what it says.
    """
    return canonical_digest(
        {
            "statement": entry["statement"],
            "security_consequence": entry["security_consequence"],
            "scope": entry["scope"],
        }
    )


def _dependency_closure(theorem_id: str, by_id: dict[str, dict]) -> dict[str, str]:
    """The transitive `depends_on` closure, each premise mapped to ITS claim digest.

    Ids alone would let a premise be weakened — its statement narrowed, its scope widened —
    without any dependent theorem moving, which is the composition-shaped version of the
    same false green `trusted_assumptions` closes one layer down. The closure is transitive
    because a claim rests on everything underneath it, not only its direct premises.

    The registry's loader rejects cycles, so the walk terminates; `seen` is kept anyway, as
    a fingerprint that could be made to hang by a malformed input is a denial of the gate.
    """
    out: dict[str, str] = {}
    stack = list(by_id[theorem_id].get("depends_on", []))
    seen: set[str] = {theorem_id}
    while stack:
        dep = stack.pop()
        if dep in seen or dep not in by_id:
            continue
        seen.add(dep)
        out[dep] = _claim_digest(by_id[dep])
        stack.extend(by_id[dep].get("depends_on", []))
    return out


def fingerprint_theorem(entry: dict, theorems: dict) -> dict:
    """Deterministic fingerprint over one theorem's specification.

    `review_requirement` participates: an approval given under "Owner security-specification
    review" is not an approval under a weaker requirement, so relaxing who must review is a
    change to what the approval meant. Leaving it out would make the one edit that lowers
    the review bar the one edit that dirties nothing.
    """
    by_id = {row["id"]: row for row in theorems.get("theorem", [])}
    components = {
        "encoding_version": THEOREM_ENCODING_VERSION,
        "theorem_id": entry["id"],
        "theorem_claim": _claim_digest(entry),
        "theorem_dependencies": _dependency_closure(entry["id"], by_id),
        "theorem_review_requirement": entry["review_requirement"],
    }
    return {
        "theorem_id": entry["id"],
        "fingerprint": canonical_digest(components),
        "components": components,
    }


