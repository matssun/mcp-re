# SPDX-License-Identifier: Apache-2.0
"""The Verus lane's own false-green catalogue — ADR-MCPRE-059.

The single property under test: **the lane reports a pass only for evidence it actually
measured, about the unit it claims to be measuring.**

Every case here is a real failure this lane has produced, not a hypothetical. They are
tests rather than paragraphs in a document because each one was found by the next thing
going wrong, and a list of stories does not stop the fourth instance.

Run with `python3 -m pytest tools/verification/test_verus_lane.py`, or directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _load_tool import load_tool  # noqa: E402
from _manifest import load_toolchains, unpinned_identities  # noqa: E402
from _verus_results import evaluate_unit, parse_reports  # noqa: E402

LANE = load_tool("verify-verus")

PIN = "92f466f247f45128c630d1c843fd6e27d2115587"


def report(
    symbols: list[str],
    verified: int,
    errors: int = 0,
    entire: bool = True,
    commit: str = PIN,
    success: bool | None = None,
) -> str:
    """One prover report, in the shape `verus --output-json` emits."""
    import json

    return json.dumps(
        {
            "func-details": {name: {"failed_proof_notes": []} for name in symbols},
            "verification-results": {
                "success": (errors == 0) if success is None else success,
                "verified": verified,
                "errors": errors,
                "is-verifying-entire-crate": entire,
            },
            "verus": {"version": "0.2026.08.09.92f466f", "commit": commit},
        }
    )


CORE = "mcp_re_core::time::parse_rfc3339_utc"
PROFILE = "mcp_re_http_profile::verify::check_params"


def test_a_real_pass_is_a_pass():
    ok, detail = evaluate_unit(
        parse_reports(report([CORE], verified=5)), "mcp-re-core", [CORE], PIN
    )
    assert ok, detail


def test_cargo_chatter_around_the_report_is_harmless():
    """Cargo shares the stream. Anything that is not a JSON document is skipped."""
    noisy = f"   Compiling mcp-re-core v0.16.0\n{report([CORE], verified=5)}\n    Finished\n"
    ok, _ = evaluate_unit(parse_reports(noisy), "mcp-re-core", [CORE], PIN)
    assert ok


def test_no_report_at_all_is_never_a_pass():
    """The original defect: a crate with no specifications compiles and exits 0."""
    ok, detail = evaluate_unit(parse_reports("   Finished in 0.14s\n"), "mcp-re-core", [], PIN)
    assert not ok
    assert "no report" in detail


def test_zero_verified_is_never_a_pass():
    ok, detail = evaluate_unit(
        parse_reports(report([], verified=0)), "mcp-re-core", [], PIN
    )
    assert not ok


def test_errors_are_never_a_pass():
    ok, _ = evaluate_unit(
        parse_reports(report([CORE], verified=4, errors=1)), "mcp-re-core", [CORE], PIN
    )
    assert not ok


def test_another_crates_success_does_not_satisfy_this_unit():
    """THE cross-crate control.

    `cargo verus verify -p B` verifies B's dependencies too. When the lane read the first
    result it found, unit B passed on crate A's proofs — both pilot units reported an
    identical `5 verified`, which was mcp-re-core's, and the freshness unit had never been
    measured at all.
    """
    only_a = report([CORE], verified=5)
    ok, detail = evaluate_unit(parse_reports(only_a), "mcp-re-http-profile", [PROFILE], PIN)
    assert not ok
    assert "no report for mcp-re-http-profile" in detail


def test_a_valid_crate_beside_a_broken_one_fails_only_the_broken_unit():
    """A PASS, B FAIL, and no way for A's success to carry B."""
    both = report([CORE], verified=5) + "\n" + report([PROFILE], verified=0, errors=1)
    ok_a, _ = evaluate_unit(parse_reports(both), "mcp-re-core", [CORE], PIN)
    ok_b, _ = evaluate_unit(parse_reports(both), "mcp-re-http-profile", [PROFILE], PIN)
    assert ok_a
    assert not ok_b


def test_a_deleted_specification_fails_even_though_the_crate_still_verifies():
    """Coverage cannot silently halve.

    Two theorems, one deleted: the crate still reports a healthy `verified` count, and
    every earlier version of this lane called that a pass.
    """
    survivor = "mcp_re_core::time::days_from_civil"
    ok, detail = evaluate_unit(
        parse_reports(report([survivor], verified=3)),
        "mcp-re-core",
        [CORE, survivor],
        PIN,
    )
    assert not ok
    assert "absent from the report" in detail


def test_a_partial_run_is_never_authoritative():
    """Operational Rule 5: `focus` output is not evidence for the crate."""
    ok, detail = evaluate_unit(
        parse_reports(report([CORE], verified=1, entire=False)), "mcp-re-core", [CORE], PIN
    )
    assert not ok
    assert "in part" in detail


def test_an_unpinned_prover_is_never_a_pass():
    """The report carries the prover's own identity, so the lane no longer has to trust
    that the binary at the pinned path is the pinned build."""
    ok, detail = evaluate_unit(
        parse_reports(report([CORE], verified=5, commit="0" * 40)), "mcp-re-core", [CORE], PIN
    )
    assert not ok
    assert "identity mismatch" in detail


def test_a_report_with_no_commit_is_never_a_pass():
    """The identity check must not fail OPEN on the one field the prover itself controls:
    a locally built or substituted binary that emits no commit was accepted as the pinned
    one, and its verdict was recorded as evidence."""
    ok, detail = evaluate_unit(
        parse_reports(report([CORE], verified=5, commit="")), "mcp-re-core", [CORE], PIN
    )
    assert not ok
    assert "no commit" in detail


def test_an_unpinned_lock_is_never_a_pass():
    """No pinned commit means no declared identity to check the run against."""
    ok, detail = evaluate_unit(
        parse_reports(report([CORE], verified=5)), "mcp-re-core", [CORE], ""
    )
    assert not ok
    assert "no Verus commit" in detail


def test_success_false_is_never_a_pass():
    """`success` and a zero error count can disagree; the conjunction is what counts."""
    ok, _ = evaluate_unit(
        parse_reports(report([CORE], verified=5, success=False)), "mcp-re-core", [CORE], PIN
    )
    assert not ok


def test_hyphenated_package_names_match_underscored_symbols():
    """Cargo says `mcp-re-core`; the prover says `mcp_re_core`. A lane that missed this
    would report "no report for this crate" for every unit that actually passed."""
    ok, _ = evaluate_unit(parse_reports(report([CORE], verified=5)), "mcp-re-core", [], PIN)
    assert ok


# ---------------------------------------------------------------------------
# Prover identity — R9-C069, R9-C070, R9-C083
# ---------------------------------------------------------------------------
#
# The cases above ask whether the lane believed a REPORT it should not have. These ask the
# question one level down: whether it believed the PROVER. A lane that correctly refuses
# every bad report still reports a pass it did not earn if the thing producing the reports
# is not the thing the lock names.


def _lock_without(*paths: str) -> dict:
    """The real lock with entries removed, so a control is tested against the real shape."""
    import copy

    doc = copy.deepcopy(load_toolchains())
    for path in paths:
        head, _, tail = path.partition(".")
        if tail:
            doc.get(head, {}).pop(tail, None)
        else:
            doc.pop(head, None)
    return doc


def test_a_deleted_toolchain_table_is_not_a_satisfied_requirement():
    """R9-C069. The strongest way to unpin a tool was to stop mentioning it.

    `unresolved_pins` answers over the tables the lock CONTAINS, so a deleted `[verus.z3]`
    left `REQUIRED & unresolved_pins(...)` empty and the lane ran — against whatever the
    environment supplied — while every message it printed said the toolchain was pinned.
    """
    gone = _lock_without("verus.z3", "rust")
    assert unpinned_identities(gone, LANE.REQUIRED) == {
        "rust": "absent",
        "verus.z3": "absent",
    }


def test_absent_and_unresolved_are_both_disqualifying_and_stay_distinguishable():
    """One decision, two remedies. Collapsing them would trade one bad message for another:
    an unresolved pin is repaired by installing the tool and recording it, an absent one by
    declaring that the tool exists at all."""
    doc = _lock_without()
    doc["verus"]["z3"]["state"] = "unresolved"
    del doc["rust"]
    reasons = unpinned_identities(doc, LANE.REQUIRED)
    assert set(reasons) == {"verus.z3", "rust"}
    assert reasons["verus.z3"] == "unresolved"
    assert reasons["rust"] == "absent"
    detail = LANE._unpinned_detail(reasons)
    assert "verus.z3 (unresolved)" in detail and "rust (absent)" in detail


def test_the_lock_identifies_the_prover_binaries_and_the_solver_by_digest():
    """R9-C070 / R9-C083. `libvstd.rlib` was recorded in a `note` — the one field the
    fingerprint strips — and the solver's `identity` was the sentence "bundled in the
    pinned Verus release archive", which is a claim about provenance that can be compared
    with nothing. A solver answering `unsat` to everything discharges every proof in the
    repository."""
    pinned = LANE._pinned_files(load_toolchains())
    assert {"libvstd.rlib", "z3", "verus", "rust_verify", "cargo-verus"} <= set(pinned)
    for name, digest in pinned.items():
        assert digest.startswith("sha256:"), f"{name} is identified by {digest!r}"


def test_a_prose_identity_is_refused_rather_than_skipped(tmp_path=None):
    """An identity that cannot be compared with the bytes on disk is not an identity, and
    it must FAIL rather than pass over — skipping it is how the sentence stood for a year
    while the lock read as fully pinned."""
    doc = _lock_without()
    doc["verus"]["z3"]["identity"] = "bundled in the pinned Verus release archive"
    detail = LANE._pinned_file_mismatch(doc, Path("/nonexistent"))
    assert detail is not None and "not a digest" in detail


def test_a_substituted_prover_binary_is_a_mismatch():
    """The whole of R9-C083: `vstd.vir` plus a truthful `version.json` established that the
    pinned SPECIFICATION LIBRARY was installed, and that was read as establishing that the
    pinned PROVER was."""
    doc = _lock_without()
    doc["verus"]["binaries"]["rust_verify"] = "sha256:" + "0" * 64
    root = Path(load_toolchains()["verus"]["install_root"])
    if not (root / "rust_verify").is_file():
        return  # the prover is not installed on this host; nothing to compare against
    detail = LANE._pinned_file_mismatch(doc, root)
    assert detail is not None and "rust_verify identity mismatch" in detail


def test_the_installed_prover_matches_every_digest_the_lock_records():
    """The positive control, and the one that makes the negatives mean something: a lock
    whose digests match nothing on disk would pass every mismatch test above."""
    toolchains = load_toolchains()
    root = Path(toolchains["verus"]["install_root"])
    if not (root / "vstd.vir").is_file():
        return  # the prover is not installed on this host
    assert LANE._pinned_file_mismatch(toolchains, root) is None


def test_the_lane_names_its_solver_instead_of_inheriting_it():
    """R9-C070. The lane built its environment as `{**os.environ, …}`, so an exported
    `VERUS_Z3_PATH` reached the prover and the pinned lock stayed silent about it. Unsetting
    it would not be the repair either: the prover would then resolve the solver beside
    itself, which is resolution BY LAYOUT — the same unstated identity one directory down.
    """
    import os

    toolchains = load_toolchains()
    root = Path(toolchains["verus"]["install_root"])
    hostile = "/tmp/a-solver-that-answers-unsat"
    os.environ["VERUS_Z3_PATH"] = hostile
    try:
        env = LANE._lane_env(toolchains, root)
    finally:
        del os.environ["VERUS_Z3_PATH"]
    assert env["VERUS_Z3_PATH"] == str(root / "z3") != hostile


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
