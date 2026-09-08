#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Controls for the extraction container's computed identity.

The defect these exist for was not a wrong value — it was a value nobody computed. The
lock recorded a tag derived from the toolchain pins AND the Dockerfile, the Dockerfile
changed three times, and the tag stayed, because nothing ever recomputed it. Every control
below therefore asks the gate to FAIL at something, because a gate that only ever passes is
indistinguishable from one that measures nothing.
"""

from __future__ import annotations

import copy
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _extraction_identity import (  # noqa: E402
    DOCKERFILE,
    content_tag,
    definition_digest,
    definition_drift,
    identity_problems,
)
from _manifest import ManifestError, load_toolchains  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent
LOCK = REPO / "verification" / "policy" / "toolchains.lock.toml"


def lock() -> dict:
    return tomllib.load(open(LOCK, "rb"))


def test_the_committed_lock_is_internally_consistent():
    """The recorded tag follows from the pins and the definition beside it."""
    assert identity_problems(lock()) == [], identity_problems(lock())


def test_the_real_loader_accepts_the_real_lock():
    """The check is wired into `load_toolchains`, not only available beside it."""
    load_toolchains()


def test_a_resolved_pin_with_no_definition_digest_is_refused():
    """Without it, nothing can check that the tag follows from anything.

    This is the state the lock was in: resolved, tagged, and uncheckable.
    """
    doc = copy.deepcopy(lock())
    del doc["extraction_container"]["definition_digest"]
    problems = identity_problems(doc)
    assert problems and "definition_digest" in problems[0], problems


def test_moving_a_prover_pin_without_republishing_is_caught():
    """A pin change mints a different image; the recorded tag stops following."""
    for key, field, value in [
        ("charon", "commit", "0" * 40),
        ("aeneas", "commit", "1" * 40),
        ("lean", "toolchain", "leanprover/lean4:v4.99.0"),
        ("aeneas_lean_backend", "mathlib_revision", "2" * 40),
    ]:
        doc = copy.deepcopy(lock())
        doc[key][field] = value
        problems = identity_problems(doc)
        assert problems, f"moving {key}.{field} left the recorded identity unchallenged"
        assert "does not follow from its inputs" in problems[0], problems


def test_a_hand_edited_tag_is_caught():
    doc = copy.deepcopy(lock())
    doc["extraction_container"]["tag"] = "tc-0000000000000000"
    assert identity_problems(doc), "an arbitrary tag was accepted"


def test_an_unresolved_container_is_not_asked_to_be_consistent():
    """An unresolved pin has no identity to check; refusing it here would be the wrong
    complaint, and `unresolved_pins` is what reports it."""
    doc = copy.deepcopy(lock())
    doc["extraction_container"]["state"] = "unresolved"
    assert identity_problems(doc) == []


def test_the_dockerfile_is_load_bearing_in_the_identity():
    """THE mutation probe. The Dockerfile is in the hash precisely so a build-step change
    cannot slip in under an unchanged tag — and one did, because nothing recomputed. If this
    control ever passes with an unchanged tag, the gate above is decoration."""
    pins = lock()
    unchanged = content_tag(pins, definition_digest())
    mutated = content_tag(pins, "f" * 64)
    assert unchanged != mutated, (
        "the content tag is blind to the Dockerfile, so a build-step change would mint no "
        "new identity — which is the whole failure this identity exists to prevent"
    )


def test_drift_is_reported_when_the_pin_is_not_a_build_of_the_declared_definition():
    """A CURRENCY question, not a consistency one: the record is fine, the image is old."""
    doc = copy.deepcopy(lock())
    doc["extraction_container"]["definition_digest"] = "e" * 64
    drift = definition_drift(doc)
    assert drift is not None
    assert "NOT a build of the declared definition" in drift, drift
    # And it stays internally consistent only if the tag follows; the two questions are
    # separate, and this one must not masquerade as the other.
    assert identity_problems(doc), "a stale definition must not also read as a valid tag"


def test_no_drift_when_the_pin_names_the_declared_definition():
    doc = copy.deepcopy(lock())
    doc["extraction_container"]["definition_digest"] = definition_digest()
    doc["extraction_container"]["tag"] = content_tag(doc, definition_digest())
    assert definition_drift(doc) is None
    assert identity_problems(doc) == []


def test_the_dockerfile_the_identity_reads_is_the_one_the_image_is_built_from():
    """`.github/workflows/extraction-image.yml` builds `verification/extraction`, so the
    Dockerfile hashed here has to be that directory's — a hash of some other file would be a
    tag that tracked nothing."""
    assert DOCKERFILE == REPO / "verification" / "extraction" / "Dockerfile"
    assert DOCKERFILE.exists()


def test_the_loader_refuses_an_inconsistent_lock_rather_than_returning_it():
    """The consumer-facing half: every caller of `load_toolchains` inherits the refusal, so
    no script has to remember to ask."""
    import _manifest

    original = _manifest.identity_problems
    try:
        _manifest.identity_problems = lambda _doc: ["synthetic inconsistency"]
        try:
            load_toolchains()
        except ManifestError as exc:
            assert "synthetic inconsistency" in str(exc)
        else:
            raise AssertionError("load_toolchains returned a lock it should have refused")
    finally:
        _manifest.identity_problems = original


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
