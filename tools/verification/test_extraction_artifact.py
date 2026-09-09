#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Controls for the preserved extraction artifact.

The defect these exist for is one a digest cannot state. The 2026-09-09 ruling established
that no proposition requires a registry, and `_extraction_identity` establishes WHICH
environment the lock names. Neither establishes that the named environment still exists:
its only copy lived in Docker's local image store, which `docker image prune`, a reset, or
a full disk empties — and this image cannot be rebuilt, because apt and opam resolve
versions nothing pins and the opam libraries are linked into the Aeneas binary. What would
survive is an identity nobody can execute: a claim still identifiable and no longer
reproducible.

Every control below asks the mechanism to REFUSE something, because a store that only ever
reports PRESENT is indistinguishable from one that checks nothing.
"""

from __future__ import annotations

import copy
import hashlib
import os
import sys
import tempfile
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _load_tool import load_tool  # noqa: E402
from _extraction_artifact import (  # noqa: E402
    DEFAULT_STORE,
    STORE_ENV,
    artifact_path,
    file_digest,
    preservation,
    record_problems,
    store_root,
)

REPO = Path(__file__).resolve().parent.parent.parent
LOCK = REPO / "verification" / "policy" / "toolchains.lock.toml"

#: A resolved container pin, whatever state the committed lock is in. The controls are about
#: the mechanism's behaviour on a resolved entry, and they must keep asking that question
#: while the real lock is `unresolved` between a Dockerfile change and its rebuild.
IMAGE = f"sha256:{'1' * 64}"


def lock() -> dict:
    return tomllib.load(open(LOCK, "rb"))


def resolved(archive: str) -> dict:
    doc = copy.deepcopy(lock())
    doc["extraction_container"] = {
        "state": "resolved",
        "artifact_digest": IMAGE,
        "archive_digest": archive,
        "definition_digest": doc["extraction_container"].get("definition_digest", "0" * 64),
        "platform": "linux/arm64",
        "definition": "verification/extraction/Dockerfile",
    }
    return doc


def store_with(payload: bytes) -> tuple[Path, Path, str]:
    """A real store directory holding `payload` as the pinned image's preserved form."""
    root = Path(tempfile.mkdtemp(prefix="extraction-store-"))
    path = artifact_path(IMAGE, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return root, path, f"sha256:{hashlib.sha256(payload).hexdigest()}"


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


def test_the_committed_lock_records_what_it_claims_to_record():
    """Whatever state it is in: unresolved records nothing, resolved records both digests."""
    assert record_problems(lock()) == [], record_problems(lock())


def test_a_resolved_pin_with_no_artifact_digest_is_refused():
    doc = resolved(f"sha256:{'2' * 64}")
    del doc["extraction_container"]["artifact_digest"]
    problems = record_problems(doc)
    assert problems and "artifact_digest" in problems[0], problems


def test_a_resolved_pin_with_no_archive_digest_is_refused():
    """THE control for this mechanism. An image identity with no preserved bytes is exactly
    the state the ruling left behind: a name for an environment a prune can delete."""
    doc = resolved(f"sha256:{'2' * 64}")
    del doc["extraction_container"]["archive_digest"]
    problems = record_problems(doc)
    assert problems and "archive_digest" in problems[0], problems
    assert "cannot be rebuilt" in problems[0], problems


def test_a_malformed_digest_is_named_as_malformed():
    """It must not fail closed as an ABSENT artifact: those call for opposite actions —
    fix the record, versus copy the bytes onto this host."""
    for field in ("artifact_digest", "archive_digest"):
        doc = resolved(f"sha256:{'2' * 64}")
        doc["extraction_container"][field] = "sha256:not-a-digest"
        problems = record_problems(doc)
        assert problems and "not a `sha256:" in problems[0], problems


def test_an_unresolved_container_is_not_asked_for_an_artifact():
    doc = copy.deepcopy(lock())
    doc["extraction_container"] = {"state": "unresolved"}
    assert record_problems(doc) == []
    assert preservation(doc) is None


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------


def test_a_present_intact_artifact_is_usable():
    root, path, digest = store_with(b"the exact preserved environment")
    state = preservation(resolved(digest), root)
    assert state is not None and state.status == "PRESENT", state
    assert state.usable and state.path == path


def test_a_missing_artifact_is_ABSENT_and_never_a_rebuild_instruction():
    """ABSENT means this host cannot execute the pinned environment. It must not read as
    'rebuild it': the image is not reproducible from its declared inputs, so a rebuild is a
    DIFFERENT instrument carrying the same declared pins."""
    root = Path(tempfile.mkdtemp(prefix="extraction-store-empty-"))
    state = preservation(resolved(f"sha256:{'2' * 64}"), root)
    assert state is not None and state.status == "ABSENT", state
    assert not state.usable
    assert "is not on this host" in (state.detail or "")
    assert "DIFFERENT instrument" in (state.detail or "")


def test_a_substituted_artifact_is_MISMATCH_not_ABSENT():
    """A file under an identity it does not have. The independent archive digest is what
    makes this detectable without loading several gigabytes to find out."""
    root, path, digest = store_with(b"the exact preserved environment")
    path.write_bytes(b"something else entirely")
    state = preservation(resolved(digest), root)
    assert state is not None and state.status == "MISMATCH", state
    assert not state.usable


def test_a_truncated_artifact_is_MISMATCH():
    """THE reason `_preserve` writes through a staging file and renames. A partial save at
    the content-addressed path would otherwise sit there under a valid identity."""
    payload = b"the exact preserved environment"
    root, path, digest = store_with(payload)
    path.write_bytes(payload[:10])
    state = preservation(resolved(digest), root)
    assert state is not None and state.status == "MISMATCH", state


def test_the_digest_is_over_the_whole_file():
    """Chunked, and the control uses more than one chunk: a helper that digested only the
    first read would accept every artifact sharing a prefix, which every Docker archive of
    the same base image does."""
    payload = (b"x" * (1 << 22)) + b"tail"
    _root, path, digest = store_with(payload)
    assert file_digest(path) == digest
    assert file_digest(path) != f"sha256:{hashlib.sha256(payload[: 1 << 22]).hexdigest()}"


def test_the_store_is_addressed_by_the_IMAGE_identity():
    """So "the preserved artifact for the pinned environment" names exactly one file, and a
    second build's archive cannot land on top of the first's."""
    a = artifact_path(f"sha256:{'a' * 64}", Path("/store"))
    b = artifact_path(f"sha256:{'b' * 64}", Path("/store"))
    assert a != b
    assert a.name == f"{'a' * 64}.tar"


# ---------------------------------------------------------------------------
# Where the store lives
# ---------------------------------------------------------------------------


def test_the_default_store_is_outside_dockers_disposable_state():
    """The whole mechanism. A default under Docker's own tree, or under the repository's
    gitignored build output, would be preserved exactly as long as the cache it replaces."""
    assert DEFAULT_STORE == Path("/opt/verification/extraction-artifacts")
    assert not str(DEFAULT_STORE).startswith("/var/lib/docker")
    assert REPO not in DEFAULT_STORE.parents


def test_the_store_location_is_overridable_for_a_test_but_not_by_accident():
    original = os.environ.get(STORE_ENV)
    try:
        os.environ[STORE_ENV] = "/tmp/some-store"
        assert store_root() == Path("/tmp/some-store")
        del os.environ[STORE_ENV]
        assert store_root() == DEFAULT_STORE
    finally:
        if original is None:
            os.environ.pop(STORE_ENV, None)
        else:
            os.environ[STORE_ENV] = original


# ---------------------------------------------------------------------------
# The consumer-facing half
# ---------------------------------------------------------------------------


def test_the_loader_refuses_a_lock_that_records_no_preserved_bytes():
    """Every caller of `load_toolchains` inherits the refusal, so no script has to remember
    to ask — the same wiring `identity_problems` has."""
    import _manifest

    original = _manifest.artifact_record_problems
    try:
        _manifest.artifact_record_problems = lambda _doc: ["synthetic missing archive"]
        try:
            _manifest.load_toolchains()
        except _manifest.ManifestError as exc:
            assert "synthetic missing archive" in str(exc)
        else:
            raise AssertionError("load_toolchains returned a lock it should have refused")
    finally:
        _manifest.artifact_record_problems = original


def test_verify_says_nothing_on_stdout():
    """`load` prints an image id a caller substitutes into `docker run`, and it calls
    `verify` first — so a report on stdout is read as part of that id. Measured, not feared:
    the first real run of the lane died with `docker: invalid reference format`."""
    import contextlib
    import io

    tool = load_tool("extraction-image")
    for doc in (
        resolved(f"sha256:{'2' * 64}"),          # ABSENT, on an empty store
        {"extraction_container": {"state": "unresolved"}},
    ):
        out, err = io.StringIO(), io.StringIO()
        root = Path(tempfile.mkdtemp(prefix="extraction-store-quiet-"))
        os.environ[STORE_ENV] = str(root)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                tool._verify(doc)
        finally:
            os.environ.pop(STORE_ENV, None)
        assert out.getvalue() == "", f"verify wrote to stdout: {out.getvalue()!r}"
        assert err.getvalue() != "", "verify said nothing at all, on either stream"


def test_the_preserved_bytes_are_part_of_the_model_stamp_identity():
    """A stamp naming only the image identity would stay valid across a store whose file had
    been replaced, and the archive is the only copy this repository can still execute."""
    import _lean_model

    identity = _lean_model.extraction_identity(resolved(f"sha256:{'2' * 64}"))
    assert identity.get("extraction_container.archive_digest") == f"sha256:{'2' * 64}"
    assert identity.get("extraction_container.artifact_digest") == IMAGE


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
