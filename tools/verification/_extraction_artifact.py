# SPDX-License-Identifier: Apache-2.0
"""WHERE the pinned extraction environment's BYTES are kept, and whether they are still there.

`_extraction_identity` answers *which* environment the lock names. This module answers the
question that one cannot: *does the thing it names still exist, and is what exists it?*

# A digest is identity, not preservation

The 2026-09-09 ruling established that no proposition requires a registry: a content digest
identifies an image whether the bytes sit in a registry or a local image store, and this
lane runs on one machine. What that left unsaid is that the local image store is
**disposable**. `docker image prune`, a Docker reset, a full disk — each removes the only
copy of an artifact this repository cannot rebuild.

It cannot rebuild it because the build is not reproducible, and that is measured rather than
feared: the Dockerfile resolves apt package versions and opam library versions at build time,
and the opam libraries are linked into the Aeneas binary. A rebuild is a DIFFERENT
instrument. So an artifact identity plus a disposable store is a claim that stays
*identifiable* and stops being *reproducible* the moment the cache is cleared — the lock
would name an environment nothing on earth could execute again.

The artifact is therefore persisted outside Docker's state, under its own digest, and every
consumption checks it. Docker's cache is an execution optimisation; it is not an evidence
store, and a lane that runs whatever sits under the pinned tag is a lane reporting on
whatever was lying around.

# Two digests, because they answer two questions

    artifact_digest   the image's own content digest — what EXECUTES once loaded, and the
                      identity every fingerprint and every stamp already carries
    archive_digest    SHA-256 over the preserved archive's exact bytes — the independent
                      check that the file in the store IS that image's preserved form

The store is addressed by the first and verified against the second. One digest could not do
both: the archive is a container format around the image, so its bytes are not the image's
digest, and checking a file by loading it would mean loading several gigabytes to discover
that they were the wrong ones.

# Still deliberately not a registry

The ruling stands and this does not reopen it. The bytes live in a directory on the
verification runner. A host that does not hold them CANNOT run the lane — `ABSENT` is
UNAVAILABLE, never a silent rebuild — and moving them between hosts is an operator act
(`scp`), not a resolution step.

# What is NOT claimed

That the artifact can be reconstructed from the Dockerfile indefinitely. It cannot, for the
reason in the first section, and the residual unpinned apt/opam inputs are a measured
limitation rather than an unnoticed one. What a preserved artifact establishes is the
honest, weaker thing:

    this theorem was checked against THIS exact preserved extraction artifact.

Pinning the complete Debian and opam dependency closure would raise that to a reconstruction
claim. That is future assurance work, and it is deliberately not a precondition here.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

#: The store's location, overridable so the controls can exercise a real directory rather
#: than a mocked one. An env var rather than a flag: every consumer resolves the same store
#: without threading it down a call chain, and a test that sets it cannot accidentally
#: measure the operator's real one.
STORE_ENV = "MCP_RE_EXTRACTION_ARTIFACT_STORE"

#: Beside the Verus install root, and for the same reason: `/opt/verification` is the
#: persistent, operator-owned tree that survives a Docker reset, a prune, and a VM
#: recreate. A path under the repository would be gitignored build output; a path under
#: Docker's own state is the exact failure this module exists to prevent.
DEFAULT_STORE = Path("/opt/verification/extraction-artifacts")

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Read in chunks. The artifact is several gigabytes, and a digest helper that loads it into
#: memory turns "check the pin" into an out-of-memory failure.
_CHUNK = 1 << 22


def store_root() -> Path:
    """The directory holding preserved artifacts on this host."""
    override = os.environ.get(STORE_ENV)
    return Path(override) if override else DEFAULT_STORE


def artifact_path(artifact_digest: str, root: Path | None = None) -> Path:
    """The one path the preserved form of a given image may live at.

    Addressed by the IMAGE identity, so "the preserved artifact for the pinned environment"
    names exactly one file and a second build cannot overwrite the first's.
    """
    base = store_root() if root is None else root
    return base / "sha256" / f"{artifact_digest.split(':', 1)[-1]}.tar"


def file_digest(path: Path) -> str:
    """`sha256:<hex>` over a file's exact bytes."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def record_problems(toolchains: dict) -> list[str]:
    """Every way the RECORD of the preserved artifact fails to be a record.

    Always fatal, and separate from whether the artifact is present: a lock that does not
    say which archive bytes were preserved is not a lock with a missing file, it is a lock
    that cannot be checked against any file at all.
    """
    entry = toolchains.get("extraction_container")
    if not isinstance(entry, dict) or entry.get("state") != "resolved":
        return []
    where = "toolchains.lock.toml: [extraction_container]"
    problems: list[str] = []
    for field, what in (
        (
            "artifact_digest",
            "the image's own content digest — what EXECUTES once the archive is loaded",
        ),
        (
            "archive_digest",
            "the preserved archive's exact bytes — the independent check that the file in "
            "the store is that image's preserved form",
        ),
    ):
        value = entry.get(field)
        if not value:
            problems.append(
                f"{where} is resolved but records no `{field}`, which names {what}. "
                "Without it a run would execute whatever the local image cache happens to "
                "hold, and the cache is disposable while this image cannot be rebuilt: "
                "apt and opam resolve versions nothing pins, and the opam libraries are "
                "linked into the Aeneas binary."
            )
        elif not _SHA256.match(str(value)):
            problems.append(
                f"{where} records `{field}` = {value!r}, which is not a `sha256:<64 hex>` "
                "digest. A malformed identity matches nothing and fails closed on every "
                "host, which reads as an absent artifact rather than as the malformed "
                "record it is."
            )
    return problems


@dataclass(frozen=True)
class Preservation:
    """What this host can say about the pinned artifact's bytes.

    A value rather than a pair of booleans, because the three outcomes call for opposite
    actions and must never collapse into "not ok": ABSENT is an environment to populate,
    MISMATCH is a substituted or truncated store and is always fatal, and PRESENT is the
    only one a lane may execute from.
    """

    status: str
    path: Path
    detail: str | None = None

    @property
    def usable(self) -> bool:
        return self.status == "PRESENT"


def preservation(toolchains: dict, root: Path | None = None) -> Preservation | None:
    """Whether the pinned artifact exists HERE, and whether it is the pinned artifact.

    Returns None when the container pin is unresolved or its record is malformed: there is
    no artifact to look for, and `unpinned_identities` / `record_problems` are what report
    that. A caller reading None as "fine" would be reading an unpinned lane as a preserved
    one, so every caller asks `record_problems` first.
    """
    entry = toolchains.get("extraction_container")
    if not isinstance(entry, dict) or entry.get("state") != "resolved":
        return None
    image = entry.get("artifact_digest")
    archive = entry.get("archive_digest")
    if not image or not archive:
        return None
    if not _SHA256.match(str(image)) or not _SHA256.match(str(archive)):
        return None
    path = artifact_path(str(image), root)
    if not path.exists():
        return Preservation(
            "ABSENT",
            path,
            f"the preserved extraction artifact for {image} is not on this host "
            f"(expected at {path}). The lane cannot run, and a rebuild is not the remedy: "
            "this definition resolves apt and opam versions at build time and the opam "
            "libraries build the Aeneas binary, so a rebuild is a DIFFERENT instrument "
            "under the same declared pins. Copy the artifact from a host that holds it, or "
            "build, preserve, and move the pin onto the new identity in a reviewed commit.",
        )
    measured = file_digest(path)
    if measured != archive:
        return Preservation(
            "MISMATCH",
            path,
            f"the file at {path} digests {measured}, and the lock records {archive}. It is "
            "sitting under an identity it does not have — substituted, truncated, or "
            "corrupted — and nothing may execute from it.",
        )
    return Preservation("PRESENT", path)
