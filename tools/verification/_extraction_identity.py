# SPDX-License-Identifier: Apache-2.0
"""WHICH extraction container the pinned digest IS — computed, not remembered.

The image's identity is a function of the toolchain it contains: the Charon and Aeneas
commits, their compilers, the Lean toolchain, the mathlib revision, the Dockerfile that
assembles them, and the platform. `tools/verification/extraction-image` derives a tag from
exactly those and the lock records the digest a build of them produced.

# The gap this module closes

That recording was one-directional. The lock's own note says the tag is "for human
navigation only — nothing resolves through it", which is true of RESOLUTION and was taken as
true of CHECKING: nothing recomputed it. So when the Dockerfile changed — three times, to
install the Lean toolchain and build the Aeneas Lean backend with mathlib — the pinned digest
went on naming an image built from the old one, and every consumer read a valid pin.

The Dockerfile was put into the hash precisely to catch "a build-step change slipping in
under an unchanged tag". One slipped in anyway, because the derived tag was never compared to
the recorded one. Computing it is the whole fix.

# Two different questions, kept apart

*Is the record internally consistent?* — does the recorded tag follow from the pins and the
definition the image was built from. A mismatch means the lock was hand-edited or a pin moved
without a republish, and it is always fatal: an identity that does not follow from its own
inputs is not an identity.

*Is the record CURRENT?* — is the definition the image was built from the definition the tree
declares now. A mismatch here is not a corrupt record, it is a known state: somebody changed
the Dockerfile and has not published and pinned the result. Publishing is deliberately
operator-only (`workflow_dispatch`, "publishing an image is minting a new evidence
identity"), so this must be *statable* rather than merely fatal — otherwise the tree is red
for as long as it takes a human to run a workflow, which is how a gate gets disabled.

It becomes fatal exactly where it can mislead: when a unit actually asks the extraction lane
for evidence. That is the same condition the workflow already uses to decide whether to pull
the image at all.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = REPO / "verification" / "extraction" / "Dockerfile"

#: The platform the pinned image is built for. An amd64 build of identical pins is a
#: DIFFERENT image with a different digest, which is why it is part of the identity.
PLATFORM = "linux/arm64"


def definition_digest(dockerfile: Path | None = None) -> str:
    """SHA-256 of the Dockerfile's exact bytes."""
    path = DOCKERFILE if dockerfile is None else dockerfile
    return hashlib.sha256(path.read_bytes()).hexdigest()


def content_tag(toolchains: dict, definition: str | None = None) -> str:
    """The tag a build of these pins and this definition produces.

    `definition` is the Dockerfile digest to compute against. It defaults to the tree's
    current Dockerfile, which is what a PUBLISHER wants; a VALIDATOR passes the digest the
    pinned image was built from, so the two questions above stay separable.
    """
    charon = toolchains.get("charon", {})
    aeneas = toolchains.get("aeneas", {})
    lean = toolchains.get("lean", {})
    backend = toolchains.get("aeneas_lean_backend", {})

    parts = [
        f"charon={charon.get('commit', '')}",
        f"charon_rustc={charon.get('rust_toolchain', '')}",
        f"aeneas={aeneas.get('commit', '')}",
        f"ocaml={aeneas.get('ocaml_compiler', '')}",
        f"lean={lean.get('toolchain', '')}",
        f"mathlib={backend.get('mathlib_revision', '')}",
        f"dockerfile={definition_digest() if definition is None else definition}",
        f"platform={PLATFORM}",
    ]
    digest = hashlib.sha256("\n".join(parts).encode()).hexdigest()
    return f"tc-{digest[:16]}"


def identity_problems(toolchains: dict) -> list[str]:
    """Every way the recorded extraction-container identity fails to follow from its inputs.

    Always fatal, because each one means the record does not describe a real build.
    """
    entry = toolchains.get("extraction_container")
    if not isinstance(entry, dict) or entry.get("state") != "resolved":
        return []
    where = "toolchains.lock.toml: [extraction_container]"
    problems: list[str] = []

    # An identity with no ARTIFACT is not an identity. The declared inputs do not determine
    # the image — this definition still resolves apt and opam versions at build time, and
    # those build the Aeneas binary — so the bytes that were actually produced have to be
    # recorded rather than derived. WHERE they are kept is not this module's business:
    # `artifact_digest` is a content digest over the image, and a local image store and a
    # registry give the same immutability. See
    # verification/reviews/rulings/extraction-artifact-storage-2026-09-09.md.
    if not entry.get("artifact_digest"):
        problems.append(
            f"{where} is resolved but records no `artifact_digest`. The declared pins do "
            "not determine the image, so an identity that names none says which toolchain "
            "was INTENDED and nothing about which one ran."
        )

    built_from = entry.get("definition_digest")
    if not built_from:
        return [
            f"{where} is resolved but records no `definition_digest`. The identity names "
            "an image somebody built from SOME Dockerfile; without saying which, nothing can "
            "check that the recorded tag follows from it, and a build-step change slips in "
            "under an unchanged tag — which is the failure this field exists to make "
            "impossible."
        ]
    expected = content_tag(toolchains, built_from)
    recorded = entry.get("tag")
    if recorded != expected:
        problems.append(
            f"{where} records tag {recorded!r}, but its own pins and "
            f"definition_digest compute {expected!r}. An identity that does not follow "
            "from its inputs is not an identity: either a pin moved without a republish, "
            "or the record was edited by hand."
        )
    return problems


def definition_drift(toolchains: dict) -> str | None:
    """The pinned image's definition against the one this tree declares, or None if current.

    NOT a corrupt record — a known state. `verification/extraction/Dockerfile` has changed
    and no build of it has been published and pinned. The caller decides how loud that is:
    it is fatal where a unit asks the extraction lane for evidence, and a stated fact
    otherwise.
    """
    entry = toolchains.get("extraction_container")
    if not isinstance(entry, dict) or entry.get("state") != "resolved":
        return None
    built_from = entry.get("definition_digest")
    current = definition_digest()
    if not built_from or built_from == current:
        return None
    return (
        "the pinned extraction container was built from "
        f"verification/extraction/Dockerfile@{built_from[:12]}, and this tree declares "
        f"@{current[:12]}. The pinned artifact is therefore NOT a build of the declared "
        f"definition: it computes tag {content_tag(toolchains, built_from)!r} where the "
        f"tree computes {content_tag(toolchains)!r}. Rebuild the current definition "
        "(.github/workflows/extraction-image.yml) and move the pin onto the identity it "
        "reports."
    )
