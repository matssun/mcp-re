# SPDX-License-Identifier: Apache-2.0
"""The owner-approval ledger, read as evidence rather than as a file that exists.

`docs/security/owner-approvals-*.jsonl` is the ruling log: one line per owner signature,
carrying the signed `text` and its `sha256`. It is NOT the review axis — `verification/reviews/`
is, and a review record there is what `_review.derive_review_state` compares against the
tree. The ledger is the cross-check that a review record or a claim correction is backed by
an owner act that says what it is relied on to say.

Two kinds of ledger line, told apart by `source`:

    an ENTRY approval   `source` names one registry entry
                        (`verification/policy/assumptions.toml [[assumption]] id = "ASM-0071"`)
                        and `text` IS that entry, as `entry_text` renders it. It approves
                        exactly those bytes: the entry as it stands now is approved only if
                        its rendering hashes to a signed `sha256`.
    a RULING approval   any other `source` (a re-adjudication item, an in-session ruling).
                        `text` is the owner's prose. It approves what it names in
                        `surfaces`, and it cannot be compared to an entry's bytes.

Every line must hash: `sha256(text) == sha256`. A line that does not is a corrupted or
hand-edited signature, and the whole ledger is refused rather than the line skipped —
skipping would let a forged line be ignored while a reader believed the ledger was checked.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

#: Where the ledger lives, relative to the repository root.
LEDGER_GLOB = "docs/security/owner-approvals-*.jsonl"

#: The keys every ledger line carries. Closed in the required direction only: the ledger has
#: grown descriptive fields (`superseded_sha256`, `reference_correction`, …) and those are
#: the owner's to add.
_REQUIRED = {"ruling", "approved_by", "approved", "sha256", "text", "source"}

#: An entry approval's `source`: the registry file, the table, and the one id it signs.
ENTRY_SOURCE = re.compile(
    r'^verification/policy/(?P<file>assumptions|theorems)\.toml '
    r'\[\[(?P<table>assumption|theorem)\]\] id = "(?P<id>(?:ASM|THM)-\d{4})"'
)


class ApprovalError(Exception):
    """The ledger cannot be read as evidence. Fail closed: the caller refuses."""


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_ledger(repo_root: Path) -> list[dict]:
    """Every ledger line, each with `_file` set to its repository-relative path."""
    out: list[dict] = []
    for path in sorted(repo_root.glob(LEDGER_GLOB)):
        rel = path.relative_to(repo_root).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            where = f"{rel}:{number}"
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ApprovalError(f"{where}: unparsable ({exc})") from exc
            if not isinstance(row, dict) or not _REQUIRED <= set(row):
                raise ApprovalError(f"{where}: missing {sorted(_REQUIRED - set(row or {}))}")
            if text_digest(str(row["text"])) != row["sha256"]:
                raise ApprovalError(
                    f"{where}: `sha256` is not the digest of `text` — the signature does "
                    f"not cover what the line says it signed"
                )
            out.append({**row, "_file": rel})
    return out


def entry_subject(row: dict) -> str | None:
    """The id an ENTRY approval signs, or None for a ruling approval."""
    match = ENTRY_SOURCE.match(str(row.get("source", "")))
    return match.group("id") if match else None


def names(row: dict, subject: str) -> bool:
    """Whether a ledger line speaks about `subject` at all."""
    return entry_subject(row) == subject or subject in row.get("surfaces", [])


def entry_text(registry_text: str, subject: str) -> str | None:
    """`subject`'s registry entry as an entry approval signs it: from its `[[table]]` header
    to the next header, without the comment lines and blank lines that end the block — a
    comment between two entries introduces the next one, so it is not part of what was
    signed — and ending in exactly one newline."""
    table = "assumption" if subject.startswith("ASM-") else "theorem"
    blocks = re.split(r"(?m)^(?=\[\[%s\]\])" % table, registry_text)
    for block in blocks:
        if re.search(r'(?m)^id = "%s"$' % re.escape(subject), block):
            lines = block.rstrip().split("\n")
            while lines and (not lines[-1].strip() or lines[-1].lstrip().startswith("#")):
                lines.pop()
            return "\n".join(lines).rstrip() + "\n"
    return None


def ledger_state(
    subject: str, current_text: str | None, ledger: list[dict], *, allow_ruling: bool
) -> tuple[bool, str]:
    """Whether the ledger backs `subject` AS IT STANDS.

    If any ENTRY approval signs this subject, one of them must sign the current entry's bytes:
    a signature over an earlier version is evidence about that version only.

    With no entry approval, `allow_ruling` decides. An assumption is a premise every claim
    above it inherits, and the owner's prose cannot be compared to an entry's bytes, so for
    assumptions it is False: only an entry approval at the current text backs one. Theorem
    specification records predate the ledger and are the owner's own commits naming a
    fingerprint, so for theorems it is True: the ledger can only refute them, by signing
    their entry at some other text.
    """
    entries = [row for row in ledger if entry_subject(row) == subject]
    if entries:
        if current_text is None:
            return False, f"{subject} is not in the registry, so no signature can be current"
        digest = text_digest(current_text)
        signed = [row for row in entries if row["sha256"] == digest]
        if signed:
            return True, f"signed at its current text by {signed[-1]['ruling']}"
        return False, (
            f"the ledger signs {subject} only at {len(entries)} earlier text(s); the entry "
            f"now hashes {digest[:16]}"
        )
    if allow_ruling:
        return True, "no entry approval signs it; its review record is the authority"
    return False, f"no owner-approval ledger line signs {subject}'s entry text"
