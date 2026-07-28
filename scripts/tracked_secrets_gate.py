#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tracked-file secret / personal-identifier gate (CI gate).

`scripts/test-gcp-cloud.sh.example` promised a guard "asserts none of the real
identifiers ever land in a tracked file", and
`scripts/bazel_gazelle_gate.py` allowlisted it as a permanent cargo-only guard.
It did not exist: the crate it named (`mcp-re-walkthrough`) is not in the
workspace and its test file is nowhere in the tree, so the control could never
run and never fail. This is that guard, implemented.

**Scope, stated honestly.** This is NOT "no GCP identifier may be committed" —
that invariant was never true and should not be. The disposable test project id
is deliberately tracked, because `docs/security/gcp-kms-root-rotation.sh` uses it
as an `ALLOWED_PROJECTS` fence: a destructive KMS rotation refuses to run against
any project not on that list, so the id has to be *in the file* to bound the
blast radius. A gate that forbade it would delete a safety control.

What this gate forbids is the class the template was actually worried about:

  * **Private key material** in a tracked file — PEM private-key blocks, an SSH
    private key, a PKCS#8/PKCS#12 blob.
  * **Credential documents** — a GCP service-account JSON key (recognised by its
    `"private_key"` + `"private_key_id"` pair), an AWS access-key id.
  * **Personal account identifiers** — a real `@gmail.com` / `@googlemail.com`
    address, or a `*-compute@developer.gserviceaccount.com` /
    `*.iam.gserviceaccount.com` account with a concrete project in it.
  * **Bearer-shaped secrets** — a GitHub token, a Google OAuth refresh token, a
    Slack token.

Test fixtures are the obvious false-positive source, and they are handled by
being explicit rather than by pattern-guessing: a file is scanned unless it is on
`ALLOWED_PATHS` (with a stated reason). A deterministic 32-byte demo seed is not
a secret and does not match these patterns anyway.

Run:  python3 scripts/tracked_secrets_gate.py            # scan tracked files
      python3 scripts/tracked_secrets_gate.py --selftest # prove the detector
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Paths excluded from the scan, each with the reason it is safe to exclude.
#: Prefix match against the repo-relative path.
ALLOWED_PATHS: dict[str, str] = {
    # This gate has to name the patterns it forbids in order to forbid them.
    "scripts/tracked_secrets_gate.py": "the detector itself",
    # Frozen pre-ADR-MCPRE-050 history; never edited, never re-run.
    "docs/archive/": "frozen historical material",
}

#: `(name, compiled pattern, what it means)`. Each pattern is deliberately narrow:
#: a gate that cries wolf gets disabled, and a disabled gate is the state this
#: file exists to correct.
PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        "a private key belongs in a secret store, never in git",
    ),
    (
        "gcp-service-account-key",
        re.compile(r'"private_key_id"\s*:\s*"[0-9a-f]{8,}"'),
        "a GCP service-account JSON key grants the account's full authority",
    ),
    (
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "an AWS access-key id names a live credential",
    ),
    (
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "a GitHub token grants repository authority",
    ),
    (
        "google-oauth-refresh-token",
        re.compile(r"\b1//[0-9A-Za-z_-]{30,}\b"),
        "a Google refresh token mints access tokens indefinitely",
    ),
    (
        "slack-token",
        re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
        "a Slack token grants workspace authority",
    ),
    (
        "personal-mail-account",
        re.compile(r"\b[A-Za-z0-9._%+-]+@(?:gmail|googlemail)\.com\b"),
        "a personal account identifier; use a placeholder",
    ),
    (
        "gcp-service-account-email",
        # A concrete `<name>@<project>.iam.gserviceaccount.com`. Placeholders
        # (`<gsa>@<project>...`, `YOUR_...`, `$VAR`) do not match: the project
        # part is restricted to characters a real project id can contain.
        re.compile(r"\b[a-z0-9][a-z0-9-]{2,}@[a-z0-9][a-z0-9-]{2,}\.iam\.gserviceaccount\.com\b"),
        "a concrete service-account identity; use a placeholder",
    ),
    (
        "gcp-default-compute-account",
        # The default compute SA is `<projectNumber>-compute@developer...`, so the
        # numeric prefix is what makes it concrete. A runbook that DERIVES it at
        # runtime — `$(gcloud projects describe ... )-compute@developer...` —
        # commits no identity and must not be flagged, which is why the digits are
        # required rather than matching the `-compute@` suffix alone.
        re.compile(r"\b\d{6,}-compute@developer\.gserviceaccount\.com\b"),
        "a concrete service-account identity; use a placeholder",
    ),
]


def tracked_files() -> list[str]:
    """Every tracked path, from git. The git tree IS the subject under test."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    return [p for p in out.stdout.split("\0") if p]


def is_allowed(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in ALLOWED_PATHS)


def scan_text(path: str, text: str) -> list[tuple[str, int, str, str]]:
    """Every (path, line-number, pattern-name, reason) hit in `text`."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern, why in PATTERNS:
            if pattern.search(line):
                hits.append((path, lineno, name, why))
    return hits


def scan_repo() -> list[tuple[str, int, str, str]]:
    hits = []
    for rel in tracked_files():
        if is_allowed(rel):
            continue
        full = REPO / rel
        try:
            text = full.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or vanished; nothing line-oriented to scan
        hits.extend(scan_text(rel, text))
    return hits


#: `(should_flag, sample)` — proves the detector fires on what it must and stays
#: quiet on what the repo legitimately contains. Without this, a gate that
#: silently matches nothing is indistinguishable from a clean tree, which is
#: exactly how the guard this replaces went unnoticed.
SELFTEST_CASES: list[tuple[bool, str]] = [
    (True, "-----BEGIN PRIVATE KEY-----"),
    (True, "-----BEGIN OPENSSH PRIVATE KEY-----"),
    (True, '  "private_key_id": "a1b2c3d4e5f6a7b8",'),
    (True, "AKIAIOSFODNN7EXAMPLE"),
    (True, "ghp_" + "A" * 36),
    (True, "token: xoxb-1234567890-abcdefghij"),
    (True, "someone@gmail.com"),
    (True, "svc-runner@my-real-project.iam.gserviceaccount.com"),
    (True, "123456789012-compute@developer.gserviceaccount.com"),
    # Must NOT flag — these are what the repo actually, correctly contains.
    (False, 'ALLOWED_PROJECTS=("project-b19bbb5e-9be8-4fcb-a2f")'),
    (False, "_AR: us-central1-docker.pkg.dev/project-b19bbb5e-9be8-4fcb-a2f/mcp-re"),
    (False, "account = YOUR_GCP_ACCOUNT@example.com"),
    (False, "  iam.gke.io/gcp-service-account: <gsa>@<project>.iam.gserviceaccount.com"),
    (False, "mats@sundvall.name"),
    # Derived at runtime from a gcloud lookup — no identity is committed.
    (
        False,
        "CBSA=\"$(gcloud projects describe \"$PROJECT\" "
        "--format='value(projectNumber)')-compute@developer.gserviceaccount.com\"",
    ),
    (False, "const CLIENT_SEED: [u8; 32] = [11u8; 32];"),
    (False, "did:example:server-1"),
]


def selftest() -> int:
    failures = 0
    for should_flag, sample in SELFTEST_CASES:
        flagged = bool(scan_text("<selftest>", sample))
        if flagged != should_flag:
            verb = "did not flag" if should_flag else "wrongly flagged"
            print(f"SELFTEST FAIL: detector {verb}: {sample!r}")
            failures += 1
    if failures:
        print(f"\n{failures} selftest case(s) failed — the gate is not trustworthy.")
        return 1
    print(f"selftest ok: {len(SELFTEST_CASES)} cases")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    hits = scan_repo()
    if not hits:
        print("tracked-secrets gate: clean")
        return 0

    print("Tracked files carry credential material or personal identifiers:\n")
    for path, lineno, name, why in hits:
        print(f"  {path}:{lineno}  [{name}] {why}")
    print(
        "\nRemove the value and rotate it — a tracked file is public history even "
        "after a later commit deletes it. Use a placeholder, or read it from the "
        "environment. If a match is a genuine false positive, add the path to "
        "ALLOWED_PATHS with the reason it is safe."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
