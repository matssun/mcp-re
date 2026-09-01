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
    private key, a PKCS#8/PKCS#12 blob. The binary formats are covered by their
    own detector (`binary_key_signature` / `BINARY_KEY_SUFFIXES`), because the
    line-oriented scan below decodes UTF-8 and a .p12/.der/.jks key is exactly
    the thing that does not decode — matching nothing while the gate reported
    green.
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
        # Every PEM/armor label that carries a private key, including the OpenPGP
        # one — whose real header is `-----BEGIN PGP PRIVATE KEY BLOCK-----`, so a
        # `PGP ` alternative in front of a bare `PRIVATE KEY-----` never matches an
        # actual armored key.
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"),
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


#: Suffixes whose formats carry NOTHING BUT private key material — there is no
#: public-artifact use of a .p12/.jks/.pk8, so the name alone is the finding and
#: the file need not be parsed. `.pem`/`.key`/`.crt` are deliberately absent:
#: those names carry public certificates and CA bundles just as often, and a gate
#: that cries wolf gets disabled. Their private-key case is caught by content —
#: the PEM pattern above, or `binary_key_signature` below.
BINARY_KEY_SUFFIXES: dict[str, str] = {
    ".p12": "a PKCS#12 bundle exists to carry a private key",
    ".pfx": "a PKCS#12 bundle exists to carry a private key",
    ".jks": "a Java keystore exists to carry private keys",
    ".bcfks": "a Bouncy Castle keystore exists to carry private keys",
    ".keystore": "a keystore exists to carry private keys",
    ".pk8": "a PKCS#8 blob is a private key",
    ".p8": "a PKCS#8 blob is a private key",
    ".ppk": "a PuTTY private key",
    ".kdbx": "a KeePass database is a credential store",
}


def der_private_key_kind(data: bytes) -> str | None:
    """Name the DER structure if `data` opens as one that carries a private key.

    ASN.1 DER gives an exact discriminator and it costs a header parse. Every
    private-key container opens as a SEQUENCE whose FIRST member is a version
    INTEGER, and the value separates them:

      3  PKCS#12 PFX
      1  SEC1 ECPrivateKey (RFC 5915) — what `openssl ecparam -genkey -outform DER`
         writes, i.e. an EC TLS or signing key in its most ordinary binary form
      0  PKCS#8 PrivateKeyInfo, PKCS#1 RSAPrivateKey, traditional DSA

    An X.509 certificate, a CRL, a CSR and a public SubjectPublicKeyInfo all open
    with a NESTED SEQUENCE (0x30) as their first member, never an INTEGER, so none
    of them can collide with any of the three.

    Not covered here: PKCS#8 EncryptedPrivateKeyInfo, whose first member is an
    AlgorithmIdentifier SEQUENCE and is therefore shaped exactly like a
    certificate. Distinguishing it needs OID matching, which would trade this
    zero-false-positive property for coverage of the one form that is at least
    password-wrapped; the `.p8`/`.pk8` suffix rule is what catches it by name.
    """
    if len(data) < 4 or data[0] != 0x30:
        return None
    length_octet = data[1]
    if length_octet & 0x80:
        header = 2 + (length_octet & 0x7F)
    else:
        header = 2
    body = data[header : header + 3]
    if body == b"\x02\x01\x03":
        return "a PKCS#12 bundle exists to carry a private key"
    if body == b"\x02\x01\x01":
        return "a DER SEC1 ECPrivateKey is a private key"
    if body == b"\x02\x01\x00":
        return "a DER PKCS#8 / PKCS#1 blob is a private key"
    return None


def binary_key_signature(data: bytes) -> str | None:
    """The reason `data` is private key material, or None.

    A file that does not decode as UTF-8 is not a file with nothing in it — it is
    the exact shape a .p12/.der/.jks key has, and it is what the line-oriented
    scan cannot see.
    """
    if data.startswith(b"\xfe\xed\xfe\xed"):
        return "a Java keystore (JKS magic) exists to carry private keys"
    if data.startswith(b"\xce\xce\xce\xce"):
        return "a JCEKS keystore exists to carry private keys"
    der = der_private_key_kind(data)
    if der is not None:
        return der
    # A PEM block inside a file that is otherwise not valid UTF-8 — the armor is
    # ASCII either way, so match it on the raw bytes.
    if re.search(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", data):
        return "a private key belongs in a secret store, never in git"
    return None


def scan_binary(path: str, data: bytes) -> list[tuple[str, int, str, str]]:
    """Suffix and magic-byte hits for one tracked file, reported at line 0."""
    hits = []
    suffix = Path(path).suffix.lower()
    if suffix in BINARY_KEY_SUFFIXES:
        hits.append((path, 0, "key-material-file", BINARY_KEY_SUFFIXES[suffix]))
    why = binary_key_signature(data)
    if why is not None:
        hits.append((path, 0, "binary-private-key", why))
    return hits


#: Exclusion patterns that must appear in EVERY file that decides what leaves this
#: repository. Two such files exist and they govern different transfers:
#: `.dockerignore` keeps a path out of an image LAYER, `.gcloudignore` keeps it out
#: of the tarball `gcloud builds submit .` uploads to
#: gs://<project>_cloudbuild/source/, which is readable by every principal with
#: project-level storage read and survives the build.
#:
#: These paths are exactly the ones a developer is TOLD to fill in with real
#: credentials — `work/` because it is gitignored, `.aws/` / `.kube/` because that is
#: where the tooling writes them. Being gitignored is why the scan above cannot see
#: them, and gcloud reads `.gcloudignore` INSTEAD of `.gitignore` when it exists, so
#: the ignore list is the whole control. Round 6 added them to one file and not the
#: other; this check is what makes that asymmetry impossible to reintroduce.
UPLOAD_IGNORE_FILES: tuple[str, ...] = (".dockerignore", ".gcloudignore")
REQUIRED_UPLOAD_EXCLUSIONS: tuple[str, ...] = (
    "work/",
    "**/work/",
    "**/.env",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/kubeconfig",
    ".aws/",
    ".gcloud/",
    ".kube/",
    # Local agent and editor state. `.claude/` is TRACKED, so it is not even gitignored:
    # `COPY . .` and `git archive HEAD` both emit it unconditionally, and
    # `.claude/settings.local.json` is where env vars and MCP server tokens live.
    ".claude/",
    "**/.claude/",
    ".verification/",
)

#: Patterns one upload-ignore file may carry alone, with the reason. Everything else must
#: appear in BOTH — see `asymmetric_upload_exclusions`.
#:
#: The list above is a FLOOR, and a floor is why round 8 got through: `.claude/` and
#: `.verification/` were added to `.gcloudignore` alone, the floor did not name them, and
#: a gate that only checks a fixed list has nothing to say about a pattern nobody thought
#: to add to it. Parity is the property that does not need the list to be complete.
FILE_SPECIFIC_UPLOAD_EXCLUSIONS: dict[str, dict[str, str]] = {
    ".dockerignore": {
        "**/*.rs.bk": "rustfmt backup litter; build-size only",
    },
    ".gcloudignore": {
        "node_modules/": "build size; the image build needs no npm tree",
        "**/node_modules/": "build size",
        ".venv*/": "build size",
        "**/.venv*/": "build size",
        "sdk/**/dist/": "build size; the Docker build produces its own",
        "sdk/**/native/": "build size; the Docker build produces its own",
    },
}


def missing_upload_exclusions(text: str) -> list[str]:
    """Which REQUIRED_UPLOAD_EXCLUSIONS an ignore file's body does not carry.

    Whole-line equality, not a substring search: `work/` appearing inside a comment
    that explains the rule is not the rule, and that is the exact shape the
    unremediated `.gcloudignore` had — a long preamble and no pattern.
    """
    present = {line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")}
    return [pattern for pattern in REQUIRED_UPLOAD_EXCLUSIONS if pattern not in present]


def patterns_of(text: str) -> set[str]:
    """The rules an ignore file states, which is not the same as what it says.

    Comment lines are dropped: a preamble explaining that `work/` must be excluded is not
    an exclusion of `work/`, and that is the exact shape the unremediated `.gcloudignore`
    had.
    """
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def asymmetric_upload_exclusions(bodies: dict[str, str]) -> list[tuple[str, str]]:
    """`(file, pattern)` for every rule one upload-ignore file carries and the other lacks.

    The two files govern different transfers — `.dockerignore` keeps a path out of an image
    LAYER, `.gcloudignore` out of the tarball `gcloud builds submit` uploads — but a path
    too sensitive to appear in one is too sensitive to appear in the other, so the sets must
    agree. A deliberate difference is declared in `FILE_SPECIFIC_UPLOAD_EXCLUSIONS` with the
    reason, which is why every difference is either justified or a finding.

    This is what `REQUIRED_UPLOAD_EXCLUSIONS` alone cannot do. A required list can only
    check the patterns someone already thought to require; parity checks the ones they did
    not, which is where the last two gaps were.
    """
    found = []
    for name, text in bodies.items():
        others = set().union(*(patterns_of(b) for n, b in bodies.items() if n != name))
        allowed = FILE_SPECIFIC_UPLOAD_EXCLUSIONS.get(name, {})
        for pattern in sorted(patterns_of(text) - others - allowed.keys()):
            found.append((name, pattern))
    return found


def scan_upload_ignores() -> list[tuple[str, int, str, str]]:
    """Every credential exclusion missing from, or unmatched between, the ignore files."""
    hits = []
    bodies = {}
    for name in UPLOAD_IGNORE_FILES:
        path = REPO / name
        if not path.is_file():
            hits.append((name, 0, "upload-ignore-missing",
                         "this file decides what leaves the repo; its absence is not a default"))
            continue
        bodies[name] = path.read_text(encoding="utf-8")
        for pattern in missing_upload_exclusions(bodies[name]):
            hits.append((name, 0, "upload-ignore-gap",
                         f"{pattern!r} is not excluded, so it ships with the build context"))
    if len(bodies) == len(UPLOAD_IGNORE_FILES):
        others = [n for n in UPLOAD_IGNORE_FILES]
        for name, pattern in asymmetric_upload_exclusions(bodies):
            missing_from = ", ".join(n for n in others if n != name)
            hits.append((name, 0, "upload-ignore-asymmetry",
                         f"{pattern!r} is excluded here and not in {missing_from}. Add it "
                         f"there, or declare it in FILE_SPECIFIC_UPLOAD_EXCLUSIONS with "
                         f"the reason it is build-size only"))
    return hits


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
            data = full.read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            continue  # vanished or a submodule entry
        # EVERY tracked file goes through the binary detector, decodable or not: a
        # .p12 that happens to be valid UTF-8 is still a PKCS#12 key, and the
        # line-oriented pass below would not see it.
        hits.extend(scan_binary(rel, data))
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue  # not line-oriented; scan_binary above is what covers it
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
    # The real OpenPGP armor header. The pattern used to spell this
    # `-----BEGIN PGP PRIVATE KEY-----`, which no tool emits, so an armored key
    # passed the gate.
    (True, "-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    (True, "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    (True, "-----BEGIN DSA PRIVATE KEY-----"),
    (False, "-----BEGIN CERTIFICATE-----"),
    (False, "-----BEGIN PUBLIC KEY-----"),
]

#: `(should_flag, name, bytes)` for the binary detector — the class the
#: line-oriented scan structurally cannot see. Without these the extension and
#: magic-byte rules are untested code, which is the same failure mode as the
#: guard this file replaced.
BINARY_SELFTEST_CASES: list[tuple[bool, str, bytes]] = [
    # PKCS#12: SEQUENCE (long-form length) then version INTEGER 3.
    (True, "bundle.bin", b"\x30\x82\x04\x00\x02\x01\x03\x30\x82\x03\xc6"),
    # DER PKCS#8 PrivateKeyInfo: version INTEGER 0.
    (True, "key.bin", b"\x30\x82\x01\x54\x02\x01\x00\x30\x0d\x06\x09"),
    # SEC1 ECPrivateKey (RFC 5915), version INTEGER 1 — the literal first bytes of
    # `openssl ecparam -genkey -name prime256v1 -outform DER`, i.e. an EC TLS key
    # in its most ordinary binary form. Short-form length, so the version follows
    # the header immediately.
    (True, "ec.bin", b"\x30\x77\x02\x01\x01\x04\x20\x11\x22\x33\x44"),
    (True, "store.bin", b"\xfe\xed\xfe\xed\x00\x00\x00\x02"),
    # A .p12 is a private key by name; the bytes need not be parsed.
    (True, "client.p12", b"not even DER"),
    (True, "server.jks", b"\x00\x01\x02\x03"),
    # An armored key inside a file the UTF-8 pass cannot decode.
    (True, "mixed.bin", b"\xff\xfe binary \n-----BEGIN OPENSSH PRIVATE KEY-----\n"),
    # Must NOT flag. A DER X.509 certificate: the outer SEQUENCE's first member is
    # the tbsCertificate SEQUENCE (0x30), never a version INTEGER.
    (False, "cert.der", b"\x30\x82\x03\x1c\x30\x82\x02\x04\xa0\x03\x02\x01\x02"),
    (False, "logo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"),
    (False, "fixture.json", b'{"schema": "mcp-re-scitt-service-trust-pin/v1"}'),
    (False, "chain.pem", b"-----BEGIN CERTIFICATE-----\nMIIB\n"),
]

#: `(should_flag, label, ignore-file body)`. The first case is the VERBATIM
#: `.gcloudignore` this check was written against — the one that excluded build
#: output and nothing else while `.dockerignore` already carried the credential
#: block. Without it the parity check is code that has only ever seen a passing
#: input.
#: `(should_flag, label, {file: body})` for the PARITY half. The first case is the round-8
#: shape verbatim — an exclusion added to one file and not the other, which the required
#: list could not see because nobody had added it to the required list either. That is the
#: whole reason parity exists beside the floor, so it is the case the check is written
#: against.
UPLOAD_PARITY_SELFTEST_CASES: list[tuple[bool, str, dict[str, str]]] = [
    (
        True,
        "round 8: an agent-state exclusion added to one file only",
        {".dockerignore": "work/\n", ".gcloudignore": "work/\n.claude/\n"},
    ),
    (
        True,
        "an exclusion present only in a comment on the other side",
        {".dockerignore": "work/\n# .claude/\n", ".gcloudignore": "work/\n.claude/\n"},
    ),
    (
        False,
        "the same rules on both sides",
        {".dockerignore": "work/\n.claude/\n", ".gcloudignore": ".claude/\nwork/\n"},
    ),
    (
        False,
        "a difference declared as build-size only",
        {".dockerignore": "work/\n**/*.rs.bk\n", ".gcloudignore": "work/\nnode_modules/\n"},
    ),
    (
        True,
        "a difference that is NOT the declared one",
        {".dockerignore": "work/\n**/*.rs.bk\n", ".gcloudignore": "work/\n.ssh/\n"},
    ),
]

UPLOAD_IGNORE_SELFTEST_CASES: list[tuple[bool, str, str]] = [
    (
        True,
        "the pre-remediation .gcloudignore (build output only)",
        "# Keep the Cloud Build upload small.\n"
        ".git/\ntarget/\n**/target/\nnode_modules/\n**/node_modules/\n"
        ".venv*/\n**/.venv*/\nsdk/**/dist/\nsdk/**/native/\n*.log\n",
    ),
    (
        True,
        "the exclusions named only inside a comment",
        "".join(f"# {pattern}\n" for pattern in REQUIRED_UPLOAD_EXCLUSIONS),
    ),
    (
        True,
        "one exclusion dropped from an otherwise complete list",
        "".join(f"{pattern}\n" for pattern in REQUIRED_UPLOAD_EXCLUSIONS[1:]),
    ),
    (
        False,
        "every exclusion present",
        "*.log\n" + "".join(f"{pattern}\n" for pattern in REQUIRED_UPLOAD_EXCLUSIONS),
    ),
]


def selftest() -> int:
    failures = 0
    for should_flag, sample in SELFTEST_CASES:
        flagged = bool(scan_text("<selftest>", sample))
        if flagged != should_flag:
            verb = "did not flag" if should_flag else "wrongly flagged"
            print(f"SELFTEST FAIL: detector {verb}: {sample!r}")
            failures += 1
    for should_flag, name, data in BINARY_SELFTEST_CASES:
        flagged = bool(scan_binary(name, data))
        if flagged != should_flag:
            verb = "did not flag" if should_flag else "wrongly flagged"
            print(f"SELFTEST FAIL: binary detector {verb}: {name} {data[:16]!r}")
            failures += 1
    for should_flag, label, body in UPLOAD_IGNORE_SELFTEST_CASES:
        flagged = bool(missing_upload_exclusions(body))
        if flagged != should_flag:
            verb = "did not flag" if should_flag else "wrongly flagged"
            print(f"SELFTEST FAIL: upload-ignore check {verb}: {label}")
            failures += 1
    for should_flag, label, bodies in UPLOAD_PARITY_SELFTEST_CASES:
        flagged = bool(asymmetric_upload_exclusions(bodies))
        if flagged != should_flag:
            verb = "did not flag" if should_flag else "wrongly flagged"
            print(f"SELFTEST FAIL: upload-ignore parity {verb}: {label}")
            failures += 1
    total = (len(SELFTEST_CASES) + len(BINARY_SELFTEST_CASES)
             + len(UPLOAD_IGNORE_SELFTEST_CASES) + len(UPLOAD_PARITY_SELFTEST_CASES))
    if failures:
        print(f"\n{failures} selftest case(s) failed — the gate is not trustworthy.")
        return 1
    print(f"selftest ok: {total} cases")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    hits = scan_upload_ignores() + scan_repo()
    if not hits:
        print("tracked-secrets gate: clean")
        return 0

    print("Credential material is reachable from a tracked file or a build upload:\n")
    for path, lineno, name, why in hits:
        print(f"  {path}:{lineno}  [{name}] {why}")
    print(
        "\nFor a tracked file: remove the value and rotate it — a tracked file is "
        "public history even after a later commit deletes it. Use a placeholder, or "
        "read it from the environment. If a match is a genuine false positive, add "
        "the path to ALLOWED_PATHS with the reason it is safe.\n"
        "For an upload-ignore gap: add the pattern verbatim. `.dockerignore` and "
        "`.gcloudignore` govern different transfers, so both need it."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
