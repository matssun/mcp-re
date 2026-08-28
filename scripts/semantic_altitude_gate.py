#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Semantic-altitude gate — no provider-qualified sibling on the top-level request.

ADR-MCPRE-067 §16.3, §21.2. After the signing-source migration, a new provider or
mechanism adds one typed mechanism payload, one tagged variant, one adapter and its
evidence. It does NOT add a provider-qualified field beside the selector on
`DeploymentRequest`, because that shape is what the migration removed: 17 sibling fields
whose meaning depended on a `key_source` discriminator, and a nine-entry table of
"belongs to a different custody source" refusals explaining why a request did not mean
what it said.

## What this checks, and what it deliberately does not

It reads ONE struct — `DeploymentRequest`'s field declarations — and refuses a field
whose name carries a mechanism qualifier from a family that has already been migrated.

It is not a forbidden-word grep over the repository, and must not become one. AWS is
legal in an AWS adapter; `AwsKmsSigningSourceRequest` is the correct name for an AWS
payload, and `ocsp.rs` is the correct name for an RFC 6960 implementation. The control
enforces architectural DIRECTION at one boundary, which is the only thing a name-based
check can honestly enforce.

## Why it carries a registry of families not yet migrated

`DeploymentRequest` still has Redis, etcd, OCSP and CRL siblings. Those are ADR Phases 4
and 5 and are listed in `NOT_YET_MIGRATED` with the phase that owns them. The gate
therefore states what it does NOT check, rather than passing silently over it: an
unlisted family is refused, and a family whose fields have all left must be removed from
the registry — so the list can only shrink, and finishing a phase is a visible edit here.

That direction matters more than the check itself. A gate whose scope is invisible
reports "OK" for a boundary nobody has examined.

Run:  python3 scripts/semantic_altitude_gate.py
      python3 scripts/semantic_altitude_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The request whose field declarations are the subject.
REQUEST = Path("mcp-re-proxy/src/deployment_request/mod.rs")
REQUEST_TYPE = "DeploymentRequest"

#: Mechanism qualifiers that may NOT appear in a top-level field name. Each names a
#: family whose configuration is already a typed mechanism payload, so a sibling field
#: for it would be a regression to the shape the migration removed.
MIGRATED: dict[str, str] = {
    "aws": "ADR-MCPRE-067 Phase 2 — AwsKmsSigningSourceRequest / AwsKmsChannelKeyRequest",
    "gcp": "ADR-MCPRE-067 Phase 2 — GcpKmsSigningSourceRequest / GcpKmsChannelKeyRequest",
    "kms": "ADR-MCPRE-067 Phase 2 — the KMS payloads under deployment_request::signing_source",
    "pkcs11": "ADR-MCPRE-067 Phase 2 — Pkcs11SigningSourceRequest / Pkcs11ChannelKeyRequest",
    "sts": "ADR-MCPRE-067 Phase 2 — AwsKmsSigningSourceRequest::sts_endpoint",
    "irsa": "ADR-MCPRE-067 Phase 2 — AwsKmsSigningSourceRequest::use_web_identity",
    "spiffe": "no mechanism payload exists; a new one must not start as a sibling field",
    "spire": "no mechanism payload exists; a new one must not start as a sibling field",
    "rustls": "a library name is never a request coordinate",
    "tls": (
        "ADR-MCPRE-067 Phase 3 — ChannelCredentialRequest carries the credential chain "
        "and the tagged ChannelKeyRequest"
    ),
    "x509": "ADR-MCPRE-067 Phase 3 — a certificate format is never a request coordinate",
    "cose": "no mechanism payload exists; a new one must not start as a sibling field",
    "jose": "no mechanism payload exists; a new one must not start as a sibling field",
    "jws": "no mechanism payload exists; a new one must not start as a sibling field",
}

#: Families whose siblings are still on the request, with the phase that owns them.
#: Fields matching these are reported as KNOWN and not refused. The registry may only
#: shrink: a family with no matching field left must be deleted from it.
NOT_YET_MIGRATED: dict[str, str] = {
    "redis": "Phase 4 — replay, continuity and storage",
    "etcd": "Phase 4 — replay, continuity and storage",
    "cpstore": "Phase 4 — replay, continuity and storage",
    "ocsp": "Phase 5 — revocation",
    "crl": "Phase 5 — revocation",
    "mtls": "Phase 6 — the ingress-assertion inputs, which no proving slice has reached",
}

FIELD = re.compile(r"^\s*pub ([a-z][a-z0-9_]*)\s*:", re.MULTILINE)


def request_fields(text: str) -> list[str]:
    """The field names declared by `struct DeploymentRequest { ... }`.

    Read from the struct body only. A `pub x:` inside another type in the same file, or
    inside a doc comment, is not a field of the subject.
    """
    start = text.index(f"pub struct {REQUEST_TYPE} {{")
    depth = 0
    end = start
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    body = text[start:end]
    return [match.group(1) for match in FIELD.finditer(body)]


def qualifier_hits(field: str, qualifiers: dict[str, str]) -> list[str]:
    """The qualifiers a field name carries, matched on word parts rather than substrings.

    `crl` must not match `crl_paths` by accident of spelling and miss `client_crl_paths`,
    and `sts` must not match a field merely containing those letters. Splitting on `_`
    and comparing whole parts answers both.
    """
    parts = set(field.split("_"))
    return sorted(q for q in qualifiers if q in parts)


def check(text: str) -> tuple[list[str], list[str]]:
    """Refusals, and the known-outstanding fields, for one request source."""
    problems: list[str] = []
    known: list[str] = []
    seen_families: set[str] = set()
    for field in request_fields(text):
        for qualifier in qualifier_hits(field, MIGRATED):
            problems.append(
                f"`{REQUEST_TYPE}::{field}` carries the mechanism qualifier "
                f"`{qualifier}`. That family already has a typed mechanism payload "
                f"({MIGRATED[qualifier]}); a new value belongs inside it, not beside "
                f"the selector"
            )
        outstanding = qualifier_hits(field, NOT_YET_MIGRATED)
        seen_families.update(outstanding)
        # One line per FIELD, not per qualifier: `cpstore_etcd_endpoint` carries two and
        # is still one field awaiting one phase.
        if outstanding:
            known.append(
                f"{REQUEST_TYPE}::{field} — {NOT_YET_MIGRATED[outstanding[0]]}"
            )
    for qualifier in sorted(set(NOT_YET_MIGRATED) - seen_families):
        problems.append(
            f"`{qualifier}` is registered in NOT_YET_MIGRATED but no "
            f"`{REQUEST_TYPE}` field carries it — its migration is done, so remove the "
            f"entry rather than leaving the gate claiming an exemption nothing uses"
        )
    return problems, known


def selftest() -> int:
    """Prove the gate fails on the shape it exists to refuse."""
    failures = 0

    regressed = (
        "pub struct DeploymentRequest {\n"
        "    /// doc\n"
        "    pub aws_kms_region: Option<String>,\n"
        "    pub tls_key: String,\n"
        "    pub client_crl_paths: Vec<String>,\n"
        "    pub replay_redis_url: Option<String>,\n"
        "    pub cpstore_etcd_endpoint: Option<String>,\n"
        "    pub client_ocsp: OcspKind,\n"
        "    pub ingress_pinned_mtls: bool,\n"
        "}\n"
    )
    problems, known = check(regressed)
    if not any("aws_kms_region" in p for p in problems):
        print("selftest FAIL: a re-added AWS sibling field was accepted")
        failures += 1
    if not any("tls_key" in p for p in problems):
        print("selftest FAIL: a re-added channel-credential sibling field was accepted")
        failures += 1
    if not any("client_crl_paths" in k for k in known):
        print("selftest FAIL: an outstanding Phase-5 field was not reported as known")
        failures += 1

    clean = regressed.replace("    pub aws_kms_region: Option<String>,\n", "").replace(
        "    pub tls_key: String,\n", ""
    )
    problems, _ = check(clean)
    if problems:
        print(f"selftest FAIL: a clean request was refused: {problems}")
        failures += 1

    # A family whose fields have all gone must leave the registry.
    emptied = clean.replace("    pub client_ocsp: OcspKind,\n", "")
    problems, _ = check(emptied)
    if not any("`ocsp` is registered" in p for p in problems):
        print("selftest FAIL: a stale NOT_YET_MIGRATED entry was accepted")
        failures += 1

    # Substring matching would make `sts` fire on a field it does not qualify.
    if qualifier_hits("hosts_checked", MIGRATED):
        print("selftest FAIL: a qualifier matched a substring rather than a word part")
        failures += 1

    if failures:
        return 1
    print("semantic-altitude gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    source = REPO / REQUEST
    if not source.is_file():
        print(f"semantic-altitude gate: FAIL — {REQUEST} does not exist")
        return 1
    problems, known = check(source.read_text(encoding="utf-8"))

    if problems:
        print(f"semantic-altitude gate: FAIL — {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        print(
            "\nA new mechanism adds one typed payload, one tagged variant, one adapter "
            "and its evidence (ADR-MCPRE-067 §16.3)."
        )
        return 1

    print(
        f"semantic-altitude gate: OK — {REQUEST_TYPE} carries no sibling field for a "
        f"migrated mechanism family ({', '.join(sorted(MIGRATED))})."
    )
    print(f"  Still outstanding, by the phase that owns each ({len(known)} field(s)):")
    for entry in known:
        print(f"    - {entry}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
