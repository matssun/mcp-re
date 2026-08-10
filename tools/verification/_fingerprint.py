# SPDX-License-Identifier: Apache-2.0
"""Deterministic ReviewFingerprint over a review unit — ADR-MCPRE-059 §2.

    ReviewFingerprint(U) = H(
        source_inputs, generated_inputs, build_configuration, enabled_features,
        exported_contracts, consumed_contracts, proof_dependencies,
        test_evidence_definition, trusted_assumptions, toolchain_identity,
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

Components not yet implemented (proof artifacts, resolved Cargo features, generated inputs)
are recorded as the explicit sentinel `"unimplemented"` rather than omitted. An omitted
component would silently mean "no such input"; the sentinel means "this input is not yet
accounted for", which the freshness engine reads as UNKNOWN, and unknown is dirty.

Importable as a module — `_graph` and `review-frontier` both need `fingerprint_unit`, and
the `fingerprint` command is a thin CLI over it. It lives here rather than in the
extensionless script because an extensionless file cannot be imported.
"""

from __future__ import annotations

import hashlib
import json

from _manifest import REPO_ROOT

ENCODING_VERSION = 1

UNIMPLEMENTED = "unimplemented"


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


def fingerprint_unit(unit: dict, doc: dict, toolchains: dict, assumptions: dict) -> dict:
    scoped = [
        entry["id"]
        for entry in assumptions.get("assumption", [])
        if f"unit://{unit['id']}" in entry.get("scope", [])
    ]
    components = {
        "encoding_version": ENCODING_VERSION,
        "unit_id": unit["id"],
        "class": unit["class"],
        "source_inputs": _digest_paths(unit["paths"]),
        "generated_inputs": UNIMPLEMENTED,
        "build_configuration": UNIMPLEMENTED,
        "enabled_features": unit.get("features", UNIMPLEMENTED),
        "exported_contracts": sorted(unit.get("exported_contracts", [])),
        "consumed_contracts": sorted(unit.get("consumed_contracts", [])),
        "proof_dependencies": UNIMPLEMENTED,
        "test_evidence_definition": sorted(unit.get("evidence", [])),
        "trusted_assumptions": sorted(scoped),
        "toolchain_identity": _toolchain_identity(toolchains),
        "formal_model_revision": doc.get("formal_model_revision"),
        "threat_model_revision": doc.get("threat_model_revision"),
        "review_policy_revision": doc["policy_revision"],
    }
    canonical = json.dumps(
        components, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return {
        "unit_id": unit["id"],
        "fingerprint": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "components": components,
    }


