<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-Party Dependencies

This document records the dependency-license policy for MCP-S.

## Policy

MCP-S should use dependencies that are compatible with Apache-2.0 distribution and with the goal of future MCP ecosystem adoption.

Security-sensitive dependencies should be pinned through the repository's normal dependency-locking mechanism.

## Current inventory

Fill this table from the repository's lockfiles and dependency manifests before public release.

| Dependency | Purpose | License | Runtime / Dev | Notes |
|---|---|---:|---:|---|
| rustls | TLS/mTLS | TBD | Runtime | Verify actual license from package metadata. |
| ring | Cryptography dependency | TBD | Runtime | Verify actual license from package metadata. |
| x509-parser | X.509 parsing | TBD | Runtime | Verify actual license from package metadata. |
| rcgen | Test certificate generation | TBD | Dev/Test | Verify actual license from package metadata. |
| serde / serde_json | Serialization | TBD | Runtime | Verify actual license from package metadata. |

## Release requirement

Before public release, replace `TBD` values with verified license information from package metadata.

If a dependency has a restrictive or unclear license, resolve it before proposing MCP-S upstream.

## Supply-chain note

The current project may be lockfile-reproducible with network access rather than offline-hermetic. If offline or air-gapped reproducibility is required, add a separate supply-chain hardening workstream for vendoring, registry mirroring, and provenance verification.
