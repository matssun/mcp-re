<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-Party Dependencies

This document records the dependency-license policy for MCP-RE.

## Policy

MCP-RE should use dependencies that are compatible with Apache-2.0 distribution and with the goal of future MCP ecosystem adoption.

Security-sensitive dependencies should be pinned through the repository's normal dependency-locking mechanism.

## Current inventory

The inventory is **not** maintained by hand here. `deny.toml` is the authoritative,
machine-checked allow-list, and it is enforced over all four Cargo lockfiles by
`.github/workflows/mcp-re-supply-chain.yml`. A hand-copied table of a few crates
cannot stay true against a resolved tree of ~250, and a stale row reads as a
verified fact — so the list lives where it is checked.

Regenerate the full per-crate listing (crate, version, license) at any time:

```
cargo deny --manifest-path Cargo.toml list
```

Every license id in the resolved tree, and why it is allowed, is documented inline
in the `[licenses]` section of `deny.toml`. As of this writing the tree resolves to
Apache-2.0, MIT, BSD-3-Clause, ISC, Unicode-3.0, Unlicense, CDLA-Permissive-2.0
(the Mozilla CA root **data** in `webpki-roots`), and Apache-2.0 WITH
LLVM-exception (`target-lexicon`, a pyo3 build dependency). All are permissive and
Apache-2.0-distribution compatible; no copyleft crate is present or allowed.

## Release requirement

A dependency with a restrictive or unclear license fails the supply-chain gate
rather than reaching a release: `deny.toml` allows an explicit set of license ids
with no blanket allow-all, and its `[advisories]` `ignore` list is deliberately
empty, so a RustSec vulnerability, an unmaintained/unsound advisory, or a yanked
crate blocks the gate instead of being silently suppressed.

## Supply-chain note

The current project may be lockfile-reproducible with network access rather than offline-hermetic. If offline or air-gapped reproducibility is required, add a separate supply-chain hardening workstream for vendoring, registry mirroring, and provenance verification.
