// SPDX-License-Identifier: Apache-2.0
//! Which source files the drift guards read, and where they live in the workspace.
//!
//! Data, kept apart from the resolver that uses it. The two change for entirely different
//! reasons: this table moves whenever a guard gains an input or a file is relocated, and
//! [`super::resolve_runfile`] moves only when the runfiles/cargo lookup itself changes. A
//! resolver that grows every time an unrelated guard adds an input is a resolver nobody can
//! read for what it does.
//!
//! What it does NOT hold is the security-traceability guard's witness map — the per-test
//! sources each manifest claim is evidenced by. That is a different fact with a different
//! owner ([`super::traceability_sources`]): this table answers *where does a guard's input
//! live*, and that one answers *which test witnesses a claim*. They sat together only
//! because both resolve through the same lookup.
//!
//! Note what this table IS: a hand-maintained list of a guard's inputs, and therefore the
//! exact shape ADR-MCPRE-066 §2.1 warns about — it describes yesterday's architecture on
//! the day a file moves. Two things keep that honest rather than latent. Every consumer
//! resolves through `resolve_runfile`, which FAILS loudly on a path that is not there
//! instead of scanning nothing; and the guards that can state their claim structurally
//! (ADR-MCPRE-066 Slice 2) no longer depend on this list being complete.

pub(super) const SOURCE_FALLBACKS: &[(&str, &str)] = &[
    // Conformance + traceability manifests
    (
        "MCP_RE_SECURITY_MANIFEST",
        "mcp-re-conformance/security_traceability_manifest.json",
    ),
    // ADR-MCPS-034: Core src sentinel (method-name drift guard scans its dir).
    ("MCP_RE_CORE_SRC_LIB", "mcp-re-core/src/lib.rs"),
    // ADR-MCPS-035: frozen error taxonomy + audit vocabulary (the audit drift
    // guard asserts every audit rejection reason ∈ McpReError::wire_code()).
    ("MCP_RE_CORE_SRC_ERROR", "mcp-re-core/src/error.rs"),
    ("MCP_RE_CORE_SRC_AUDIT", "mcp-re-core/src/audit.rs"),
    // The REAL producer of audit rejection reasons: the RFC 9421 serving path
    // reaches its verdict as an `HttpProfileError` and hands `wire_code()` to the
    // audit sink, so the vocabulary guard checks THIS taxonomy mints no token of its
    // own — the containment itself is now a type property (ADR-MCPRE-066 Slice 2).
    (
        "MCP_RE_PROFILE_SRC_ERROR",
        "mcp-re-http-profile/src/error.rs",
    ),
    // ADR-MCPRE-066 Slice 2: where the carrier's Core verdicts are decided, and from
    // which its wire token is derived rather than spelled a second time.
    (
        "MCP_RE_PROFILE_SRC_PROJECTION",
        "mcp-re-http-profile/src/error/core_projection.rs",
    ),
    // The replay-tier gate, a third producer of audit rejection reasons.
    (
        "MCP_RE_PROXY_SRC_DISPATCH",
        "mcp-re-proxy/src/http_profile_dispatch.rs",
    ),
    (
        "MCP_RE_PROXY_SRC_DISPATCH_PROJECTION",
        "mcp-re-proxy/src/http_profile_dispatch/core_projection.rs",
    ),
    // The client seam's binding-spec refusal, the fourth producer — rendered by both
    // published SDKs, and the one this list had never been told about.
    (
        "MCP_RE_CLIENT_CORE_SRC_BINDING_REFUSAL",
        "mcp-re-client-core/src/binding_spec/refusal.rs",
    ),
    (
        "MCP_RE_CLIENT_CORE_SRC_PROJECTION",
        "mcp-re-client-core/src/core_projection.rs",
    ),
    // ADR-MCPRE-056 §8: a projected plane's own source, read by the reach-back rule
    // that asserts materialization names no configuration type.
    // ADR-MCPRE-056 §8 fourth clause: the composition root's own source, read by the
    // raw-read inventory that pins which request fields it still consumes directly.
    ("MCP_RE_APP_SRC", "mcp-re-proxy/src/app.rs"),
    // ADR-MCPRE-057 §4: the serving path's own source, read by the transition-ownership
    // rule that asserts no event a stage establishes is also advanced by the assembly.
    (
        "MCP_RE_HTTP_PROFILE_SERVE_SRC",
        "mcp-re-proxy/src/http_profile_serve/mod.rs",
    ),
    (
        "MCP_RE_TRUST_PLANE_SRC",
        "mcp-re-proxy/src/trust_plane/mod.rs",
    ),
    ("MCP_RE_TLS_PLANE_SRC", "mcp-re-proxy/src/tls_plane/mod.rs"),
    (
        "MCP_RE_REPLAY_PLANE_SRC",
        "mcp-re-proxy/src/replay_plane/mod.rs",
    ),
    (
        "MCP_RE_SIGNING_PLANE_SRC",
        "mcp-re-proxy/src/signing_plane/mod.rs",
    ),
    (
        "MCP_RE_DELEGATED_WIRING_SRC",
        "mcp-re-proxy/src/delegated_wiring.rs",
    ),
    // The operator-facing guide whose worked example is fed to the real `parse_args`
    // + `ValidatedDeployment::try_from`, so a command line the docs teach cannot drift
    // into one the proxy refuses to start with.
    ("MCP_RE_SIDECAR_GUIDE", "docs/sidecar-deployment-guide.md"),
    // Per-crate BUILD.bazel (read by drift / traceability guards)
    ("MCP_RE_BUILD_CONFORMANCE", "mcp-re-conformance/BUILD.bazel"),
    ("MCP_RE_BUILD_CORE", "mcp-re-core/BUILD.bazel"),
    ("MCP_RE_BUILD_DEMO", "mcp-re-demo/BUILD.bazel"),
    ("MCP_RE_BUILD_HOST", "mcp-re-host/BUILD.bazel"),
    ("MCP_RE_BUILD_POLICY", "mcp-re-policy/BUILD.bazel"),
    ("MCP_RE_BUILD_PROXY", "mcp-re-proxy/BUILD.bazel"),
    ("MCP_RE_BUILD_TRANSPORT", "mcp-re-transport/BUILD.bazel"),
    // ADR-MCPS-036: proposal-facing docs scanned by the forbidden-claim guard.
    (
        "MCP_RE_DOC_SECURITY_BOUNDARY",
        "docs/spec/security-boundary.md",
    ),
    ("MCP_RE_DOC_CLAIM_MATRIX", "docs/spec/v0.5-claim-matrix.md"),
    (
        "MCP_RE_DOC_THREAT_COVERAGE",
        "docs/spec/threat-coverage-matrix.md",
    ),
    ("MCP_RE_DOC_COMPOSABILITY", "docs/spec/composability.md"),
    ("MCP_RE_DOC_PROPOSAL_SCOPE", "docs/spec/proposal-scope.md"),
    (
        "MCP_RE_DOC_SECURITY_BOUNDARY_STUB",
        "docs/SECURITY_BOUNDARY.md",
    ),
];
