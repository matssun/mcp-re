// SPDX-License-Identifier: Apache-2.0
//! Which source files the drift guards read, and where they live in the workspace.
//!
//! Data, kept apart from the resolver that uses it. The two change for entirely different
//! reasons: this table moves whenever a guard gains an input or a file is relocated, and
//! [`super::resolve_runfile`] moves only when the runfiles/cargo lookup itself changes. A
//! resolver that grows every time an unrelated guard adds an input is a resolver nobody can
//! read for what it does.
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
    // ADR-MCPRE-056 §8: a projected plane's own source, read by the reach-back rule
    // that asserts materialization names no configuration type.
    // ADR-MCPRE-056 §8 fourth clause: the composition root's own source, read by the
    // raw-read inventory that pins which request fields it still consumes directly.
    ("MCP_RE_APP_SRC", "mcp-re-proxy/src/app.rs"),
    // ADR-MCPRE-057 §4: the serving path's own source, read by the transition-ownership
    // rule that asserts no event a stage establishes is also advanced by the assembly.
    (
        "MCP_RE_HTTP_PROFILE_SERVE_SRC",
        "mcp-re-proxy/src/http_profile_serve.rs",
    ),
    ("MCP_RE_TRUST_PLANE_SRC", "mcp-re-proxy/src/trust_plane.rs"),
    ("MCP_RE_TLS_PLANE_SRC", "mcp-re-proxy/src/tls_plane.rs"),
    (
        "MCP_RE_REPLAY_PLANE_SRC",
        "mcp-re-proxy/src/replay_plane.rs",
    ),
    (
        "MCP_RE_SIGNING_PLANE_SRC",
        "mcp-re-proxy/src/signing_plane.rs",
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
    // Per-test source files (read by the security-traceability guard)
    //
    // ADR-MCPS-034: the two method-transparency proof artifacts.
    (
        "MCP_RE_SRC_METHOD_TRANSPARENCY",
        "mcp-re-conformance/tests/method_transparency_test.rs",
    ),
    (
        "MCP_RE_SRC_METHOD_NAME_DRIFT_GUARD",
        "mcp-re-conformance/tests/method_name_drift_guard_test.rs",
    ),
    (
        "MCP_RE_SRC_KEY_SOURCE",
        "mcp-re-proxy/tests/key_source_test.rs",
    ),
    (
        "MCP_RE_SRC_DEV_ENV_KEY_SOURCE",
        "mcp-re-proxy/tests/dev_env_key_source_test.rs",
    ),
    (
        "MCP_RE_SRC_MTLS_CLIENT",
        "mcp-re-transport/tests/mtls_client_test.rs",
    ),
    (
        "MCP_RE_SRC_DELEGATED_SERVING",
        "mcp-re-proxy/tests/integration_async/delegated_serving_test.rs",
    ),
    (
        "MCP_RE_SRC_DELEGATED_PROD_WIRING",
        "mcp-re-proxy/tests/integration_async/delegated_production_wiring_test.rs",
    ),
    (
        "MCP_RE_SRC_DELEGATED_E2E",
        "mcp-re-proxy/tests/integration_async/delegated_client_server_e2e_test.rs",
    ),
    (
        "MCP_RE_SRC_DELEGATION_VECTORS",
        "mcp-re-conformance/tests/delegation_vectors_test.rs",
    ),
    (
        "MCP_RE_SRC_ROOT_KEY_LIFECYCLE",
        "mcp-re-proxy/tests/integration_async/root_key_lifecycle_test.rs",
    ),
    (
        "MCP_RE_SRC_ROOT_AUTHORITY_MANIFEST",
        "mcp-re-proxy/tests/integration_async/root_authority_manifest_test.rs",
    ),
    (
        "MCP_RE_SRC_MRT_CONTINUATION",
        "mcp-re-proxy/tests/integration_async/mrt_continuation_serving_test.rs",
    ),
    ("MCP_RE_SRC_CLI", "mcp-re-proxy/src/cli.rs"),
    // MCPS-72 (#252): KMS-lifecycle offline negatives are in-crate #[cfg(test)]
    // unit tests, so the traceability guard reads their src/*.rs (not tests/*.rs).
    (
        "MCP_RE_SRC_KMS_KEYSOURCE",
        "mcp-re-proxy/src/kms_keysource.rs",
    ),
    (
        "MCP_RE_SRC_GCP_KMS_KEYSOURCE",
        "mcp-re-proxy/src/gcp_kms_keysource.rs",
    ),
    (
        "MCP_RE_SRC_AWS_KMS_KEYSOURCE",
        "mcp-re-proxy/src/aws_kms_keysource.rs",
    ),
    // ADR-MCPS-036 gate spine: the conformance-guard test sources the
    // traceability manifest maps for the audit (#151) and forbidden-claim
    // (#155) guards, plus the §A claim matrix read by the §A-coverage check.
    (
        "MCP_RE_SRC_AUDIT_VOCABULARY_GUARD",
        "mcp-re-conformance/tests/audit_vocabulary_guard_test.rs",
    ),
    (
        "MCP_RE_SRC_FORBIDDEN_CLAIM_GUARD",
        "mcp-re-conformance/tests/forbidden_claim_guard_test.rs",
    ),
    // ADR-MCPRE-050 §A witnesses: the RFC 9421 security-property proofs that map
    // each §A capability claim to a green test.
    (
        "MCP_RE_SRC_RFC9421_SECURITY_PROPERTIES",
        "mcp-re-conformance/tests/rfc9421_security_properties_test.rs",
    ),
    ("MCP_RE_CLAIM_MATRIX", "docs/spec/v0.5-claim-matrix.md"),
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
