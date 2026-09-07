// SPDX-License-Identifier: Apache-2.0
//! Which test source witnesses each security-traceability claim.
//!
//! Split from [`super::source_fallbacks`] because the two answer different questions. That
//! table says *where a guard's input lives* and moves when a file is relocated; this one
//! says *which test evidences a manifest claim* and moves when the EVIDENCE changes — a
//! claim gaining a witness, a witness being retired. A relocation and a re-evidencing are
//! not the same event, and a reader asking which test proves a claim should not have to
//! read a BUILD-file index to find out.
//!
//! Consumed through the same `resolve_runfile` lookup, so nothing about how a path is found
//! differs; only what the entry MEANS does.

/// The per-test sources the security-traceability guard reads, and the proof artifacts and
/// claim matrix it maps them against.
pub(super) const TRACEABILITY_SOURCES: &[(&str, &str)] = &[
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
        "mcp-re-proxy/src/kms_keysource/mod.rs",
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
];

#[cfg(test)]
mod tests {
    use super::TRACEABILITY_SOURCES;

    #[test]
    fn every_witness_names_a_file_that_exists() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the crate has a workspace root");
        for (key, rel) in TRACEABILITY_SOURCES {
            assert!(
                root.join(rel).exists(),
                "{key} names {rel}, which does not exist — a witness that cannot be read is \
                 not evidence"
            );
        }
    }

    #[test]
    fn no_witness_is_declared_twice() {
        let mut keys: Vec<&str> = TRACEABILITY_SOURCES.iter().map(|(k, _)| *k).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "a traceability key is declared twice");
    }
}
