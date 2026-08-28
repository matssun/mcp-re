// SPDX-License-Identifier: Apache-2.0
//! The mechanism payloads for keys held in GCP Cloud KMS.

/// Which Cloud KMS key version signs responses, and how this deployment reaches it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GcpKmsSigningSourceRequest {
    /// Fully-qualified `projects/.../cryptoKeyVersions/N` of the `EC_SIGN_ED25519`
    /// response-signing key version.
    pub key_version: Option<String>,
    /// A non-default Cloud KMS endpoint (emulator/test), held to the endpoint-authority
    /// guard: on GCP every request to it also carries a live workload-identity bearer
    /// token.
    pub endpoint: Option<String>,
    /// Take the OAuth2 bearer from the GCE/GKE metadata server (workload identity)
    /// instead of an operator-supplied `MCP_RE_GCP_ACCESS_TOKEN`.
    pub use_metadata: bool,
}

/// The second, distinct Cloud KMS key version that custodies the channel-establishment
/// key.
///
/// Independent of the response-signing key version and a separate security principal an
/// operator should scope with its own IAM policy. It reuses this deployment's endpoint and
/// credential mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpKmsChannelKeyRequest {
    /// Fully-qualified `projects/.../cryptoKeyVersions/N` of the channel key version. Its
    /// presence is what selects non-exporting channel custody.
    pub key_version: String,
}
