// SPDX-License-Identifier: Apache-2.0
//! The client-side signing ambassador (MCPS-014, ADR-MCPS-003 signing locus),
//! rebuilt on the RFC 9421 carrier (ADR-MCPRE-050).
//!
//! [`HostSigner`] is the local key/actor context. It owns the agent's Ed25519
//! signing key PRIVATELY: there is no accessor that returns the key or a raw
//! signature, so model logic that holds a `HostSigner` can request a fully signed
//! MCP-RE request but can never extract the key or forge a signature itself
//! (ADR-MCPS-003: the model never holds keys).
//!
//! Signing is delegated to `mcp-re-client-core` (the shared RFC 9421 evidence
//! seam): the host composes the HTTP-profile request evidence block and signs the
//! RFC 9421 HTTP Message Signature + RFC 9530 Content-Digest. There is NO object/JCS
//! `_meta` signature.

use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::build_signed_tool_call;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::SignedRequest;
use mcp_re_core::SigningKey;
use serde_json::Map;
use serde_json::Value;

/// A client-side signer holding the agent identity and its private signing key.
///
/// The key is never exposed: only [`HostSigner::sign_request`] /
/// [`HostSigner::sign_tool_call`] can use it, and they return a finished, signed
/// [`SignedRequest`] — not a key or a detached signature.
pub struct HostSigner {
    signing_key: SigningKey,
    signer: String,
    key_id: String,
}

impl HostSigner {
    /// Construct a host signer from the agent's signing key and identity.
    pub fn new(
        signing_key: SigningKey,
        signer: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        HostSigner {
            signing_key,
            signer: signer.into(),
            key_id: key_id.into(),
        }
    }

    /// The signer identity (public — this is an identity, not a secret).
    pub fn signer(&self) -> &str {
        &self.signer
    }

    /// The key id (public — names the key, does not reveal it).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    // NOTE: there is deliberately NO accessor for `signing_key`. The private key
    // never leaves the host; model logic cannot read it or construct signatures.

    /// Compose and sign an RFC 9421 request, returning the signed request.
    ///
    /// `params` is the method's parameter object. `target_uri`/`audience` are the
    /// canonical `@target-uri` and the resolved audience tuple; `artifact_bindings`
    /// are the (required, non-empty) authorization bindings; `nonce`/`created`/
    /// `expires` are the RFC 9421 freshness parameters (Unix seconds).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_request(
        &self,
        id: &Value,
        method: &str,
        params: Map<String, Value>,
        target_uri: &str,
        audience: AudienceTuple,
        artifact_bindings: Vec<ArtifactBinding>,
        nonce: &str,
        created: i64,
        expires: i64,
    ) -> Result<SignedRequest, HttpProfileError> {
        let inputs = RequestSigningInputs::new(
            self.key_id.clone(),
            audience,
            artifact_bindings,
            nonce,
            created,
            expires,
        );
        build_signed_request(id, method, params, target_uri, &inputs, &self.signing_key)
    }

    /// Convenience for the common `tools/call` case.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_tool_call(
        &self,
        id: &Value,
        tool_name: &str,
        arguments: Value,
        target_uri: &str,
        audience: AudienceTuple,
        artifact_bindings: Vec<ArtifactBinding>,
        nonce: &str,
        created: i64,
        expires: i64,
    ) -> Result<SignedRequest, HttpProfileError> {
        let inputs = RequestSigningInputs::new(
            self.key_id.clone(),
            audience,
            artifact_bindings,
            nonce,
            created,
            expires,
        );
        build_signed_tool_call(id, tool_name, arguments, target_uri, &inputs, &self.signing_key)
    }
}
