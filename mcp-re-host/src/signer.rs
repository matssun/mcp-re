//! The client-side signing ambassador (MCPS-014, ADR-MCPS-003 signing locus).
//!
//! [`HostSigner`] is the local key/actor context. It owns the agent's Ed25519
//! signing key PRIVATELY: there is no accessor that returns the key or a raw
//! signature, so model logic that holds a `HostSigner` can request a fully
//! signed MCP-RE request but can never extract the key or forge a signature
//! itself (ADR-MCPS-003: the model never holds keys).
//!
//! The host injects the request envelope (carrying `on_behalf_of` and
//! `authorization_hash`), computes the canonical signing preimage with
//! `mcp-re-core`, signs it, and returns the wire bytes. Response verification is
//! re-exported from `mcp-re-core` (see the crate root).

use mcp_re_core::request_signing_preimage;
use mcp_re_core::McpReError;
use mcp_re_core::SigningKey;
use mcp_re_core::REQUEST_META_KEY;
use mcp_re_core::SIG_ALG_ED25519;
use mcp_re_core::VERSION_DRAFT_01;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

/// A client-side signer holding the agent identity and its private signing key.
///
/// The key is never exposed: only [`HostSigner::sign_request`] /
/// [`HostSigner::sign_tool_call`] can use it, and they return finished wire
/// bytes — not a key or a detached signature.
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

    /// Inject and sign the request envelope, returning the signed wire bytes.
    ///
    /// `params` is the method's parameter object (e.g. `{"name","arguments"}`
    /// for `tools/call`). Any caller-supplied `_meta` request envelope is
    /// overwritten — the host is the sole author of the `*.request` block.
    /// Taking a [`Map`] makes "params is a JSON object" a type guarantee, so no
    /// runtime shape check is needed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_request(
        &self,
        id: &Value,
        method: &str,
        params: Map<String, Value>,
        on_behalf_of: &str,
        audience: &str,
        authorization_hash: &str,
        nonce: &str,
        issued_at: &str,
        expires_at: &str,
    ) -> Result<Vec<u8>, McpReError> {
        let envelope = json!({
            "version": VERSION_DRAFT_01,
            "signer": self.signer,
            "on_behalf_of": on_behalf_of,
            "audience": audience,
            "authorization_hash": authorization_hash,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signature": { "alg": SIG_ALG_ED25519, "key_id": self.key_id },
        });

        // Merge the envelope into params._meta, overwriting any caller copy.
        let mut params = params;
        let mut meta = params
            .remove("_meta")
            .and_then(|value| match value {
                Value::Object(map) => Some(map),
                _ => None,
            })
            .unwrap_or_default();
        meta.insert(REQUEST_META_KEY.to_string(), envelope);
        params.insert("_meta".to_string(), Value::Object(meta));

        let mut request = json!({
            "id": id.clone(),
            "jsonrpc": "2.0",
            "method": method,
            "params": Value::Object(params),
        });

        // Sign the canonical preimage (signature.value omitted), then graft the
        // signature value into the envelope.
        let preimage = request_signing_preimage(&request)?;
        let signature = self.signing_key.sign(&preimage);
        request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] =
            Value::String(signature);

        serde_json::to_vec(&request).map_err(|_| McpReError::CanonicalizationFailed)
    }

    /// Convenience for the common `tools/call` case: builds
    /// `{"name","arguments"}` params and signs them.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_tool_call(
        &self,
        id: &Value,
        tool_name: &str,
        arguments: Value,
        on_behalf_of: &str,
        audience: &str,
        authorization_hash: &str,
        nonce: &str,
        issued_at: &str,
        expires_at: &str,
    ) -> Result<Vec<u8>, McpReError> {
        let mut params = Map::new();
        params.insert("name".to_string(), Value::String(tool_name.to_string()));
        params.insert("arguments".to_string(), arguments);
        self.sign_request(
            id,
            "tools/call",
            params,
            on_behalf_of,
            audience,
            authorization_hash,
            nonce,
            issued_at,
            expires_at,
        )
    }
}
