//! Signed tool-manifest data types + minting (issue #3866).
//!
//! A [`ToolManifest`] is the serde-serializable artifact a server publishes and
//! signs so a client can cryptographically verify the exact set of tools the
//! server exposes — their names, versions, and input/output schemas — and later
//! detect a "rug pull" (a silent schema/behaviour change under an unchanged
//! identity).
//!
//! ## Signed shape (frozen JSON object)
//!
//! ```text
//! {
//!   "signer":     "<issuer / signing-authority identity>",
//!   "key_id":     "<key id used to resolve the verification key>",
//!   "manifest_id":"<opaque manifest identity (revocation handle)>",
//!   "version":    "<manifest version>",
//!   "issued_at":  <unix secs, optional>,
//!   "expires_at": <unix secs, optional>,
//!   "tools": [
//!     { "name": "...", "version": "...",
//!       "input_schema": { ... }, "output_schema": { ... },
//!       "schema_hash": "sha256:<b64url>" }
//!   ],
//!   "signature": { "alg": "Ed25519", "key_id": "...", "value": "<b64url>" }
//! }
//! ```
//!
//! Each tool's `schema_hash` is `sha256_hash_id(canonicalize(combined schema))`,
//! where the combined schema is the JCS canonicalization of
//! `{ "input": <input_schema>, "output": <output_schema> }`. The manifest
//! signature covers the JCS canonicalization of the WHOLE object with
//! `signature.value` removed — the identical recipe Core / the reference profile
//! use (clone → drop `signature.value` → `canonicalize_json_value` → sign).
//!
//! These are tightly-coupled serde DTOs for one artifact; like `envelope.rs`
//! (RequestEnvelope/ResponseEnvelope/SignatureBlock) and `reference.rs` (its
//! grant DTOs + `mint_reference_grant`) they live in one module.

use mcps_core::canonicalize_json_value;
use mcps_core::sha256_hash_id;
use mcps_core::SigningKey;
use mcps_core::SIG_ALG_ED25519;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;

use crate::manifest_error::ManifestError;

/// The signature block carried at the manifest's top level. Mirrors the Core
/// `SignatureBlock` shape (`alg` / `key_id` / `value`); `value` is the
/// Base64URL-no-pad Ed25519 signature over the canonical manifest minus
/// `signature.value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSignature {
    /// Signature algorithm; MUST be `Ed25519`.
    pub alg: String,
    /// The key id used to resolve the verification key via the `TrustResolver`.
    pub key_id: String,
    /// The Base64URL-no-pad Ed25519 signature value.
    pub value: String,
}

/// One tool's identity + schemas + per-tool schema hash.
///
/// `(name, version)` is the tool identity; `schema_hash` is the integrity binding
/// over the input/output schemas (recomputed and compared at verify time).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolEntry {
    /// The tool name (identity component).
    pub name: String,
    /// The tool version (identity component — part of the rug-pull pin key).
    pub version: String,
    /// The tool's input schema (an arbitrary JSON value).
    pub input_schema: Value,
    /// The tool's output schema (an arbitrary JSON value).
    pub output_schema: Value,
    /// `sha256_hash_id(canonicalize({ "input": input_schema, "output":
    /// output_schema }))`. Recomputed and compared during verification.
    pub schema_hash: String,
}

impl ToolEntry {
    /// Build a [`ToolEntry`], computing `schema_hash` from the supplied schemas via
    /// the in-house JCS canonicalization + SHA-256 hash id. A schema that is not a
    /// JCS-safe value (non-integer numbers, etc.) is [`ManifestError::ManifestMalformed`].
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        input_schema: Value,
        output_schema: Value,
    ) -> Result<Self, ManifestError> {
        let schema_hash = compute_schema_hash(&input_schema, &output_schema)?;
        Ok(ToolEntry {
            name: name.into(),
            version: version.into(),
            input_schema,
            output_schema,
            schema_hash,
        })
    }

    /// Recompute this entry's schema hash from its own `input_schema` /
    /// `output_schema`. Used by the verifier to compare against the recorded
    /// `schema_hash` (reject on mismatch).
    pub fn recompute_schema_hash(&self) -> Result<String, ManifestError> {
        compute_schema_hash(&self.input_schema, &self.output_schema)
    }
}

/// Compute the per-tool schema hash: canonicalize the combined
/// `{ "input": <input>, "output": <output> }` object with the in-house JCS and
/// hash the canonical bytes with `sha256_hash_id`. Wrapping both schemas in one
/// object binds them together so neither can be swapped independently.
pub fn compute_schema_hash(
    input_schema: &Value,
    output_schema: &Value,
) -> Result<String, ManifestError> {
    let combined = json!({ "input": input_schema, "output": output_schema });
    let canon =
        canonicalize_json_value(&combined).map_err(|_| ManifestError::ManifestMalformed)?;
    Ok(sha256_hash_id(&canon))
}

/// The signed tool manifest: manifest-level identity, the tool list, and the
/// signature block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolManifest {
    /// The signing-authority / issuer identity. Resolves a verification key via
    /// the injected `TrustResolver` together with `signature.key_id`.
    pub signer: String,
    /// The key id used to resolve the verification key (mirrors `signature.key_id`;
    /// the verifier resolves on the signature's `key_id`).
    pub key_id: String,
    /// The opaque manifest identity — the handle used for manifest revocation.
    pub manifest_id: String,
    /// The manifest version.
    pub version: String,
    /// Optional issue time, integer unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
    /// Optional expiry time, integer unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// The tools this manifest attests to.
    pub tools: Vec<ToolEntry>,
    /// The Ed25519 signature over the canonical manifest minus `signature.value`.
    pub signature: ManifestSignature,
}

/// The claims used to mint a signed manifest (test/host support). Holds tools as
/// `(name, version, input_schema, output_schema)`; the minter computes each
/// `schema_hash` and the manifest signature.
#[derive(Debug, Clone)]
pub struct ManifestSpec {
    /// The signing-authority identity.
    pub signer: String,
    /// The opaque manifest identity (revocation handle).
    pub manifest_id: String,
    /// The manifest version.
    pub version: String,
    /// Optional issue time, integer unix seconds.
    pub issued_at: Option<i64>,
    /// Optional expiry time, integer unix seconds.
    pub expires_at: Option<i64>,
    /// The tools, each `(name, version, input_schema, output_schema)`.
    pub tools: Vec<ToolSpec>,
}

/// One tool's claims for minting (name + version + the two schemas; the
/// `schema_hash` is derived).
#[derive(Debug, Clone)]
pub struct ToolSpec {
    /// The tool name.
    pub name: String,
    /// The tool version.
    pub version: String,
    /// The tool's input schema.
    pub input_schema: Value,
    /// The tool's output schema.
    pub output_schema: Value,
}

/// Mint a signed [`ToolManifest`]: compute each tool's `schema_hash`, build the
/// object, sign the canonical preimage (object minus `signature.value`) with the
/// issuer key, and return the populated manifest. Pure — signing has no side
/// effects (matches `mint_reference_grant`). Used by tests and the host.
pub fn mint_signed_manifest(
    spec: &ManifestSpec,
    signing_key: &SigningKey,
    key_id: &str,
) -> Result<ToolManifest, ManifestError> {
    let mut tools = Vec::with_capacity(spec.tools.len());
    for tool in &spec.tools {
        tools.push(ToolEntry::new(
            tool.name.clone(),
            tool.version.clone(),
            tool.input_schema.clone(),
            tool.output_schema.clone(),
        )?);
    }

    // Build the unsigned manifest with a placeholder (empty) signature value, then
    // sign the canonicalization of the object with `signature.value` removed.
    let mut manifest = ToolManifest {
        signer: spec.signer.clone(),
        key_id: key_id.to_string(),
        manifest_id: spec.manifest_id.clone(),
        version: spec.version.clone(),
        issued_at: spec.issued_at,
        expires_at: spec.expires_at,
        tools,
        signature: ManifestSignature {
            alg: SIG_ALG_ED25519.to_string(),
            key_id: key_id.to_string(),
            value: String::new(),
        },
    };

    let preimage = manifest_signing_preimage(&manifest)?;
    manifest.signature.value = signing_key.sign(&preimage);
    Ok(manifest)
}

/// Build the canonical signing preimage for a manifest: serialize to a
/// `serde_json::Value`, remove `signature.value`, and canonicalize via the
/// in-house JCS — the identical "canonicalize object minus signature.value"
/// recipe Core / the reference profile use. Serialization or canonicalization
/// failure (e.g. a non-JCS-safe schema number) → [`ManifestError::ManifestMalformed`].
pub fn manifest_signing_preimage(manifest: &ToolManifest) -> Result<Vec<u8>, ManifestError> {
    let mut value =
        serde_json::to_value(manifest).map_err(|_| ManifestError::ManifestMalformed)?;
    match value.get_mut("signature").and_then(Value::as_object_mut) {
        Some(sig) => {
            sig.remove("value");
        }
        None => return Err(ManifestError::ManifestMalformed),
    }
    canonicalize_json_value(&value).map_err(|_| ManifestError::ManifestMalformed)
}

#[cfg(test)]
mod tests {
    use super::compute_schema_hash;
    use super::manifest_signing_preimage;
    use super::mint_signed_manifest;
    use super::ManifestSpec;
    use super::ToolEntry;
    use super::ToolSpec;
    use mcps_core::canonicalize_json_value;
    use mcps_core::sha256_hash_id;
    use mcps_core::SigningKey;
    use serde_json::json;
    use serde_json::Value;

    fn input_schema() -> Value {
        json!({ "type": "object", "properties": { "text": { "type": "string" } } })
    }

    fn output_schema() -> Value {
        json!({ "type": "string" })
    }

    fn spec() -> ManifestSpec {
        ManifestSpec {
            signer: "did:example:server-1".to_string(),
            manifest_id: "manifest-1".to_string(),
            version: "1".to_string(),
            issued_at: Some(1_700_000_000),
            expires_at: Some(1_800_000_000),
            tools: vec![ToolSpec {
                name: "echo".to_string(),
                version: "1.0.0".to_string(),
                input_schema: input_schema(),
                output_schema: output_schema(),
            }],
        }
    }

    #[test]
    fn schema_hash_is_sha256_of_canonical_combined_schema() {
        let combined = json!({ "input": input_schema(), "output": output_schema() });
        let canon = canonicalize_json_value(&combined).unwrap();
        assert_eq!(
            compute_schema_hash(&input_schema(), &output_schema()).unwrap(),
            sha256_hash_id(&canon)
        );
    }

    #[test]
    fn schema_hash_changes_when_schema_changes() {
        let baseline = compute_schema_hash(&input_schema(), &output_schema()).unwrap();
        let changed = compute_schema_hash(
            &json!({ "type": "object", "properties": { "text": { "type": "number" } } }),
            &output_schema(),
        )
        .unwrap();
        assert_ne!(baseline, changed);
    }

    #[test]
    fn tool_entry_new_records_the_computed_hash() {
        let entry = ToolEntry::new("echo", "1.0.0", input_schema(), output_schema()).unwrap();
        assert_eq!(
            entry.schema_hash,
            compute_schema_hash(&input_schema(), &output_schema()).unwrap()
        );
        assert_eq!(entry.recompute_schema_hash().unwrap(), entry.schema_hash);
    }

    #[test]
    fn minted_manifest_carries_a_nonempty_signature_and_hashes() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        assert!(!manifest.signature.value.is_empty());
        assert_eq!(manifest.signature.alg, "Ed25519");
        assert_eq!(manifest.tools.len(), 1);
        assert!(manifest.tools[0].schema_hash.starts_with("sha256:"));
    }

    #[test]
    fn preimage_excludes_signature_value() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        let preimage = manifest_signing_preimage(&manifest).unwrap();
        let text = String::from_utf8(preimage).unwrap();
        assert!(!text.contains(&manifest.signature.value));
        // alg + key_id are retained in the preimage.
        assert!(text.contains("Ed25519"));
        assert!(text.contains("server-key-1"));
    }

    #[test]
    fn preimage_is_independent_of_signature_value() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let mut manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        let baseline = manifest_signing_preimage(&manifest).unwrap();
        manifest.signature.value = "ZGlmZmVyZW50".to_string();
        assert_eq!(baseline, manifest_signing_preimage(&manifest).unwrap());
    }

    #[test]
    fn round_trips_through_serde_json() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let manifest = mint_signed_manifest(&spec(), &key, "server-key-1").unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let back: super::ToolManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, manifest);
    }
}
