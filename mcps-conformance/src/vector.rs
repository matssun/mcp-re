//! Conformance-vector data model (MCPS-010).
//!
//! Mirrors the committed fixture schema produced by MCPS-002 under
//! `components/mcps/mcps-core/tests/vectors/`. The vectors are the SINGLE SOURCE
//! OF TRUTH — this module only deserializes them; it never owns a copy.
//!
//! A fixture file is one of three `kind`s:
//!   - `"request"` / `"response"`: carries a `message` JSON object plus an
//!     optional `resolver` entry (signer_key + public key).
//!   - `"raw"`: carries `raw_text` (UTF-8 source) or `raw_bytes_b64url`
//!     (arbitrary bytes, e.g. invalid UTF-8) instead of a `message`.

use serde::Deserialize;
use serde_json::Value;

/// The expected outcome of running a vector through verification.
///
/// `VerifyOk` ⇔ the fixture's `"expected"` was the literal `"verify_ok"`;
/// otherwise it is an `mcps.*` wire token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    /// Verification (or, for raw fixtures, canonicalization) succeeds.
    VerifyOk,
    /// Verification fails with the given frozen `mcps.*` wire token.
    Error(String),
}

impl Expected {
    /// Parse the fixture's `expected` string into the typed outcome.
    pub fn from_token(token: &str) -> Self {
        if token == "verify_ok" {
            Expected::VerifyOk
        } else {
            Expected::Error(token.to_string())
        }
    }

    /// The wire token form (`"verify_ok"` or the `mcps.*` code) for reporting.
    pub fn as_token(&self) -> &str {
        match self {
            Expected::VerifyOk => "verify_ok",
            Expected::Error(code) => code.as_str(),
        }
    }
}

/// The resolver entry committed alongside an OK request/response vector: the
/// `signer#key_id` composite and the Base64URL-no-pad public key.
#[derive(Debug, Clone, Deserialize)]
pub struct ResolverEntry {
    pub signer_key: String,
    pub public_key_b64url: String,
}

/// One conformance vector, deserialized from a committed fixture JSON file.
#[derive(Debug, Clone, Deserialize)]
pub struct VectorCase {
    pub name: String,
    /// `"request"`, `"response"`, or `"raw"`.
    pub kind: String,
    /// Present for request/response kinds; absent for raw kinds.
    #[serde(default)]
    pub message: Option<Value>,
    /// Raw UTF-8 source (raw kind, valid-or-malformed UTF-8 text).
    #[serde(default)]
    pub raw_text: Option<String>,
    /// Raw bytes as Base64URL-no-pad (raw kind, e.g. invalid UTF-8 sequences).
    #[serde(default)]
    pub raw_bytes_b64url: Option<String>,
    /// Raw fixture `expected` token, parsed via [`VectorCase::expected`].
    pub expected: String,
    #[serde(default)]
    pub resolver: Option<ResolverEntry>,
    #[serde(default)]
    pub requires_pipeline: bool,
}

impl VectorCase {
    /// The typed expected outcome.
    pub fn expected(&self) -> Expected {
        Expected::from_token(&self.expected)
    }
}

/// One entry in the committed `manifest.json` (the ordered vector index).
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestEntry {
    pub name: String,
    pub file: String,
    pub kind: String,
    pub expected: String,
    #[serde(default)]
    pub requires_pipeline: bool,
}
