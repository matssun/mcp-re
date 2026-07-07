// SPDX-License-Identifier: Apache-2.0
//! Typed artifact-binding verification (ADR-MCPRE-050 §Resolved Q5, MCPRE-95).
//!
//! `artifact_bindings[]` prove that the request is bound to specific external
//! authorization artifacts WITHOUT ever carrying raw secret bytes in evidence.
//! Each binding stores only a digest; the credential surface it commits to
//! (the access token, the client certificate, the RAR `authorization_details`)
//! is supplied to the verifier by the transport — the raw `authorization` /
//! `dpop` headers are RFC 9421-covered exactly once, and the client certificate
//! comes from the mTLS layer. The digest, never the bytes, is the binding.
//!
//! The three typed OAuth-family proofs all reduce to the same primitive —
//! `base64url-no-pad(SHA-256(credential bytes))` — but over different,
//! type-tagged byte sources:
//!
//! - `oauth-dpop` → RFC 9449 `ath` = SHA-256 of the access token;
//! - `oauth-mtls` → RFC 8705 `x5t#S256` = SHA-256 of the DER certificate;
//! - `oauth-rar` → SHA-256 of the canonical RFC 9396 `authorization_details`.
//!
//! A mismatch is [`HttpProfileError::ArtifactBindingFailed`]
//! (`mcp-re.artifact_binding_failed`).

use mcp_re_core::b64url_encode;
use sha2::Digest;
use sha2::Sha256;

use crate::block::ArtifactBinding;
use crate::block::ArtifactType;
use crate::block::BindingType;
use crate::error::HttpProfileError;

/// Extract the bearer credential from an `Authorization` header value. Only the
/// `Bearer` scheme is recognized; the token bytes are the ASCII characters
/// after the single space. Returns `None` for any other scheme/shape.
pub fn bearer_token(authorization_header: &str) -> Option<&str> {
    let rest = authorization_header.strip_prefix("Bearer ")?;
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// `base64url-no-pad(SHA-256(bytes))` — the shared thumbprint primitive.
fn sha256_b64url(bytes: &[u8]) -> String {
    b64url_encode(&Sha256::digest(bytes))
}

/// Verify a DPoP `ath` binding (RFC 9449): the binding digest must equal the
/// SHA-256 thumbprint of `access_token`.
pub fn verify_dpop_ath(
    binding: &ArtifactBinding,
    access_token: &[u8],
) -> Result<(), HttpProfileError> {
    expect_type(binding, ArtifactType::OauthDpop)?;
    compare(binding, access_token)
}

/// Verify an mTLS `x5t#S256` binding (RFC 8705): the binding digest must equal
/// the SHA-256 thumbprint of the client certificate's DER bytes.
pub fn verify_mtls_x5t_s256(
    binding: &ArtifactBinding,
    cert_der: &[u8],
) -> Result<(), HttpProfileError> {
    expect_type(binding, ArtifactType::OauthMtls)?;
    compare(binding, cert_der)
}

/// Verify a RAR binding (RFC 9396): the binding digest must equal the SHA-256
/// thumbprint of the canonical `authorization_details` bytes. The caller
/// supplies the canonical serialization; MCP-RE binds it, never interprets it.
pub fn verify_rar_details(
    binding: &ArtifactBinding,
    authorization_details_canonical: &[u8],
) -> Result<(), HttpProfileError> {
    expect_type(binding, ArtifactType::OauthRar)?;
    compare(binding, authorization_details_canonical)
}

/// Type-dispatched verification for the typed OAuth family. The `credential` is
/// the type-appropriate byte source (token / cert DER / canonical RAR details).
/// The four non-OAuth registry types have no typed verifier yet (MCPRE-95
/// scope): they bind by digest/reference only and are rejected here so a caller
/// cannot silently treat an un-verifiable type as verified.
pub fn verify_artifact_binding(
    binding: &ArtifactBinding,
    credential: &[u8],
) -> Result<(), HttpProfileError> {
    match binding.artifact_type {
        ArtifactType::OauthDpop => verify_dpop_ath(binding, credential),
        ArtifactType::OauthMtls => verify_mtls_x5t_s256(binding, credential),
        ArtifactType::OauthRar => verify_rar_details(binding, credential),
        ArtifactType::PdpDecision
        | ArtifactType::DtrApproval
        | ArtifactType::ClassifierResult
        | ArtifactType::HumanApproval => Err(HttpProfileError::MalformedEvidence(
            "no typed verifier for this artifact_type yet",
        )),
    }
}

fn expect_type(binding: &ArtifactBinding, want: ArtifactType) -> Result<(), HttpProfileError> {
    // The typed OAuth proofs are always the opaque-digest form (the digest is
    // over the presented credential bytes, not an external reference).
    if binding.artifact_type != want || binding.binding_type != BindingType::OpaqueDigest {
        return Err(HttpProfileError::ArtifactBindingFailed);
    }
    binding.validate()
}

fn compare(binding: &ArtifactBinding, credential: &[u8]) -> Result<(), HttpProfileError> {
    if sha256_b64url(credential) == binding.digest_value {
        Ok(())
    } else {
        Err(HttpProfileError::ArtifactBindingFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opaque(artifact_type: ArtifactType, digest_value: &str) -> ArtifactBinding {
        ArtifactBinding {
            artifact_type,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: "sha256".into(),
            digest_value: digest_value.into(),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        }
    }

    fn bind_over(artifact_type: ArtifactType, credential: &[u8]) -> ArtifactBinding {
        opaque(artifact_type, &sha256_b64url(credential))
    }

    #[test]
    fn dpop_ath_binds_the_access_token() {
        let token = b"access-token-abc";
        let b = bind_over(ArtifactType::OauthDpop, token);
        verify_dpop_ath(&b, token).expect("matching ath verifies");
    }

    #[test]
    fn dpop_ath_mismatch_fails_with_artifact_binding_failed() {
        let b = bind_over(ArtifactType::OauthDpop, b"access-token-abc");
        let err = verify_dpop_ath(&b, b"access-token-EVIL").unwrap_err();
        assert_eq!(err, HttpProfileError::ArtifactBindingFailed);
        assert_eq!(err.wire_code(), "mcp-re.artifact_binding_failed");
    }

    #[test]
    fn mtls_x5t_binds_the_certificate() {
        let cert = b"\x30\x82fake-der-bytes";
        let b = bind_over(ArtifactType::OauthMtls, cert);
        verify_mtls_x5t_s256(&b, cert).expect("matching thumbprint verifies");
        assert_eq!(
            verify_mtls_x5t_s256(&b, b"other-cert").unwrap_err(),
            HttpProfileError::ArtifactBindingFailed
        );
    }

    #[test]
    fn rar_binds_the_authorization_details() {
        let details = br#"[{"type":"payment","actions":["read"]}]"#;
        let b = bind_over(ArtifactType::OauthRar, details);
        verify_rar_details(&b, details).expect("matching RAR digest verifies");
        assert_eq!(
            verify_rar_details(&b, br#"[{"type":"payment","actions":["write"]}]"#).unwrap_err(),
            HttpProfileError::ArtifactBindingFailed
        );
    }

    #[test]
    fn wrong_artifact_type_fails_closed() {
        // A DPoP verifier must not accept a binding typed as mTLS, even if the
        // digest happens to match the bytes.
        let token = b"tok";
        let b = bind_over(ArtifactType::OauthMtls, token);
        assert_eq!(
            verify_dpop_ath(&b, token).unwrap_err(),
            HttpProfileError::ArtifactBindingFailed
        );
    }

    #[test]
    fn dispatch_matches_the_typed_verifiers() {
        let token = b"tok";
        assert!(verify_artifact_binding(&bind_over(ArtifactType::OauthDpop, token), token).is_ok());
        // Non-OAuth types have no typed verifier yet — never silently "ok".
        let pdp = bind_over(ArtifactType::PdpDecision, token);
        assert!(verify_artifact_binding(&pdp, token).is_err());
    }

    #[test]
    fn bearer_token_extraction() {
        assert_eq!(bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(bearer_token("bearer abc123"), None); // scheme is case-sensitive here
        assert_eq!(bearer_token("Basic Zm9v"), None);
        assert_eq!(bearer_token("Bearer   "), None);
    }

    #[test]
    fn end_to_end_dpop_from_authorization_header() {
        // The token lives in the covered Authorization header; only its digest
        // is in evidence. Recompute the ath from the header, verify the binding.
        let auth = "Bearer real-access-token";
        let token = bearer_token(auth).unwrap();
        let b = bind_over(ArtifactType::OauthDpop, token.as_bytes());
        verify_dpop_ath(&b, token.as_bytes()).expect("binds the presented bearer token");
    }
}
