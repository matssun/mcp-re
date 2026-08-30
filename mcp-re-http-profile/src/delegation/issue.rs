// SPDX-License-Identifier: Apache-2.0
//! Minting a delegation credential — the ROOT custody seam (ADR-MCPS-028).
//!
//! A different authority from [`super::verify`], and deliberately so. Verification decides
//! whether a credential may be believed and runs on every request; issuance holds the §2
//! root, runs at rotation, and in the deployment that matters does not hold the root key at
//! all — a Cloud KMS or HSM signs the credential and the private key never exists in this
//! process.
//!
//! The seam is where the two meet, and it is checked here rather than trusted: an external
//! signer that hands back a DER-wrapped or truncated signature is a contract violation, and
//! catching it at issuance is what stops it being emitted as a malformed credential that
//! every verifier then refuses.

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;

use crate::error::HttpProfileError;

use super::DelegationClaims;
use super::DelegationHeader;

/// Bytes in a raw Ed25519 signature (RFC 8032 / RFC 8037 `EdDSA`). The external
/// root-signer seam MUST return exactly this — a KMS/HSM that hands back a
/// DER-wrapped or truncated signature is a contract violation, caught here rather
/// than emitted as a malformed credential (mirrors the response-signer seam).
const ED25519_SIGNATURE_LEN: usize = 64;

/// Issue (mint) a compact JWS delegation credential using an EXTERNAL root signer
/// — the Cloud KMS / HSM custody seam (ADR-MCPS-028), where the ADR-MCPRE-052 §2
/// root is held OFF the hot path and signs ONLY the credential at issuance /
/// rotation. The root private key never has to exist in this process.
///
/// `sign_root` receives the exact JWS signing input
/// (`base64url(header) "." base64url(claims)`, ASCII) and MUST return exactly the
/// 64 raw Ed25519 signature bytes (RFC 8037); any other length is rejected
/// `DelegationCredentialInvalid` rather than emitted. This is the KMS-capable
/// sibling of [`issue_delegation_credential`] (which requires an in-process
/// [`SigningKey`]); both route through the same builder, so the compact-JWS wire
/// bytes are identical for the same key and claims.
///
/// The caller builds a consistent pair: `typ`/`alg` pinned, header `kid` ==
/// claims `issuer_kid`, and `cnf.jwk` == the delegated key.
pub fn issue_delegation_credential_with_signer(
    header: &DelegationHeader,
    claims: &DelegationClaims,
    sign_root: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<String, HttpProfileError> {
    let h = b64url_encode(&serde_json::to_vec(header).expect("delegation header serializes"));
    let p = b64url_encode(&serde_json::to_vec(claims).expect("delegation claims serialize"));
    let signing_input = format!("{h}.{p}");
    let sig = sign_root(signing_input.as_bytes())?;
    if sig.len() != ED25519_SIGNATURE_LEN {
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }
    Ok(format!("{h}.{p}.{}", b64url_encode(&sig)))
}

/// Issue (mint) a compact JWS delegation credential with an IN-PROCESS root key
/// (ADR-MCPRE-052 §1) — the software-key path. Routes through
/// [`issue_delegation_credential_with_signer`], so it is wire-identical to the
/// KMS/HSM seam for the same key and claims. Production with the root in KMS/HSM
/// uses the signer seam instead, keeping the root off the hot path.
pub fn issue_delegation_credential(
    root_key: &SigningKey,
    header: &DelegationHeader,
    claims: &DelegationClaims,
) -> String {
    issue_delegation_credential_with_signer(header, claims, |input| {
        // `SigningKey::sign` returns Base64URL; decode to the raw 64 bytes the
        // seam contract speaks. An in-process Ed25519 signer is always 64 bytes.
        Ok(b64url_decode(&root_key.sign(input)).expect("own signature is valid base64url"))
    })
    .expect("in-process Ed25519 signer yields a 64-byte signature")
}
