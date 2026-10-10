// SPDX-License-Identifier: Apache-2.0
//! Checking a `COSE_Sign1` signature under a resolved key.
//!
//! One fact: **the algorithm that was allowlisted is the algorithm that runs.** The match on
//! the resolved key is exhaustive, which is the point: a new
//! [`CoseVerificationKey`](super::CoseVerificationKey) variant does not compile until its
//! verifier is wired here. The protected `alg` is then required to be the one that key names.
//!
//! A CHILD of the key rather than a sibling, because what it establishes is a property OF a
//! key: possession of a [`P256Point`](super::P256Point) is already possession of a decoded
//! on-curve key, so this module never re-decodes and cannot be handed one that was not.

use coset::iana;
use coset::CoseSign1;
use coset::TaggedCborSerializable;

use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;

use crate::error::HttpProfileError;

use super::CoseVerificationKey;

/// Verify a tagged `COSE_Sign1`'s signature over its own `Sig_structure`.
///
/// The algorithm is read from the PROTECTED header and must be one this verifier
/// implements AND must match the resolved key's algorithm. Both halves matter: an
/// unrecognized `alg` is refused rather than guessed at, and an `alg` that disagrees
/// with the key is refused rather than resolved in the message's favour.
pub(crate) fn verify_cose_sign1(
    cose: &[u8],
    key: &CoseVerificationKey,
) -> Result<(), HttpProfileError> {
    verify_cose_sign1_with_payload(cose, key, false, &[])
}
/// Verify a tagged `COSE_Sign1`, optionally supplying a DETACHED payload.
///
/// When `detached` is set the message carries no payload and `payload` is the value the
/// `Sig_structure` is built with. For a receipt that value is the Merkle root the
/// verifier re-derived from the statement, never anything a caller chose.
pub(crate) fn verify_cose_sign1_with_payload(
    cose: &[u8],
    key: &CoseVerificationKey,
    detached: bool,
    payload: &[u8],
) -> Result<(), HttpProfileError> {
    let sign1 = CoseSign1::from_tagged_slice(cose).map_err(|_| HttpProfileError::ReceiptInvalid)?;
    let alg = match &sign1.protected.header.alg {
        Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) => *alg,
        _ => {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt cose unsupported algorithm",
            ))
        }
    };
    match key {
        CoseVerificationKey::Ed25519(ed) => {
            require_alg(alg, iana::Algorithm::EdDSA)?;
            let check = |sig: &[u8], data: &[u8]| {
                verify_ed25519_with(data, &b64url_encode(sig), ed, McpReError::InvalidSignature)
            };
            if detached {
                sign1.verify_detached_signature(payload, &[], check)
            } else {
                sign1.verify_signature(&[], check)
            }
            .map_err(|_| HttpProfileError::ReceiptInvalid)
        }
        CoseVerificationKey::EcdsaP256(point) => {
            require_alg(alg, iana::Algorithm::ES256)?;
            let verifying = point.verifying_key();
            let check = |sig: &[u8], data: &[u8]| verify_es256(verifying, sig, data);
            if detached {
                sign1.verify_detached_signature(payload, &[], check)
            } else {
                sign1.verify_signature(&[], check)
            }
            .map_err(|_| HttpProfileError::ReceiptInvalid)
        }
    }
}
/// The protected `alg` must be the one the resolved key names; a supported `alg` naming the
/// other key is a mismatch, anything else is unsupported (`iana::Algorithm` is a foreign
/// non-exhaustive enum, so the `alg` side needs a catch-all and exhaustiveness is taken over
/// the key).
fn require_alg(alg: iana::Algorithm, expected: iana::Algorithm) -> Result<(), HttpProfileError> {
    if alg == expected {
        return Ok(());
    }
    match alg {
        iana::Algorithm::EdDSA | iana::Algorithm::ES256 => Err(
            HttpProfileError::MalformedEvidence("scitt cose algorithm key mismatch"),
        ),
        _ => Err(HttpProfileError::MalformedEvidence(
            "scitt cose unsupported algorithm",
        )),
    }
}
/// Verify an `ES256` COSE signature: fixed-width `r || s`, 64 octets, over SHA-256.
///
/// RFC 9053 §2.1 requires the fixed-width concatenation, NOT the ASN.1/DER `SEQUENCE`
/// that most TLS and X.509 tooling emits, so DER is refused as a non-COSE encoding that
/// would add a whole family of variable-length re-encodings.
///
/// This does not make a signature's octets unique: `p256` does not enforce low-S, so for
/// any valid `(r, s)` the pair `(r, n - s)` also verifies. RFC 9053 does not require low-S
/// and a transparency service signs with whatever its ECDSA implementation emits, so
/// refusing high-S would refuse conforming receipts. Receipt octets are therefore not a
/// receipt identity; a verified receipt establishes the attested tuple (the derived root
/// under the pinned service key), not its bytes.
fn verify_es256(
    key: &p256::ecdsa::VerifyingKey,
    signature: &[u8],
    signed: &[u8],
) -> Result<(), McpReError> {
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| McpReError::InvalidSignature)?;
    let signature =
        p256::ecdsa::Signature::from_slice(signature).map_err(|_| McpReError::InvalidSignature)?;
    p256::ecdsa::signature::Verifier::verify(key, signed, &signature)
        .map_err(|_| McpReError::InvalidSignature)
}
