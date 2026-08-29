// SPDX-License-Identifier: Apache-2.0
//! The typed operands and products of the Ed25519 KMS protocol mapping.
//!
//! The seam these cross — [`KmsEd25519Backend`](super::KmsEd25519Backend) — is where a
//! provider's network client meets the provider-agnostic mapping, and it used to carry
//! `&[u8]` in and `Vec<u8>` out. A byte slice states nothing: it cannot say whether the
//! bytes are a message or a digest of one, and it cannot say whether 64 bytes came back or
//! 65. Both facts are load-bearing here, so both are types.
//!
//! These are NOT aliases. Each one makes a specific wrong value unconstructible:
//!
//! | type | what cannot exist |
//! |---|---|
//! | [`RawEd25519Message`] | a pre-hashed input reaching a RAW-only signing call |
//! | [`RawEd25519Signature`] | a signature of any length but 64 leaving the seam |
//! | [`Ed25519SpkiDer`] | a public key that has not been through RFC 8410 interpretation |
//!
//! The mechanism stays below: nothing here knows AWS from GCP.

use crate::key_source::KeyError;

use crate::communication_assurance::ED25519_PUBLIC_KEY_LEN;
use crate::communication_assurance::ED25519_SIGNATURE_LEN;

/// The message a PureEdDSA signature is computed over, un-pre-hashed.
///
/// Ed25519 and Ed25519ph are different algorithms over the same key, and a signature made
/// by the second does not verify under the first. AWS expresses the difference as
/// `MessageType: RAW` versus `DIGEST`, GCP as which field the request populates — so the
/// distinction is a per-provider spelling of one protocol fact, and it belongs here.
///
/// **This type is the RAW arm and there is no digest arm**, because nothing in this tree
/// pre-hashes: the missing input is named rather than fabricated. A pre-hashed variant
/// arrives as a sibling type when something produces one, and every backend's `match` then
/// fails to compile until it says what it does with it — which is the point.
#[derive(Debug, Clone, Copy)]
pub struct RawEd25519Message<'a>(&'a [u8]);

impl<'a> RawEd25519Message<'a> {
    /// The signature preimage, as the bytes to be signed directly.
    pub(crate) fn for_preimage(preimage: &'a [u8]) -> Self {
        RawEd25519Message(preimage)
    }

    /// The bytes to hand the provider's RAW signing operation.
    pub fn bytes(self) -> &'a [u8] {
        self.0
    }
}

/// A raw Ed25519 signature: exactly 64 bytes, by construction.
///
/// The length check is not a step a caller performs — it is the only way in. A backend that
/// returns 65 bytes, or an empty body, or a DER-wrapped signature, cannot produce one of
/// these, so no such value reaches the re-verification seam or the wire.
///
/// The operational test: delete every length check elsewhere and an over-long signature is
/// still unconstructible. That is what makes this the owner of the rule rather than the
/// third place it is remembered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEd25519Signature([u8; ED25519_SIGNATURE_LEN]);

impl RawEd25519Signature {
    /// Interpret a provider's signature bytes, refusing any length but 64.
    ///
    /// `provider` names the operation in the refusal — the operator needs to know which
    /// call misbehaved, and that is the one provider-specific thing this owner accepts.
    pub fn interpret(bytes: &[u8], provider: &str) -> Result<Self, KeyError> {
        let array: [u8; ED25519_SIGNATURE_LEN] = bytes.try_into().map_err(|_| {
            KeyError::Malformed(format!(
                "{provider}: returned a {}-byte signature; expected a raw \
                 {ED25519_SIGNATURE_LEN}-byte Ed25519 signature",
                bytes.len()
            ))
        })?;
        Ok(RawEd25519Signature(array))
    }

    /// The 64 raw bytes.
    pub fn bytes(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.0
    }
}

/// An Ed25519 public key that has been through RFC 8410 `SubjectPublicKeyInfo`
/// interpretation.
///
/// Holding one means the DER was well-formed AND declared Ed25519 AND carried a canonical
/// 32-byte point — because [`Ed25519PublicKeyValue`] decided all three before this exists.
/// The interpretation happens once, here, rather than in each provider adapter.
///
/// [`Ed25519PublicKeyValue`]: crate::communication_assurance::Ed25519PublicKeyValue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519SpkiDer([u8; ED25519_PUBLIC_KEY_LEN]);

impl Ed25519SpkiDer {
    /// Interpret a provider's DER `SubjectPublicKeyInfo`.
    ///
    /// The rule is NOT implemented here. What makes a blob a legal Ed25519 public key is a
    /// property of the key representation, not of KMS — the same rule binds an AWS key, a
    /// GCP key, a PKCS#11 token key and the public key inside a served certificate — and
    /// ADR-MCPRE-063 Slice 2 gives it one owner. This maps that owner's refusal into the
    /// `KeyError` vocabulary these callers already match on.
    ///
    /// The owner distinguishes unreadable bytes from a well-formed key of another algorithm
    /// from a non-canonical Ed25519 encoding. This vocabulary has one variant for all three,
    /// so the distinction is rendered into the message rather than lost: a KMS operator who
    /// configured an RSA key is told the algorithm the key declares.
    pub fn interpret(der: &[u8]) -> Result<Self, KeyError> {
        use crate::communication_assurance::Ed25519PublicKeyValue;

        Ed25519PublicKeyValue::interpret_rfc8410_spki(der)
            .map(|key| Ed25519SpkiDer(key.raw_point()))
            .map_err(|refusal| {
                KeyError::Malformed(format!(
                    "kms: public key is not an RFC 8410 Ed25519 SubjectPublicKeyInfo — \
                     {refusal}; the KMS key MUST be an Ed25519 key (AWS \
                     ECC_NIST_EDWARDS25519 / GCP EC_SIGN_ED25519)"
                ))
            })
    }

    /// The 32 raw Ed25519 public-key bytes.
    pub fn raw_point(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The length rule is the constructor. Nothing but 64 bytes yields a signature, so the
    /// invalid value never exists to be checked for later.
    #[test]
    fn only_sixty_four_bytes_make_a_signature() {
        assert!(RawEd25519Signature::interpret(&[7u8; 64], "test").is_ok());
        for len in [0usize, 63, 65, 128] {
            let err = RawEd25519Signature::interpret(&vec![7u8; len], "aws-kms")
                .expect_err("only 64 bytes is a raw Ed25519 signature");
            let KeyError::Malformed(message) = err else {
                panic!("a wrong length is intrinsic, not transient");
            };
            assert!(
                message.contains("aws-kms") && message.contains(&len.to_string()),
                "the refusal names the operation and what came back; got: {message}"
            );
        }
    }

    /// The 64 bytes come back unchanged: the type transports the signature, it does not
    /// re-encode it.
    #[test]
    fn the_signature_bytes_survive_the_seam() {
        let mut raw = [0u8; 64];
        raw.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        let signature = RawEd25519Signature::interpret(&raw, "test").expect("64 bytes");
        assert_eq!(signature.bytes(), &raw);
    }

    /// A message carries the preimage verbatim — the RAW arm signs what it was given.
    #[test]
    fn a_raw_message_is_the_preimage_itself() {
        let preimage = b"the signature base";
        assert_eq!(RawEd25519Message::for_preimage(preimage).bytes(), preimage);
    }

    /// Public-key interpretation is delegated to the representation's owner and its refusal
    /// is rendered, not swallowed: a non-Ed25519 or malformed SPKI never becomes a key.
    #[test]
    fn a_public_key_that_is_not_an_ed25519_spki_is_refused() {
        for bad in [
            b"".as_slice(),
            b"not der".as_slice(),
            &[0x30, 0x03, 0x02, 0x01, 0x00],
        ] {
            let err = Ed25519SpkiDer::interpret(bad).expect_err("not an Ed25519 SPKI");
            let KeyError::Malformed(message) = err else {
                panic!("a malformed public key is intrinsic");
            };
            assert!(
                message.contains("RFC 8410"),
                "the refusal names the representation; got: {message}"
            );
        }
    }
}
