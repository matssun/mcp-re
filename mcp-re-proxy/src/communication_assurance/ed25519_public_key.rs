// SPDX-License-Identifier: Apache-2.0
//! The canonical Ed25519 public key, and the one owner of the RFC 8410 SPKI invariant.
//!
//! A public key is legal here when its `SubjectPublicKeyInfo` is the canonical RFC 8410
//! Ed25519 encoding: the fixed twelve-byte header naming `id-Ed25519` (1.3.101.112),
//! followed by exactly thirty-two key bytes. That is a property of the key representation,
//! not of TLS, not of KMS, and not of any provider — an AWS KMS key, a GCP KMS key, a
//! PKCS#11 token key and the public key inside a served certificate are all held to it,
//! and they must be held to the SAME one.
//!
//! # Why the profile is an invariant rather than a policy
//!
//! There is exactly one legal profile today. A one-variant `RequiredKeyProfile` enum would
//! advertise a choice nobody can make and would put the check back at the call sites that
//! remembered to consult it. Instead the profile is what construction MEANS:
//! [`Ed25519PublicKeyValue`] has a private representation and one fallible constructor, so
//! holding one is the proof that the required profile held. If a second profile ever
//! becomes genuinely legal, that is the moment to introduce a real sum type — and it will
//! be a change to this owner rather than to everyone who consumes it.
//!
//! # Classification never widens acceptance
//!
//! The accepting path is an exact match against the canonical encoding, which is what the
//! implementation this owner replaces already required. The general SPKI parse runs ONLY
//! when that match fails, and only to say WHY. Accepting whatever a general parse yields
//! would newly admit non-canonical encodings that are refused today — a loosening
//! disguised as better error reporting.

use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

/// Raw Ed25519 public key length, in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// The canonical RFC 8410 `SubjectPublicKeyInfo` header for an Ed25519 key: SEQUENCE(42),
/// SEQUENCE(5), OID 1.3.101.112, BIT STRING(33) with no unused bits.
///
/// Private, because the canonical encoding has two directions and this owner owns BOTH.
/// A provider holding a bare thirty-two-byte key gets its SPKI from
/// [`Ed25519PublicKeyValue::to_rfc8410_spki_der`] rather than from these bytes: handing
/// out the header invites every provider to assemble DER by hand, and two copies of it —
/// one to write and one to read — are the same fact stated twice.
const CANONICAL_ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Total length of a canonical RFC 8410 Ed25519 SPKI.
const CANONICAL_ED25519_SPKI_LEN: usize =
    CANONICAL_ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_LEN;

/// The dotted form of `id-Ed25519`.
const ED25519_OID: &str = "1.3.101.112";

/// Why a `SubjectPublicKeyInfo` is not a canonical Ed25519 public key.
///
/// Three facts, because the representation can tell them apart and they send an operator
/// to three different places: a corrupted or truncated blob, a correctly-formed key of an
/// algorithm this system does not use, and an Ed25519 key that is not in the encoding this
/// system requires. Collapsing them — which the implementation this owner replaces did,
/// by comparing a byte prefix and reporting one message — makes a provider misconfiguration
/// (an RSA KMS key) indistinguishable from a transport fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rfc8410SpkiRefusal {
    /// The bytes are not a readable `SubjectPublicKeyInfo` at all.
    Uninterpretable,
    /// A readable `SubjectPublicKeyInfo` whose algorithm is not `id-Ed25519`.
    UnsupportedAlgorithm {
        /// The algorithm OID the key actually declares, in dotted form.
        oid: String,
    },
    /// A readable `id-Ed25519` key whose encoding is not the canonical RFC 8410 form.
    ///
    /// Refused, and named rather than folded into [`Rfc8410SpkiRefusal::Uninterpretable`]:
    /// the key IS interpretable, and the reason it is rejected is this system's strictness
    /// about the encoding, which a reader deserves to see stated.
    NonCanonicalEd25519Encoding,
}

impl std::fmt::Display for Rfc8410SpkiRefusal {
    /// A refusal describing itself. Every caller that must render this into its own error
    /// vocabulary — the KMS key vocabulary, the delegated-TLS one — then renders the same
    /// words, so an operator reading two different logs is reading one fact.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rfc8410SpkiRefusal::Uninterpretable => {
                write!(f, "not a readable SubjectPublicKeyInfo")
            }
            Rfc8410SpkiRefusal::UnsupportedAlgorithm { oid } => {
                write!(f, "declares algorithm {oid}, and Ed25519 is required")
            }
            Rfc8410SpkiRefusal::NonCanonicalEd25519Encoding => write!(
                f,
                "an Ed25519 key, but not in the canonical RFC 8410 encoding"
            ),
        }
    }
}

/// A public key known to be a canonical RFC 8410 Ed25519 key.
///
/// Possession is the proof. The thirty-two raw bytes are private and the only constructor
/// is [`Ed25519PublicKeyValue::interpret_rfc8410_spki`], so no caller can assemble a value
/// of another algorithm, another length, or another encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKeyValue {
    raw_point: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl Ed25519PublicKeyValue {
    /// Interpret DER `SubjectPublicKeyInfo` bytes as a canonical Ed25519 public key.
    pub fn interpret_rfc8410_spki(der: &[u8]) -> Result<Self, Rfc8410SpkiRefusal> {
        if der.len() == CANONICAL_ED25519_SPKI_LEN
            && der[..CANONICAL_ED25519_SPKI_PREFIX.len()] == CANONICAL_ED25519_SPKI_PREFIX
        {
            let mut raw_point = [0u8; ED25519_PUBLIC_KEY_LEN];
            raw_point.copy_from_slice(&der[CANONICAL_ED25519_SPKI_PREFIX.len()..]);
            return Ok(Ed25519PublicKeyValue { raw_point });
        }
        Err(classify(der))
    }

    /// The canonical RFC 8410 `SubjectPublicKeyInfo` encoding of a raw thirty-two-byte
    /// public key.
    ///
    /// The WRITE direction, so a provider that holds a bare key — a PKCS#11 token, a KMS
    /// response, a test fake — never assembles the DER header itself. It is total, and
    /// that is not a hole in the invariant: the invariant is the canonical encoding, and
    /// every thirty-two-byte string has exactly one. Whether those bytes are a valid curve
    /// point is a different proposition, owned by whatever signs or verifies with the key.
    ///
    /// `interpret_rfc8410_spki(spki_der_for_point(p))` yields a value whose `raw_point()`
    /// is `p`, for every `p` — the property that makes it safe for one side to encode with
    /// this owner and the other to interpret with it.
    pub fn spki_der_for_point(raw_point: [u8; ED25519_PUBLIC_KEY_LEN]) -> Vec<u8> {
        let mut der = CANONICAL_ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&raw_point);
        der
    }

    /// The thirty-two raw key bytes.
    ///
    /// The only projection. It is what a verifier, a signer and a key comparison all need,
    /// and handing out the bytes cannot un-prove the invariant that produced them.
    pub fn raw_point(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.raw_point
    }
}

/// Say why `der` is not a canonical Ed25519 SPKI. Reached only after the canonical match
/// has already failed, so it never decides acceptance — only the reason for refusal.
fn classify(der: &[u8]) -> Rfc8410SpkiRefusal {
    let Ok((_, spki)) = SubjectPublicKeyInfo::from_der(der) else {
        return Rfc8410SpkiRefusal::Uninterpretable;
    };
    let oid = spki.algorithm.algorithm.to_id_string();
    if oid == ED25519_OID {
        Rfc8410SpkiRefusal::NonCanonicalEd25519Encoding
    } else {
        Rfc8410SpkiRefusal::UnsupportedAlgorithm { oid }
    }
}

#[cfg(test)]
mod tests {
    use super::Ed25519PublicKeyValue;
    use super::Rfc8410SpkiRefusal;
    fn canonical(point: [u8; 32]) -> Vec<u8> {
        Ed25519PublicKeyValue::spki_der_for_point(point)
    }

    #[test]
    fn a_canonical_key_is_accepted_and_projects_its_point() {
        let point = [7u8; 32];
        let value = Ed25519PublicKeyValue::interpret_rfc8410_spki(&canonical(point))
            .expect("canonical Ed25519 SPKI");
        assert_eq!(value.raw_point(), point);
    }

    #[test]
    fn unreadable_bytes_are_uninterpretable_not_an_unsupported_algorithm() {
        for der in [
            [0x30, 0x82, 0xff, 0xff, 0x00].as_slice(),
            [].as_slice(),
            [0u8; 10].as_slice(),
        ] {
            assert_eq!(
                Ed25519PublicKeyValue::interpret_rfc8410_spki(der),
                Err(Rfc8410SpkiRefusal::Uninterpretable),
                "corrupt bytes name no algorithm, so no algorithm may be reported"
            );
        }
    }

    #[test]
    fn a_well_formed_key_of_another_algorithm_names_the_algorithm_it_declares() {
        // A real P-256 SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier {
        // id-ecPublicKey, prime256v1 }, BIT STRING }. Readable, and not Ed25519.
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        der.extend_from_slice(&[0x11u8; 64]);
        assert_eq!(
            Ed25519PublicKeyValue::interpret_rfc8410_spki(&der),
            Err(Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                oid: "1.2.840.10045.2.1".to_string()
            }),
            "a provider configured with the wrong key type must be told which type it gave"
        );
    }

    #[test]
    fn a_readable_ed25519_key_in_a_non_canonical_encoding_is_refused_as_such() {
        // id-Ed25519, but the outer SEQUENCE uses a long-form length the canonical
        // encoding does not: readable, right algorithm, wrong encoding.
        let mut der = vec![
            0x30, 0x81, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(&[0x22u8; 32]);
        assert_eq!(
            Ed25519PublicKeyValue::interpret_rfc8410_spki(&der),
            Err(Rfc8410SpkiRefusal::NonCanonicalEd25519Encoding),
            "the key is interpretable and is Ed25519; what it is not is canonically encoded"
        );
    }

    #[test]
    fn classification_never_widens_acceptance() {
        // Every refusal above is a refusal, not a repaired acceptance. Stated as its own
        // control because the whole risk of adding a parser on the refusal path is that it
        // quietly becomes the accepting path.
        let mut non_canonical = vec![
            0x30, 0x81, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        non_canonical.extend_from_slice(&[0x22u8; 32]);
        assert!(Ed25519PublicKeyValue::interpret_rfc8410_spki(&non_canonical).is_err());
        assert!(Ed25519PublicKeyValue::interpret_rfc8410_spki(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn the_two_directions_are_inverse() {
        // The property that makes it safe for a provider to encode with this owner and a
        // reader to interpret with it: what one writes, the other accepts, and it comes
        // back as the same key.
        for point in [[0u8; 32], [0xffu8; 32], [3u8; 32]] {
            let der = Ed25519PublicKeyValue::spki_der_for_point(point);
            let key = Ed25519PublicKeyValue::interpret_rfc8410_spki(&der)
                .expect("what this owner writes, this owner accepts");
            assert_eq!(key.raw_point(), point);
        }
    }

    #[test]
    fn two_keys_differing_in_one_byte_are_different_values() {
        let a = Ed25519PublicKeyValue::interpret_rfc8410_spki(&canonical([1u8; 32])).expect("a");
        let mut other = [1u8; 32];
        other[31] = 2;
        let b = Ed25519PublicKeyValue::interpret_rfc8410_spki(&canonical(other)).expect("b");
        assert_ne!(a, b, "equality of this value is equality of the key");
    }
}
