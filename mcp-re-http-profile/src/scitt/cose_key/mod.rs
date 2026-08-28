// SPDX-License-Identifier: Apache-2.0
//! COSE signature verification — authority E.
//!
//! One fact: **this `COSE_Sign1` is valid under a key whose algorithm the protected header
//! agrees with.** Neither half is negotiable from the message: an unrecognized `alg` is
//! refused rather than guessed at, and an `alg` disagreeing with the RESOLVED key is
//! refused rather than resolved in the message's favour — reading the algorithm out of a
//! message and then finding a key that might work is the COSE/JOSE confusion shape.
//!
//! [`P256Point`] is the seal: the on-curve check is the constructor, so nothing here
//! re-decodes a key or can be handed one that was never decoded.

use mcp_re_core::VerificationKey;

use crate::error::HttpProfileError;

mod verify;

pub(super) use verify::verify_cose_sign1;
pub(super) use verify::verify_cose_sign1_with_payload;

/// A key a `COSE_Sign1` in the SCITT profile may be verified with.
///
/// Two algorithms, for two different reasons. MCP-RE issues its own Signed Statements
/// with Ed25519. A transparency service is not ours and signs with what it signs with:
/// RFC 9942's own receipt examples use `ES256`, and every running implementation
/// observed uses a P-256 or P-384 key. Verifying a receipt therefore requires ECDSA,
/// while MCP-RE's request and response signing stays Ed25519-only — `mcp-re-core`
/// still refuses `ES256` for message signatures, and nothing here changes that.
///
/// The key names the algorithm, so a message cannot. A verifier that took the
/// algorithm from the message and then looked for any key that might work is the
/// classic COSE/JOSE algorithm-confusion shape; here the resolved key and the
/// protected `alg` must agree or verification is refused.
#[derive(Debug, Clone)]
pub enum CoseVerificationKey {
    /// Ed25519, for `alg: EdDSA` (-8).
    Ed25519(VerificationKey),
    /// ECDSA on NIST P-256, for `alg: ES256` (-7).
    ///
    /// The payload is a [`P256Point`], not the two coordinate arrays it is decoded from.
    /// Two 32-octet arrays are a pair of numbers; most such pairs are not points on the
    /// curve, and a struct-literal `EcdsaP256 { x, y }` could name one of those while the
    /// variant's own name says otherwise.
    EcdsaP256(P256Point),
}

/// A P-256 point PROVEN to be on the curve.
///
/// The representation is the DECODED verifying key, not the coordinates, and the decode is
/// the proof: `p256::ecdsa::VerifyingKey::from_sec1_bytes` refuses anything off-curve, and
/// there is no other way in. The operational test (ADR-MCPRE-061 §11) passes — delete the
/// check and an invalid value is still unconstructible, because the check IS the
/// constructor.
///
/// Before this, `from_ec2_p256` checked the point and then discarded the parsed key, so
/// every verification re-decoded it and the invariant was carried by *"the only constructor
/// happens to check"*. That is a statement about one call site; this is a statement about
/// the type.
#[derive(Debug, Clone)]
pub struct P256Point {
    verifying: p256::ecdsa::VerifyingKey,
}

impl From<VerificationKey> for CoseVerificationKey {
    fn from(key: VerificationKey) -> Self {
        CoseVerificationKey::Ed25519(key)
    }
}

impl CoseVerificationKey {
    /// Build a P-256 key from COSE `EC2` affine coordinates.
    ///
    /// Both coordinates must be exactly 32 octets. RFC 9053 §7.1.1 requires the
    /// fixed-width, leading-zero-preserving form, so a 31-octet `x` is not a small
    /// number to be left-padded — it is a different encoding, and accepting it would
    /// mean two byte strings naming one key. The point is then checked to be on the
    /// curve: an off-curve "public key" has no discrete log to verify against, and
    /// feeding one to a verifier is how invalid-curve attacks start.
    pub fn from_ec2_p256(x: &[u8], y: &[u8]) -> Result<Self, HttpProfileError> {
        Ok(CoseVerificationKey::EcdsaP256(P256Point::from_ec2(x, y)?))
    }
}

impl P256Point {
    /// Decode COSE `EC2` affine coordinates into a point on the curve, or refuse.
    ///
    /// This is the type's SOLE producer, and everything the variant's name claims is
    /// established here.
    fn from_ec2(x: &[u8], y: &[u8]) -> Result<Self, HttpProfileError> {
        let x: [u8; 32] = x.try_into().map_err(|_| {
            HttpProfileError::MalformedEvidence("scitt ec2 p256 x coordinate width")
        })?;
        let y: [u8; 32] = y.try_into().map_err(|_| {
            HttpProfileError::MalformedEvidence("scitt ec2 p256 y coordinate width")
        })?;
        // SEC1 uncompressed: 0x04 || X || Y.
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..].copy_from_slice(&y);
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| {
            HttpProfileError::MalformedEvidence("scitt ec2 p256 point not on curve")
        })?;
        Ok(P256Point { verifying })
    }

    /// The verifying key. INFALLIBLE, which is the whole point of the seal: possession of
    /// a `P256Point` is possession of a decoded on-curve key, so there is nothing left for
    /// a verification path to re-check or to get wrong.
    fn verifying_key(&self) -> &p256::ecdsa::VerifyingKey {
        &self.verifying
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainLabel;
    use crate::scitt::commitment::EvidenceCommitment;
    use crate::scitt::fixtures::*;
    use coset::CoseSign1;
    use coset::TaggedCborSerializable;

    use crate::scitt::offline::verify_receipt_offline;
    use crate::scitt::prototype::PrototypeTransparencyService;
    use crate::scitt::receipt::Receipt;
    use crate::scitt::wire::HEADER_VDS;
    use crate::scitt::wire::VDS_RFC9162_SHA256;
    use ciborium::Value;
    use coset::iana;
    use coset::HeaderBuilder;

    /// An ES256 receipt verifies. This is the capability #501 needs: MCP-RE issues its
    /// statements with Ed25519, and the service that countersigns them does not.
    #[test]
    fn an_es256_receipt_from_a_foreign_service_verifies() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let receipt = Receipt::from_cose(&es256_receipt(&st)).expect("parses");
        verify_receipt_offline(&st, &receipt, ir(), ts_with(ts_p256_key()))
            .expect("an ES256 receipt over a single-leaf tree verifies");
    }

    /// The message does not get to choose the algorithm. An ES256 receipt presented
    /// against an Ed25519 key is refused as a mismatch rather than resolved in the
    /// message's favour — the algorithm-confusion shape.
    #[test]
    fn an_algorithm_that_disagrees_with_the_resolved_key_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let receipt = Receipt::from_cose(&es256_receipt(&st)).expect("parses");
        assert_eq!(
            verify_receipt_offline(&st, &receipt, ir(), tr()).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt cose algorithm key mismatch"),
        );

        // And the converse: an EdDSA receipt against a P-256 key.
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let eddsa = register(&mut svc, &st);
        assert_eq!(
            verify_receipt_offline(&st, &eddsa, ir(), ts_with(ts_p256_key())).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt cose algorithm key mismatch"),
        );
    }

    /// RFC 9053 §2.1 requires fixed-width `r || s`. A DER `SEQUENCE` — what most X.509
    /// and TLS tooling emits, and the same signature mathematically — is refused,
    /// because admitting both would mean one signature has more than one valid byte
    /// string while `Sig_structure` verification rests on exact octets.
    #[test]
    fn a_der_encoded_es256_signature_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let cose = es256_receipt(&st);
        let sign1 = CoseSign1::from_tagged_slice(&cose).expect("parses");
        let fixed = p256::ecdsa::Signature::from_slice(&sign1.signature).expect("fixed width");

        let mut der = sign1.clone();
        der.signature = fixed.to_der().as_bytes().to_vec();
        assert_ne!(der.signature.len(), 64, "DER is a different length");
        let receipt =
            Receipt::from_cose(&der.to_tagged_vec().expect("re-encode")).expect("still parses");
        assert_eq!(
            verify_receipt_offline(&st, &receipt, ir(), ts_with(ts_p256_key())).unwrap_err(),
            HttpProfileError::ReceiptInvalid,
        );
    }

    /// Coordinates must be exactly 32 octets, and the point must be on the curve. A
    /// short coordinate is a different encoding rather than a small number to pad, and
    /// an off-curve point has no discrete log to verify against at all.
    #[test]
    fn a_malformed_p256_key_is_refused_at_construction() {
        let point = ts_p256().verifying_key().to_sec1_point(false);
        let (x, y) = (point.x().expect("x"), point.y().expect("y"));

        assert_eq!(
            CoseVerificationKey::from_ec2_p256(&x[1..], y).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt ec2 p256 x coordinate width"),
        );
        assert_eq!(
            CoseVerificationKey::from_ec2_p256(x, &y[..31]).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt ec2 p256 y coordinate width"),
        );
        // Right widths, wrong curve point.
        let mut off = y.to_vec();
        off[31] ^= 0x01;
        assert_eq!(
            CoseVerificationKey::from_ec2_p256(x, &off).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt ec2 p256 point not on curve"),
        );
    }

    /// An algorithm this verifier does not implement is refused, never attempted with
    /// whatever key happened to resolve.
    #[test]
    fn an_unsupported_algorithm_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let cose = es256_receipt(&st);
        let sign1 = CoseSign1::from_tagged_slice(&cose).expect("parses");
        let mut es512 = sign1.clone();
        es512.protected = coset::ProtectedHeader {
            original_data: None,
            header: HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES512)
                .key_id(TS_KID.as_bytes().to_vec())
                .value(HEADER_VDS, Value::Integer(VDS_RFC9162_SHA256.into()))
                .build(),
        };
        let receipt =
            Receipt::from_cose(&es512.to_tagged_vec().expect("re-encode")).expect("parses");
        assert_eq!(
            verify_receipt_offline(&st, &receipt, ir(), ts_with(ts_p256_key())).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt cose unsupported algorithm"),
        );
    }
}
