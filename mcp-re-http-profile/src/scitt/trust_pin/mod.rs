// SPDX-License-Identifier: Apache-2.0
//! Transparency-service trust pin — authority G.
//!
//! One fact: **the key an interoperability run verified against, and where it came from.**
//!
//! The pin is what makes the offline property possible: once pinned, verification contacts
//! nobody, which is exactly what an auditor holding only the archived bytes can reproduce.
//! Discovery is deliberately NOT here — it lives in `tools/scitt_fetch_service_key.py`, and
//! the verifier receives the pinned artifact.

use serde::Deserialize;
use serde::Serialize;

mod document;

use document::pinned_key;
use document::PinDocument;

use super::cose_key::CoseVerificationKey;
use super::merkle::StatementLeafProfile;
use super::service::ResolvedTransparencyService;
use super::wire::ReceiptPositionProfile;

/// A pin whose `(algorithm, public_key)` PAIR has been shown to name one key.
///
/// # What the seal removes
///
/// The census (EX-004 question 11) found `ScittServiceTrustPin` with every field `pub`, so
/// an `EdDSA` pin carrying an `ES256` `y` coordinate — an ES256 key mislabelled, or a pin
/// cut by something that did not know which curve it had — was CONSTRUCTIBLE, and refused
/// only if somebody later called `verification_key`. The illegal state was not the
/// algorithm and not the key; it was the PAIR, which is why the seal belongs here and not
/// on [`PinnedPublicKey`], a wire record with no invariant of its own.
///
/// Deserialization is the only producer, and it goes through [`PinDocument`] and
/// `TryFrom`, so **every inhabitant has had its pair checked** — including the P-256
/// on-curve check, since the key is decoded once here and kept. `verification_key` is
/// therefore infallible: it returns what construction proved.
///
/// A pin is still only a record of one moment (see the type-level notes above). The seal
/// says the document names a key; it says nothing about whether the service deserves trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "PinDocument", into = "PinDocument")]
pub struct ScittServiceTrustPin {
    document: PinDocument,
    /// Decoded once, at construction, from `document.algorithm` and `document.public_key`.
    key: CoseVerificationKey,
}

impl TryFrom<PinDocument> for ScittServiceTrustPin {
    type Error = String;

    fn try_from(document: PinDocument) -> Result<Self, Self::Error> {
        let key = pinned_key(&document).map_err(|e| format!("{e:?}"))?;
        Ok(ScittServiceTrustPin { document, key })
    }
}

impl From<ScittServiceTrustPin> for PinDocument {
    fn from(pin: ScittServiceTrustPin) -> Self {
        pin.document
    }
}

/// The key material inside a pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedPublicKey {
    /// The `x` coordinate (`ES256`) or the public key (`EdDSA`), base64url.
    pub x: String,
    /// The `y` coordinate, base64url. `ES256` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// The schema token a pin must carry.
pub const TRUST_PIN_SCHEMA: &str = "mcp-re-scitt-service-trust-pin/v1";

impl ScittServiceTrustPin {
    /// The verification key this pin holds.
    ///
    /// INFALLIBLE. The algorithm/key pair was resolved at construction, so this returns
    /// what the seal proved rather than re-deciding it — and there is no inhabitant for
    /// which it could fail.
    pub fn verification_key(&self) -> &CoseVerificationKey {
        &self.key
    }

    /// The `kid` this pin answers for.
    pub fn kid(&self) -> &str {
        &self.document.kid
    }

    /// How the deployment names this service.
    pub fn service_identifier(&self) -> &str {
        &self.document.service_identifier
    }

    /// Which bytes this service's log hashes as the Merkle entry.
    pub fn leaf_profile(&self) -> StatementLeafProfile {
        self.document.leaf_profile
    }

    /// Whether this service's receipts must carry a position commitment.
    pub fn position_profile(&self) -> ReceiptPositionProfile {
        self.document.position_profile
    }

    /// Resolve `kid` against this pin, for [`verify_receipt_offline`].
    ///
    /// A `kid` that does not match returns nothing: a pin answers for the one key it
    /// pinned, and a receipt naming a different key has not been pinned at all.
    pub fn resolve(&self, kid: &str) -> Option<ResolvedTransparencyService> {
        (kid == self.document.kid).then(|| ResolvedTransparencyService::pinned(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainLabel;
    use crate::error::HttpProfileError;
    use crate::scitt::commitment::EvidenceCommitment;
    use crate::scitt::fixtures::*;

    use crate::scitt::offline::verify_receipt_offline;
    use crate::scitt::receipt::Receipt;
    use mcp_re_core::b64url_encode;

    /// A pin DOCUMENT — the wire record, which may or may not be a legal pin.
    fn pin_document(algorithm: &str, x: &str, y: Option<&str>) -> PinDocument {
        PinDocument {
            schema: TRUST_PIN_SCHEMA.to_owned(),
            service_identifier: "test-service".into(),
            discovery_method: "well-known-scitt-keys".into(),
            discovery_uri: "https://example.test/.well-known/scitt-keys".into(),
            fetched_at: "2026-07-31T00:00:00Z".into(),
            // A real external SCITT service does not emit MCP-RE's profile extension,
            // so an interoperability pin is `Unbound` and its receipts verify under the
            // pre-v2 contract. This is the transition working as intended: the stronger
            // profile is something a deployment opts into per service, not something
            // that retroactively invalidates every receipt anyone else issues.
            position_profile: ReceiptPositionProfile::Unbound,
            kid: TS_KID.into(),
            algorithm: algorithm.to_owned(),
            public_key: PinnedPublicKey {
                x: x.to_owned(),
                y: y.map(str::to_owned),
            },
            public_key_thumbprint: "unused-by-this-test".into(),
            discovery_document_digest: "unused-by-this-test".into(),
            leaf_profile: StatementLeafProfile::StatementBytes,
        }
    }

    /// A pin. There is no struct literal for this type, so a test builds one the only way
    /// anything does: by showing a document names a key.
    fn pin(algorithm: &str, x: &str, y: Option<&str>) -> ScittServiceTrustPin {
        ScittServiceTrustPin::try_from(pin_document(algorithm, x, y)).expect("a legal pin")
    }

    /// A pinned ES256 key verifies a real ES256 receipt, resolved by `kid`.
    #[test]
    fn a_pinned_es256_key_verifies_a_receipt() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let receipt = Receipt::from_cose(&es256_receipt(&st)).expect("parses");
        let point = ts_p256().verifying_key().to_sec1_point(false);
        let pinned = pin(
            "ES256",
            &b64url_encode(point.x().expect("x")),
            Some(&b64url_encode(point.y().expect("y"))),
        );

        verify_receipt_offline(&st, &receipt, ir(), |kid| pinned.resolve(kid))
            .expect("the pinned key verifies the receipt");

        // A receipt naming a different kid is not covered by this pin.
        assert!(pinned.resolve("some-other-kid").is_none());
    }

    /// A document whose schema, algorithm or key material is wrong **never becomes a pin**.
    ///
    /// This is the seal, stated as the ADR-MCPRE-061 §11 operational test. The check used
    /// to live in `verification_key`, so each of these documents WAS a
    /// `ScittServiceTrustPin` and was refused only if somebody asked it for a key — and
    /// question 11 of the EX-004 census found exactly that. Both halves are asserted: the
    /// typed reason, and that no inhabitant carrying it exists.
    #[test]
    fn a_malformed_pin_document_never_becomes_a_pin() {
        let x = b64url_encode(&[7u8; 32]);

        let mut wrong_schema = pin_document("EdDSA", &x, None);
        wrong_schema.schema = "something-else/v1".into();

        for (document, reason) in [
            (wrong_schema, "scitt trust pin schema"),
            (
                pin_document("RS256", &x, None),
                "scitt trust pin unsupported algorithm",
            ),
            (pin_document("ES256", &x, None), "scitt trust pin ec2 y"),
            // An Ed25519 pin carrying a y coordinate is a mislabelled EC2 key, not an
            // Ed25519 key with a spare field.
            (
                pin_document("EdDSA", &x, Some(&x)),
                "scitt trust pin eddsa carries an ec2 y coordinate",
            ),
        ] {
            assert_eq!(
                pinned_key(&document).unwrap_err(),
                HttpProfileError::MalformedEvidence(reason),
            );
            assert!(
                ScittServiceTrustPin::try_from(document).is_err(),
                "{reason}: the document must not become a pin at all",
            );
        }
    }

    /// A pin read from JSON is validated on the way in, so the artifact an operator ships
    /// is where an illegal pair is caught — not a later call that happens to ask.
    #[test]
    fn an_illegal_pin_document_is_refused_at_deserialization() {
        let x = b64url_encode(&ts().public_key().to_bytes());
        let legal = serde_json::to_string(&pin_document("EdDSA", &x, None)).expect("json");
        serde_json::from_str::<ScittServiceTrustPin>(&legal).expect("a legal document parses");

        let illegal = serde_json::to_string(&pin_document("EdDSA", &x, Some(&x))).expect("json");
        assert!(
            serde_json::from_str::<ScittServiceTrustPin>(&illegal).is_err(),
            "an EdDSA pin carrying an ec2 y must not deserialize",
        );
    }
}
