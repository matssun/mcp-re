// SPDX-License-Identifier: Apache-2.0
//! The pin AS WRITTEN, and the one check that turns it into a pin.
//!
//! One fact: **whether a pin document's `(algorithm, public_key)` pair names one key.**
//!
//! [`PinDocument`] is the wire record and it is `pub(super)` at most: nothing outside this
//! subtree may hold one, because holding one means holding a pin that has NOT been checked.
//! [`pinned_key`] is the check, and [`super::ScittServiceTrustPin`]'s `TryFrom` is its only
//! caller — which is what makes the pin's `verification_key` infallible.

use serde::Deserialize;
use serde::Serialize;

use mcp_re_core::b64url_decode;
use mcp_re_core::VerificationKey;

use crate::error::HttpProfileError;
use crate::scitt::cose_key::CoseVerificationKey;
use crate::scitt::merkle::StatementLeafProfile;
use crate::scitt::wire::ReceiptPositionProfile;

use super::PinnedPublicKey;
use super::TRUST_PIN_SCHEMA;

/// A pinned transparency-service verification key, recorded from a discovery document
/// at a moment in time (`ScittServiceTrustPinV1`).
///
/// **What a pin does and does not establish.** It does NOT say the service is
/// trustworthy, that its log is append-only, or that its operator is independent. It
/// records exactly WHICH key an interoperability run verified against, and where that
/// key came from, so the run is reproducible and auditable after the service is gone.
/// That is the whole claim, and it is worth having: without it, "the receipt verified"
/// is unfalsifiable, because the key it verified against was fetched live and never
/// written down.
///
/// **Why the fetch is not here.** This crate is pure — no networking, async or fs — so
/// discovery lives in tooling (`tools/scitt_fetch_service_key.py`) and the verifier
/// receives the pinned artifact. That split is the point of the offline property: once
/// pinned, verification contacts nobody, which is exactly what an auditor holding
/// only the archived bytes can reproduce.
/// The pin AS WRITTEN — the wire record, before anything about it is checked.
///
/// Private, and it is the only thing `serde` ever sees. A `ScittServiceTrustPin` is what
/// you get once this document has been shown to name a key of the algorithm it declares.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PinDocument {
    /// The schema token, so a reader of the artifact knows what it is holding.
    pub(super) schema: String,
    /// How the deployment names this service — free-form, for humans reading a corpus.
    pub(super) service_identifier: String,
    /// How the key was discovered (for example `well-known-scitt-keys`).
    pub(super) discovery_method: String,
    /// The exact URI the key came from.
    pub(super) discovery_uri: String,
    /// When it was fetched, RFC 3339. Not a validity claim: keys rotate, and a pin is
    /// a record of one moment rather than a promise about later ones.
    pub(super) fetched_at: String,
    /// The `kid` the receipt names and this key answers to.
    pub(super) kid: String,
    /// The COSE algorithm this key is for — `EdDSA` or `ES256`.
    pub(super) algorithm: String,
    /// The public key: `x`/`y` base64url for `ES256`, `x` alone for `EdDSA`.
    pub(super) public_key: PinnedPublicKey,
    /// SHA-256 over the canonical COSE_Key (RFC 9679 thumbprint), base64url. A short
    /// value a human can compare across a corpus, a report and a log.
    pub(super) public_key_thumbprint: String,
    /// SHA-256 over the discovery document's exact bytes, base64url — so a later reader
    /// can tell whether the document it fetches is the one the pin was cut from.
    pub(super) discovery_document_digest: String,
    /// Which bytes this service's log hashes as the Merkle entry. Absent means the
    /// default: the statement's own octets. Recorded in the PIN because it cannot be
    /// inferred from a receipt, and because an operator should have to write it down
    /// before MCP-RE will fold a service's log any other way.
    #[serde(default)]
    pub(super) leaf_profile: StatementLeafProfile,
    /// Whether this service's receipts must carry a position commitment. Absent means
    /// the default, `unbound` — the pre-v2 contract, where `tree_size` and `leaf_index`
    /// are unauthenticated hints.
    ///
    /// In the PIN for the same reason as `leaf_profile`: it is a property of the service
    /// that cannot be inferred from the receipt under attack, and requiring it must be a
    /// thing an operator wrote down.
    #[serde(default)]
    pub(super) position_profile: ReceiptPositionProfile,
}
/// The verification key a pin document names, or a refusal.
///
/// The algorithm comes from the DOCUMENT, never from a receipt: the pin is what the
/// operator recorded and reviewed, and letting an incoming receipt nominate the algorithm
/// to verify itself with is the confusion this whole seam avoids.
pub(super) fn pinned_key(document: &PinDocument) -> Result<CoseVerificationKey, HttpProfileError> {
    if document.schema != TRUST_PIN_SCHEMA {
        return Err(HttpProfileError::MalformedEvidence(
            "scitt trust pin schema",
        ));
    }
    let x = b64url_decode(&document.public_key.x)
        .map_err(|_| HttpProfileError::MalformedEvidence("scitt trust pin key encoding"))?;
    match document.algorithm.as_str() {
        "ES256" => {
            let y = document
                .public_key
                .y
                .as_deref()
                .ok_or(HttpProfileError::MalformedEvidence("scitt trust pin ec2 y"))?;
            let y = b64url_decode(y)
                .map_err(|_| HttpProfileError::MalformedEvidence("scitt trust pin key encoding"))?;
            CoseVerificationKey::from_ec2_p256(&x, &y)
        }
        "EdDSA" => {
            // An `EdDSA` pin carrying a `y` is not an Ed25519 key with a harmless extra
            // field — it is an ES256 key mislabelled, or a pin built by something that did
            // not know which curve it had. This used to be reachable only if somebody
            // asked; now such a document does not become a pin at all.
            if document.public_key.y.is_some() {
                return Err(HttpProfileError::MalformedEvidence(
                    "scitt trust pin eddsa carries an ec2 y coordinate",
                ));
            }
            let key = VerificationKey::from_b64url(&document.public_key.x)
                .map_err(|_| HttpProfileError::MalformedEvidence("scitt trust pin ed25519"))?;
            let _ = &x;
            Ok(CoseVerificationKey::Ed25519(key))
        }
        _ => Err(HttpProfileError::MalformedEvidence(
            "scitt trust pin unsupported algorithm",
        )),
    }
}
