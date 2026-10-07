// SPDX-License-Identifier: Apache-2.0
//! How to check one transparency service's receipts.
//!
//! One fact: **the key, the leaf profile and the position profile that go together.** It is
//! its own module rather than a struct beside the fold because the question it answers is
//! *whose log is this* — and because its two producers are the whole of what the type
//! establishes. See the type's own note for which producer a product build has.

use super::cose_key::CoseVerificationKey;
use super::merkle::StatementLeafProfile;
use super::trust_pin::ScittServiceTrustPin;
use super::wire::ReceiptPositionProfile;

/// A resolved transparency service: the key its receipts are verified with, the leaf
/// profile its log uses, and whether its receipts must carry a position commitment.
///
/// The three travel together because they are three parts of one question — "how do I check
/// this service's receipts" — and as independent parameters a caller could pair a pinned key
/// with a profile nobody pinned.
///
/// # Producers
///
/// The fields are private, so every producer is NAMED and a call site says which one it is:
/// [`pinned`](Self::pinned), where all three came from one operator-reviewed document, or
/// `stated`, where the caller is asserting them.
///
/// In a product build `stated` does not exist, so every service a resolver can return came
/// from a pin, and the position profile in particular is one an operator pinned. `stated`
/// is compiled only into test builds and the test-only `pre_052_fixtures` flavor, which the
/// conformance corpora link because they are produced by the in-process prototype log with
/// no pin to resolve from (`docs/dev/sealed-owners.md`).
#[derive(Debug, Clone)]
pub struct ResolvedTransparencyService {
    key: CoseVerificationKey,
    leaf_profile: StatementLeafProfile,
    position_profile: ReceiptPositionProfile,
}

impl ResolvedTransparencyService {
    /// The service a PIN resolves to: all three parts from one document an operator wrote
    /// down and reviewed.
    pub(super) fn pinned(pin: &ScittServiceTrustPin) -> Self {
        ResolvedTransparencyService {
            key: pin.verification_key().clone(),
            leaf_profile: pin.leaf_profile(),
            position_profile: pin.position_profile(),
        }
    }

    /// The key that verifies this service's receipt signatures.
    pub(super) fn key(&self) -> &CoseVerificationKey {
        &self.key
    }

    /// Which bytes this service's log hashes as the Merkle entry.
    pub(super) fn leaf_profile(&self) -> StatementLeafProfile {
        self.leaf_profile
    }

    /// Whether this service's receipts must carry a position commitment.
    pub(super) fn position_profile(&self) -> ReceiptPositionProfile {
        self.position_profile
    }

    /// A service whose parts the CALLER states, because there is no pin to resolve from.
    ///
    /// The conformance corpora built from the in-process prototype log are the real cases.
    /// The name is the contract: this establishes only that the caller said so, and in
    /// particular does not establish that the leaf and position profiles are ones any
    /// operator pinned.
    ///
    /// Compiled only under `test` or the test-only `pre_052_fixtures` feature, so a product
    /// build has [`pinned`](Self::pinned) as its sole producer and
    /// [`ReceiptPositionProfile::Bound`] is selected only by a pin's `position_profile`.
    #[cfg(any(test, feature = "pre_052_fixtures"))]
    pub fn stated(
        key: CoseVerificationKey,
        leaf_profile: StatementLeafProfile,
        position_profile: ReceiptPositionProfile,
    ) -> Self {
        ResolvedTransparencyService {
            key,
            leaf_profile,
            position_profile,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scitt::fixtures::*;

    const LEAVES: [StatementLeafProfile; 3] = [
        StatementLeafProfile::StatementBytes,
        StatementLeafProfile::StatementDigest,
        StatementLeafProfile::SigStructureDigest,
    ];
    const POSITIONS: [ReceiptPositionProfile; 2] = [
        ReceiptPositionProfile::Unbound,
        ReceiptPositionProfile::Bound,
    ];

    fn pin(leaf: StatementLeafProfile, position: ReceiptPositionProfile) -> ScittServiceTrustPin {
        serde_json::from_value::<ScittServiceTrustPin>(serde_json::json!({
            "schema": crate::scitt::TRUST_PIN_SCHEMA,
            "service_identifier": "test-service",
            "discovery_method": "well-known-scitt-keys",
            "discovery_uri": "https://example.test/.well-known/scitt-keys",
            "fetched_at": "2026-07-31T00:00:00Z",
            "kid": TS_KID,
            "algorithm": "EdDSA",
            "public_key": {"x": mcp_re_core::b64url_encode(&ts().public_key().to_bytes())},
            "public_key_thumbprint": "unused-by-this-test",
            "discovery_document_digest": "unused-by-this-test",
            "leaf_profile": serde_json::to_value(leaf).expect("leaf"),
            "position_profile": serde_json::to_value(position).expect("position"),
        }))
        .expect("a legal pin document")
    }

    fn assert_parts(
        service: &ResolvedTransparencyService,
        leaf: StatementLeafProfile,
        position: ReceiptPositionProfile,
    ) {
        assert_eq!(service.leaf_profile(), leaf);
        assert_eq!(service.position_profile(), position);
        let CoseVerificationKey::Ed25519(k) = service.key() else {
            panic!("an EdDSA service key must be Ed25519");
        };
        assert_eq!(k.to_bytes(), ts().public_key().to_bytes());
    }

    #[test]
    fn a_pinned_service_carries_every_part_the_pin_states() {
        for leaf in LEAVES {
            for position in POSITIONS {
                let service = ResolvedTransparencyService::pinned(&pin(leaf, position));
                assert_parts(&service, leaf, position);
            }
        }
    }

    #[test]
    fn a_stated_service_carries_exactly_what_the_caller_said() {
        for leaf in LEAVES {
            for position in POSITIONS {
                let service =
                    ResolvedTransparencyService::stated(ts().public_key().into(), leaf, position);
                assert_parts(&service, leaf, position);
            }
        }
    }
}
