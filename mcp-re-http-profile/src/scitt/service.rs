// SPDX-License-Identifier: Apache-2.0
//! How to check one transparency service's receipts.
//!
//! One fact: **the key, the leaf profile and the position profile that go together.** It is
//! its own module rather than a struct beside the fold because the question it answers is
//! *whose log is this* — and because its two producers are the whole of what the type
//! establishes. See the type's own note for why it is deliberately NOT sealed.

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
/// # What the private fields buy, and what they do NOT
///
/// They remove the struct literal, so every producer is NAMED and a call site says which
/// one it is: [`pinned`](Self::pinned), where all three came from one operator-reviewed
/// document, or [`stated`](Self::stated), where the caller is asserting them.
///
/// They do **not** make the census's illegal pairing unconstructible, and this record does
/// not claim they do. `verify_receipt_offline` takes the service as a
/// `Fn(&str) -> Option<ResolvedTransparencyService>` seam, so outside code is a legitimate
/// producer — the in-process prototype log is one, with no pin to resolve from — and
/// against a seam a private field only forces a constructor taking the same arguments with
/// the same absence of checking. Ask ADR-MCPRE-061's question: *if this value is illegal,
/// whose bug is it?* The answer here is "whoever implemented the resolver", so a seal would
/// be ceremony. This is the same measurement `ResolvedActor` and the trust seam already
/// produced (`docs/dev/sealed-owners.md`); what changes is that the two provenances now
/// have names, not that one of them became impossible.
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
    /// The in-process [`PrototypeTransparencyService`] and the conformance corpora built
    /// from it are the real cases. The name is the contract: this establishes only that
    /// the caller said so, and in particular does not establish that the leaf and position
    /// profiles are ones any operator pinned.
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
