// SPDX-License-Identifier: Apache-2.0
//! The DEFERRED ingress-attestation capability (ADR-MCPS-023 Tier 3, issue #71).
//!
//! # Unreachable, on purpose
//!
//! Nothing in this module can be reached from a serving path. `--transport-binding
//! lb-assertion` and `--transport-binding attested-ingress` are refused at Layer-A
//! validation, and [`TransportBinding`](super::TransportBinding) has exactly one
//! constructor — the Mode-A exact match. EX-005 measured this half as 913 of the
//! pre-split file's 1268 production lines.
//!
//! **That is an intentional deployment fact and this module is not the place to change
//! it.** The capability is not deleted, because the Mode-C verifier is a correct
//! implementation whose tests mint real assertions and verify them; and it is not made
//! selectable, because the rebinding of an attestation onto the RFC 9421 request evidence
//! is not yet specified. `docs/AGENT_INSTRUCTIONS.md` §9 names both mistakes.
//!
//! Mode B (`LbAssertion`) is refused for a different reason, and it is a RULING rather
//! than a gap: the load balancer belongs outside the trusted computing base.
//!
//! # What changes here
//!
//! Its change rule is the opposite of the live half's: nothing here is exercised by a
//! deployment, so the only thing that keeps it correct is its own test suite. Keep the
//! suite exhaustive, and do not weaken a check on the grounds that nothing reaches it.
//!
//! # Two frozen formats, one capability
//!
//! ```text
//! ingress capability          this module — what these mechanisms ARE, and the
//!     |                       attestor keys a node trusts for either of them
//!     +-- v1  Mode B / Tier 3  mcp-re/lb-ingress-assertion/v1
//!     +-- v2  Mode C / Tier 4  mcp-re/lb-ingress-assertion/v2
//! ```
//!
//! v2 is a NEW frozen format rather than an extension of v1 — a distinct
//! domain-separation tag, a distinct field layout and a distinct verifier order — so each
//! version owns its own wire vocabulary, preimage, parser, verifier and rejections.
//! Nothing here abstracts over the two: an abstraction that made the formats
//! interchangeable would erase the property their separation exists to guarantee, and the
//! disjointness test below is what pins it.

mod v1;
mod v2;

pub use v1::LbAssertion;
pub use v1::LbAssertionBinding;
pub use v1::LbAssertionRejection;
pub use v1::DEFAULT_LB_ASSERTION_MAX_AGE_SECS;
pub use v2::AttestedCertVerification;
pub use v2::AttestedIngressVerified;
pub use v2::AttestedRevocation;
pub use v2::LbAssertionV2;
pub use v2::LbAssertionV2Binding;
pub use v2::LbAssertionV2Rejection;

use mcp_re_core::VerificationKey;

/// A trusted LB verification key, addressed by its key id, used to verify Tier-3
/// LB-signed assertions. The key id is the opaque label the LB stamps into the
/// assertion's `key_id` field; the node looks the verification key up by it.
#[derive(Debug, Clone)]
struct LbKeyEntry {
    /// The LB key id (matches the assertion's `key_id` field byte-for-byte).
    key_id: String,
    /// The Ed25519 verification (public) key for this key id.
    key: VerificationKey,
}

/// Fixtures both frozen formats' suites are written against.
///
/// Shared because they describe the REQUEST under test rather than either wire format —
/// a version-specific fixture belongs in that version's own module.
#[cfg(test)]
mod test_support {
    /// A fixed attestor signing seed so the minted assertions are reproducible.
    pub(super) const LB_SEED: [u8; 32] = [42u8; 32];

    /// The request hash the node holds in hand for the request under test.
    pub(super) fn in_hand_request_hash() -> String {
        mcp_re_core::sha256_hash_id(br#"{"jsonrpc":"2.0","method":"tools/call","id":1}"#)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::in_hand_request_hash;

    /// The two frozen formats are DISJOINT, which is the one property neither version can
    /// establish alone and the reason they are two modules rather than one with a flag.
    ///
    /// For identical shared field values the preimages must differ, because the domain tag
    /// is the leading bytes — so a v1 signature can never be re-framed as a v2 assertion.
    #[test]
    fn the_two_frozen_formats_have_disjoint_preimages() {
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let client = "spiffe://example.org/agent-1";
        let v1 = LbAssertion {
            key_id: "k".to_string(),
            asserted_client_identity: client.to_string(),
            request_hash: rh.clone(),
            validation_time: now,
        };
        let v2 = LbAssertionV2 {
            key_id: "k".to_string(),
            ingress_identity: "spiffe://example.org/ingress-attestor-1".to_string(),
            asserted_client_identity: client.to_string(),
            request_hash: rh,
            audience: "did:example:server-1".to_string(),
            cert_verification_result: AttestedCertVerification::Verified,
            revocation_result: AttestedRevocation::Good,
            validation_time: now,
            crl_next_update: now + 3600,
            expires_at: None,
        };
        assert_ne!(v1.signing_preimage(), v2.signing_preimage());
        assert!(v2
            .signing_preimage()
            .starts_with(b"mcp-re/lb-ingress-assertion/v2"));
        assert!(!v2
            .signing_preimage()
            .starts_with(b"mcp-re/lb-ingress-assertion/v1"));
        assert!(v1
            .signing_preimage()
            .starts_with(b"mcp-re/lb-ingress-assertion/v1"));
    }
}
