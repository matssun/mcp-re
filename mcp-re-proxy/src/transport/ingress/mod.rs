// SPDX-License-Identifier: Apache-2.0
//! The DEFERRED ingress-attestation capability (ADR-MCPS-023 Tier 4, issue #71).
//!
//! # Unreachable, on purpose
//!
//! Nothing in this module can be reached from a serving path. `--transport-binding
//! attested-ingress` is refused at Layer-A validation, and
//! [`TransportBinding`](super::TransportBinding) has exactly one constructor — the Mode-A
//! exact match.
//!
//! **That is an intentional deployment fact and this module is not the place to change
//! it.** The capability is not deleted, because the Mode-C verifier is a correct
//! implementation whose tests mint real assertions and verify them; and it is not made
//! selectable, because the rebinding of an attestation onto the RFC 9421 request evidence
//! is not yet specified. `docs/AGENT_INSTRUCTIONS.md` §9 names both mistakes.
//!
//! # What changes here
//!
//! Its change rule is the opposite of the live half's: nothing here is exercised by a
//! deployment, so the only thing that keeps it correct is its own test suite. Keep the
//! suite exhaustive, and do not weaken a check on the grounds that nothing reaches it.
//!
//! # One frozen format, one capability
//!
//! ```text
//! ingress capability          this module — what the mechanism IS, and the
//!     |                       attestor keys a node trusts for it
//!     +-- v2  Mode C / Tier 4  mcp-re/lb-ingress-assertion/v2
//! ```
//!
//! The format is FROZEN: it owns its wire vocabulary, preimage, parser, verifier and
//! rejections as one definition, and its preimage is domain-separated by a
//! version-qualified tag, so a signature produced under another version of this mechanism
//! can never be re-framed as one of these. The domain-separation test below is what pins
//! that.

mod v2;
mod v2_wire;

pub use v2::AttestedCertVerification;
pub use v2::AttestedIngressVerified;
pub use v2::AttestedRevocation;
pub use v2::LbAssertionV2;
pub use v2::LbAssertionV2Binding;
pub use v2::LbAssertionV2Rejection;

use mcp_re_core::VerificationKey;

/// The default freshness window (seconds) for an LB ingress assertion: how far the
/// assertion's `validation_time` may lag behind the node's `now_unix` and still be
/// accepted. Small by design — the attestor signs the assertion at the moment it admits
/// the request, so a legitimate assertion reaches the node within seconds.
pub const DEFAULT_LB_ASSERTION_MAX_AGE_SECS: i64 = 30;

/// A trusted attestor verification key, addressed by its key id, used to verify
/// attestor-signed ingress assertions. The key id is the opaque label the LB stamps into the
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

    /// The frozen format's preimage is domain-separated by a VERSION-QUALIFIED tag,
    /// which is what keeps a signature produced under one version of the ingress
    /// assertion from being re-framed as another. The tag is the leading bytes, so the
    /// separation holds for every field assignment rather than for a chosen one.
    #[test]
    fn the_frozen_format_is_domain_separated_by_its_version_tag() {
        let now = 1_000_000;
        let v2 = LbAssertionV2 {
            key_id: "k".to_string(),
            ingress_identity: "spiffe://example.org/ingress-attestor-1".to_string(),
            asserted_client_identity: "spiffe://example.org/agent-1".to_string(),
            request_hash: in_hand_request_hash(),
            audience: "did:example:server-1".to_string(),
            cert_verification_result: AttestedCertVerification::Verified,
            revocation_result: AttestedRevocation::Good,
            validation_time: now,
            crl_next_update: now + 3600,
            expires_at: None,
        };
        assert!(v2
            .signing_preimage()
            .starts_with(b"mcp-re/lb-ingress-assertion/v2"));
        assert!(!v2
            .signing_preimage()
            .starts_with(b"mcp-re/lb-ingress-assertion/v1"));
    }
}
