// SPDX-License-Identifier: Apache-2.0
//! The closed set of evidence-handle roles, and the one labeled derivation every handle
//! is minted through (#416 rev 2 §7.1/§7.3).

use mcp_re_core::b64url_encode;
use sha2::Digest;
use sha2::Sha256;

use crate::ids::EVIDENCE_LABEL_REQUEST;
use crate::ids::EVIDENCE_LABEL_REQUEST_STATE;
use crate::ids::EVIDENCE_LABEL_RESPONSE;

/// Which input an evidence handle commits to. Closed: a handle's role label is chosen
/// from this enum, never passed as a string, so the set of labels the derivation can
/// see is exactly the three constants [`EvidenceRole::label`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRole {
    /// A request's RFC 9421 signature base.
    Request,
    /// A response's RFC 9421 signature base.
    Response,
    /// The opaque MRTR `requestState` bytes.
    RequestState,
}

impl EvidenceRole {
    /// The profile-scoped role label the derivation prefixes.
    pub fn label(self) -> &'static str {
        match self {
            EvidenceRole::Request => EVIDENCE_LABEL_REQUEST,
            EvidenceRole::Response => EVIDENCE_LABEL_RESPONSE,
            EvidenceRole::RequestState => EVIDENCE_LABEL_REQUEST_STATE,
        }
    }
}

/// `base64url-no-pad(SHA-256(label || 0x00 || bytes))` under `role`'s label.
///
/// Injective in `(role, bytes)` up to SHA-256: every label is ASCII without a NUL (the
/// test below checks all three, and the enum is closed), so the first `0x00` in the
/// preimage ends the label and no two `(role, bytes)` pairs share a preimage. Cross-role
/// distinctness of the DIGESTS is the hash's collision resistance, which stays at
/// `boundary.crypto_primitives`.
pub(crate) fn labeled_digest_value(role: EvidenceRole, bytes: &[u8]) -> String {
    let label = role.label();
    // Saturating on a capacity HINT: an unrepresentable one is simply not reserved.
    let capacity = label.len().saturating_add(1).saturating_add(bytes.len());
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(label.as_bytes());
    preimage.push(0x00);
    preimage.extend_from_slice(bytes);
    b64url_encode(&Sha256::digest(&preimage))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [EvidenceRole; 3] = [
        EvidenceRole::Request,
        EvidenceRole::Response,
        EvidenceRole::RequestState,
    ];

    /// The injectivity argument's premise, over the whole closed domain: every label is
    /// ASCII, NUL-free, and distinct from every other.
    #[test]
    fn every_label_is_nul_free_ascii_and_distinct() {
        for (i, a) in ALL.iter().enumerate() {
            assert!(a.label().is_ascii(), "{a:?}");
            assert!(!a.label().as_bytes().contains(&0x00), "{a:?}");
            for b in ALL.iter().skip(i.saturating_add(1)) {
                assert_ne!(a.label(), b.label(), "{a:?} / {b:?}");
            }
        }
    }

    /// No label is a prefix of another, so a byte moved across the separator cannot turn
    /// one role's preimage into another's.
    #[test]
    fn no_label_is_a_prefix_of_another() {
        for a in ALL {
            for b in ALL {
                if a != b {
                    assert!(!b.label().starts_with(a.label()), "{a:?} / {b:?}");
                }
            }
        }
    }

    #[test]
    fn roles_differ_over_identical_bytes() {
        let bytes = b"identical bytes";
        for a in ALL {
            for b in ALL {
                if a != b {
                    assert_ne!(
                        labeled_digest_value(a, bytes),
                        labeled_digest_value(b, bytes)
                    );
                }
            }
        }
    }

    /// A handle is bound to its profile-scoped label, so it is not a plain SHA-256 of the
    /// input that some other profile might also produce.
    #[test]
    fn handle_is_not_a_bare_digest() {
        let bytes = b"base bytes";
        assert_ne!(
            labeled_digest_value(EvidenceRole::Request, bytes),
            b64url_encode(&Sha256::digest(bytes)),
        );
    }
}
