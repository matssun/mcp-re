// SPDX-License-Identifier: Apache-2.0
//! The trust document's OWN lifetime, which outranks every individual root.
//!
//! A trust picture is published by a document, and that document expires. The
//! per-issuer lifecycle — current, retired-in-overlap, revoked — answers *is this root
//! still good*; this answers *is the picture it belongs to still usable at all*, and it
//! wins: once the document has expired every root in it resolves to nothing, however
//! current that root's own state says it is.
//!
//! Carried INTO the anchor set rather than checked at load time, so *a stale trust picture
//! is never used* is a property of every verification rather than of the one moment the
//! document was read. Left at the loader, the gate lives only in `load_signed_manifest`
//! and in whatever refresher a deployment happens to run: a client that disables refresh
//! keeps verifying against anchors from a document that expired weeks ago, and even one
//! that refreshes keeps them for up to a full reload interval past expiry.
//!
//! `Absent` is a real state, not a missing value: a set assembled by hand has no document
//! behind it and therefore no deadline to enforce. It is not "expiry unknown", and it never
//! fails closed.

/// When the document behind a trust picture stops being usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum ManifestValidity {
    /// No document — a set assembled by hand. Nothing to expire.
    #[default]
    Absent,
    /// The publishing document's `expires_at`, in unix seconds.
    Until(i64),
}

impl ManifestValidity {
    /// The deadline, if there is a document behind this picture.
    pub(super) fn expires_at(self) -> Option<i64> {
        match self {
            ManifestValidity::Absent => None,
            ManifestValidity::Until(expires_at) => Some(expires_at),
        }
    }

    /// Whether the document has expired at `now`. A picture with no document never has.
    pub(super) fn is_expired(self, now: i64) -> bool {
        matches!(self, ManifestValidity::Until(expires_at) if now > expires_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hand_assembled_picture_has_no_deadline_to_miss() {
        // `Absent` is a state, not an absent value. A set with no document behind it must
        // not fail closed at every instant merely because it cannot name a deadline.
        assert_eq!(ManifestValidity::Absent.expires_at(), None);
        assert!(!ManifestValidity::Absent.is_expired(i64::MAX));
    }

    #[test]
    fn the_deadline_is_inclusive_of_the_instant_it_names() {
        // `now > expires_at`, not `>=`: a document is usable through the last second it
        // claims, and the loader and the verifier must agree on which second that is.
        let validity = ManifestValidity::Until(100);
        assert!(!validity.is_expired(100));
        assert!(validity.is_expired(101));
        assert_eq!(validity.expires_at(), Some(100));
    }
}
