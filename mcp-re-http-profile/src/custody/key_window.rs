// SPDX-License-Identifier: Apache-2.0
//! The delegated key's lifecycle window: the credential life `T` and the rotation overlap
//! `O`, with `0 < O < T` true of every inhabitant.
//!
//! # Why the relation lives here and the ceiling does not
//!
//! Two bounds apply to these numbers and they have different owners.
//!
//! `0 < O < T` is a relation between two fields of ONE struct. No owner outside the struct
//! can hold a relation between its own fields without the struct's cooperation — which is
//! why, while [`CustodyConfig`](super::CustodyConfig) carried `pub ttl: i64` and
//! `pub overlap: i64`, the proxy's validated pair was destructured at the crate boundary and
//! `CustodyConfig { ttl: 60, overlap: 60 }` remained an ordinary expression. With
//! `overlap >= ttl`, `rotation_due` reads `exp - overlap <= now` on every pass, so the rotor
//! mints a fresh keypair against the root on every attempt for the life of the process —
//! putting the root/KMS issuer on the per-request path, which is the one thing the whole
//! delegated-custody design exists to prevent.
//!
//! `T <= MAX_DELEGATED_TTL_SECS` is NOT a relation between these fields. It is a deployment
//! policy number — how long an exfiltrated hot-path key stays verifiable — and nothing about
//! this type makes it the authority on that. It stays with the proxy's configuration owner,
//! which applies it before producing a window.
//!
//! So this type states exactly one thing, and states it for every value that exists.
//!
//! # What it does not remove
//!
//! The terms in [`issuance_terms`](super::issuance_terms) still fail in the restrictive
//! direction, and still must. `of` bounds the RELATION, not the magnitude: `T` may still be
//! large enough that `now + T` is unrepresentable, because the ceiling that would prevent
//! that belongs to a different owner and does not reach this crate. What `of` does remove is
//! the `overlap >= ttl` case, which the restrictive arithmetic compensated for with nothing
//! at all.

/// Why a `(ttl, overlap)` pair is not a legal delegated key window.
///
/// Two variants rather than one, because the caller renders them to an operator and the two
/// mistakes have different remedies: a non-positive overlap is a value error, and an overlap
/// at or beyond the TTL is a pairing error that names both numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWindowError {
    /// `overlap <= 0`. The rotor mints a successor one overlap before expiry, so a
    /// non-positive overlap is a rotation that never begins.
    NonPositiveOverlap,
    /// `overlap >= ttl`. Every instant is inside the rotation window, so every request
    /// finds the credential due for replacement and the root is approached on each one.
    OverlapNotInsideTtl,
}

impl std::fmt::Display for KeyWindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyWindowError::NonPositiveOverlap => {
                write!(f, "the rotation overlap must be greater than 0")
            }
            KeyWindowError::OverlapNotInsideTtl => {
                write!(f, "the rotation overlap must be strictly less than the TTL")
            }
        }
    }
}

/// The delegated credential life `T` and rotation overlap `O`, with `0 < O < T`.
///
/// The fields are private and [`DelegatedKeyWindow::of`] is the only producer, so possessing
/// one IS the statement that the pair satisfies the relation. That is the property the two
/// bare `i64`s could not carry: a consumer that needs the TTL needs the overlap it was
/// checked against, and reading them as independent integers is what allowed a validated TTL
/// to be paired with an arbitrary overlap one crate away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegatedKeyWindow {
    ttl: i64,
    overlap: i64,
}

impl DelegatedKeyWindow {
    /// The window `(ttl, overlap)`, or why that pair is not one.
    ///
    /// Fallible at construction rather than checked at use: a check at use is a statement
    /// about the sites that remember to perform it, and this is a statement about the type.
    pub fn of(ttl: i64, overlap: i64) -> Result<Self, KeyWindowError> {
        if overlap <= 0 {
            return Err(KeyWindowError::NonPositiveOverlap);
        }
        if overlap >= ttl {
            return Err(KeyWindowError::OverlapNotInsideTtl);
        }
        Ok(DelegatedKeyWindow { ttl, overlap })
    }

    /// The life of every delegated response-signing credential, in seconds.
    pub fn ttl(&self) -> i64 {
        self.ttl
    }

    /// How long before expiry the rotor mints the successor, in seconds.
    pub fn overlap(&self) -> i64 {
        self.overlap
    }
}

impl std::fmt::Display for DelegatedKeyWindow {
    /// Renders the PAIR, because the pair is what the value is. An operator reading a
    /// startup line needs the overlap next to the TTL it sits inside — printing one
    /// without the other is the same halving this type exists to prevent, in prose.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TTL {}s / overlap {}s", self.ttl, self.overlap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair the whole type exists to exclude, in both of its shapes.
    ///
    /// `overlap == ttl` is the boundary case and the one a `<=`/`<` slip would admit; with
    /// it, `exp - overlap` equals the issuance instant and every later `now` reads as due.
    #[test]
    fn an_overlap_outside_the_ttl_is_not_a_window() {
        assert_eq!(
            DelegatedKeyWindow::of(60, 60),
            Err(KeyWindowError::OverlapNotInsideTtl)
        );
        assert_eq!(
            DelegatedKeyWindow::of(60, 61),
            Err(KeyWindowError::OverlapNotInsideTtl)
        );
        // A non-positive overlap is reported as its own mistake, not as a pairing one: it
        // is wrong against no TTL at all.
        assert_eq!(
            DelegatedKeyWindow::of(60, 0),
            Err(KeyWindowError::NonPositiveOverlap)
        );
        assert_eq!(
            DelegatedKeyWindow::of(60, -1),
            Err(KeyWindowError::NonPositiveOverlap)
        );
        // And a non-positive TTL cannot be a window either — it is caught by the relation
        // rather than by a clause of its own, because no positive overlap fits inside it.
        assert_eq!(
            DelegatedKeyWindow::of(0, 1),
            Err(KeyWindowError::OverlapNotInsideTtl)
        );
    }

    /// The vacuity guard: a legal pair is accepted and projects back unchanged.
    #[test]
    fn a_legal_pair_is_a_window_and_projects_what_it_was_given() {
        let w = DelegatedKeyWindow::of(300, 60).expect("0 < 60 < 300");
        assert_eq!((w.ttl(), w.overlap()), (300, 60));
        // The rendering names both numbers; an operator reading only one cannot tell
        // whether the overlap sits inside the life it was checked against.
        assert_eq!(w.to_string(), "TTL 300s / overlap 60s");
    }

    /// The MAGNITUDE bound is not this type's, and the ceiling's owner is one crate away —
    /// so a TTL large enough to make `now + ttl` unrepresentable is still constructible
    /// here, and `issuance_terms` must still refuse it rather than mint a wrapped `exp`.
    ///
    /// Stated as a test because it is the exact boundary between the two owners, and a
    /// future reader tempted to "finish" this guard by bounding the magnitude would be
    /// taking a deployment policy decision inside a profile type.
    #[test]
    fn the_magnitude_ceiling_is_not_this_types_to_apply() {
        assert!(DelegatedKeyWindow::of(i64::MAX, 1).is_ok());
    }
}
