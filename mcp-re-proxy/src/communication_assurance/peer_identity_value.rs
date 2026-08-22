// SPDX-License-Identifier: Apache-2.0
//! The generic peer-identity value invariant — one owner, every provenance.
//!
//! A peer identity value is non-empty after trimming, length-bounded, and free of control
//! characters. That is a property of an identity value as such: it is what makes the value
//! safe to compare, to bind a signer to, and to write to a log. It is NOT a property of
//! X.509, of a SAN, of an HTTP header, or of any other mechanism that happens to carry
//! one. An issuer can mint a SAN holding a CR/LF or a megabyte of padding exactly as a
//! downstream proxy can inject a header holding one, so the two provenances must not
//! disagree about what a well-formed identity is — and the way to make them agree is one
//! owner, not two implementations that currently match.
//!
//! [`PeerIdentityValue`] is that owner. Its representation is private and its only
//! constructor is fallible, so **possession is the proof**: a `PeerIdentityValue` in hand
//! satisfies the invariant with no trailing clause about which caller remembered to check.
//! Deleting the check at any call site cannot bring an invalid inhabitant into existence,
//! because no call site can construct one.
//!
//! This value establishes well-formedness and nothing else. It does not establish that the
//! identity is authenticated, trusted, admitted, or authorized, and it does not know which
//! evidence produced it — provenance is carried by the evidence product that wraps it.

/// Maximum accepted length, in bytes, of a peer identity value (ADR-MCPS-023: identity
/// metadata MUST be length-bounded — oversized values fail closed). Generous enough for
/// SPIFFE URIs and RFC 2253 DNs, small enough to bound parse/compare/log cost and to
/// refuse a smuggling payload.
pub const MAX_PEER_IDENTITY_LEN: usize = 8192;

/// Why a candidate value is not a peer identity value.
///
/// A closed algebra rather than an absence: "the certificate field held something the
/// identity rules refuse" and "the certificate had no such field" are different security
/// facts, and a caller that cannot tell them apart cannot report or test either one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentityValueRefusal {
    /// Empty after trimming — whitespace is not an identity.
    Empty,
    /// Longer than [`MAX_PEER_IDENTITY_LEN`].
    TooLong,
    /// Contains a control character (CR / LF / NUL / …): a log-injection and
    /// header-smuggling shape that a well-formed identity value never has.
    ControlCharacter,
}

/// A well-formed peer identity value, whatever evidence produced it.
///
/// The inner `String` is private and there is no public constructor other than
/// [`PeerIdentityValue::interpret`], which is fallible. Every inhabitant therefore
/// satisfies the invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentityValue {
    value: String,
}

impl PeerIdentityValue {
    /// Interpret a candidate string as a peer identity value, or refuse with the reason.
    ///
    /// The accepted value is the TRIMMED one: surrounding whitespace is not part of the
    /// identity, and keeping it would let two spellings of the same identity compare
    /// unequal at the transport binding.
    pub fn interpret(candidate: &str) -> Result<Self, PeerIdentityValueRefusal> {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return Err(PeerIdentityValueRefusal::Empty);
        }
        if trimmed.len() > MAX_PEER_IDENTITY_LEN {
            return Err(PeerIdentityValueRefusal::TooLong);
        }
        if trimmed.chars().any(char::is_control) {
            return Err(PeerIdentityValueRefusal::ControlCharacter);
        }
        Ok(PeerIdentityValue {
            value: trimmed.to_string(),
        })
    }

    /// The identity value itself — the only projection.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::PeerIdentityValue;
    use super::PeerIdentityValueRefusal;
    use super::MAX_PEER_IDENTITY_LEN;

    #[test]
    fn a_well_formed_value_is_accepted_and_trimmed() {
        let value =
            PeerIdentityValue::interpret("  spiffe://example.org/agent-1  ").expect("accepted");
        assert_eq!(
            value.as_str(),
            "spiffe://example.org/agent-1",
            "the accepted value is the trimmed one; surrounding whitespace is not part of \
             the identity"
        );
    }

    #[test]
    fn whitespace_only_is_empty_not_a_value() {
        assert_eq!(
            PeerIdentityValue::interpret("   "),
            Err(PeerIdentityValueRefusal::Empty)
        );
    }

    #[test]
    fn the_length_bound_is_inclusive_and_refuses_one_byte_past_it() {
        let at_bound = "a".repeat(MAX_PEER_IDENTITY_LEN);
        assert!(
            PeerIdentityValue::interpret(&at_bound).is_ok(),
            "a value exactly at the bound is accepted"
        );
        let past_bound = "a".repeat(MAX_PEER_IDENTITY_LEN + 1);
        assert_eq!(
            PeerIdentityValue::interpret(&past_bound),
            Err(PeerIdentityValueRefusal::TooLong)
        );
    }

    #[test]
    fn every_control_character_shape_is_refused_for_the_same_reason() {
        for candidate in [
            "spiffe://example.org/a\rb",
            "spiffe://example.org/a\nb",
            "spiffe://example.org/a\0b",
            "spiffe://example.org/a\tb",
        ] {
            assert_eq!(
                PeerIdentityValue::interpret(candidate),
                Err(PeerIdentityValueRefusal::ControlCharacter),
                "a control character makes {candidate:?} a smuggling shape, not an identity"
            );
        }
    }

    #[test]
    fn refusal_precedence_reports_the_first_failing_rule() {
        // Existence before shape: an empty candidate is Empty, never ControlCharacter,
        // even though the untrimmed form is nothing but control characters.
        assert_eq!(
            PeerIdentityValue::interpret(" \t "),
            Err(PeerIdentityValueRefusal::Empty),
            "a control character that vanishes under trimming leaves an empty value"
        );
    }
}
