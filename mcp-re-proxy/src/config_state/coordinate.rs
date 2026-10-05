// SPDX-License-Identifier: Apache-2.0
//! The canonical form of a configured coordinate.
//!
//! A value the deployment mints into a credential or an identity, or compares byte for
//! byte against a request, is the exact bytes it was given. A padded value names a
//! different coordinate from the one written without the padding, and a blank one names
//! none, so a coordinate is legal only when it is non-blank and equal to its own trim.
//! Each owner words the refusal, because only it knows what the coordinate is minted into.

/// Why a configured value is not a canonical coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoordinateFault {
    /// Empty, or whitespace only.
    Blank,
    /// Non-blank, with leading or trailing whitespace.
    Padded,
}

/// The fault in `value` as a coordinate, or `None` when it is canonical.
pub(crate) fn fault(value: &str) -> Option<CoordinateFault> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Some(CoordinateFault::Blank)
    } else if trimmed != value {
        Some(CoordinateFault::Padded)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_canonical_value_has_no_fault() {
        assert_eq!(fault("corp.example"), None);
        assert_eq!(fault("did:example:server 1"), None);
    }

    #[test]
    fn an_empty_or_whitespace_value_is_blank() {
        for value in ["", " ", "\t\n"] {
            assert_eq!(fault(value), Some(CoordinateFault::Blank), "{value:?}");
        }
    }

    #[test]
    fn a_value_unequal_to_its_trim_is_padded() {
        for value in [" corp.example", "did:x\n", "2026-07-28 ", "\tv"] {
            assert_eq!(fault(value), Some(CoordinateFault::Padded), "{value:?}");
        }
    }
}
