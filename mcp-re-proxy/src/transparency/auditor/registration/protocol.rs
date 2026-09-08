// SPDX-License-Identifier: Apache-2.0
//! WHICH registration protocol this run speaks.
//!
//! One fact: **the mechanism the operator named.**
//!
//! It is named, never inferred. A service's base URL does not say what it speaks, and
//! guessing from the shape of an answer would let a client reach one service by
//! coincidence while calling a different contract by the other's name — which is exactly
//! the laundering the mechanism-leaf boundary exists to prevent.
//!
//! # It also decides what a successful run may CLAIM
//!
//! The two mechanisms do not earn the same sentence. A run against a SCRAPI peer earns
//! *SCRAPI interoperability*; a run against `capsule-anchor` earns *external Transparency
//! Service interoperability* and no more, because that service does not speak SCRAPI. The
//! selection is therefore carried into the artifact rather than spent at the call, so a
//! reader of the artifact can never be told a stronger claim than the peer that actually
//! answered.

/// The registration contracts this auditor can speak.
///
/// A closed enum, and deliberately: each variant is a mechanism leaf that exists, so a
/// value here always names something a run can actually do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::transparency::auditor) enum RegistrationProtocol {
    /// `draft-ietf-scitt-scrapi-11`. The default, unchanged from before there was a
    /// choice: an operator who does not name a protocol gets the one they were getting.
    #[default]
    Scrapi11,
    /// The `capsule-anchor` service contract.
    CapsuleAnchor,
}

/// The flag token for `Scrapi11`.
const SCRAPI_11_TOKEN: &str = "scrapi-11";

/// The flag token for `CapsuleAnchor`.
const CAPSULE_ANCHOR_TOKEN: &str = "capsule-anchor";

impl RegistrationProtocol {
    /// The protocol an operator named, or the refusal listing what may be named.
    pub(in crate::transparency::auditor) fn parse(token: &str) -> Result<Self, String> {
        match token {
            SCRAPI_11_TOKEN => Ok(RegistrationProtocol::Scrapi11),
            CAPSULE_ANCHOR_TOKEN => Ok(RegistrationProtocol::CapsuleAnchor),
            other => Err(format!(
                "--registration-protocol {other:?}: not a protocol this auditor speaks \
                 ({SCRAPI_11_TOKEN}, {CAPSULE_ANCHOR_TOKEN})",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every token names a mechanism, and nothing else does. The refusal lists both, so
    /// an operator who mistyped one is told what may be typed rather than only that this
    /// was not it.
    #[test]
    fn each_token_names_its_mechanism_and_nothing_else_parses() {
        assert_eq!(
            RegistrationProtocol::parse(SCRAPI_11_TOKEN),
            Ok(RegistrationProtocol::Scrapi11),
        );
        assert_eq!(
            RegistrationProtocol::parse(CAPSULE_ANCHOR_TOKEN),
            Ok(RegistrationProtocol::CapsuleAnchor),
        );
        for other in ["", "scrapi", "scrapi-10", "SCRAPI-11", "capsule_anchor"] {
            let refused =
                RegistrationProtocol::parse(other).expect_err("not a protocol this auditor speaks");
            assert!(refused.contains("scrapi-11"), "{refused}");
            assert!(refused.contains("capsule-anchor"), "{refused}");
        }
    }

    /// The default is the protocol that was the only one, so an existing invocation that
    /// names none behaves exactly as it did.
    #[test]
    fn the_default_is_the_protocol_that_was_the_only_one() {
        assert_eq!(
            RegistrationProtocol::default(),
            RegistrationProtocol::Scrapi11
        );
    }
}
