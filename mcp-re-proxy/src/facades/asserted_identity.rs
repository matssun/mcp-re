// SPDX-License-Identifier: Apache-2.0
//! The historical identity vocabulary, as a facade over the communication-assurance
//! authority.
//!
//! Everything here is compatibility surface for ADR-MCPRE-063 Slice 1. The names predate
//! the authority — `MAX_ASSERTED_IDENTITY_LEN` names a bound that belongs to an identity
//! value rather than to an ingress mechanism, and `validate_asserted_identity_value` names
//! a rule that is not specific to an assertion — and they survive so their callers can
//! migrate one at a time instead of in this slice.
//!
//! **Nothing here owns anything.** Every item is a projection, a conversion, or a mapping
//! of the owner's refusal into a caller's existing vocabulary. Deleting a check in this
//! file is impossible, because there is no check in this file to delete: that is what
//! distinguishes a facade from the second implementation it replaced.
//!
//! Keeping the facade in its own module makes the migration surface countable. When the
//! last consumer of these names is gone, this file is deleted whole, and nothing else has
//! to be untangled first.

use crate::communication_assurance::peer_identity_value::MAX_PEER_IDENTITY_LEN;
use crate::communication_assurance::CertificateIdentityPolicy;
use crate::communication_assurance::CertificateIdentitySource;
use crate::communication_assurance::PeerIdentityValue;
use crate::communication_assurance::PeerIdentityValueRefusal;
use crate::transport::IdentityPolicy;
use crate::transport::IdentitySource;

/// Maximum accepted length (bytes) of an asserted trusted-ingress identity value
/// (ADR-MCPS-023: asserted-identity metadata MUST be length-bounded — oversized values
/// fail closed).
///
/// This is [`MAX_PEER_IDENTITY_LEN`] under its historical name. One number, not two that
/// currently agree.
pub const MAX_ASSERTED_IDENTITY_LEN: usize = MAX_PEER_IDENTITY_LEN;

/// Why a trusted-ingress asserted-identity value was rejected (ADR-MCPS-023).
///
/// The historical spelling of [`PeerIdentityValueRefusal`], preserved because the ingress
/// path's callers match on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertedIdentityRejection {
    /// Empty after trimming.
    Empty,
    /// Longer than [`MAX_ASSERTED_IDENTITY_LEN`].
    TooLong,
    /// Contains a control character (CR / LF / NUL / …) — a header-smuggling and
    /// log-injection risk; a well-formed identity value has none.
    Malformed,
}

impl From<PeerIdentityValueRefusal> for AssertedIdentityRejection {
    fn from(refusal: PeerIdentityValueRefusal) -> Self {
        match refusal {
            PeerIdentityValueRefusal::Empty => AssertedIdentityRejection::Empty,
            PeerIdentityValueRefusal::TooLong => AssertedIdentityRejection::TooLong,
            PeerIdentityValueRefusal::ControlCharacter => AssertedIdentityRejection::Malformed,
        }
    }
}

/// Validate a single asserted trusted-ingress identity value: non-empty, length-bounded,
/// and free of control characters. Returns the trimmed value, or the reason it fails
/// closed.
///
/// The rules are NOT implemented here. Well-formedness is a property of a peer identity
/// value whatever produced it, and [`PeerIdentityValue`] owns it — reimplementing it here
/// is what previously made the certificate path and the header path two authorities over
/// one fact.
///
/// The **single-valued** rule is a different fact and belongs to the caller, which checks
/// it via `RequestHeaders::count` before the value is ever read.
pub fn validate_asserted_identity_value(value: &str) -> Result<&str, AssertedIdentityRejection> {
    match PeerIdentityValue::interpret(value) {
        Ok(_) => Ok(value.trim()),
        Err(refusal) => Err(refusal.into()),
    }
}

// `rendered_transport_identity` was removed here by ADR-MCPRE-064 Slice 4. Its only
// consumer was the transport-binding comparison, and that relation now takes two SEMANTIC
// products — an authenticated channel peer and a verified request subject — so nothing in
// production renders a peer into the historical `TransportIdentity` any more.
//
// `TransportIdentity` itself survives for the ingress-assertion paths (Tier 3 and Mode C),
// which assert an identity rather than authenticating a TLS peer. Both are refused by
// configuration validation today.

impl From<IdentityPolicy> for CertificateIdentityPolicy {
    /// The configuration vocabulary names the same choice the authority names.
    fn from(policy: IdentityPolicy) -> Self {
        match policy {
            IdentityPolicy::UriSan => CertificateIdentityPolicy::UriSan,
            IdentityPolicy::DnsSan => CertificateIdentityPolicy::DnsSan,
            IdentityPolicy::CnLegacy => CertificateIdentityPolicy::CommonNameLegacy,
        }
    }
}

impl From<CertificateIdentitySource> for IdentitySource {
    /// The provenance the authority established, in the historical vocabulary.
    fn from(source: CertificateIdentitySource) -> Self {
        match source {
            CertificateIdentitySource::UriSan => IdentitySource::UriSan,
            CertificateIdentitySource::DnsSan => IdentitySource::DnsSan,
            CertificateIdentitySource::CommonName => IdentitySource::CommonName,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_asserted_identity_value;
    use super::AssertedIdentityRejection;
    use crate::communication_assurance::CertificateIdentityPolicy;
    use crate::communication_assurance::CertificateIdentitySource;
    use crate::transport::IdentityPolicy;
    use crate::transport::IdentitySource;

    #[test]
    fn every_owner_refusal_maps_to_the_historical_rejection_it_replaced() {
        assert_eq!(
            validate_asserted_identity_value("   "),
            Err(AssertedIdentityRejection::Empty)
        );
        assert_eq!(
            validate_asserted_identity_value("bad\rvalue"),
            Err(AssertedIdentityRejection::Malformed)
        );
        let huge = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN + 1);
        assert_eq!(
            validate_asserted_identity_value(&huge),
            Err(AssertedIdentityRejection::TooLong)
        );
    }

    #[test]
    fn a_valid_value_comes_back_trimmed_and_borrowed() {
        assert_eq!(
            validate_asserted_identity_value("  spiffe://example.org/agent-1  "),
            Ok("spiffe://example.org/agent-1")
        );
    }

    #[test]
    fn the_two_vocabularies_agree_field_for_field() {
        // A conversion that dropped a case would silently repoint a deployment at another
        // certificate field, so both directions are enumerated rather than spot-checked.
        for (legacy, semantic) in [
            (IdentityPolicy::UriSan, CertificateIdentityPolicy::UriSan),
            (IdentityPolicy::DnsSan, CertificateIdentityPolicy::DnsSan),
            (
                IdentityPolicy::CnLegacy,
                CertificateIdentityPolicy::CommonNameLegacy,
            ),
        ] {
            assert_eq!(CertificateIdentityPolicy::from(legacy), semantic);
        }
        for (semantic, legacy) in [
            (CertificateIdentitySource::UriSan, IdentitySource::UriSan),
            (CertificateIdentitySource::DnsSan, IdentitySource::DnsSan),
            (
                CertificateIdentitySource::CommonName,
                IdentitySource::CommonName,
            ),
        ] {
            assert_eq!(IdentitySource::from(semantic), legacy);
        }
    }
}
