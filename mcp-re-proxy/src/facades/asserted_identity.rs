// SPDX-License-Identifier: Apache-2.0
//! The historical identity-configuration vocabulary, as a facade over the
//! communication-assurance authority.
//!
//! What remains here is TWO CONVERSIONS between the configuration vocabulary
//! (`IdentityPolicy` / `IdentitySource`) and the authority's own
//! (`CertificateIdentityPolicy` / `CertificateIdentitySource`) — the same choice and the
//! same provenance under two spellings, kept because their creditors still speak the
//! historical one.
//!
//! **Nothing here owns anything.** Both items are conversions. Deleting a check in this
//! file is impossible, because there is no check in this file to delete: that is what
//! distinguishes a facade from the second implementation it replaced.
//!
//! Their creditors are `transport/identity.rs`'s `extract_identity` and `tls.rs`'s
//! `authenticate_relationship_peer` call, and while those speak the configuration
//! vocabulary this module is the one place the two spellings are reconciled.

use crate::communication_assurance::CertificateIdentityPolicy;
use crate::communication_assurance::CertificateIdentitySource;
use crate::transport::IdentityPolicy;
use crate::transport::IdentitySource;

// Nothing in production renders a peer into the historical `TransportIdentity`: the
// transport-binding relation takes two SEMANTIC products — an authenticated channel peer
// and a verified request subject. `TransportIdentity` survives for the Mode-C
// ingress-assertion path, which asserts an identity rather than authenticating a TLS peer,
// and which configuration validation refuses today.

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
    use crate::communication_assurance::CertificateIdentityPolicy;
    use crate::communication_assurance::CertificateIdentitySource;
    use crate::transport::IdentityPolicy;
    use crate::transport::IdentitySource;

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
