// SPDX-License-Identifier: Apache-2.0
//! Which certificate field is the authoritative identity, and which one an interpretation
//! actually read.
//!
//! These are two different facts and they are two different types. The policy is a
//! deployment decision made before any certificate is seen; the source is a property of a
//! completed interpretation. They coincide on every success — that coincidence is the
//! no-fallback law, and it is a theorem about the interpreter, not an identity between the
//! types.

/// The authoritative identity field, chosen by the deployment.
///
/// This is a policy, not a heuristic: the interpreter reads exactly the configured field
/// and never falls through to a weaker one. An absent URI SAN is a refusal, not a reason
/// to accept a DNS SAN or a Common Name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertificateIdentityPolicy {
    /// URI Subject Alternative Name (SPIFFE-style): unambiguous, namespaced, and the
    /// workload-identity convention. The default.
    #[default]
    UriSan,
    /// DNS Subject Alternative Name — for deployments whose client identities genuinely
    /// are DNS names, as an explicit choice.
    DnsSan,
    /// Subject Common Name. LEGACY ONLY: the CN is unstructured and deprecated for
    /// identity by the CA/Browser Forum.
    CommonNameLegacy,
}

/// The certificate field an interpretation actually read.
///
/// Carried by the evidence product so a consumer can tell a SPIFFE URI apart from a legacy
/// CN without reparsing the certificate. It is written only by the interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateIdentitySource {
    /// The value came from a URI SAN.
    UriSan,
    /// The value came from a DNS SAN.
    DnsSan,
    /// The value came from the subject Common Name.
    CommonName,
}

impl CertificateIdentityPolicy {
    /// The source a successful interpretation under this policy must report.
    ///
    /// The interpreter uses this to label its own result, which is why no code path can
    /// pair a value read from one field with a source naming another.
    pub(super) fn selects(self) -> CertificateIdentitySource {
        match self {
            CertificateIdentityPolicy::UriSan => CertificateIdentitySource::UriSan,
            CertificateIdentityPolicy::DnsSan => CertificateIdentitySource::DnsSan,
            CertificateIdentityPolicy::CommonNameLegacy => CertificateIdentitySource::CommonName,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateIdentityPolicy;
    use super::CertificateIdentitySource;

    #[test]
    fn every_policy_selects_exactly_one_source() {
        assert_eq!(
            CertificateIdentityPolicy::UriSan.selects(),
            CertificateIdentitySource::UriSan
        );
        assert_eq!(
            CertificateIdentityPolicy::DnsSan.selects(),
            CertificateIdentitySource::DnsSan
        );
        assert_eq!(
            CertificateIdentityPolicy::CommonNameLegacy.selects(),
            CertificateIdentitySource::CommonName
        );
    }

    #[test]
    fn the_default_policy_is_the_uri_san() {
        assert_eq!(
            CertificateIdentityPolicy::default(),
            CertificateIdentityPolicy::UriSan,
            "the default must stay the unambiguous namespaced field; changing it silently \
             changes which value every deployment binds to"
        );
    }
}
