// SPDX-License-Identifier: Apache-2.0
//! An endpoint that has passed the KMS/STS rule — and the only thing that grants
//! credential egress to it.
//!
//! One fact: **holding this value means the rule in the parent module ran over this
//! endpoint and admitted it.** The rule itself lives there, unchanged and still available
//! to the command line and the validation boundary, which want the refusal text rather
//! than a capability.
//!
//! # Why a value rather than a call
//!
//! [`super::kms_endpoint_authority`] returned a `String` every key source discarded. What
//! remained of the check at each site was that somebody had written the call — delete the
//! line and the constructor still builds, still reaches the endpoint, and still sends the
//! root-key trust bootstrap and a live bearer token to whoever it names. The check was
//! being remembered, not owned.
//!
//! Here the key sources hold a [`CredentialEgress`], and this is the only way in the crate
//! to obtain one for a KMS/STS endpoint. Deleting the call does not weaken the check; it
//! removes the value the constructor needs, and the build fails.
//!
//! # Scope
//!
//! This is the KMS/STS leaf, not a general endpoint authority. It answers one question —
//! may this operator-supplied KMS/STS endpoint be used — and it composes the answer with
//! the generic destination authority rather than restating any of it: the scheme
//! allowlist, the address classification and the connect-time client all belong to
//! [`crate::outbound_fetch`].

use std::time::Duration;

use crate::outbound_fetch::{CredentialEgress, VettedDestination};

/// A KMS/STS endpoint the rule admitted, and the authority a request to it reaches.
///
/// # Why the representation is private
///
/// Both fields are established by [`Self::parse`] from one input, and the whole point of
/// the type is that they were established there. A settable `authority` is the flag the
/// EX-006 census objected to; a settable destination is the unchecked endpoint this
/// exists to make unconstructible.
pub(crate) struct KmsEndpoint {
    /// Vetted by [`VettedDestination::operator_configured`] — an operator may point a KMS
    /// endpoint at an internal address, and the KMS rule above has already decided what
    /// spellings of one are admissible.
    destination: VettedDestination,
    /// The `host[:port]` a request will reach, as the rule computed it.
    ///
    /// Carried only where something reads it: AWS SigV4 signs a `Host` header. A build
    /// without that backend still runs the rule — the rule is what admits the endpoint —
    /// and simply keeps no projection nothing consults.
    #[cfg(feature = "aws_kms_keysource")]
    authority: String,
}

impl KmsEndpoint {
    /// `value` if it may be used as a KMS/STS endpoint, or why it may not.
    ///
    /// The error is the parent rule's text, so an operator sees the same refusal whether
    /// it is raised at the command line, at the validation boundary, or here — and the
    /// three cannot drift, because there is one decision.
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        #[cfg(feature = "aws_kms_keysource")]
        let authority = super::kms_endpoint_authority(value)?;
        #[cfg(not(feature = "aws_kms_keysource"))]
        super::kms_endpoint_authority(value)?;
        let destination = VettedDestination::operator_configured(value)
            .ok_or_else(|| format!("has a scheme no outbound fetch may use (got {value:?})"))?;
        Ok(KmsEndpoint {
            destination,
            #[cfg(feature = "aws_kms_keysource")]
            authority,
        })
    }

    /// The `host[:port]` a request to this endpoint reaches.
    #[cfg(feature = "aws_kms_keysource")]
    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    /// The capability to send credential-bearing requests to this endpoint, and to no
    /// other authority.
    pub(crate) fn egress(&self, timeout: Duration) -> CredentialEgress {
        CredentialEgress::to(&self.destination, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusals are the parent rule's, reached through this constructor: a value that
    /// the rule rejects yields no endpoint, and therefore no egress.
    #[test]
    fn an_endpoint_the_rule_refuses_yields_no_egress() {
        for value in [
            "https://cloudkms.googleapis.com@evil.example.com",
            "http://localhost:80@evil.example.com",
            "http://kms.example.com",
            "https://127.1",
            "https://kms.example.com:0443",
            "kms.example.com",
            "",
        ] {
            assert!(
                KmsEndpoint::parse(value).is_err(),
                "{value:?} must not yield a KMS endpoint"
            );
        }
    }

    /// A legitimate endpoint yields the authority the rule computed, and egress to it.
    #[test]
    fn an_admitted_endpoint_carries_its_authority_into_the_egress() {
        let endpoint = KmsEndpoint::parse("https://cloudkms.googleapis.com")
            .expect("a plain https KMS endpoint is admissible");
        #[cfg(feature = "aws_kms_keysource")]
        assert_eq!(endpoint.authority(), "cloudkms.googleapis.com");
        // The egress exists, and this is the only place that can produce one for a KMS
        // endpoint. What it does with a path is its own module's property.
        let _egress = endpoint.egress(Duration::from_secs(5));
    }

    /// The loopback exception that keeps the KMS-emulator lane working reaches egress
    /// too — it is the rule's decision, and nothing here re-takes it.
    #[test]
    fn the_loopback_plaintext_exception_reaches_egress() {
        let endpoint = KmsEndpoint::parse("http://localhost:4566")
            .expect("plaintext loopback is the emulator exception the rule grants");
        #[cfg(feature = "aws_kms_keysource")]
        assert_eq!(endpoint.authority(), "localhost:4566");
        let _egress = endpoint.egress(Duration::from_secs(5));
    }
}
