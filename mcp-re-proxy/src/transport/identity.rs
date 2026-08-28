// SPDX-License-Identifier: Apache-2.0
//! The client identity a channel carries, and the only two verifications that may produce
//! one.
//!
//! The type's NAME is the claim, so arbitrary construction was incompatible with it: the
//! representation was two public fields behind a constructor taking any string and any
//! claimed source, and nothing stopped a caller from asserting `spiffe://…/admin` came
//! from a URI SAN it had never seen.
//!
//! The representation is now private and there are exactly two producers, both of them
//! verifications:
//!
//! | producer | what it proved | reachable |
//! |---|---|---|
//! | [`extract_identity`] | the value is the configured field of a leaf certificate the TLS stack verified | **yes — every served request** |
//! | [`TransportIdentity::attested_by_verified_ingress`] | the value rode in an assertion this node verified against a configured attestor key | no — Mode C is refused at Layer-A validation |
//!
//! Both are stated because both exist; only the first is on a serving path. The live
//! proposition is therefore the strong one — *every transport identity a served request
//! binds against was extracted from a verified client certificate* — and it holds by
//! construction rather than by convention, because the second producer cannot be reached.
//!
//! It is deliberately NOT written down as a theorem here. The proposition is an open gap in
//! `docs/architecture/components/transport-binding.md`, and closing it in prose ahead of
//! the deployment reachability that makes it true is the over-claim ADR-MCPRE-061 exists to
//! prevent (EX-005, ruling 5).
//!
//! [`extract_identity`] lives here rather than in `tls.rs` for the seal to mean anything:
//! a `pub(crate)` constructor beside a sibling producer is not a boundary in a crate whose
//! composition root is in the same crate. It is a compatibility facade over the
//! ADR-MCPRE-063 certificate identity authority and owns nothing of the semantics — it
//! parses no certificate, selects no field and validates no value.

use crate::communication_assurance::CertificateChainEvidence;

use super::IdentityPolicy;

/// Where a verified transport identity was read from in the client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// A URI Subject Alternative Name (SPIFFE-style).
    UriSan,
    /// A DNS Subject Alternative Name.
    DnsSan,
    /// The subject Common Name (last resort).
    CommonName,
}

/// A client identity a verification established — on the served path, always from the leaf
/// of a successfully-verified mTLS client certificate.
///
/// Private representation: see the module note for the two producers and why only one of
/// them is reachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIdentity {
    /// The identity string (e.g. `spiffe://example.org/agent-1`).
    value: String,
    /// Which certificate field it came from.
    source: IdentitySource,
}

impl TransportIdentity {
    /// The identity string the channel presented.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Which certificate field the value was read from.
    pub fn source(&self) -> IdentitySource {
        self.source
    }

    /// The identity an ingress attestor asserted, once THIS node has verified the
    /// assertion (ADR-MCPS-023 Mode C).
    ///
    /// `pub(super)`, and the reason at the point of widening is that the ingress verifier
    /// is a sibling module of this one and is the only other code in the crate that
    /// establishes a client identity by checking something. It is deferred and
    /// unreachable — `--transport-binding attested-ingress` is refused at Layer-A
    /// validation — so it does not weaken what the served path can claim. It is named
    /// rather than hidden: a producer that exists and is not stated is how a seal becomes
    /// a story about the producers somebody remembered.
    pub(super) fn attested_by_verified_ingress(
        value: impl Into<String>,
        source: IdentitySource,
    ) -> Self {
        TransportIdentity {
            value: value.into(),
            source,
        }
    }
}

/// Extract the verified client identity from a leaf certificate (DER) using the
/// authoritative field named by `policy`.
///
/// **Compatibility facade.** The semantics live in the certificate identity authority
/// (ADR-MCPRE-063 Slice 1): this converts the historical vocabulary in and out and owns
/// nothing. It parses no certificate, selects no field, validates no value, and decides no
/// fallback — deleting the authority's checks would break it, and no check deleted here
/// could let an invalid identity through, because there is none here to delete.
///
/// The `Option` return is the historical shape, and it is lossy: the authority
/// distinguishes an absent peer certificate, an unreadable one, a missing configured field,
/// and a malformed configured value, and all four arrive here as `None`. Callers that need
/// the reason should consume
/// [`CertificateChainEvidence::interpret_identity`](crate::communication_assurance::CertificateChainEvidence::interpret_identity)
/// directly.
pub fn extract_identity(leaf_der: &[u8], policy: IdentityPolicy) -> Option<TransportIdentity> {
    let evidence = CertificateChainEvidence::from_leaf_der(leaf_der)
        .interpret_identity(policy.into())
        .ok()?;
    Some(TransportIdentity {
        value: evidence.value().as_str().to_owned(),
        source: evidence.source().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_that_does_not_carry_the_configured_field_yields_nothing() {
        // The policy is authoritative and there is NO fallback: a missing URI SAN must
        // never be quietly downgraded to a DNS SAN or a Common Name. Bytes that are not a
        // certificate at all take the same exit.
        assert!(extract_identity(b"not a certificate", IdentityPolicy::UriSan).is_none());
    }

    #[test]
    fn the_projections_are_the_only_way_to_read_one() {
        // What the seal buys, stated as a control: there is no public field and no public
        // constructor, so a value of this type exists only where a verification put it
        // there. `attested_by_verified_ingress` is `pub(super)` and reachable only from the
        // deferred ingress verifier next door.
        let identity = TransportIdentity::attested_by_verified_ingress(
            "spiffe://example.org/a",
            IdentitySource::UriSan,
        );
        assert_eq!(identity.value(), "spiffe://example.org/a");
        assert_eq!(identity.source(), IdentitySource::UriSan);
    }
}
