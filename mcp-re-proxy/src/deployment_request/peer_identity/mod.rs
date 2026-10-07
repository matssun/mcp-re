// SPDX-License-Identifier: Apache-2.0
//! Which evidence carries the peer's identity to this node — ADR-MCPRE-067 §7, §10.
//!
//! The durable question is *what this node is entitled to believe an identity because of*.
//! Three answers exist, and they are alternatives: the credential that established the
//! channel carries it, a load balancer signs a request-bound assertion carrying it, or a
//! controlled attestor asserts it over a channel the operator has acknowledged. Only the
//! channel-credential form is deployable: the boundary refuses the load-balancer and
//! attestor forms, as well as a further form binding nothing at all.
//!
//! ```text
//! semantic role            which evidence carries the peer identity
//!         ↓
//! typed selection          PeerIdentityEvidenceRequest
//!         ↓
//! mechanism payload        ChannelCredentialIdentityRequest / IngressAssertionRequest /
//!                          AttestedIngressRequest
//!         ↓
//! leaf                     the X.509 SAN reader, transport::ingress' wire formats
//! ```
//!
//! **What the union deleted.** The four forms were a `binding` discriminator beside six
//! sibling fields, and five boundary clauses existed to say that a value belonged to a form
//! the deployment had not selected — `--ingress-identity has no effect without
//! --transport-binding attested-ingress` and its siblings. An attested-ingress selection
//! has nowhere to put a load-balancer key, so those clauses have no configuration left to
//! refuse (ADR-MCPRE-067 §7). What survives is every clause that is INTERNAL to one form:
//! a form with no verification key admits nothing, and a trusted identity that is the empty
//! string admits everything.

mod attested_ingress;
mod channel_credential_identity;
mod ingress_assertion;

pub use attested_ingress::{AttestedIngressRequest, PinnedChannelAcknowledgement};
pub use channel_credential_identity::ChannelCredentialIdentityRequest;
pub use ingress_assertion::IngressAssertionRequest;

/// Which evidence carries the peer's identity to this node.
///
/// The variant IS the selection; there is no separate discriminator that could disagree
/// with the payload beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentityEvidenceRequest {
    /// The identity is a named field of the credential the peer established the channel
    /// with. The only form a validated deployment can be in.
    ChannelCredential(ChannelCredentialIdentityRequest),
    /// Nothing binds the request signer to the channel. A request an operator can make,
    /// and one the configuration boundary refuses: it decouples the verified signer from
    /// the authenticated channel.
    Unbound,
    /// ADR-MCPS-023 Tier 3: a load balancer terminates the client's channel and signs a
    /// request-bound assertion carrying the identity. Refused at the boundary — it places
    /// the load balancer in the trusted computing base — and retained as an input form so
    /// the refusal can name what was asked for.
    IngressAssertion(IngressAssertionRequest),
    /// ADR-MCPS-023 §C Mode C: a controlled attestor asserts the identity over a pinned,
    /// mutually authenticated channel the operator has acknowledged. Refused at the boundary
    /// in every build (`config_state::transport::undeployable_transport_binding_refusal`) —
    /// the rebinding of an attestation onto the RFC 9421 request evidence is not yet
    /// specified — and retained as an input form so the refusal can name what was asked for.
    /// The acknowledgement is a statement, not a control: it is not what keeps Mode C out.
    AttestedIngress(AttestedIngressRequest),
}

impl Default for PeerIdentityEvidenceRequest {
    /// The channel credential's own identity: a deployment that has said nothing reads the
    /// peer it authenticated.
    fn default() -> Self {
        PeerIdentityEvidenceRequest::ChannelCredential(ChannelCredentialIdentityRequest::default())
    }
}

impl PeerIdentityEvidenceRequest {
    /// The channel-credential form over an identity field the operator chose.
    pub fn channel_credential(field: crate::transport::IdentityPolicy) -> Self {
        PeerIdentityEvidenceRequest::ChannelCredential(ChannelCredentialIdentityRequest {
            field: Some(field),
        })
    }

    /// The channel credential's identity request, where that is the form.
    ///
    /// `None` under every other form is not a missing value: no other form reads a
    /// certificate field, so there is none to name.
    pub fn credential_identity(&self) -> Option<ChannelCredentialIdentityRequest> {
        match self {
            PeerIdentityEvidenceRequest::ChannelCredential(identity) => Some(*identity),
            _ => None,
        }
    }

    /// The operator-facing spelling of the form, for a refusal that must name what was
    /// asked for.
    pub fn flag_value(&self) -> &'static str {
        match self {
            PeerIdentityEvidenceRequest::ChannelCredential(_) => "exact",
            PeerIdentityEvidenceRequest::Unbound => "none",
            PeerIdentityEvidenceRequest::IngressAssertion(_) => "lb-assertion",
            PeerIdentityEvidenceRequest::AttestedIngress(_) => "attested-ingress",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::IdentityPolicy;

    /// Disjointness: a form projects only what it inhabits. The five "has no effect
    /// without" clauses existed because every form could carry every other form's value;
    /// none can now.
    #[test]
    fn a_form_carries_only_its_own_material() {
        let credential = PeerIdentityEvidenceRequest::channel_credential(IdentityPolicy::DnsSan);
        assert_eq!(
            credential.credential_identity().map(|c| c.field),
            Some(Some(IdentityPolicy::DnsSan))
        );
        let attested = PeerIdentityEvidenceRequest::AttestedIngress(AttestedIngressRequest {
            asserted_identity_kind: IdentityPolicy::UriSan,
            attestor_keys: Vec::new(),
            identities: Vec::new(),
            audience: String::new(),
            pinned_channel: PinnedChannelAcknowledgement::acknowledged(),
        });
        assert_eq!(attested.credential_identity(), None);
        assert_eq!(attested.flag_value(), "attested-ingress");
    }

    /// The default is the channel credential's own identity: a deployment that named no
    /// form reads the peer it authenticated, and never a header. It names no field either,
    /// so it is not the request of an operator who chose `uri_san`.
    #[test]
    fn the_default_form_is_the_channel_credential_naming_no_field() {
        let default = PeerIdentityEvidenceRequest::default();
        assert_eq!(default.credential_identity().map(|c| c.field), Some(None));
        assert_ne!(
            default,
            PeerIdentityEvidenceRequest::channel_credential(IdentityPolicy::UriSan)
        );
    }
}
