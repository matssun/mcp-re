// SPDX-License-Identifier: Apache-2.0
//! How an authenticated peer identity reaches this node — ADR-MCPRE-067 §5.
//!
//! The durable question is not which protocol terminates here. It is *where the identity
//! this node acts on came from*, and there are two answers a deployment can give: the
//! credential that established the channel carries it, or a trusted ingress asserts it in
//! a request-bound statement. Both survive the mechanisms below them being replaced — a
//! channel established by something other than TLS still carries a credential, and an
//! ingress that signs with something other than today's scheme still asserts.
//!
//! Nothing here names a certificate, a SAN or a handshake. Which field of which credential
//! carries the identity is the identity policy's question, and extracting it is the
//! mechanism's; both live below this fact, in `tls.rs` and in
//! [`crate::communication_assurance::certificate_identity_policy`].

/// Where a served request's verified peer identity comes from.
///
/// Mutually exclusive: a connection's identity is established EITHER by the credential
/// that established the channel OR by a signed, request-bound ingress assertion — never
/// both. The serve loop honours the one chosen provenance and never mixes them on a
/// single connection.
#[derive(Debug, Clone, Default)]
pub enum PeerIdentityProvenance {
    /// The identity is a configured field of the credential the peer established the
    /// channel with — today, the verified leaf certificate of a locally terminated mTLS
    /// connection. This is the default.
    #[default]
    ChannelCredential,
    /// ADR-MCPS-023 Tier 3 (issue #71): the verified identity comes from a signed,
    /// request-bound assertion made by a trusted ingress and presented in the
    /// [`crate::tls::MCP_INGRESS_ASSERTION_HEADER`]. The identity CANNOT be resolved at
    /// the connection seam — the assertion binds the request hash, known only after object
    /// verification — so under this provenance `resolve_identity` yields `None` and the
    /// serve loop instead extracts the raw assertion header and hands it to the
    /// post-verification check (`Proxy::with_lb_assertion`). The channel credential is NOT
    /// consulted for identity.
    IngressAssertion,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is the channel credential's own identity: a deployment that configures
    /// no ingress assertion reads the peer it authenticated, and never a header.
    #[test]
    fn the_default_provenance_is_the_channel_credential() {
        assert!(matches!(
            PeerIdentityProvenance::default(),
            PeerIdentityProvenance::ChannelCredential
        ));
    }
}
