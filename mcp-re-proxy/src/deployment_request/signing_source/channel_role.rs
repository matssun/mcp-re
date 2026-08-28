// SPDX-License-Identifier: Apache-2.0
//! The communication-channel credential role.

use super::{AwsKmsChannelKeyRequest, GcpKmsChannelKeyRequest, Pkcs11ChannelKeyRequest};

/// Which key establishes this deployment's communication channel.
///
/// A distinct role from [`ResponseSigningRequest`](super::ResponseSigningRequest), and
/// distinct structurally rather than by convention: nothing here can be read where the
/// response-signing key was meant (ADR-MCPRE-067 §10).
///
/// `None` is the exported posture — the channel private key is read from a file and can
/// leave the device it lives on. That locator is still a sibling of this field; moving it
/// belongs to the campaign phase that owns channel custody, and this type is where it
/// lands.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChannelCredentialRequest {
    /// The non-exporting key object asked to establish the channel, when one is named.
    pub delegated: Option<DelegatedChannelKeyRequest>,
}

/// Which key object a delegated handshake signature is made with.
///
/// One tagged value rather than three sibling options: the selectors are alternatives, and
/// a request that held all three would let a consumer ask "which one signs?" and get an
/// answer nothing chose.
///
/// The mechanism named here must be the one the response-signing source names — a channel
/// key object in a backend this deployment does not reach would silently do nothing,
/// leaving an operator who believes the handshake key is device-resident. That relation is
/// stated explicitly by the configuration boundary
/// ([`cross_machine`](crate::config_state::cross_machine)) rather than being implied by
/// reusing one provider discriminator for two roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedChannelKeyRequest {
    /// A second key object on the PKCS#11 token.
    Pkcs11(Pkcs11ChannelKeyRequest),
    /// A second, distinct AWS KMS key.
    AwsKms(AwsKmsChannelKeyRequest),
    /// A second, distinct GCP Cloud KMS key version.
    GcpKms(GcpKmsChannelKeyRequest),
}
