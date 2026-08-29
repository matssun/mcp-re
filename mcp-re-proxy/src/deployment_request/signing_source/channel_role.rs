// SPDX-License-Identifier: Apache-2.0
//! The communication-channel credential role.

use super::{AwsKmsChannelKeyRequest, GcpKmsChannelKeyRequest, Pkcs11ChannelKeyRequest};

/// The credential this deployment establishes its communication channel with.
///
/// A distinct role from [`ResponseSigningRequest`](super::ResponseSigningRequest), and
/// distinct structurally rather than by convention: nothing here can be read where the
/// response-signing key was meant (ADR-MCPRE-067 §10).
///
/// Two facts, both of which every custody needs: the credential chain this node presents,
/// and the key that proves it holds it. The chain is a sibling of the key rather than a
/// member of it because it is required under every custody — it is not behind the
/// selector, so no combination of the two is illegal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChannelCredentialRequest {
    /// The credential chain this node presents to peers. A filesystem path under every
    /// signing mechanism but the environment seed, where it names an environment variable
    /// — an interpretation the custody state decides, not this field.
    pub credential_chain: String,
    /// Which key establishes the channel, and therefore whether it can leave its signer.
    pub key: ChannelKeyRequest,
}

/// Where the channel-establishment private key lives.
///
/// A tagged union, so a request cannot assert both custodies at once. The pair it makes
/// unrepresentable is the contradiction ADR-MCPS-028 §G names: a key that never leaves its
/// device AND a file copy of that key. Relation X2b existed to refuse that pair at the
/// configuration boundary and is gone, because a boundary cannot refuse a value no
/// configuration can hold (ADR-MCPRE-067 §7).
///
/// A command line CAN still state the contradiction — argv is flat — and the CLI adapter
/// refuses it there, which is the one place that can still see both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelKeyRequest {
    /// The key is read from a file and can be copied out of it.
    ExportedFile(ExportedChannelKeyRequest),
    /// The key stays behind a non-exporting signer and is used through it.
    Delegated(DelegatedChannelKeyRequest),
}

impl Default for ChannelKeyRequest {
    /// A file naming nothing — what a request that has said nothing has asked for. The
    /// configuration boundary refuses it, exactly as an omitted `--tls-key` was refused.
    fn default() -> Self {
        ChannelKeyRequest::ExportedFile(ExportedChannelKeyRequest::default())
    }
}

/// The exported-file channel key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportedChannelKeyRequest {
    /// Path to the PEM private key.
    pub key_path: String,
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
