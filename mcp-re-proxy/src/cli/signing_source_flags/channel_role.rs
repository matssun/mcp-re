// SPDX-License-Identifier: Apache-2.0
//! The channel-credential half of the family: which key object establishes the channel.
//!
//! Its own module because it is its own ROLE. Response signing and channel establishment
//! are different propositions over potentially different credentials (ADR-MCPRE-067 §10),
//! and the parser reads the second WITHOUT consulting the first — the two are related by
//! an explicit boundary rule, not by sharing a discriminator.

use super::SigningSourceFlags;
use crate::deployment_request::{
    AwsKmsChannelKeyRequest, DelegatedChannelKeyRequest, GcpKmsChannelKeyRequest,
    Pkcs11ChannelKeyRequest,
};

impl SigningSourceFlags {
    /// Whether a non-exporting channel key object was named.
    ///
    /// What it decides in the parser is whether `--tls-key` names a file this deployment
    /// reads. Whether the two channel custodies may be asserted together is relation X2b's.
    ///
    /// `pub(in crate::cli)` rather than `pub(super)`: its one legitimate consumer is
    /// `parse_args`, two levels up, and nothing wider needs it.
    pub(in crate::cli) fn has_delegated_channel_key(&self) -> bool {
        self.channel_key().is_some()
    }

    /// The channel key object this command line names, if any.
    ///
    /// Read WITHOUT consulting the response-signing selection, deliberately. The two are
    /// separate roles, so nothing here forces them to agree — and whether the named key
    /// object lives in a backend this deployment reaches is relation X2a's, at the
    /// configuration boundary, where it is reported alongside every other violation
    /// instead of cutting the parse short. A programmatically built request can state the
    /// same mismatch, and it passes through the same boundary.
    ///
    /// Two key objects at once picks the first in this fixed order, and that choice is
    /// never observed: such a command line has at least one that does not match its
    /// response-signing mechanism, so X2a refuses it.
    pub(super) fn channel_key(&self) -> Option<DelegatedChannelKeyRequest> {
        if let Some(key_label) = self.pkcs11_channel_key_label.clone() {
            return Some(DelegatedChannelKeyRequest::Pkcs11(
                Pkcs11ChannelKeyRequest { key_label },
            ));
        }
        if let Some(key_id) = self.aws_channel_key_id.clone() {
            return Some(DelegatedChannelKeyRequest::AwsKms(
                AwsKmsChannelKeyRequest { key_id },
            ));
        }
        self.gcp_channel_key_version.clone().map(|key_version| {
            DelegatedChannelKeyRequest::GcpKms(GcpKmsChannelKeyRequest { key_version })
        })
    }
}
