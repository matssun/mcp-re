// SPDX-License-Identifier: Apache-2.0
//! The channel-credential half of the family: which key object establishes the channel.
//!
//! Its own module because it is its own ROLE. Response signing and channel establishment
//! are different propositions over potentially different credentials (ADR-MCPRE-067 §10),
//! and the parser reads the second WITHOUT consulting the first — the two are related by
//! an explicit boundary rule, not by sharing a discriminator.

use super::SigningSourceFlags;
use crate::deployment_request::{
    AwsKmsChannelKeyRequest, ChannelKeyRequest, DelegatedChannelKeyRequest,
    ExportedChannelKeyRequest, GcpKmsChannelKeyRequest, Pkcs11ChannelKeyRequest,
};

impl SigningSourceFlags {
    /// Which custody this command line asks for the channel key, or why it asks for
    /// neither coherently.
    ///
    /// **This is where the delegated-XOR-exported rule now lives** (ADR-MCPS-028 §G, issue
    /// #58). It was relation X2b, at the configuration boundary, and it cannot be there any
    /// more: [`ChannelKeyRequest`] is a tagged union, so no request can hold both arms and
    /// a boundary cannot refuse a value nothing can build. A flat command line still can
    /// state the pair, and the parser is the one place that still sees both — so the
    /// refusal is an argv-coherence failure, answered here (ADR-MCPRE-067 §16).
    ///
    /// The wording is unchanged, so an operator who hit the old boundary refusal reads the
    /// same sentence.
    pub(super) fn channel_key_request(&self) -> Result<ChannelKeyRequest, String> {
        match (self.tls_key.as_ref(), self.channel_key()) {
            (Some(_), Some(_)) => Err(
                "TLS signing is delegated XOR exported (ADR-MCPS-028 §G): a delegated-TLS \
                 key source must not also be given an exported --tls-key. Remove --tls-key \
                 when using a delegated (non-exporting device/KMS) TLS signer."
                    .to_string(),
            ),
            (_, Some(delegated)) => Ok(ChannelKeyRequest::Delegated(delegated)),
            (Some(key_path), None) => {
                Ok(ChannelKeyRequest::ExportedFile(ExportedChannelKeyRequest {
                    key_path: key_path.clone(),
                }))
            }
            // No delegated key object and no file: the exported arm naming nothing, which
            // is what an operator who named nothing asked for. NOT refused here — the
            // configuration boundary already refuses an exported custody with no key to
            // export, and refusing it there keeps it aggregated with every other violation.
            // Only the pair above is argv-shaped, because only the pair stops existing once
            // the request is assembled.
            (None, None) => Ok(ChannelKeyRequest::default()),
        }
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
    fn channel_key(&self) -> Option<DelegatedChannelKeyRequest> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A command line naming both arms of the tagged value. Only argv can state it, and
    /// this is where it is answered — the boundary has no such configuration to refuse.
    #[test]
    fn naming_both_custodies_for_one_channel_key_is_refused_by_the_adapter() {
        let mut flags = SigningSourceFlags::default();
        flags.take("--tls-key", "/key").expect("a value flag");
        flags
            .take("--pkcs11-tls-key-label", "tls")
            .expect("a value flag");
        let err = flags
            .channel_key_request()
            .expect_err("both arms at once is a contradiction");
        assert!(err.contains("delegated XOR exported"), "{err}");
    }

    /// The negative controls: EITHER arm alone is coherent, and so is neither. Without
    /// these the assertion above would pass just as well if every command line were
    /// refused. Naming neither is the exported arm over no path — refused at the
    /// configuration boundary, with every other violation, and not here.
    #[test]
    fn either_arm_alone_and_neither_are_coherent_command_lines() {
        let exported = {
            let mut flags = SigningSourceFlags::default();
            flags.take("--tls-key", "/key").expect("a value flag");
            flags.channel_key_request().expect("one arm is coherent")
        };
        assert!(matches!(exported, ChannelKeyRequest::ExportedFile(_)));
        let delegated = {
            let mut flags = SigningSourceFlags::default();
            flags
                .take("--aws-kms-tls-key-id", "alias/tls")
                .expect("a value flag");
            flags.channel_key_request().expect("one arm is coherent")
        };
        assert!(matches!(delegated, ChannelKeyRequest::Delegated(_)));
        let neither = SigningSourceFlags::default()
            .channel_key_request()
            .expect("naming neither is not an argv contradiction");
        assert_eq!(neither, ChannelKeyRequest::default());
    }
}
