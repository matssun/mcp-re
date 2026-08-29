// SPDX-License-Identifier: Apache-2.0
//! The mechanism payload of the channel-establishment credential.
//!
//! The layer below
//! [`ChannelCredentialCustodyState`](crate::config_state::ChannelCredentialCustodyState):
//! its semantic projection is [`PrivateKeyExposure`](crate::config_state::PrivateKeyExposure),
//! and this is what the materializer needs once that question is settled. Its own module
//! because the two altitudes are two units — the owner decides a custody fact, and this
//! carries the locators a specific backend is addressed by (ADR-MCPRE-067 §6, §8).

/// The material a channel-establishment signer must be built from.
///
/// Borrowed and matchable, the shape [`crate::config_state::custody::CustodyMaterial`]
/// already has for the response-signing role. It names mechanisms because the one consumer
/// that matches it is the materializer, and selecting a backend is materialization's own
/// job (ADR-MCPRE-067 §6, §8). No state can project a variant it does not inhabit, so the
/// combination X2b forbids — a delegated key with a file copy beside it — stays
/// unrepresentable downstream as well as at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKeyMaterial<'a> {
    /// A PEM private key file this process reads.
    ExportedFile {
        /// Path to the key.
        key_path: &'a str,
    },
    /// A second object on the PKCS#11 token.
    Pkcs11 {
        /// The channel key object's label.
        key_label: &'a str,
    },
    /// A second, distinct AWS KMS key, reached through the response-signing key's region,
    /// endpoint and credential mode (X2a holds them to the same backend).
    AwsKms {
        /// Key id, ARN or alias.
        key_id: &'a str,
    },
    /// A second, distinct GCP Cloud KMS key version.
    GcpKms {
        /// Fully-qualified `projects/.../cryptoKeyVersions/N`.
        key_version: &'a str,
    },
}

impl<'a> ChannelKeyMaterial<'a> {
    /// The exported key file, or `None` where the key never leaves its signer.
    ///
    /// `None` is not a missing value: a delegated state carries no file, because carrying
    /// one would make the combination X2b forbids representable.
    pub fn exported_key_path(self) -> Option<&'a str> {
        match self {
            ChannelKeyMaterial::ExportedFile { key_path } => Some(key_path),
            _ => None,
        }
    }

    /// The PKCS#11 label of the delegated channel key.
    pub fn pkcs11_key_label(self) -> Option<&'a str> {
        match self {
            ChannelKeyMaterial::Pkcs11 { key_label } => Some(key_label),
            _ => None,
        }
    }

    /// The AWS KMS key id of the delegated channel key.
    pub fn aws_key_id(self) -> Option<&'a str> {
        match self {
            ChannelKeyMaterial::AwsKms { key_id } => Some(key_id),
            _ => None,
        }
    }

    /// The GCP Cloud KMS key version of the delegated channel key.
    pub fn gcp_key_version(self) -> Option<&'a str> {
        match self {
            ChannelKeyMaterial::GcpKms { key_version } => Some(key_version),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Disjointness: every variant projects its own locator and none of its neighbours'.
    /// A materializer asking for a mechanism the state does not inhabit gets `None`,
    /// which is why there is no arm that can address the wrong backend.
    #[test]
    fn a_key_object_projects_its_own_locator_and_no_neighbours() {
        let cases = [
            (
                ChannelKeyMaterial::ExportedFile { key_path: "/k" },
                [Some("/k"), None, None, None],
            ),
            (
                ChannelKeyMaterial::Pkcs11 { key_label: "tls" },
                [None, Some("tls"), None, None],
            ),
            (
                ChannelKeyMaterial::AwsKms { key_id: "alias/t" },
                [None, None, Some("alias/t"), None],
            ),
            (
                ChannelKeyMaterial::GcpKms {
                    key_version: "projects/p",
                },
                [None, None, None, Some("projects/p")],
            ),
        ];
        for (material, expected) in cases {
            assert_eq!(
                [
                    material.exported_key_path(),
                    material.pkcs11_key_label(),
                    material.aws_key_id(),
                    material.gcp_key_version(),
                ],
                expected,
                "{material:?}"
            );
        }
    }
}
