// SPDX-License-Identifier: Apache-2.0
//! The `ChannelCredentialCustody` configuration machine — unit
//! `proxy.channel_credential_custody_state`.
//!
//! Whether the private key that establishes this deployment's communication channel can
//! leave the signer holding it. Two states:
//!
//! | State | Required | Guards |
//! |---|---|---|
//! | `ExportedFile` | a key path | — |
//! | `Delegated` | the key object matching `Custody` (X2a) | — |
//!
//! Separate from `Custody` because the two keys are separate ROLES: a deployment may hold
//! its response-signing key in a KMS while its channel key is a file, and the reverse. What
//! ties them is that a delegated key object names a backend this deployment must already
//! reach, which is why X2a is a relation between the machines rather than a column inside
//! either — and why the request models the two roles as two values rather than reusing one
//! provider discriminator for both (ADR-MCPRE-067 §10).
//!
//! **The two roles project the same custody fact and remain separate owners.**
//! [`ChannelCredentialCustodyState::exposure`] answers with the response-signing machine's
//! own [`PrivateKeyExposure`], because *whether private key material can enter this
//! process* is one proposition and not two that happen to agree. What differs is the key it
//! is asked about, and that is a role, not a vocabulary (ADR-MCPRE-067 §10).
//!
//! **Altitude.** Nothing above [`Self::material`] names TLS: the durable question is about
//! the channel-establishment credential, and it survives the handshake protocol being
//! replaced. TLS vocabulary starts at the materializer, which is the consumer that must
//! pick a key object on a specific backend.
//!
//! **There is no forbidden column any more.** It held one entry — a file copy beside a
//! delegated key, which says the channel key never leaves the device AND that a copy of it
//! exists — and relation X2b refused it. `ChannelKeyRequest` is a tagged union, so no
//! configuration can state the pair and there is nothing left at this boundary to refuse
//! (ADR-MCPRE-067 §7). A flat command line still can, and the CLI adapter answers it there.

use crate::config_state::channel_key_material::ChannelKeyMaterial;
use crate::config_state::custody::PrivateKeyExposure;
use crate::deployment_request::{ChannelKeyRequest, DelegatedChannelKeyRequest, DeploymentRequest};

/// Which key object a delegated channel-establishment signature is made with.
///
/// One value rather than three `Option`s: the selectors are alternatives, and a state that
/// held all three would let a caller ask "which one delegated this?" and get an answer the
/// classification never made. X2a decides whether the chosen one is legal beside the
/// configured `Custody` source; this only records which one it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DelegatedChannelKey {
    /// A second key object on the PKCS#11 token.
    Pkcs11 {
        /// The channel key object's label.
        key_label: String,
    },
    /// A second, distinct AWS KMS key.
    AwsKms {
        /// Key id, ARN or alias of the channel key.
        key_id: String,
    },
    /// A second, distinct GCP Cloud KMS key version.
    GcpKms {
        /// Fully-qualified `projects/.../cryptoKeyVersions/N` of the channel key.
        key_version: String,
    },
}

/// Which channel-credential custody state a configuration requests, and what it is
/// inhabited by.
///
/// The representation is private to this module and [`classify`] is the only producer, so
/// a consumer cannot name a channel key this deployment did not configure. Two projections,
/// at two altitudes: [`Self::exposure`] is the durable proposition and names no mechanism;
/// [`Self::material`] is the mechanism payload and names one, because its consumer is the
/// materializer that must build a key object on a specific backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCredentialCustodyState {
    kind: ChannelCredentialCustodyKind,
}

/// The two states, as the owner's own representation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChannelCredentialCustodyKind {
    /// The channel key is read from a file.
    Exported {
        /// Path to the PEM private key. Its presence IS this state's requirement.
        key_path: String,
    },
    /// The channel key stays on a non-exporting device or KMS and is used through it.
    Delegated {
        /// Which key object establishes the channel.
        selector: DelegatedChannelKey,
    },
}

impl ChannelCredentialCustodyState {
    /// What may be believed about this deployment's channel-establishment private key.
    ///
    /// The same proposition the response-signing role answers, asked about the other key —
    /// so it is the same type, and a consumer of the fact needs no case for which role or
    /// which mechanism produced it. A mechanism not yet invented establishes `NonExporting`
    /// exactly as today's three do (ADR-MCPRE-067 §5, §8).
    pub fn exposure(&self) -> PrivateKeyExposure {
        match self.kind {
            ChannelCredentialCustodyKind::Exported { .. } => PrivateKeyExposure::ProcessReadable,
            ChannelCredentialCustodyKind::Delegated { .. } => PrivateKeyExposure::NonExporting,
        }
    }

    /// The key object a channel-establishment signer is built from.
    pub fn material(&self) -> ChannelKeyMaterial<'_> {
        match &self.kind {
            ChannelCredentialCustodyKind::Exported { key_path } => {
                ChannelKeyMaterial::ExportedFile { key_path }
            }
            ChannelCredentialCustodyKind::Delegated { selector } => match selector {
                DelegatedChannelKey::Pkcs11 { key_label } => {
                    ChannelKeyMaterial::Pkcs11 { key_label }
                }
                DelegatedChannelKey::AwsKms { key_id } => ChannelKeyMaterial::AwsKms { key_id },
                DelegatedChannelKey::GcpKms { key_version } => {
                    ChannelKeyMaterial::GcpKms { key_version }
                }
            },
        }
    }
}

/// Recognise the requested state.
///
/// The request's own tagged [`ChannelKeyRequest`] IS the state; this reads it into the
/// machine's representation. Fallible when the arm names nothing — an `ExportedFile` with
/// no key path or a `Delegated` selector that is empty — so possessing a state means a
/// non-empty key object was named.
///
/// There is no order to pick from at either level. The request names ONE custody and, under
/// `Delegated`, ONE key object, so a configuration that once named two at a time no longer
/// has two places to name them.
fn classify(config: &DeploymentRequest) -> Result<ChannelCredentialCustodyState, String> {
    match &config.channel_credential.key {
        ChannelKeyRequest::Delegated(delegated) => Ok(ChannelCredentialCustodyState {
            kind: ChannelCredentialCustodyKind::Delegated {
                selector: selector_of(delegated)?,
            },
        }),
        ChannelKeyRequest::ExportedFile(exported) if !exported.key_path.is_empty() => {
            Ok(ChannelCredentialCustodyState {
                kind: ChannelCredentialCustodyKind::Exported {
                    key_path: exported.key_path.clone(),
                },
            })
        }
        ChannelKeyRequest::ExportedFile(_) => Err(
            "--tls-key is required: no delegated TLS custody selector is set, so the \
             handshake key has no source. Give --tls-key <path>, or select a delegated TLS \
             signer for the configured --key-source"
                .to_string(),
        ),
    }
}

/// Read the requested channel key object into this machine's own representation.
fn selector_of(request: &DelegatedChannelKeyRequest) -> Result<DelegatedChannelKey, String> {
    Ok(match request {
        DelegatedChannelKeyRequest::Pkcs11(token) => DelegatedChannelKey::Pkcs11 {
            key_label: named("--pkcs11-tls-key-label", &token.key_label)?,
        },
        DelegatedChannelKeyRequest::AwsKms(kms) => DelegatedChannelKey::AwsKms {
            key_id: named("--aws-kms-tls-key-id", &kms.key_id)?,
        },
        DelegatedChannelKeyRequest::GcpKms(kms) => DelegatedChannelKey::GcpKms {
            key_version: named("--gcp-kms-tls-key-version", &kms.key_version)?,
        },
    })
}

/// A delegated selector names a key object only when it is non-empty.
fn named(flag: &str, value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!(
            "{flag} is empty: a delegated TLS signer needs its key object"
        ));
    }
    Ok(value.to_string())
}

/// Classify the requested channel-credential custody state and check its local columns.
///
/// `Delegated`'s legal selector is a relation to another machine (X2a, against `Custody`),
/// so it is checked in the cross-machine pass and deliberately not here. A local validator
/// that reached into another machine's fields would break the layering even when its
/// answer was right.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<ChannelCredentialCustodyState>, Vec<String>) {
    match classify(config) {
        Ok(state) => (Some(state), Vec::new()),
        Err(violation) => (None, vec![violation]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::{
        AwsKmsChannelKeyRequest, ExportedChannelKeyRequest, GcpKmsChannelKeyRequest,
        Pkcs11ChannelKeyRequest,
    };

    /// Name a delegated channel key object. Which response-signing mechanism it must
    /// accompany is relation X2a's, not this machine's.
    fn delegate(config: &mut DeploymentRequest, key: DelegatedChannelKeyRequest) {
        config.channel_credential.key = ChannelKeyRequest::Delegated(key);
    }

    /// The exported custody over one path. A file and a delegated key object are the two
    /// arms of one value, so naming one is how the other is unnamed.
    fn exported(key_path: &str) -> ChannelKeyRequest {
        ChannelKeyRequest::ExportedFile(ExportedChannelKeyRequest {
            key_path: key_path.to_string(),
        })
    }

    fn pkcs11_channel_key(label: &str) -> DelegatedChannelKeyRequest {
        DelegatedChannelKeyRequest::Pkcs11(Pkcs11ChannelKeyRequest {
            key_label: label.to_string(),
        })
    }

    /// A key object this machine must record, and the configuration that requests it.
    type Form = (ChannelKeyMaterial<'static>, fn(&mut DeploymentRequest));

    fn run(
        mutate: impl FnOnce(&mut DeploymentRequest),
    ) -> (Option<ChannelCredentialCustodyState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn a_file_key_is_the_exported_state_and_carries_the_key_it_exports() {
        let (state, violations) = run(|c| c.channel_credential.key = exported("/key"));
        let state = state.expect("recognised");
        assert_eq!(state.material().exported_key_path(), Some("/key"));
        assert_eq!(state.exposure(), PrivateKeyExposure::ProcessReadable);
        assert!(violations.is_empty(), "{violations:?}");
    }

    /// One machine, three key objects — and the material says WHICH one delegated it, so
    /// nothing downstream tests three `Option`s to find out. The request no longer has
    /// three either: [`DelegatedChannelKeyRequest`] is one tagged value.
    #[test]
    fn any_backends_selector_names_the_same_state_and_records_itself() {
        let cases: Vec<Form> = vec![
            (ChannelKeyMaterial::Pkcs11 { key_label: "tls" }, |c| {
                delegate(c, pkcs11_channel_key("tls"));
            }),
            (
                ChannelKeyMaterial::AwsKms {
                    key_id: "alias/tls",
                },
                |c| {
                    delegate(
                        c,
                        DelegatedChannelKeyRequest::AwsKms(AwsKmsChannelKeyRequest {
                            key_id: "alias/tls".to_string(),
                        }),
                    );
                },
            ),
            (
                ChannelKeyMaterial::GcpKms {
                    key_version: "projects/p/..",
                },
                |c| {
                    delegate(
                        c,
                        DelegatedChannelKeyRequest::GcpKms(GcpKmsChannelKeyRequest {
                            key_version: "projects/p/..".to_string(),
                        }),
                    );
                },
            ),
        ];
        for (expected, mutate) in cases {
            let (state, _) = run(|c| {
                mutate(c);
            });
            let state = state.expect("recognised");
            assert_eq!(state.material(), expected, "one machine, three key objects");
            assert_eq!(state.exposure(), PrivateKeyExposure::NonExporting);
            assert_eq!(
                state.material().exported_key_path(),
                None,
                "a delegated state carries no file to export"
            );
        }
    }

    /// No file to export means no state at all, not an `Exported` holding an empty path.
    #[test]
    fn the_exported_state_cannot_start_without_the_key_it_exports() {
        let (state, violations) = run(|c| c.channel_credential.key = exported(""));
        assert!(state.is_none(), "an exported state was built over no key");
        assert!(
            violations.iter().any(|v| v.contains("--tls-key")),
            "{violations:?}"
        );
    }

    /// A delegated state naming its key object is `NonExporting` and needs no file key.
    #[test]
    fn the_delegated_state_does_not_want_that_key() {
        let (state, violations) = run(|c| delegate(c, pkcs11_channel_key("tls")));
        assert_eq!(
            state.map(|s| s.exposure()),
            Some(PrivateKeyExposure::NonExporting)
        );
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn a_delegated_state_cannot_start_without_the_key_object_it_names() {
        let cases = [
            (
                DelegatedChannelKeyRequest::Pkcs11(Pkcs11ChannelKeyRequest {
                    key_label: String::new(),
                }),
                "--pkcs11-tls-key-label",
            ),
            (
                DelegatedChannelKeyRequest::AwsKms(AwsKmsChannelKeyRequest {
                    key_id: String::new(),
                }),
                "--aws-kms-tls-key-id",
            ),
            (
                DelegatedChannelKeyRequest::GcpKms(GcpKmsChannelKeyRequest {
                    key_version: String::new(),
                }),
                "--gcp-kms-tls-key-version",
            ),
        ];
        for (key, flag) in cases {
            let (state, violations) = run(|c| delegate(c, key));
            assert!(
                state.is_none(),
                "{flag}: a delegated state was built over no key"
            );
            assert!(
                violations.iter().any(|v| v.contains(flag)),
                "{flag}: {violations:?}"
            );
            assert!(
                violations
                    .iter()
                    .all(|v| !v.contains("--tls-key is required")),
                "{flag}: {violations:?}"
            );
        }
    }

    /// The generic projection control (ADR-MCPRE-067 §21): the two ROLES answer the custody
    /// question with the SAME type, so a consumer of the fact has no case for which role or
    /// which mechanism produced it. The roles stay separate owners — this asserts that
    /// their projections meet, not that the states do — and the fixture below proves the
    /// separation by answering the same question differently for the two keys.
    #[test]
    fn both_roles_answer_the_custody_question_with_one_semantic_fact() {
        let mut config = legal_config();
        delegate(&mut config, pkcs11_channel_key("tls"));
        let (channel, _) = classify_and_validate(&config);
        let (response, _) = crate::config_state::custody::classify_and_validate(&config);
        let channel: PrivateKeyExposure = channel.expect("recognised").exposure();
        let response: PrivateKeyExposure = response.expect("recognised").exposure();
        // One type, two ANSWERS: this fixture delegates its channel key and keeps its
        // response-signing seed in a file. That the two disagree is the point — the roles
        // are separate owners, and sharing a projection does not merge them.
        assert_eq!(channel, PrivateKeyExposure::NonExporting);
        assert_eq!(response, PrivateKeyExposure::ProcessReadable);
    }

    /// The replacement negative control (ADR-MCPRE-067 §5, §21). A channel-establishment
    /// mechanism this repository does not have answers the same question, and the consumer
    /// of the answer needs no edit to accept it — which is what makes [`PrivateKeyExposure`]
    /// a proposition rather than a spelling of today's three backends.
    #[test]
    fn a_channel_mechanism_that_does_not_exist_drives_the_same_consumer() {
        enum HypotheticalChannelMechanism {
            RemoteAttestedEnclave,
            SoftwareVault,
        }
        impl HypotheticalChannelMechanism {
            fn exposure(&self) -> PrivateKeyExposure {
                match self {
                    Self::RemoteAttestedEnclave => PrivateKeyExposure::NonExporting,
                    Self::SoftwareVault => PrivateKeyExposure::ProcessReadable,
                }
            }
        }
        /// The consumer: it reads the fact and names no mechanism and no role.
        fn key_may_be_copied(exposure: PrivateKeyExposure) -> bool {
            exposure == PrivateKeyExposure::ProcessReadable
        }
        let mut config = legal_config();
        config.channel_credential.key = exported("/key");
        let real = classify_and_validate(&config).0.expect("recognised");
        assert!(key_may_be_copied(real.exposure()));
        assert!(!key_may_be_copied(
            HypotheticalChannelMechanism::RemoteAttestedEnclave.exposure()
        ));
        assert!(key_may_be_copied(
            HypotheticalChannelMechanism::SoftwareVault.exposure()
        ));
    }
}
