// SPDX-License-Identifier: Apache-2.0
//! The `TlsCustody` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.3.
//!
//! Whether the TLS *handshake* key can leave the device it lives on. Two states:
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `Exported` | `tls_key` | every delegated selector | — |
//! | `Delegated` | the selector matching `Custody` (X2a) | a non-empty `tls_key` (X2b) |
//!
//! Separate from `Custody` because the two keys are separate: a deployment may hold its
//! response-signing key in a KMS while its TLS key is a file, and the reverse. What ties
//! them is that the delegated selector is expressed per custody backend, which is why
//! X2a is a relation between the machines rather than a column inside either.
//!
//! The forbidden cell of `Delegated` is the one that matters: a configuration asserting
//! both custodies says the handshake key never leaves the device AND that a file copy of
//! it exists — the exact belief the delegated modes are chosen to make true, being false.

use crate::deployment_request::DeploymentRequest;

/// Which key object a delegated handshake signature is made with.
///
/// One value rather than three `Option`s: the selectors are alternatives, and a state that
/// held all three would let a caller ask "which one delegated this?" and get an answer the
/// classification never made. X2a decides whether the chosen one is legal beside the
/// configured `Custody` source; this only records which one it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DelegatedTlsKey {
    /// A second key object on the PKCS#11 token.
    Pkcs11 {
        /// The TLS key object's label.
        key_label: String,
    },
    /// A second, distinct AWS KMS key.
    AwsKms {
        /// Key id, ARN or alias of the TLS key.
        key_id: String,
    },
    /// A second, distinct GCP Cloud KMS key version.
    GcpKms {
        /// Fully-qualified `projects/.../cryptoKeyVersions/N` of the TLS key.
        key_version: String,
    },
}

/// Which TLS-custody state a configuration requests, and what it is inhabited by.
///
/// The representation is private to this module and [`classify`] is the only producer, so
/// a consumer cannot name a handshake key this deployment did not configure. Each locator
/// a consumer may legitimately want is a named projection below, and none can produce one
/// for a state that does not carry it — which keeps the combination X2b forbids, a
/// delegated key with a file copy beside it, unrepresentable downstream as well as at the
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCustodyState {
    kind: TlsCustodyKind,
}

/// The two states, as the owner's own representation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TlsCustodyKind {
    /// The handshake key is read from a file.
    Exported {
        /// Path to the PEM private key. Its presence IS this state's requirement.
        key_path: String,
    },
    /// The handshake key stays on a non-exporting device or KMS and is used through it.
    Delegated {
        /// Which key object signs the handshake.
        selector: DelegatedTlsKey,
    },
}

impl TlsCustodyState {
    /// Whether the handshake key is held by a non-exporting device.
    pub fn is_delegated(&self) -> bool {
        matches!(self.kind, TlsCustodyKind::Delegated { .. })
    }

    /// The exported handshake-key locator, or `None` under delegated custody.
    ///
    /// `None` is not a missing value: the delegated state does not carry one, because
    /// carrying it would make the combination X2b forbids representable, and the delegated
    /// path never reads a key file.
    pub fn exported_key_path(&self) -> Option<&str> {
        match &self.kind {
            TlsCustodyKind::Exported { key_path } => Some(key_path),
            TlsCustodyKind::Delegated { .. } => None,
        }
    }

    /// The PKCS#11 label of the delegated TLS key, where the handshake key is a second
    /// object on the token.
    pub fn delegated_pkcs11_label(&self) -> Option<&str> {
        match &self.kind {
            TlsCustodyKind::Delegated {
                selector: DelegatedTlsKey::Pkcs11 { key_label },
            } => Some(key_label),
            _ => None,
        }
    }

    /// The AWS KMS key id of the delegated TLS key, where it is a second, distinct key.
    pub fn delegated_aws_key_id(&self) -> Option<&str> {
        match &self.kind {
            TlsCustodyKind::Delegated {
                selector: DelegatedTlsKey::AwsKms { key_id },
            } => Some(key_id),
            _ => None,
        }
    }

    /// The GCP Cloud KMS key version of the delegated TLS key, where it is a second,
    /// distinct version.
    pub fn delegated_gcp_key_version(&self) -> Option<&str> {
        match &self.kind {
            TlsCustodyKind::Delegated {
                selector: DelegatedTlsKey::GcpKms { key_version },
            } => Some(key_version),
            _ => None,
        }
    }
}

/// Recognise the requested state.
///
/// Presence of any per-backend selector IS the request; there is no `--tls-custody` flag.
/// This is atlas structural rule 3 — a machine is a semantic ownership unit, and it need
/// not correspond to a selector of its own.
/// `None` only for `Exported` with no key to export — exactly the case
/// `classify_and_validate` refuses below. `Delegated` is never fallible: the selector whose
/// presence names the state IS the material it needs.
///
/// Two selectors at once picks the first in this fixed order, and that choice is never
/// observed: a configuration naming two of them has at least one that does not match its
/// `Custody` source, so X2a refuses it and the state is discarded with the refusal.
fn classify(config: &DeploymentRequest) -> Option<TlsCustodyState> {
    let delegated = |selector| {
        Some(TlsCustodyState {
            kind: TlsCustodyKind::Delegated { selector },
        })
    };
    if let Some(key_label) = config.pkcs11_tls_key_label.clone() {
        return delegated(DelegatedTlsKey::Pkcs11 { key_label });
    }
    if let Some(key_id) = config.aws_kms_tls_key_id.clone() {
        return delegated(DelegatedTlsKey::AwsKms { key_id });
    }
    if let Some(key_version) = config.gcp_kms_tls_key_version.clone() {
        return delegated(DelegatedTlsKey::GcpKms { key_version });
    }
    if config.tls_key.is_empty() {
        return None;
    }
    Some(TlsCustodyState {
        kind: TlsCustodyKind::Exported {
            key_path: config.tls_key.clone(),
        },
    })
}

/// Classify the requested TLS-custody state and check its local columns.
///
/// `Delegated`'s columns are both relations to other machines — which selector is legal
/// (X2a, against `Custody`) and that no file copy exists (X2b, against `Tls`) — so they
/// are checked in the cross-machine pass and deliberately not here. A local validator
/// that reached into another machine's fields would break the layering even when its
/// answer was right.
pub fn classify_and_validate(config: &DeploymentRequest) -> (Option<TlsCustodyState>, Vec<String>) {
    let state = classify(config);
    let mut violations = Vec::new();
    if state.is_none() {
        violations.push(
            "--tls-key is required: no delegated TLS custody selector is set, so the \
             handshake key has no source. Give --tls-key <path>, or select a delegated TLS \
             signer for the configured --key-source"
                .to_string(),
        );
    }
    (state, violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::KeySourceKind;

    /// A selector this machine must record, and the configuration that requests it.
    type Form = (DelegatedTlsKey, fn(&mut DeploymentRequest));

    fn run(mutate: impl FnOnce(&mut DeploymentRequest)) -> (Option<TlsCustodyState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn a_file_key_is_the_exported_state_and_carries_the_key_it_exports() {
        let (state, violations) = run(|c| c.tls_key = "/key".to_string());
        assert_eq!(
            state.as_ref().and_then(TlsCustodyState::exported_key_path),
            Some("/key")
        );
        assert!(violations.is_empty(), "{violations:?}");
    }

    /// One machine, three selectors — and the state now says WHICH one delegated it, so
    /// nothing downstream tests three `Option`s to find out.
    #[test]
    fn any_backends_selector_names_the_same_state_and_records_itself() {
        let cases: Vec<Form> = vec![
            (
                DelegatedTlsKey::Pkcs11 {
                    key_label: "tls".to_string(),
                },
                |c| {
                    c.key_source = KeySourceKind::Pkcs11;
                    c.pkcs11_tls_key_label = Some("tls".to_string());
                },
            ),
            (
                DelegatedTlsKey::AwsKms {
                    key_id: "alias/tls".to_string(),
                },
                |c| {
                    c.key_source = KeySourceKind::AwsKms;
                    c.aws_kms_tls_key_id = Some("alias/tls".to_string());
                },
            ),
            (
                DelegatedTlsKey::GcpKms {
                    key_version: "projects/p/..".to_string(),
                },
                |c| {
                    c.key_source = KeySourceKind::GcpKms;
                    c.gcp_kms_tls_key_version = Some("projects/p/..".to_string());
                },
            ),
        ];
        for (expected, mutate) in cases {
            let (state, _) = run(|c| {
                c.tls_key = String::new();
                mutate(c);
            });
            let state = state.expect("recognised");
            let named = match &expected {
                DelegatedTlsKey::Pkcs11 { key_label } => {
                    (state.delegated_pkcs11_label(), key_label.as_str())
                }
                DelegatedTlsKey::AwsKms { key_id } => {
                    (state.delegated_aws_key_id(), key_id.as_str())
                }
                DelegatedTlsKey::GcpKms { key_version } => {
                    (state.delegated_gcp_key_version(), key_version.as_str())
                }
            };
            assert_eq!(named.0, Some(named.1), "one machine, three selectors");
            assert!(state.is_delegated());
            assert_eq!(
                state.exported_key_path(),
                None,
                "a delegated state carries no file to export"
            );
        }
    }

    /// The one fallible case, and it is `Exported`: no delegated selector and no file to
    /// export means no state at all, not an `Exported` holding an empty path.
    #[test]
    fn the_exported_state_cannot_start_without_the_key_it_exports() {
        let (state, violations) = run(|c| c.tls_key = String::new());
        assert!(state.is_none(), "an exported state was built over no key");
        assert!(
            violations.iter().any(|v| v.contains("--tls-key")),
            "{violations:?}"
        );
    }

    /// `Delegated` is never fallible: the selector whose presence names the state is the
    /// material it needs. This is what makes X2b safe to ask of the state — the clause
    /// fires only on `Delegated`, which always exists when it applies.
    #[test]
    fn the_delegated_state_does_not_want_that_key() {
        let (state, violations) = run(|c| {
            c.tls_key = String::new();
            c.key_source = KeySourceKind::Pkcs11;
            c.pkcs11_tls_key_label = Some("tls".to_string());
        });
        assert!(state.is_some_and(|s| s.is_delegated()));
        assert!(violations.is_empty(), "{violations:?}");
    }
}
