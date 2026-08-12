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

use crate::cli::Config;

/// Which TLS-custody state a configuration requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCustodyState {
    /// The handshake key is read from a file.
    Exported,
    /// The handshake key stays on a non-exporting device or KMS and is used through it.
    Delegated,
}

impl TlsCustodyState {
    /// Whether the handshake key is held by a non-exporting device.
    pub fn is_delegated(&self) -> bool {
        matches!(self, Self::Delegated)
    }
}

/// Recognise the requested state.
///
/// Presence of any per-backend selector IS the request; there is no `--tls-custody` flag.
/// This is atlas structural rule 3 — a machine is a semantic ownership unit, and it need
/// not correspond to a selector of its own.
fn classify(config: &Config) -> TlsCustodyState {
    let delegated = config.pkcs11_tls_key_label.is_some()
        || config.aws_kms_tls_key_id.is_some()
        || config.gcp_kms_tls_key_version.is_some();
    if delegated {
        TlsCustodyState::Delegated
    } else {
        TlsCustodyState::Exported
    }
}

/// Classify the requested TLS-custody state and check its local columns.
///
/// `Delegated`'s columns are both relations to other machines — which selector is legal
/// (X2a, against `Custody`) and that no file copy exists (X2b, against `Tls`) — so they
/// are checked in the cross-machine pass and deliberately not here. A local validator
/// that reached into another machine's fields would break the layering even when its
/// answer was right.
pub fn classify_and_validate(config: &Config) -> (TlsCustodyState, Vec<String>) {
    let state = classify(config);
    let mut violations = Vec::new();
    if state == TlsCustodyState::Exported && config.tls_key.is_empty() {
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
    use crate::cli::KeySourceKind;
    use crate::config_state::test_support::legal_config;

    fn run(mutate: impl FnOnce(&mut Config)) -> (TlsCustodyState, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn a_file_key_is_the_exported_state_and_is_accepted() {
        let (state, violations) = run(|c| c.tls_key = "/key".to_string());
        assert_eq!(state, TlsCustodyState::Exported);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn any_backends_selector_names_the_same_state() {
        let cases: Vec<fn(&mut Config)> = vec![
            |c| {
                c.key_source = KeySourceKind::Pkcs11;
                c.pkcs11_tls_key_label = Some("tls".to_string());
            },
            |c| {
                c.key_source = KeySourceKind::AwsKms;
                c.aws_kms_tls_key_id = Some("alias/tls".to_string());
            },
            |c| {
                c.key_source = KeySourceKind::GcpKms;
                c.gcp_kms_tls_key_version = Some("projects/p/..".to_string());
            },
        ];
        for mutate in cases {
            let (state, _) = run(|c| {
                c.tls_key = String::new();
                mutate(c);
            });
            assert_eq!(
                state,
                TlsCustodyState::Delegated,
                "one machine, three selectors"
            );
            assert!(state.is_delegated());
        }
    }

    #[test]
    fn the_exported_state_cannot_start_without_the_key_it_exports() {
        let (state, violations) = run(|c| c.tls_key = String::new());
        assert_eq!(state, TlsCustodyState::Exported);
        assert!(
            violations.iter().any(|v| v.contains("--tls-key")),
            "{violations:?}"
        );
    }

    #[test]
    fn the_delegated_state_does_not_want_that_key() {
        let (state, violations) = run(|c| {
            c.tls_key = String::new();
            c.key_source = KeySourceKind::Pkcs11;
            c.pkcs11_tls_key_label = Some("tls".to_string());
        });
        assert_eq!(state, TlsCustodyState::Delegated);
        assert!(violations.is_empty(), "{violations:?}");
    }
}
