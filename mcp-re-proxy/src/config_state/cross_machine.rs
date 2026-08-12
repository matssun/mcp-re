// SPDX-License-Identifier: Apache-2.0
//! Pass 2 — compatibility BETWEEN machines (`work/CONFIG-STATE-ATLAS.md` Part D).
//!
//! A rule belongs here only if it joins two machines. A rule between two selectors of one
//! machine is that machine's own column and lives with it; applying that test is what took
//! the relation count from twelve to six, each pass moving a rule to the owner that would
//! still make sense if the dependency graph were never drawn.
//!
//! **This pass reads classified states, never raw fields.** That is what makes it a second
//! pass rather than a second opinion: every question it asks has already been answered
//! once, by the machine that owns it.
//!
//! Implemented here: X2a and X2b. X5, X6, X7 and X9 still sit inline at the boundary,
//! waiting for the machines they join.

use crate::cli::Config;
use crate::config_state::custody::CustodyState;
use crate::config_state::tls_custody::TlsCustodyState;

/// The relations, kept separate so each can be reported where its clause has always been
/// read rather than in one block at the end (CF-11 — precedence changes deliberately).
#[derive(Debug, Default)]
pub(crate) struct CrossMachineViolations {
    /// X2a — `Custody` × `TlsCustody`.
    pub(crate) x2a_delegated_selector: Vec<String>,
    /// X2b — `TlsCustody` × `Tls`.
    pub(crate) x2b_exclusive_tls_custody: Vec<String>,
}

/// X2a: which delegated TLS selector is legal depends on the custody state.
///
/// The selector names a key object in a specific backend, so it is meaningful only under
/// the custody source that has that backend. On any other source it would silently do
/// nothing, leaving a deployment that believes its handshake key is device-resident.
fn x2a(custody: CustodyState, config: &Config) -> Vec<String> {
    [
        (
            config.pkcs11_tls_key_label.is_some(),
            CustodyState::Pkcs11,
            "--pkcs11-tls-key-label has no effect without --key-source pkcs11",
        ),
        (
            config.aws_kms_tls_key_id.is_some(),
            CustodyState::AwsKms,
            "--aws-kms-tls-key-id has no effect without --key-source aws-kms",
        ),
        (
            config.gcp_kms_tls_key_version.is_some(),
            CustodyState::GcpKms,
            "--gcp-kms-tls-key-version has no effect without --key-source gcp-kms",
        ),
    ]
    .into_iter()
    .filter(|(present, owner, _)| *present && custody != *owner)
    .map(|(_, _, message)| message.to_string())
    .collect()
}

/// X2b: a delegated TLS custody forbids an exported copy of the same key.
///
/// ADR-MCPS-028 §G. Asserting both is contradictory rather than redundant: the operator
/// could believe the key never leaves the device while a file copy also exists.
fn x2b(tls_custody: TlsCustodyState, config: &Config) -> Vec<String> {
    if tls_custody.is_delegated() && !config.tls_key.is_empty() {
        return vec![crate::cli::validate_tls_signing_exclusivity(true, true)
            .expect_err("both custodies asserted")];
    }
    Vec::new()
}

/// Check the cross-machine relations over states pass 1 recognised.
pub(crate) fn validate(
    custody: CustodyState,
    tls_custody: TlsCustodyState,
    config: &Config,
) -> CrossMachineViolations {
    CrossMachineViolations {
        x2a_delegated_selector: x2a(custody, config),
        x2b_exclusive_tls_custody: x2b(tls_custody, config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::KeySourceKind;
    use crate::config_state::test_support::legal_config;

    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut Config));

    fn relations(mutate: impl FnOnce(&mut Config)) -> CrossMachineViolations {
        let mut config = legal_config();
        mutate(&mut config);
        let (custody, _) = crate::config_state::custody::classify_and_validate(&config);
        let (tls_custody, _) = crate::config_state::tls_custody::classify_and_validate(&config);
        validate(custody, tls_custody, &config)
    }

    #[test]
    fn a_selector_matching_the_custody_state_is_legal() {
        let found = relations(|c| {
            c.key_source = KeySourceKind::Pkcs11;
            c.pkcs11_tls_key_label = Some("tls".to_string());
            c.tls_key = String::new();
        });
        assert!(found.x2a_delegated_selector.is_empty());
        assert!(found.x2b_exclusive_tls_custody.is_empty());
    }

    #[test]
    fn every_selector_is_refused_under_every_other_custody_state() {
        let cases: Vec<Case> = vec![
            ("--pkcs11-tls-key-label", |c| {
                c.key_source = KeySourceKind::AwsKms;
                c.pkcs11_tls_key_label = Some("tls".to_string());
            }),
            ("--aws-kms-tls-key-id", |c| {
                c.key_source = KeySourceKind::GcpKms;
                c.aws_kms_tls_key_id = Some("alias/tls".to_string());
            }),
            ("--gcp-kms-tls-key-version", |c| {
                c.key_source = KeySourceKind::File;
                c.gcp_kms_tls_key_version = Some("projects/p/..".to_string());
            }),
        ];
        for (flag, mutate) in cases {
            let found = relations(|c| {
                c.tls_key = String::new();
                mutate(c);
            });
            assert!(
                found
                    .x2a_delegated_selector
                    .iter()
                    .any(|v| v.contains(flag)),
                "a dangling {flag} was accepted"
            );
        }
    }

    #[test]
    fn asserting_both_custodies_for_one_key_is_refused() {
        let found = relations(|c| {
            c.key_source = KeySourceKind::Pkcs11;
            c.pkcs11_tls_key_label = Some("tls".to_string());
            c.tls_key = "/key".to_string();
        });
        assert_eq!(found.x2b_exclusive_tls_custody.len(), 1);
        assert!(found.x2b_exclusive_tls_custody[0].contains("delegated XOR exported"));
    }
}
