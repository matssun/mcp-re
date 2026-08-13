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
//! All six live here: X2a, X2b, X5, X6, X7, X9.

use crate::cli::Config;
use crate::cli::KeySourceKind;
use crate::config_state::tls_custody::TlsCustodyState;
use crate::config_state::trust_revocation::TrustRevocationState;

/// The relations, kept separate so each can be reported where its clause has always been
/// read rather than in one block at the end (CF-11 — precedence changes deliberately).
#[derive(Debug, Default)]
pub(crate) struct CrossMachineViolations {
    /// X2a — `Custody` × `TlsCustody`.
    pub(crate) x2a_delegated_selector: Vec<String>,
    /// X2b — `TlsCustody` × `Tls`.
    pub(crate) x2b_exclusive_tls_custody: Vec<String>,
    /// X5 — `Limits` × `Tls`.
    pub(crate) x5_connection_outlives_credential: Vec<String>,
    /// X6 — `Authz` × `Trust`.
    pub(crate) x6_unenforceable_deny_list: Vec<String>,
    /// X7 — `ChannelBinding` × `Tls`.
    pub(crate) x7_local_mtls_xor_forwarded: Vec<String>,
    /// X9 — `TrustRevocation` × `DelegatedSigning`.
    pub(crate) x9_trust_epoch_posture: Vec<String>,
}

/// X2a: which delegated TLS selector is legal depends on the custody state.
///
/// The selector names a key object in a specific backend, so it is meaningful only under
/// the custody source that has that backend. On any other source it would silently do
/// nothing, leaving a deployment that believes its handshake key is device-resident.
/// Asked of the SELECTOR rather than of the built state, because custody is two things and
/// this relation is about only one of them. `key_source` names a source totally; the state
/// adds the material that source needs. A deployment naming `aws-kms` without its region
/// has no custody STATE, and still has a custody SOURCE that a PKCS#11 TLS selector does
/// not belong to — so asking this of the state would drop that diagnostic exactly when a
/// configuration is wrong in two ways at once.
fn x2a(kind: KeySourceKind, config: &Config) -> Vec<String> {
    [
        (
            config.pkcs11_tls_key_label.is_some(),
            KeySourceKind::Pkcs11,
            "--pkcs11-tls-key-label has no effect without --key-source pkcs11",
        ),
        (
            config.aws_kms_tls_key_id.is_some(),
            KeySourceKind::AwsKms,
            "--aws-kms-tls-key-id has no effect without --key-source aws-kms",
        ),
        (
            config.gcp_kms_tls_key_version.is_some(),
            KeySourceKind::GcpKms,
            "--gcp-kms-tls-key-version has no effect without --key-source gcp-kms",
        ),
    ]
    .into_iter()
    .filter(|(present, owner, _)| *present && kind != *owner)
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

/// X5: a connection may not outlive the credential that authenticated it.
///
/// A client certificate's chain, CRL status and validity window are checked at the TLS
/// handshake and never again on an established connection, so without a bound a peer
/// holding a stolen or revoked certificate keeps authenticated access for as long as it
/// keeps one connection open — and both the lifetime ceiling and the CRL cadence stop
/// being true statements about the deployment.
fn x5(config: &Config) -> Vec<String> {
    let ceiling = crate::cli::MAX_CLIENT_CERT_LIFETIME;
    match config.limits.max_connection_age {
        None => vec![
            "--max-connection-age-secs 0 disables the connection-age bound: the client \
             certificate is validated only at the handshake, so a peer that never \
             reconnects is never re-checked against an expiry or a reloaded CRL. Set a \
             bounded age (default 300s)"
                .to_string(),
        ],
        Some(age) if age > ceiling => vec![format!(
            "--max-connection-age-secs {}s exceeds the client-cert lifetime ceiling of {}s: \
             a connection would outlive the credential that authenticated it",
            age.as_secs(),
            ceiling.as_secs(),
        )],
        Some(_) => Vec::new(),
    }
}

/// X6: a deny-list no authorization profile will consult enforces nothing.
///
/// `Authz` is degenerate — only `Off` is reachable — so this relation is currently
/// unconditional. It is still a relation rather than a `Trust` column: the list becomes
/// meaningful the moment an authorization profile exists to read it, and nothing about
/// trust configuration changes then.
fn x6(config: &Config) -> Vec<String> {
    crate::cli::unenforceable_revocation_list_refusal(&config.revocation_list_paths)
        .into_iter()
        .collect()
}

/// X7: mTLS is terminated locally XOR a forwarded identity is trusted.
///
/// The header posture is refused outright — any peer that can reach the socket can spoof
/// it — which is what makes the second half of the relation currently unreachable: with no
/// forwarded identity there is always a local client certificate to bound.
fn x7(config: &Config) -> Vec<String> {
    if config.reverse_proxy_identity_header.is_some() {
        return vec![
            "--reverse-proxy-identity-header trusts a forwarded identity header that any peer \
             able to reach the socket can spoof; production must terminate mTLS locally (omit \
             --reverse-proxy-identity-header)"
                .to_string(),
        ];
    }
    Vec::new()
}

/// X9: the trust-epoch posture, interpreted once (CF-09).
///
/// `TrustRevocation` owns whether the epoch configuration is LEGAL — that is X8, and it is
/// checked inside that machine. What belongs here is the relation to delegated signing:
/// the credential label the operator's INCR kill switch reaches is minted under the same
/// posture the trust cache flushes on, so the two must be one decision.
///
/// The decision is `TrustRevocationState::has_networked_epoch`, made by the machine and
/// carried in `DeploymentConfigState`. Neither plan re-derives it from
/// `trust_epoch_redis_url`, and neither plane asks the other. This function therefore has
/// nothing left to refuse — which is the ruling holding, not an omission: it is stated so
/// that a future rule joining these two machines has an owner to be added to.
fn x9(_trust_revocation: Option<&TrustRevocationState>, _config: &Config) -> Vec<String> {
    Vec::new()
}

/// Check the cross-machine relations over states pass 1 recognised.
pub(crate) fn validate(
    custody_source: KeySourceKind,
    tls_custody: TlsCustodyState,
    trust_revocation: Option<&TrustRevocationState>,
    config: &Config,
) -> CrossMachineViolations {
    CrossMachineViolations {
        x2a_delegated_selector: x2a(custody_source, config),
        x2b_exclusive_tls_custody: x2b(tls_custody, config),
        x5_connection_outlives_credential: x5(config),
        x6_unenforceable_deny_list: x6(config),
        x7_local_mtls_xor_forwarded: x7(config),
        x9_trust_epoch_posture: x9(trust_revocation, config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut Config));

    fn relations(mutate: impl FnOnce(&mut Config)) -> CrossMachineViolations {
        let mut config = legal_config();
        mutate(&mut config);
        let (tls_custody, _) = crate::config_state::tls_custody::classify_and_validate(&config);
        let (trust, _) = crate::config_state::trust_revocation::classify_and_validate(&config);
        validate(config.key_source, tls_custody, trust.as_ref(), &config)
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
    fn a_connection_may_not_outlive_the_credential_that_authenticated_it() {
        assert!(relations(|_| {})
            .x5_connection_outlives_credential
            .is_empty());
        assert!(!relations(|c| c.limits.max_connection_age = None)
            .x5_connection_outlives_credential
            .is_empty());
        assert!(!relations(|c| c.limits.max_connection_age =
            Some(crate::cli::MAX_CLIENT_CERT_LIFETIME + std::time::Duration::from_secs(1)))
        .x5_connection_outlives_credential
        .is_empty());
    }

    #[test]
    fn a_deny_list_no_profile_will_read_is_refused() {
        assert!(relations(|_| {}).x6_unenforceable_deny_list.is_empty());
        assert!(
            !relations(|c| c.revocation_list_paths = vec!["/deny.json".to_string()])
                .x6_unenforceable_deny_list
                .is_empty()
        );
    }

    #[test]
    fn a_forwarded_identity_is_refused_where_mtls_terminates_locally() {
        assert!(relations(|_| {}).x7_local_mtls_xor_forwarded.is_empty());
        assert!(
            !relations(|c| c.reverse_proxy_identity_header = Some("x-client-id".to_string()))
                .x7_local_mtls_xor_forwarded
                .is_empty()
        );
    }

    /// CF-09 holding, asserted rather than assumed: the epoch posture is decided by the
    /// `TrustRevocation` machine, so this relation has nothing left to re-decide.
    #[test]
    fn the_trust_epoch_posture_is_not_re_derived_here() {
        let found = relations(|c| {
            c.revocation_tier = crate::revocation_tier::RevocationTier::Push { t_secs: 30 };
            c.trust_reload_secs = Some(30);
            c.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
        });
        assert!(found.x9_trust_epoch_posture.is_empty());
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
