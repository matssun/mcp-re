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
//! All four live here: X2a, X2b, X6, X9.

use crate::config_state::trust_revocation::TrustRevocationState;
use crate::deployment_request::{
    ChannelKeyRequest, DelegatedChannelKeyRequest, DeploymentRequest, SigningSourceRequest,
};

/// The relations, kept separate so each can be reported where its clause has always been
/// read rather than in one block at the end (CF-11 — precedence changes deliberately).
#[derive(Debug, Default)]
pub(crate) struct CrossMachineViolations {
    /// X2a — the response-signing mechanism × the channel key object.
    pub(crate) x2a_delegated_selector: Vec<String>,
    /// X6 — `Authz` × `Trust`.
    pub(crate) x6_unenforceable_deny_list: Vec<String>,
    /// X9 — `TrustRevocation` × `DelegatedSigning`.
    pub(crate) x9_trust_epoch_posture: Vec<String>,
}

/// X2a: the channel key object must live in a backend this deployment already reaches.
///
/// The two roles are modelled separately — a response-signing source and a channel
/// credential — so nothing forces them to agree, and something therefore has to say that
/// they must. This is that statement, made explicitly rather than produced as a side
/// effect of one provider discriminator serving two roles (ADR-MCPRE-067 §10).
///
/// What it protects: a channel key object named in a backend the deployment does not reach
/// would silently do nothing, leaving an operator who believes the handshake key is
/// device-resident.
///
/// Asked of the requested SOURCE rather than of the built custody state, because custody
/// is two things and this relation is about only one of them. A deployment naming AWS KMS
/// without its region has no custody STATE, and still has a mechanism selection that a
/// PKCS#11 channel key does not belong to — so asking this of the state would drop the
/// diagnostic exactly when a configuration is wrong in two ways at once.
fn x2a(source: &SigningSourceRequest, channel: Option<&DelegatedChannelKeyRequest>) -> Vec<String> {
    let Some(channel) = channel else {
        return Vec::new();
    };
    let mismatch = |flag: &str, required: &str| {
        vec![format!(
            "{flag} has no effect without --key-source {required}"
        )]
    };
    match (channel, source) {
        (DelegatedChannelKeyRequest::Pkcs11(_), SigningSourceRequest::Pkcs11(_))
        | (DelegatedChannelKeyRequest::AwsKms(_), SigningSourceRequest::AwsKms(_))
        | (DelegatedChannelKeyRequest::GcpKms(_), SigningSourceRequest::GcpKms(_)) => Vec::new(),
        (DelegatedChannelKeyRequest::Pkcs11(_), _) => mismatch("--pkcs11-tls-key-label", "pkcs11"),
        (DelegatedChannelKeyRequest::AwsKms(_), _) => mismatch("--aws-kms-tls-key-id", "aws-kms"),
        (DelegatedChannelKeyRequest::GcpKms(_), _) => {
            mismatch("--gcp-kms-tls-key-version", "gcp-kms")
        }
    }
}

/// X6: a deny-list no authorization profile will consult enforces nothing.
///
/// `Authz` is no longer degenerate — `--authz pdp-decision` is deployable — but no
/// reachable profile READS a grant deny-list, so this relation is still unconditional. It
/// is a relation rather than a `Trust` column: the list becomes meaningful the moment a
/// profile exists that consults one, and nothing about trust configuration changes then.
fn x6(config: &DeploymentRequest) -> Vec<String> {
    unenforceable_revocation_list_refusal(&config.authorization.revocation_list_paths)
        .into_iter()
        .collect()
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
fn x9(
    _trust_revocation: Option<&TrustRevocationState>,
    _config: &DeploymentRequest,
) -> Vec<String> {
    Vec::new()
}

/// The delegated key object this request names, where it names one.
///
/// X2a is a relation over the SELECTION, and the exported arm makes no selection to
/// relate. Reading the arm here rather than in `x2a` keeps that function about the pair.
fn delegated_channel_key(key: &ChannelKeyRequest) -> Option<&DelegatedChannelKeyRequest> {
    match key {
        ChannelKeyRequest::Delegated(delegated) => Some(delegated),
        ChannelKeyRequest::ExportedFile(_) => None,
    }
}

/// Check the cross-machine relations over states pass 1 recognised.
pub(crate) fn validate(
    trust_revocation: Option<&TrustRevocationState>,
    config: &DeploymentRequest,
) -> CrossMachineViolations {
    CrossMachineViolations {
        x2a_delegated_selector: x2a(
            &config.response_signing.source,
            delegated_channel_key(&config.channel_credential.key),
        ),
        x6_unenforceable_deny_list: x6(config),
        x9_trust_epoch_posture: x9(trust_revocation, config),
    }
}

/// The one decision about whether a policy-layer deny-list can be enforced.
///
/// `Some(diagnostic)` means it cannot. Today that is unconditional whenever paths are
/// supplied: the deny-list is consumed by `LiveTrustResolver::resolve_with_revocation_id`,
/// which no installed profile calls. `--authz pdp-decision` authenticates a CARRIED
/// decision and consults no grant deny-list, and `--authz reference` — the profile that
/// would have read one — is refused. So a supplied list could only be silently ignored, and
/// an operator would believe a compromised grant was revoked while it kept being
/// authorized. Withdrawing a PDP authority is done by removing its `authorization-issuer`
/// entry from `--trust` and restarting.
///
/// Refused rather than accepted-and-ignored (security-boundary §2: never surface a
/// capability that is not delivered). v0.16 deliberately REFUSES rather than implementing
/// enforcement — wiring it would be a new runtime capability, which this release does not
/// add — and rather than deleting the flag, which would turn a security-correctness fix
/// into a CLI compatibility decision. A later release can implement, deprecate or redefine
/// it; this is the single place that would change.
///
/// A function for the same reason as [`online_ocsp_refusal`]: the prohibition is stated
/// once, and relation X6 is where a `DeploymentRequest` meets it however it was built. Two
/// copies of a condition is how the parser and the validation boundary drifted apart the
/// first time.
pub(crate) fn unenforceable_revocation_list_refusal(paths: &[String]) -> Option<String> {
    (!paths.is_empty()).then(|| {
        "--revocation-list supplies a policy-layer deny-list (ADR-MCPS-013), but it is \
         consulted only by the retired reference profile, which is refused, and never by \
         --authz pdp-decision, so the list would enforce NOTHING. Remove \
         --revocation-list; use the trust store and --revocation-tier for key \
         revocation on the request path."
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::{
        AwsKmsChannelKeyRequest, AwsKmsSigningSourceRequest, DeploymentRequest,
        FileSigningSourceRequest, GcpKmsChannelKeyRequest, GcpKmsSigningSourceRequest,
        Pkcs11ChannelKeyRequest, Pkcs11SigningSourceRequest,
    };

    /// Select the response-signing mechanism, with the minimum material each needs.
    fn select_pkcs11(config: &mut DeploymentRequest) {
        config.response_signing.source = SigningSourceRequest::Pkcs11(Pkcs11SigningSourceRequest {
            module: Some("/lib/softhsm.so".to_string()),
            pin_file: Some("/pin".to_string()),
            token_label: Some("token".to_string()),
            key_label: Some("signing".to_string()),
        });
    }

    fn select_aws(config: &mut DeploymentRequest) {
        config.response_signing.source = SigningSourceRequest::AwsKms(AwsKmsSigningSourceRequest {
            region: Some("eu-north-1".to_string()),
            key_id: Some("alias/signing".to_string()),
            ..AwsKmsSigningSourceRequest::default()
        });
    }

    fn select_gcp(config: &mut DeploymentRequest) {
        config.response_signing.source = SigningSourceRequest::GcpKms(GcpKmsSigningSourceRequest {
            key_version: Some("projects/p/..".to_string()),
            ..GcpKmsSigningSourceRequest::default()
        });
    }

    fn select_file(config: &mut DeploymentRequest) {
        config.response_signing.source = SigningSourceRequest::File(FileSigningSourceRequest {
            seed_path: "/seed".to_string(),
        });
    }

    fn pkcs11_channel(config: &mut DeploymentRequest) {
        config.channel_credential.key = ChannelKeyRequest::Delegated(
            DelegatedChannelKeyRequest::Pkcs11(Pkcs11ChannelKeyRequest {
                key_label: "tls".to_string(),
            }),
        );
    }

    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut DeploymentRequest));

    fn relations(mutate: impl FnOnce(&mut DeploymentRequest)) -> CrossMachineViolations {
        let mut config = legal_config();
        mutate(&mut config);
        let (trust, _) = crate::config_state::trust_revocation::classify_and_validate(&config);
        validate(trust.as_ref(), &config)
    }

    #[test]
    fn a_selector_matching_the_custody_state_is_legal() {
        let found = relations(|c| {
            select_pkcs11(c);
            pkcs11_channel(c);
        });
        assert!(found.x2a_delegated_selector.is_empty());
    }

    #[test]
    fn every_selector_is_refused_under_every_other_custody_state() {
        let cases: Vec<Case> = vec![
            ("--pkcs11-tls-key-label", |c| {
                select_aws(c);
                pkcs11_channel(c);
            }),
            ("--aws-kms-tls-key-id", |c| {
                select_gcp(c);
                c.channel_credential.key = ChannelKeyRequest::Delegated(
                    DelegatedChannelKeyRequest::AwsKms(AwsKmsChannelKeyRequest {
                        key_id: "alias/tls".to_string(),
                    }),
                );
            }),
            ("--gcp-kms-tls-key-version", |c| {
                select_file(c);
                c.channel_credential.key = ChannelKeyRequest::Delegated(
                    DelegatedChannelKeyRequest::GcpKms(GcpKmsChannelKeyRequest {
                        key_version: "projects/p/..".to_string(),
                    }),
                );
            }),
        ];
        for (flag, mutate) in cases {
            let found = relations(|c| {
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
    fn a_deny_list_no_profile_will_read_is_refused() {
        assert!(relations(|_| {}).x6_unenforceable_deny_list.is_empty());
        assert!(!relations(
            |c| c.authorization.revocation_list_paths = vec!["/deny.json".to_string()]
        )
        .x6_unenforceable_deny_list
        .is_empty());
    }

    /// CF-09 holding, asserted rather than assumed: the epoch posture is decided by the
    /// `TrustRevocation` machine, so this relation has nothing left to re-decide.
    #[test]
    fn the_trust_epoch_posture_is_not_re_derived_here() {
        let found = relations(|c| {
            c.request_signer_currency =
                crate::deployment_request::RequestSignerCurrencyRequest::Push {
                    t_secs: 30,
                    reload_secs: 30,
                    epoch: crate::deployment_request::TrustEpochStoreRequest {
                        source: Some(crate::deployment_request::TrustEpochSource::redis(
                            "redis://127.0.0.1:6379",
                            None,
                        )),
                    },
                };
        });
        assert!(found.x9_trust_epoch_posture.is_empty());
    }

    /// X2b is GONE, and this is the control that says so honestly: the pair it refused —
    /// a delegated channel key beside an exported file copy — has no representation left
    /// to build, so there is no configuration for a relation to examine. The refusal did
    /// not move to another boundary silently; the CLI adapter answers the argv form, and
    /// the negative control for that lives with the parser (ADR-MCPRE-067 §7).
    #[test]
    fn the_exclusive_custody_relation_has_no_configuration_left_to_refuse() {
        let found = relations(|c| {
            select_pkcs11(c);
            pkcs11_channel(c);
        });
        assert!(found.x2a_delegated_selector.is_empty());
        // Naming the delegated key object is what unnames the file: one value, two arms.
        assert!(matches!(
            c_key(&legal_config()),
            ChannelKeyRequest::ExportedFile(_)
        ));
    }

    /// The request's own channel key, for the assertion above.
    fn c_key(config: &DeploymentRequest) -> &ChannelKeyRequest {
        &config.channel_credential.key
    }
}
