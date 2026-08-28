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

use crate::config_state::tls_custody::TlsCustodyState;
use crate::config_state::trust_revocation::TrustRevocationState;
use crate::deployment_request::DeploymentRequest;
use crate::deployment_request::{DelegatedChannelKeyRequest, SigningSourceRequest};

/// The relations, kept separate so each can be reported where its clause has always been
/// read rather than in one block at the end (CF-11 — precedence changes deliberately).
#[derive(Debug, Default)]
pub(crate) struct CrossMachineViolations {
    /// X2a — the response-signing mechanism × the channel key object.
    pub(crate) x2a_delegated_selector: Vec<String>,
    /// X2b — `TlsCustody` × `Tls`.
    pub(crate) x2b_exclusive_tls_custody: Vec<String>,
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

/// X2b: a delegated TLS custody forbids an exported copy of the same key.
///
/// ADR-MCPS-028 §G. Asserting both is contradictory rather than redundant: the operator
/// could believe the key never leaves the device while a file copy also exists.
/// Asked of the STATE, and safely: the fallible side of `TlsCustody` is `Exported`, and
/// this clause fires only on `Delegated`, which the presence of a selector always
/// constructs. So a configuration with no recognised TLS custody has no exported-copy
/// contradiction to report either.
///
/// The exported material is still read from the request, deliberately. Under `Delegated`
/// the state does NOT carry `--tls-key`: carrying it would make the very combination this
/// clause forbids representable. `Tls` has no state type to consult instead, so this is a
/// relation to an owner whose material still lives in the request.
fn x2b(tls_custody: Option<&TlsCustodyState>, config: &DeploymentRequest) -> Vec<String> {
    if tls_custody.is_some_and(TlsCustodyState::is_delegated) && !config.tls_key.is_empty() {
        return vec![
            validate_tls_signing_exclusivity(true, true).expect_err("both custodies asserted")
        ];
    }
    Vec::new()
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

/// Check the cross-machine relations over states pass 1 recognised.
pub(crate) fn validate(
    tls_custody: Option<&TlsCustodyState>,
    trust_revocation: Option<&TrustRevocationState>,
    config: &DeploymentRequest,
) -> CrossMachineViolations {
    CrossMachineViolations {
        x2a_delegated_selector: x2a(
            &config.response_signing.source,
            config.channel_credential.delegated.as_ref(),
        ),
        x2b_exclusive_tls_custody: x2b(tls_custody, config),
        x6_unenforceable_deny_list: x6(config),
        x9_trust_epoch_posture: x9(trust_revocation, config),
    }
}

/// Enforce the delegated-XOR-exported TLS-signing rule (ADR-MCPS-028 §G, issue
/// #58): a source's TLS handshake key is EITHER delegated to a non-exporting
/// device/KMS OR exported from a file, never both. A source that asserts both is
/// contradictory — the operator could believe the key never leaves the device while a
/// file copy also exists — so it FAILS CLOSED.
///
/// Pure and black-box-testable (no `DeploymentRequest`, no IO). Relation X2b is the caller,
/// and it asks the question of two RECOGNISED states rather than of the fields, which is
/// why there is no `DeploymentRequest` adapter here.
pub fn validate_tls_signing_exclusivity(
    has_delegated_tls: bool,
    has_exported_tls_key: bool,
) -> Result<(), String> {
    if has_delegated_tls && has_exported_tls_key {
        return Err(
            "TLS signing is delegated XOR exported (ADR-MCPS-028 §G): a delegated-TLS \
             key source must not also be given an exported --tls-key. Remove --tls-key \
             when using a delegated (non-exporting device/KMS) TLS signer."
                .to_string(),
        );
    }
    Ok(())
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
        config.channel_credential.delegated = Some(DelegatedChannelKeyRequest::Pkcs11(
            Pkcs11ChannelKeyRequest {
                key_label: "tls".to_string(),
            },
        ));
    }

    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut DeploymentRequest));

    fn relations(mutate: impl FnOnce(&mut DeploymentRequest)) -> CrossMachineViolations {
        let mut config = legal_config();
        mutate(&mut config);
        let (tls_custody, _) = crate::config_state::tls_custody::classify_and_validate(&config);
        let (trust, _) = crate::config_state::trust_revocation::classify_and_validate(&config);
        validate(tls_custody.as_ref(), trust.as_ref(), &config)
    }

    #[test]
    fn a_selector_matching_the_custody_state_is_legal() {
        let found = relations(|c| {
            select_pkcs11(c);
            pkcs11_channel(c);
            c.tls_key = String::new();
        });
        assert!(found.x2a_delegated_selector.is_empty());
        assert!(found.x2b_exclusive_tls_custody.is_empty());
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
                c.channel_credential.delegated = Some(DelegatedChannelKeyRequest::AwsKms(
                    AwsKmsChannelKeyRequest {
                        key_id: "alias/tls".to_string(),
                    },
                ));
            }),
            ("--gcp-kms-tls-key-version", |c| {
                select_file(c);
                c.channel_credential.delegated = Some(DelegatedChannelKeyRequest::GcpKms(
                    GcpKmsChannelKeyRequest {
                        key_version: "projects/p/..".to_string(),
                    },
                ));
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
            c.revocation_tier = crate::revocation_tier::RevocationTier::Push { t_secs: 30 };
            c.trust_reload_secs = Some(30);
            c.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
        });
        assert!(found.x9_trust_epoch_posture.is_empty());
    }

    #[test]
    fn asserting_both_custodies_for_one_key_is_refused() {
        let found = relations(|c| {
            select_pkcs11(c);
            pkcs11_channel(c);
            c.tls_key = "/key".to_string();
        });
        assert_eq!(found.x2b_exclusive_tls_custody.len(), 1);
        assert!(found.x2b_exclusive_tls_custody[0].contains("delegated XOR exported"));
    }

    #[test]
    fn tls_signing_exclusivity_rejects_both_and_admits_either_or_neither() {
        // ADR-MCPS-028 §G / issue #58: delegated XOR exported TLS signing.
        // Exported only — the current default path — is fine.
        assert!(super::validate_tls_signing_exclusivity(false, true).is_ok());
        // Delegated only — what #59–#61 will configure — is fine.
        assert!(super::validate_tls_signing_exclusivity(true, false).is_ok());
        // Neither set — degenerate, not contradictory — is fine (the require()
        // checks elsewhere catch a genuinely missing credential).
        assert!(super::validate_tls_signing_exclusivity(false, false).is_ok());
        // BOTH set — contradictory — fails closed.
        let err = super::validate_tls_signing_exclusivity(true, true)
            .expect_err("delegated AND exported TLS signing must be rejected");
        assert!(
            err.contains("delegated XOR exported"),
            "the rejection must name the XOR rule, got: {err}"
        );
    }
}
