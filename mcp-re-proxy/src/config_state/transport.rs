// SPDX-License-Identifier: Apache-2.0
//! The `ChannelBinding` and `CrlRevocation` machines — `work/CONFIG-STATE-ATLAS.md`
//! §C.5 and §C.6.
//!
//! Two machines in one file because they are two small closed models over the same
//! domain, and separating them into two files would say they are further apart than they
//! are. Neither has parameters beyond the ones named below.
//!
//! ## ChannelBinding — how a request is bound to the channel identity
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `Exact + UriSan` | — | every ingress parameter | — |
//! | `Exact + DnsSan` | — | every ingress parameter | — |
//!
//! `binding` and `identity_source` are **two selectors of one machine**, and the machine is
//! named for what it owns rather than for either of them. `binding` contributes one
//! reachable value today, so the live distinction is carried by `identity_source` — the
//! clearest instance of the atlas's rule that a selector is syntax and a machine is a
//! semantic ownership unit.
//!
//! ## CrlRevocation — offline client-certificate revocation
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `None` | — | a reload cadence | — |
//! | `Static` | at least one CRL path | — | — |
//! | `Reloading` | at least one CRL path, a cadence | — | cadence `> 0` |
//!
//! A zero cadence is not a disabled reloader but an unbounded one: the worker's sleep
//! returns immediately, so it re-reads every CRL, rebuilds the rustls verifier and swaps
//! the serving snapshot in a tight loop, burning a core with no diagnostic.

use crate::cli::{BindingKind, Config};
use crate::transport::IdentityPolicy;

/// How a verified request signer is bound to the authenticated channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBindingState {
    /// Exact match against a URI SAN in the client certificate.
    ExactUriSan,
    /// Exact match against a DNS SAN.
    ExactDnsSan,
}

/// Offline client-certificate revocation.
///
/// Each state carries what inhabiting it requires. No `Option` is involved and no build
/// step is needed, because here presence IS the classification: a non-empty CRL set is
/// what makes the state `Static` rather than `None`, and a cadence beside it is what makes
/// it `Reloading`. A state cannot exist without the value that selected it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlRevocationState {
    /// No CRLs — revocation rests entirely on the client-certificate lifetime ceiling.
    None,
    /// CRLs loaded once at startup.
    Static {
        /// The CRL files. Non-empty: an empty set is what `None` means.
        paths: Vec<String>,
    },
    /// CRLs re-read on a cadence, so a revocation published after startup takes effect.
    Reloading {
        /// The CRL files. Non-empty, as for `Static`.
        paths: Vec<String>,
        /// How often they are re-read. Its presence is what distinguishes this from
        /// `Static`, so the state that has one carries it.
        cadence_secs: u64,
    },
}

/// Recognise the channel-binding state, or say why the request names none.
///
/// Unlike most machines this one can fail to classify: `binding` has three variants no
/// deployment can be in, and `identity_source` has a deprecated one. They are input forms,
/// not states, so they produce no member of the model.
fn classify_binding(config: &Config) -> Result<ChannelBindingState, Vec<String>> {
    let mut refusals = Vec::new();
    if let Some(refusal) = crate::cli::undeployable_transport_binding_refusal(config.binding) {
        refusals.push(refusal);
    }
    match config.binding {
        BindingKind::None => refusals.push(
            "--transport-binding none ignores the mTLS channel identity, decoupling the \
             verified request signer from the authenticated channel; production must bind \
             them (--transport-binding exact)"
                .to_string(),
        ),
        BindingKind::LbAssertion => refusals.push(
            "--transport-binding lb-assertion places the load balancer in the trusted \
             computing base (the LB terminates the client mTLS and signs a request-bound \
             assertion); this is request-bound ingress assertion, NOT end-to-end \
             client↔node mTLS; production must bind end-to-end (--transport-binding exact \
             with locally-terminated client mTLS)"
                .to_string(),
        ),
        _ => {}
    }
    let identity = match config.identity_source {
        IdentityPolicy::UriSan => Some(ChannelBindingState::ExactUriSan),
        IdentityPolicy::DnsSan => Some(ChannelBindingState::ExactDnsSan),
        IdentityPolicy::CnLegacy => {
            refusals.push(
                "--transport-identity-source cn_legacy is a deprecated, insecure identity \
                 binding; use uri_san or dns_san"
                    .to_string(),
            );
            None
        }
    };
    match (identity, refusals.is_empty()) {
        (Some(state), true) => Ok(state),
        _ => Err(refusals),
    }
}

/// Classify the channel-binding state and check its columns.
///
/// The ingress parameters belong to states the model does not contain, and their coherence
/// is checked by `ingress_assertion_violation` at its own position in the clause list.
pub fn classify_and_validate_binding(
    config: &Config,
) -> (Option<ChannelBindingState>, Vec<String>) {
    match classify_binding(config) {
        Ok(state) => (Some(state), Vec::new()),
        Err(refusals) => (None, refusals),
    }
}

/// Recognise the CRL-revocation state. Total: the two fields name one.
fn classify_crl(config: &Config) -> CrlRevocationState {
    if config.client_crl_paths.is_empty() {
        CrlRevocationState::None
    } else if let Some(cadence_secs) = config.client_crl_reload_secs {
        CrlRevocationState::Reloading {
            paths: config.client_crl_paths.clone(),
            cadence_secs,
        }
    } else {
        CrlRevocationState::Static {
            paths: config.client_crl_paths.clone(),
        }
    }
}

/// Classify the CRL-revocation state and check its columns.
pub fn classify_and_validate_crl(config: &Config) -> (CrlRevocationState, Vec<String>) {
    let state = classify_crl(config);
    let mut violations = Vec::new();
    if config.client_crl_reload_secs == Some(0) {
        violations.push(
            "--client-crl-reload-secs 0 makes the CRL reloader spin: the cadence is the sleep \
             between re-reads, so zero re-reads every CRL and rebuilds the TLS verifier \
             continuously. Set a positive cadence, or omit the flag to load the CRLs once"
                .to_string(),
        );
    }
    // Forbidden on `None`: a cadence names how often to re-read a set that is empty, so its
    // presence states a control the deployment does not have.
    if state == CrlRevocationState::None && config.client_crl_reload_secs.is_some() {
        violations.push(
            "--client-crl-reload-secs has no effect without --client-crl: there is no \
             revocation list to re-read, so no revocation is enforced on either cadence"
                .to_string(),
        );
    }
    (state, violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn binding(mutate: impl FnOnce(&mut Config)) -> (Option<ChannelBindingState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate_binding(&config)
    }

    /// A state this machine must recognise, and how to request it.
    type Form = (CrlRevocationState, fn(&mut Config));

    fn crl(mutate: impl FnOnce(&mut Config)) -> (CrlRevocationState, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate_crl(&config)
    }

    #[test]
    fn both_binding_states_are_classified_and_accepted() {
        for (source, expected) in [
            (IdentityPolicy::UriSan, ChannelBindingState::ExactUriSan),
            (IdentityPolicy::DnsSan, ChannelBindingState::ExactDnsSan),
        ] {
            let (state, violations) = binding(|c| c.identity_source = source);
            assert_eq!(state, Some(expected));
            assert!(
                violations.is_empty(),
                "{expected:?} refused: {violations:?}"
            );
        }
    }

    /// One machine, two selectors: neither alone names the state.
    #[test]
    fn the_state_is_the_pair_not_either_selector() {
        assert_ne!(
            binding(|c| c.identity_source = IdentityPolicy::UriSan).0,
            binding(|c| c.identity_source = IdentityPolicy::DnsSan).0,
            "the same binding kind, two states"
        );
    }

    #[test]
    fn no_undeployable_binding_becomes_a_state() {
        for kind in [BindingKind::None, BindingKind::LbAssertion] {
            let (state, violations) = binding(|c| c.binding = kind);
            assert!(state.is_none(), "{kind:?} became a validated state");
            assert!(!violations.is_empty(), "{kind:?} was accepted");
        }
    }

    #[test]
    fn the_deprecated_identity_source_names_no_state() {
        let (state, violations) = binding(|c| c.identity_source = IdentityPolicy::CnLegacy);
        assert!(state.is_none());
        assert!(
            violations.iter().any(|v| v.contains("cn_legacy")),
            "{violations:?}"
        );
    }

    #[test]
    fn every_legal_crl_state_form_is_classified_and_accepted() {
        let cases: Vec<Form> = vec![
            (CrlRevocationState::None, |_| {}),
            (
                CrlRevocationState::Static {
                    paths: vec!["/crl.pem".to_string()],
                },
                |c: &mut Config| {
                    c.client_crl_paths = vec!["/crl.pem".to_string()];
                },
            ),
            (
                CrlRevocationState::Reloading {
                    paths: vec!["/crl.pem".to_string()],
                    cadence_secs: 300,
                },
                |c: &mut Config| {
                    c.client_crl_paths = vec!["/crl.pem".to_string()];
                    c.client_crl_reload_secs = Some(300);
                },
            ),
        ];
        for (expected, mutate) in cases {
            let (state, violations) = crl(mutate);
            assert_eq!(state, expected);
            assert!(
                violations.is_empty(),
                "{expected:?} refused: {violations:?}"
            );
        }
    }

    #[test]
    fn a_zero_cadence_is_an_unbounded_reloader_not_a_disabled_one() {
        let (_, violations) = crl(|c| {
            c.client_crl_paths = vec!["/crl.pem".to_string()];
            c.client_crl_reload_secs = Some(0);
        });
        assert!(
            violations.iter().any(|v| v.contains("spin")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_cadence_with_no_list_to_re_read_is_refused() {
        let (state, violations) = crl(|c| c.client_crl_reload_secs = Some(300));
        assert_eq!(state, CrlRevocationState::None);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("has no effect without --client-crl")),
            "{violations:?}"
        );
    }
}
