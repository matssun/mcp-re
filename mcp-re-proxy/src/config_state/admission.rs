// SPDX-License-Identifier: Apache-2.0
//! The `Admission` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.4.
//!
//! What a call carrying no admission evidence means here (MCPRE-493). Three states, and a
//! sub-state on the two that enforce:
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `Off` | — | authority kid/pubkey, redis url, degraded window | — |
//! | `Optional` | kid, pubkey, redis url | — | pubkey is a 32-byte base64url Ed25519 key |
//! | `Required` | kid, pubkey, redis url | — | same |
//! | …`+ Degraded` | degraded bound | — | `P > 0` |
//!
//! **`Off` is an explicit operator decision, not an absence.** That is what separates it
//! from [`ContinuationControl::Disabled`](crate::config_state::ContinuationControlState):
//! admission is a gate someone chose not to apply, so its dangling parameters are refused
//! rather than ignored — a `--admission-redis-url` beside `--admission off` reads to an
//! auditor as "admission is configured" while nothing is enforced.
//!
//! **The degraded window is checked whether or not a gate exists.** `P = 0` with
//! `allow_degraded` on is not a disabled window: the PEP serves an unreachable authority
//! for `P + max_clock_skew` seconds, so zero still admits a revoked workload for the skew
//! tolerance while claiming no window was configured.

use crate::cli::{AdmissionKind, Config};

/// Which admission state a configuration requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionState {
    /// Not enforced. Admission evidence, if present, decides nothing.
    Off,
    /// Enforced when present — for a rollout that has not reached every client.
    Optional,
    /// Enforced always: a call with no admission evidence is refused.
    Required,
}

impl AdmissionState {
    /// Whether a gate is applied at all.
    pub fn is_enforced(&self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Recognise the requested state. Total: `admission` names one directly.
fn classify(config: &Config) -> AdmissionState {
    match config.admission {
        AdmissionKind::Off => AdmissionState::Off,
        AdmissionKind::Optional => AdmissionState::Optional,
        AdmissionKind::Required => AdmissionState::Required,
    }
}

/// Classify the requested admission state and check its four columns.
///
/// The clause order inside is the order these checks have always run in, so the diagnostic
/// a multiply-misconfigured deployment meets first does not move.
pub fn classify_and_validate(config: &Config) -> (AdmissionState, Vec<String>) {
    let state = classify(config);
    let violations = crate::cli::unenforceable_admission_refusal(
        config.admission,
        config.admission_authority_kid.as_deref(),
        config.admission_authority_pubkey_b64url.as_deref(),
        config.admission_redis_url.as_deref(),
        config.admission_allow_degraded,
        config.admission_degraded_bound_secs,
    )
    .into_iter()
    .collect();
    (state, violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut Config));

    fn enforcing(config: &mut Config, kind: AdmissionKind) {
        config.admission = kind;
        config.admission_authority_kid = Some("authority-1".to_string());
        config.admission_authority_pubkey_b64url = Some(valid_pubkey());
        config.admission_redis_url = Some("redis://127.0.0.1:6379".to_string());
    }

    /// A real key, since the guard decodes it to a curve point rather than shape-checking:
    /// 32 arbitrary bytes are not necessarily a valid Ed25519 public key.
    fn valid_pubkey() -> String {
        mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32])
            .public_key()
            .to_b64url()
    }

    fn run(mutate: impl FnOnce(&mut Config)) -> (AdmissionState, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let (state, violations) = run(|c| c.admission = AdmissionKind::Off);
        assert_eq!(state, AdmissionState::Off);
        assert!(violations.is_empty(), "{violations:?}");
        assert!(!state.is_enforced());

        for (kind, expected) in [
            (AdmissionKind::Optional, AdmissionState::Optional),
            (AdmissionKind::Required, AdmissionState::Required),
        ] {
            let (state, violations) = run(|c| enforcing(c, kind));
            assert_eq!(state, expected);
            assert!(
                violations.is_empty(),
                "{expected:?} refused: {violations:?}"
            );
            assert!(state.is_enforced());
        }
    }

    #[test]
    fn the_degraded_sub_state_is_accepted_with_a_positive_window() {
        let (_, violations) = run(|c| {
            enforcing(c, AdmissionKind::Required);
            c.admission_allow_degraded = true;
            c.admission_degraded_bound_secs = 30;
        });
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn an_enforcing_state_names_every_value_it_cannot_verify_without() {
        let cases: Vec<Case> = vec![
            ("--admission-authority", |c| {
                enforcing(c, AdmissionKind::Required);
                c.admission_authority_pubkey_b64url = None;
            }),
            ("--admission-authority", |c| {
                enforcing(c, AdmissionKind::Required);
                c.admission_authority_kid = None;
            }),
            ("--admission-redis-url", |c| {
                enforcing(c, AdmissionKind::Required);
                c.admission_redis_url = None;
            }),
        ];
        for (flag, mutate) in cases {
            let (_, violations) = run(mutate);
            assert!(
                violations.iter().any(|v| v.contains(flag)),
                "a gate missing {flag} was accepted: {violations:?}"
            );
        }
    }

    #[test]
    fn an_authority_key_that_cannot_verify_anything_is_refused() {
        let (_, violations) = run(|c| {
            enforcing(c, AdmissionKind::Required);
            c.admission_authority_pubkey_b64url = Some("not-a-key".to_string());
        });
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--admission-authority-pubkey")),
            "{violations:?}"
        );
    }

    /// `Off` forbids its parameters, because it is a decision rather than an absence.
    #[test]
    fn a_parameter_dangling_on_the_off_state_is_refused() {
        for mutate in [
            (|c: &mut Config| c.admission_redis_url = Some("redis://127.0.0.1:6379".to_string()))
                as fn(&mut Config),
            |c: &mut Config| c.admission_authority_kid = Some("authority-1".to_string()),
        ] {
            let (state, violations) = run(|c| {
                c.admission = AdmissionKind::Off;
                mutate(c);
            });
            assert_eq!(state, AdmissionState::Off);
            assert!(
                violations.iter().any(|v| v.contains("--admission is")),
                "a dangling admission parameter was accepted: {violations:?}"
            );
        }
    }

    /// The guard that is deliberately NOT nested under "a gate exists": a degraded window
    /// of zero still admits a revoked workload for the clock-skew tolerance.
    #[test]
    fn a_degraded_window_of_zero_is_refused_with_or_without_a_gate() {
        for kind in [AdmissionKind::Off, AdmissionKind::Required] {
            let (_, violations) = run(|c| {
                if kind == AdmissionKind::Required {
                    enforcing(c, kind);
                }
                c.admission_allow_degraded = true;
                c.admission_degraded_bound_secs = 0;
            });
            assert!(
                violations
                    .iter()
                    .any(|v| v.contains("--admission-degraded-bound-secs")),
                "{kind:?}: {violations:?}"
            );
        }
    }
}
