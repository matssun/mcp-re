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
//!
//! # Two open gaps in the `Off` row above
//!
//! The table states the intended model; the guard is narrower, in two places, and neither
//! is closed by this module's witnesses.
//!
//! - The dangling-parameter clause tests the kid and the redis url only, so a
//!   `--admission-authority-pubkey` beside `--admission off` is ACCEPTED.
//! - A degraded window with `P > 0` beside `--admission off` is also accepted; only
//!   `P = 0` is refused there. And under `Off` the reason given for that refusal does not
//!   hold: no gate is built, so nothing serves an unreachable authority for any window.
//!   The clause is defensible under `Off` as a dangling-parameter refusal — a different
//!   argument from the one it states.
//!
//! Both are ruled real gaps, to be closed as a behaviour-changing slice. They are named
//! here rather than fixed silently, because a witness slice that also moved the legality
//! boundary would leave neither change reviewable.

use crate::cli::{AdmissionAuthority, AdmissionKind, Config};
use mcp_re_core::VerificationKey;

/// Which admission state a configuration requests.
///
/// The two enforcing states carry the authority and the record locator they cannot be
/// inhabited without. Nothing downstream re-reads them from the request, and nothing
/// downstream decodes the key a second time — see [`crate::cli::AdmissionAuthority`].
#[derive(Debug, Clone)]
pub enum AdmissionState {
    /// Not enforced. Admission evidence, if present, decides nothing.
    Off,
    /// Enforced when present — for a rollout that has not reached every client.
    Optional {
        /// The key id an assertion must present for its issuer to be recognised.
        authority_kid: String,
        /// The decoded key that verifies it.
        authority: VerificationKey,
        /// The shared authoritative record currency is compared against.
        redis_url: String,
    },
    /// Enforced always: a call with no admission evidence is refused.
    Required {
        /// The key id an assertion must present for its issuer to be recognised.
        authority_kid: String,
        /// The decoded key that verifies it.
        authority: VerificationKey,
        /// The shared authoritative record currency is compared against.
        redis_url: String,
    },
}

/// A key's identity is its encoding: [`VerificationKey`] is a curve point with no equality
/// of its own, and two admission states are the same state when they name the same issuer.
impl PartialEq for AdmissionState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Off, Self::Off) => true,
            (
                Self::Optional {
                    authority_kid: a_kid,
                    authority: a_key,
                    redis_url: a_url,
                },
                Self::Optional {
                    authority_kid: b_kid,
                    authority: b_key,
                    redis_url: b_url,
                },
            )
            | (
                Self::Required {
                    authority_kid: a_kid,
                    authority: a_key,
                    redis_url: a_url,
                },
                Self::Required {
                    authority_kid: b_kid,
                    authority: b_key,
                    redis_url: b_url,
                },
            ) => a_kid == b_kid && a_url == b_url && a_key.to_bytes() == b_key.to_bytes(),
            _ => false,
        }
    }
}

impl Eq for AdmissionState {}

impl AdmissionState {
    /// Whether a gate is applied at all.
    pub fn is_enforced(&self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Classify the requested admission state and check its four columns.
///
/// The clause order inside [`crate::cli::validated_admission_authority`] is the order these
/// checks have always run in, so the diagnostic a multiply-misconfigured deployment meets
/// first does not move. No state is recognised when it refuses: an enforcing state cannot
/// be built without the witnesses that make it inhabitable.
pub fn classify_and_validate(config: &Config) -> (Option<AdmissionState>, Vec<String>) {
    let authority = match crate::cli::validated_admission_authority(
        config.admission,
        config.admission_authority_kid.as_deref(),
        config.admission_authority_pubkey_b64url.as_deref(),
        config.admission_redis_url.as_deref(),
        config.admission_allow_degraded,
        config.admission_degraded_bound_secs,
    ) {
        Ok(authority) => authority,
        Err(refusal) => return (None, vec![refusal]),
    };
    let Some(AdmissionAuthority {
        kid,
        key,
        redis_url,
    }) = authority
    else {
        return (Some(AdmissionState::Off), Vec::new());
    };
    let state = match config.admission {
        // `validated_admission_authority` yields an authority only for the enforcing
        // kinds, so this arm is unreachable rather than a second reading of the selector.
        AdmissionKind::Off => return (Some(AdmissionState::Off), Vec::new()),
        AdmissionKind::Optional => AdmissionState::Optional {
            authority_kid: kid,
            authority: key,
            redis_url,
        },
        AdmissionKind::Required => AdmissionState::Required {
            authority_kid: kid,
            authority: key,
            redis_url,
        },
    };
    (Some(state), Vec::new())
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

    fn run(mutate: impl FnOnce(&mut Config)) -> (Option<AdmissionState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let (state, violations) = run(|c| c.admission = AdmissionKind::Off);
        assert_eq!(state, Some(AdmissionState::Off));
        assert!(violations.is_empty(), "{violations:?}");
        assert!(!state.expect("recognised").is_enforced());

        for kind in [AdmissionKind::Optional, AdmissionKind::Required] {
            let (state, violations) = run(|c| enforcing(c, kind));
            assert!(violations.is_empty(), "{kind:?} refused: {violations:?}");
            let state = state.expect("recognised");
            assert_eq!(matches!(state, AdmissionState::Required { .. }), {
                kind == AdmissionKind::Required
            });
            assert!(state.is_enforced());
        }
    }

    /// The point of the slice: an enforcing state carries the three facts it cannot be
    /// inhabited without, and carries the key DECODED. Nothing downstream reads the
    /// request for them, and nothing downstream repeats the decode.
    #[test]
    fn an_enforcing_state_carries_the_authority_that_made_it_inhabitable() {
        let (state, _) = run(|c| enforcing(c, AdmissionKind::Required));
        let Some(AdmissionState::Required {
            authority_kid,
            authority,
            redis_url,
        }) = state
        else {
            panic!("a complete admission configuration selects the enforcing state");
        };
        assert_eq!(authority_kid, "authority-1");
        assert_eq!(redis_url, "redis://127.0.0.1:6379");
        assert_eq!(authority.to_b64url(), valid_pubkey());
    }

    /// `Off` needs no authority, so it holds none — the absence is structural rather than
    /// an empty string standing in for one.
    #[test]
    fn the_off_state_carries_nothing_because_it_verifies_nothing() {
        assert_eq!(
            run(|c| c.admission = AdmissionKind::Off).0,
            Some(AdmissionState::Off)
        );
    }

    /// A refused configuration yields NO state. An enforcing state that could be built
    /// beside a refusal would be a gate assembled from parts validation rejected.
    #[test]
    fn a_refused_configuration_recognises_no_state() {
        let (state, violations) = run(|c| {
            enforcing(c, AdmissionKind::Required);
            c.admission_redis_url = None;
        });
        assert!(state.is_none(), "a state was built over a refusal");
        assert!(!violations.is_empty());
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
            assert!(state.is_none(), "a refused configuration named a state");
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
