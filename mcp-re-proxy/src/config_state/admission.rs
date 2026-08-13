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
//! | …`+ Degraded` | degraded bound | — | `P > 0`, and `P = 0` without degraded mode |
//!
//! The degraded columns, completely — two legal cells per enforcing state and none
//! anywhere else:
//!
//! | Admission | `allow_degraded` | `P` | |
//! |---|---|---|---|
//! | `Off` | false | `0` | legal — asked for nothing, configured nothing |
//! | `Off` | anything else | | dangling |
//! | enforcing | false | `0` | legal — fails closed on an unreachable authority |
//! | enforcing | false | `≠ 0` | refused: the bound is unreachable |
//! | enforcing | true | `≤ 0` | refused: the window is wider than it claims |
//! | enforcing | true | `> 0` | legal — bounded degradation |
//!
//! **`Off` is an explicit operator decision, not an absence.** That is what separates it
//! from [`ContinuationControl::Disabled`](crate::config_state::ContinuationControlState):
//! admission is a gate someone chose not to apply, so its dangling parameters are refused
//! rather than ignored — a `--admission-redis-url` beside `--admission off` reads to an
//! auditor as "admission is configured" while nothing is enforced.
//!
//! **`Off` forbids all five of its parameters**, the authority pubkey and the degraded
//! window included. Two of the five used to slip through: the dangling clause named only
//! the kid and the redis url, and the degraded window was caught only at `P = 0`, so a
//! POSITIVE window beside `--admission off` was accepted.
//!
//! **A degraded window is refused for a different reason on each side of that line.** With
//! a gate, `P = 0` and `allow_degraded` on is not a disabled window: the PEP serves an
//! unreachable authority for `P + max_clock_skew` seconds, so zero still admits a revoked
//! workload for the skew tolerance while claiming no window was configured. With no gate,
//! that argument is simply false — nothing is built, and no window of any width is opened.
//! The setting is refused there because it dangles, which is the true reason, and the
//! width clause now sits inside the enforcing branch where its own reasoning holds.

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

/// Two admission states are the same state when they name the same issuer.
///
/// [`VerificationKey`] deliberately implements neither `PartialEq` nor `Eq`, and this does
/// not widen it from the configuration layer. `to_bytes` is the canonical 32-byte public
/// key — one encoding per curve point, no equivalent spellings — so it is what identity
/// means here.
///
/// This is CONFIGURATION-STATE equality: it exists for `DeploymentConfigState`'s derive and
/// for the unit tests below. It decides nothing about a request. Whether a presented kid is
/// the deployment's authority, and whether a signature verifies under it, stay with the
/// resolver and the verifying key themselves.
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

    /// `Off` forbids every AUTHORITY parameter, the pubkey included. The pubkey used to be
    /// omitted from this clause while the module's own table said it was forbidden.
    #[test]
    fn every_authority_parameter_is_refused_beside_an_off_gate() {
        for mutate in [
            (|c: &mut Config| c.admission_authority_kid = Some("authority-1".to_string()))
                as fn(&mut Config),
            |c: &mut Config| c.admission_authority_pubkey_b64url = Some(valid_pubkey()),
            |c: &mut Config| c.admission_redis_url = Some("redis://127.0.0.1:6379".to_string()),
        ] {
            let (state, violations) = run(|c| {
                c.admission = AdmissionKind::Off;
                mutate(c);
            });
            assert!(state.is_none(), "a refused configuration named a state");
            assert!(
                violations.iter().any(|v| v.contains("--admission is off")),
                "a dangling admission parameter was accepted: {violations:?}"
            );
        }
    }

    /// What a degraded cell is expected to be, and — when refused — WHICH mistake it is.
    ///
    /// Three refusals that a single "is it rejected" assertion would conflate. They are
    /// different operator errors: a setting that applies to nothing, a setting that can
    /// never be reached, and a window that is narrower than it claims.
    #[derive(Debug, Clone, Copy)]
    enum Cell {
        Legal,
        /// No gate exists, so no admission-specific parameter means anything.
        DanglingUnderOff,
        /// A gate exists, but both readers of the bound return before consulting it.
        UnreachableBound,
        /// A gate exists and will open a window, but not the width that was asked for.
        InvalidWidth,
    }

    impl Cell {
        /// The phrase that identifies this refusal and no other.
        fn marker(self) -> &'static str {
            match self {
                Cell::Legal => unreachable!("a legal cell has no refusal to identify"),
                Cell::DanglingUnderOff => "--admission is off",
                Cell::UnreachableBound => "--admission-allow-degraded is false",
                Cell::InvalidWidth => "P + --max-clock-skew",
            }
        }
    }

    /// The complete degraded truth table, asserted cell by cell.
    ///
    /// Eight conceptual cells plus negative-bound representatives on both sides. Two are
    /// legal, and they are the two the sub-posture will encode: fail-closed, and bounded
    /// degradation over a positive window. Everything else is refused, and the table pins
    /// WHICH refusal, so that a future clause reordering cannot quietly answer one mistake
    /// with another mistake's diagnostic.
    #[test]
    fn the_degraded_truth_table_is_complete_and_each_refusal_names_its_own_mistake() {
        let cases: &[(bool, bool, i64, Cell)] = &[
            // gate off: nothing admission-specific may be configured
            (false, false, 0, Cell::Legal),
            (false, false, 30, Cell::DanglingUnderOff),
            (false, false, -30, Cell::DanglingUnderOff),
            (false, true, 0, Cell::DanglingUnderOff),
            (false, true, 30, Cell::DanglingUnderOff),
            // gate on
            (true, false, 0, Cell::Legal),
            (true, false, 30, Cell::UnreachableBound),
            (true, false, -30, Cell::UnreachableBound),
            (true, true, 0, Cell::InvalidWidth),
            (true, true, -30, Cell::InvalidWidth),
            (true, true, 30, Cell::Legal),
        ];
        for &(gate, allow, bound, expected) in cases {
            let (state, violations) = run(|c| {
                if gate {
                    enforcing(c, AdmissionKind::Required);
                } else {
                    c.admission = AdmissionKind::Off;
                }
                c.admission_allow_degraded = allow;
                c.admission_degraded_bound_secs = bound;
            });
            let at = format!("gate={gate} allow={allow} P={bound}");
            let Cell::Legal = expected else {
                assert!(
                    state.is_none(),
                    "{at}: a refused configuration named a state"
                );
                let marker = expected.marker();
                assert!(
                    violations.iter().any(|v| v.contains(marker)),
                    "{at}: expected {expected:?} ({marker}), got {violations:?}"
                );
                continue;
            };
            assert!(violations.is_empty(), "{at}: refused — {violations:?}");
            assert!(state.is_some(), "{at}: accepted but named no state");
        }
    }

    /// The `Off` half of the table again, from the other direction: the width argument is
    /// never the reason given when no gate exists, because no window is opened at all.
    #[test]
    fn no_refusal_under_an_off_gate_argues_about_window_width() {
        for (allow, bound) in [(true, 30), (true, 0), (false, 30)] {
            let (_, violations) = run(|c| {
                c.admission = AdmissionKind::Off;
                c.admission_allow_degraded = allow;
                c.admission_degraded_bound_secs = bound;
            });
            for refusal in &violations {
                assert!(
                    !refusal.contains("P + --max-clock-skew"),
                    "allow={allow} P={bound}: the width argument must not be given \
                     with no gate: {refusal}"
                );
            }
        }
    }
}
