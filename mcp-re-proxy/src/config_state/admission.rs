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

use crate::deployment_request::{AdmissionKind, DeploymentRequest};
use mcp_re_core::VerificationKey;
use std::num::NonZeroU64;

/// What an enforcing deployment does when the admission authority is unreachable.
///
/// A subordinate choice of an enabled gate, not a machine of its own. Degraded availability
/// has no meaning without an authority that can be unreachable, so an independent machine
/// would need a cross-machine rule forbidding all of its meaningful states under `Off` —
/// where the simpler and truer ontology is that `Off` has no such choice to make.
///
/// The two variants are the two legal cells of the table above, which is why the bound is a
/// [`NonZeroU64`]: layer A has already refused every non-positive window, so nothing
/// downstream can be handed one. The type records the rule; it did not create it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionAvailability {
    /// An unreachable authority refuses the call. No window.
    FailClosed,
    /// An unreachable authority is tolerated for a bounded window.
    ///
    /// `bound_secs` is P, a FLOOR on that window rather than the whole of it: the PEP
    /// serves for `P + max_clock_skew` seconds.
    BoundedDegraded {
        /// P, in seconds. Narrowed from a positive `i64`, so it is representable as one
        /// again by construction.
        bound_secs: NonZeroU64,
    },
}

/// Which admission state a configuration requests.
///
/// The representation is private to this module. [`classify_and_validate`] is the only
/// producer, so possessing an enforcing state IS the statement that its authority was
/// validated and its key decoded — see [`crate::cli::AdmissionAuthority`]. Nothing
/// downstream re-reads the witnesses from the request, and nothing decodes the key a
/// second time.
///
/// Consumers read an enforcing deployment through [`enforced`](Self::enforced), which
/// hands back the posture and the authority **as one value**. While the variants were
/// public, a consumer destructuring them could take the enforcement level from one arm and
/// the authority from another — a `Required` gate verifying assertions under whatever key
/// was to hand.
#[derive(Debug, Clone)]
pub struct AdmissionState {
    kind: AdmissionKindState,
}

/// The three states, as the owner's own representation.
///
/// Private to this module: this state's consumers live in this crate, so `pub` variants
/// would be constructible by all of them.
#[derive(Debug, Clone)]
enum AdmissionKindState {
    /// Not enforced. Admission evidence, if present, decides nothing.
    Off,
    /// Enforced when present — for a rollout that has not reached every client.
    Optional {
        authority_kid: String,
        authority: VerificationKey,
        redis_url: String,
        availability: AdmissionAvailability,
    },
    /// Enforced always: a call with no admission evidence is refused.
    Required {
        authority_kid: String,
        authority: VerificationKey,
        redis_url: String,
        availability: AdmissionAvailability,
    },
}

/// How strictly a gate is applied, for a deployment that applies one.
///
/// Separate from the state because `Off` is not a posture the gate can be built at: a
/// consumer that has one of these is already past the question of whether to build a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionPosture {
    /// Evidence is checked when presented; its absence is not a refusal.
    Optional,
    /// A call with no admission evidence is refused.
    Required,
}

/// An enforcing deployment's gate inputs, as one indivisible value.
///
/// Borrowed from the state, so it is a way to READ an admission posture and not a way to
/// assemble one. The posture and the authority it applies are handed over together because
/// they were validated together; nothing holding this can re-pair them.
#[derive(Debug, Clone, Copy)]
pub struct EnforcedAdmission<'a> {
    posture: AdmissionPosture,
    authority_kid: &'a str,
    authority: &'a VerificationKey,
    redis_url: &'a str,
    availability: AdmissionAvailability,
}

impl<'a> EnforcedAdmission<'a> {
    /// How strictly the gate is applied.
    pub fn posture(&self) -> AdmissionPosture {
        self.posture
    }

    /// The key id an assertion must present for its issuer to be recognised.
    pub fn authority_kid(&self) -> &'a str {
        self.authority_kid
    }

    /// The decoded key that verifies it.
    pub fn authority(&self) -> &'a VerificationKey {
        self.authority
    }

    /// The shared authoritative record currency is compared against.
    pub fn redis_url(&self) -> &'a str {
        self.redis_url
    }

    /// What this deployment does when that record cannot be reached.
    pub fn availability(&self) -> AdmissionAvailability {
        self.availability
    }
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
        match (&self.kind, &other.kind) {
            (AdmissionKindState::Off, AdmissionKindState::Off) => true,
            (
                AdmissionKindState::Optional {
                    authority_kid: a_kid,
                    authority: a_key,
                    redis_url: a_url,
                    availability: a_av,
                },
                AdmissionKindState::Optional {
                    authority_kid: b_kid,
                    authority: b_key,
                    redis_url: b_url,
                    availability: b_av,
                },
            )
            | (
                AdmissionKindState::Required {
                    authority_kid: a_kid,
                    authority: a_key,
                    redis_url: a_url,
                    availability: a_av,
                },
                AdmissionKindState::Required {
                    authority_kid: b_kid,
                    authority: b_key,
                    redis_url: b_url,
                    availability: b_av,
                },
            ) => {
                a_kid == b_kid
                    && a_url == b_url
                    && a_av == b_av
                    && a_key.to_bytes() == b_key.to_bytes()
            }
            _ => false,
        }
    }
}

impl Eq for AdmissionState {}

impl AdmissionState {
    /// Whether a gate is applied at all.
    pub fn is_enforced(&self) -> bool {
        !matches!(self.kind, AdmissionKindState::Off)
    }

    /// The gate inputs of an enforcing deployment, or `None` when no gate is applied.
    ///
    /// The projection replaces a match on the representation performed where the gate is
    /// established. Which posture a deployment enforces, and under which authority, is
    /// this machine's semantics; both are handed over in one value so no consumer can pair
    /// a posture with an authority the validator did not pair it with.
    pub fn enforced(&self) -> Option<EnforcedAdmission<'_>> {
        let (posture, authority_kid, authority, redis_url, availability) = match &self.kind {
            AdmissionKindState::Off => return None,
            AdmissionKindState::Optional {
                authority_kid,
                authority,
                redis_url,
                availability,
            } => (
                AdmissionPosture::Optional,
                authority_kid,
                authority,
                redis_url,
                availability,
            ),
            AdmissionKindState::Required {
                authority_kid,
                authority,
                redis_url,
                availability,
            } => (
                AdmissionPosture::Required,
                authority_kid,
                authority,
                redis_url,
                availability,
            ),
        };
        Some(EnforcedAdmission {
            posture,
            authority_kid,
            authority,
            redis_url,
            availability: *availability,
        })
    }
}

/// Classify the requested admission state and check its four columns.
///
/// The clause order inside [`crate::cli::validated_admission_authority`] is the order these
/// checks have always run in, so the diagnostic a multiply-misconfigured deployment meets
/// first does not move. No state is recognised when it refuses: an enforcing state cannot
/// be built without the witnesses that make it inhabitable.
pub fn classify_and_validate(config: &DeploymentRequest) -> (Option<AdmissionState>, Vec<String>) {
    let authority = match validated_admission_authority(
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
        availability,
    }) = authority
    else {
        return (Some(AdmissionState { kind: AdmissionKindState::Off }), Vec::new());
    };
    let state = match config.admission {
        // `validated_admission_authority` yields an authority only for the enforcing
        // kinds, so this arm is unreachable rather than a second reading of the selector.
        AdmissionKind::Off => {
            return (
                Some(AdmissionState {
                    kind: AdmissionKindState::Off,
                }),
                Vec::new(),
            )
        }
        AdmissionKind::Optional => AdmissionState {
            kind: AdmissionKindState::Optional {
                authority_kid: kid,
                authority: key,
                redis_url,
                availability,
            },
        },
        AdmissionKind::Required => AdmissionState {
            kind: AdmissionKindState::Required {
                authority_kid: kid,
                authority: key,
                redis_url,
                availability,
            },
        },
    };
    (Some(state), Vec::new())
}

/// Both halves of the authority are required, and the diagnostic must not tell an operator
/// which half is missing in a way that implies the other alone would do.
const MISSING_ADMISSION_AUTHORITY: &str =
    "--admission optional|required requires --admission-authority-kid and \
     --admission-authority-pubkey (an assertion is only evidence if the issuer is one this \
     deployment trusts)";

/// Every authority parameter is refused beside `--admission off`, the pubkey included: the
/// three are one setting, and half of a dangling authority is no less misleading than all
/// of it.
const DANGLING_ADMISSION_AUTHORITY: &str =
    "--admission-authority-kid / --admission-authority-pubkey / --admission-redis-url are \
     set but --admission is off; enable it or remove them";

/// A window configured on an enforcing deployment that never opens it. Refused for
/// unreachability rather than for width: the number is fine, nothing will ever read it.
const INERT_DEGRADED_BOUND: &str =
    "--admission-degraded-bound-secs is set but --admission-allow-degraded is false; the \
     bound is read only when degraded mode is on, so this window can never open. Pass \
     --admission-allow-degraded true to use it, or remove it to fail closed on an \
     unreachable authority";

/// The degraded window is refused beside `--admission off` for the same reason as the
/// authority triple, and NOT because a window would be too wide: no gate is built, so no
/// window is opened at all.
const DANGLING_DEGRADED_WINDOW: &str =
    "--admission-allow-degraded / --admission-degraded-bound-secs are set but --admission \
     is off; a degraded window tolerates an UNREACHABLE ADMISSION AUTHORITY, and with the \
     gate off there is no authority to be unreachable and no window to widen. Enable \
     --admission or remove them";

/// What an enforcing admission posture cannot exist without, established once.
///
/// The key is the DECODED authority rather than its encoding: the check that it decodes is
/// the same operation as decoding it, so a boundary that verifies and then discards the
/// result forces every later stage to repeat the work and to carry an unreachable failure
/// arm for a proposition already proved.
pub(crate) struct AdmissionAuthority {
    /// The key id an assertion must present.
    pub(crate) kid: String,
    /// The key that verifies it.
    pub(crate) key: VerificationKey,
    /// The shared authoritative record currency is compared against.
    pub(crate) redis_url: String,
    /// What this deployment does when that record cannot be reached. Derived here because
    /// the two flags behind it are legal only in the combinations this function accepts.
    pub(crate) availability: AdmissionAvailability,
}

/// The one decision about whether an admission-currency configuration can be enforced.
///
/// `Err(diagnostic)` means it cannot. `Ok(None)` is `--admission off`, the one state that
/// needs no authority; `Ok(Some(..))` carries what the enforcing states are inhabited by.
/// Every clause here is a property of the parsed configuration alone, so this is the
/// boundary that owns them (ADR-MCPRE-056 §AA): `DeploymentRequest` has public fields, and until this
/// moved, all four lived in `parse_args` where a programmatically built configuration
/// walked past them.
///
/// # Why a zero degraded window is refused
///
/// Not because "zero is not a policy" — that reads as though the deployment merely gets
/// nothing. `check_admission` compares the assertion's age against
/// `degraded_propagation_bound + max_clock_skew`, so P is a FLOOR on the degraded window,
/// never the whole of it. With degraded mode on and P zero, an unreachable authority still
/// serves any assertion younger than the skew tolerance — a window in which a REVOKED
/// workload keeps being admitted, on a deployment that asked for no window at all. Pinned
/// by `admission::a_zero_p_still_leaves_a_degraded_window_the_width_of_the_clock_skew`.
///
/// A NEGATIVE bound does fail closed on every call, but it is refused by the same clause:
/// a policy nobody can satisfy is not a safer spelling of "off".
///
/// That argument is about a gate that EXISTS, so the clause sits inside the enforcing
/// branch. It used to sit outside it, refusing `P = 0` under `--admission off` too, where
/// the reasoning does not hold: nothing is built, so no assertion is served for any window.
/// The setting is still refused there — by the dangling-parameter clause, which is the
/// true reason — and a positive window under `off`, which the old placement accepted, is
/// refused with it.
pub(crate) fn validated_admission_authority(
    admission: AdmissionKind,
    authority_kid: Option<&str>,
    authority_pubkey_b64url: Option<&str>,
    redis_url: Option<&str>,
    allow_degraded: bool,
    degraded_bound_secs: i64,
) -> Result<Option<AdmissionAuthority>, String> {
    // Clause order within the enforcing branch is the order these checks always ran in, so
    // the diagnostic a CLI user meets first does not change (§K1).
    let authority = if admission == AdmissionKind::Off {
        // `Off` is a decision about a gate, so EVERY admission parameter dangling beside
        // it is refused. Each one reads to an auditor as "admission is configured" while
        // nothing is enforced, and none of them has an operational meaning without a gate.
        if authority_kid.is_some() || authority_pubkey_b64url.is_some() || redis_url.is_some() {
            return Err(DANGLING_ADMISSION_AUTHORITY.to_string());
        }
        // Including the degraded window. Tolerating an unreachable authority is meaningless
        // when there is no authority to be unreachable: `Off` builds no gate, so no window
        // of any width is ever opened. A non-zero bound is refused whatever its sign — a
        // negative one is no more meaningful here than a positive one.
        if allow_degraded || degraded_bound_secs != 0 {
            return Err(DANGLING_DEGRADED_WINDOW.to_string());
        }
        None
    } else {
        // Enforcing admission needs BOTH an authority to verify assertions against and a
        // source to check currency against. With neither, the gate would verify nothing
        // while looking enabled — the most dangerous of the three states, because the
        // deployment believes it has admission control.
        let Some(pubkey) = authority_pubkey_b64url else {
            return Err(MISSING_ADMISSION_AUTHORITY.to_string());
        };
        let Some(kid) = authority_kid else {
            return Err(MISSING_ADMISSION_AUTHORITY.to_string());
        };
        // Decoded HERE rather than where the verifier is built: an unusable authority key
        // is a property of the configuration, and catching it at materialization left the
        // composition root as the only thing between a programmatic config and a gate with
        // no usable issuer. The key travels onward from here, so this is the only decode.
        let Ok(key) = VerificationKey::from_b64url(pubkey) else {
            return Err(
                "--admission-authority-pubkey is not a valid base64url-no-pad 32-byte \
                 Ed25519 public key"
                    .to_string(),
            );
        };
        let Some(redis_url) = redis_url else {
            return Err(
                "--admission optional|required requires --admission-redis-url (the shared \
                 authoritative record; without it every call fails closed on an unreachable \
                 authority)"
                    .to_string(),
            );
        };
        // The two flags become the posture they describe, and the two legal combinations
        // are the only ones that produce one.
        let availability = if !allow_degraded {
            // Both readers of the bound sit behind `if !allow_degraded_mode` early returns
            // — `check_admission` and `degraded_window_exhausted` — so with degraded mode
            // off the value is not merely unused, it is unreachable. An operator who set a
            // window and left the mode off has configured a tolerance this deployment will
            // never apply, and is one restart away from believing it did.
            if degraded_bound_secs != 0 {
                return Err(INERT_DEGRADED_BOUND.to_string());
            }
            AdmissionAvailability::FailClosed
        } else {
            // Nested under the enforcing branch, where the rationale below is TRUE: a gate
            // exists, and P is the width of the window it opens on an unreachable
            // authority. Every value the narrowing rejects — negative, and zero — is a
            // value this clause refuses, so the conversion decides nothing the rule has
            // not already decided.
            let Some(bound_secs) = u64::try_from(degraded_bound_secs)
                .ok()
                .and_then(NonZeroU64::new)
            else {
                return Err("--admission-allow-degraded true requires a positive \
                     --admission-degraded-bound-secs (P). P is a FLOOR on the degraded \
                     window, not the whole of it: the PEP serves an unreachable authority \
                     for P + --max-clock-skew seconds, so P=0 still admits a revoked \
                     workload for the skew tolerance while claiming no window was configured"
                    .to_string());
            };
            AdmissionAvailability::BoundedDegraded { bound_secs }
        };
        Some(AdmissionAuthority {
            kid: kid.to_string(),
            key,
            redis_url: redis_url.to_string(),
            availability,
        })
    };
    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut DeploymentRequest));

    fn enforcing(config: &mut DeploymentRequest, kind: AdmissionKind) {
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

    fn run(mutate: impl FnOnce(&mut DeploymentRequest)) -> (Option<AdmissionState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let (state, violations) = run(|c| c.admission = AdmissionKind::Off);
        assert!(violations.is_empty(), "{violations:?}");
        let state = state.expect("recognised");
        assert!(!state.is_enforced());
        assert!(state.enforced().is_none());

        for kind in [AdmissionKind::Optional, AdmissionKind::Required] {
            let (state, violations) = run(|c| enforcing(c, kind));
            assert!(violations.is_empty(), "{kind:?} refused: {violations:?}");
            let state = state.expect("recognised");
            assert_eq!(
                state.enforced().map(|gate| gate.posture()),
                Some(if kind == AdmissionKind::Required {
                    AdmissionPosture::Required
                } else {
                    AdmissionPosture::Optional
                })
            );
            assert!(state.is_enforced());
        }
    }

    /// An enforcing state carries every fact it cannot be inhabited without, and carries
    /// the key DECODED. Nothing downstream reads the request for them, and nothing
    /// downstream repeats the decode.
    #[test]
    fn an_enforcing_state_carries_the_authority_that_made_it_inhabitable() {
        let (state, _) = run(|c| enforcing(c, AdmissionKind::Required));
        let state = state.expect("a complete admission configuration names a state");
        let gate = state
            .enforced()
            .expect("a complete admission configuration selects the enforcing state");
        assert_eq!(gate.posture(), AdmissionPosture::Required);
        assert_eq!(gate.authority_kid(), "authority-1");
        assert_eq!(gate.redis_url(), "redis://127.0.0.1:6379");
        assert_eq!(gate.authority().to_b64url(), valid_pubkey());
        assert_eq!(gate.availability(), AdmissionAvailability::FailClosed);
    }

    /// The two flags are CLASSIFIED, not carried. Layer A owns the distinction between
    /// failing closed and tolerating a bounded window, so no consumer recombines a bool
    /// and an integer into a posture — and the illegal combinations have no encoding.
    #[test]
    fn the_availability_posture_is_classified_from_the_two_flags() {
        let (state, _) = run(|c| {
            enforcing(c, AdmissionKind::Required);
            c.admission_allow_degraded = true;
            c.admission_degraded_bound_secs = 90;
        });
        let state = state.expect("a complete admission configuration names a state");
        let gate = state
            .enforced()
            .expect("a complete admission configuration selects the enforcing state");
        assert_eq!(
            gate.availability(),
            AdmissionAvailability::BoundedDegraded {
                bound_secs: NonZeroU64::new(90).expect("90 is not zero"),
            }
        );
    }

    /// `Off` needs no authority, so it holds none — the absence is structural rather than
    /// an empty string standing in for one.
    #[test]
    fn the_off_state_carries_nothing_because_it_verifies_nothing() {
        let state = run(|c| c.admission = AdmissionKind::Off)
            .0
            .expect("off is a state");
        assert!(state.enforced().is_none());
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
            (|c: &mut DeploymentRequest| {
                c.admission_authority_kid = Some("authority-1".to_string())
            }) as fn(&mut DeploymentRequest),
            |c: &mut DeploymentRequest| c.admission_authority_pubkey_b64url = Some(valid_pubkey()),
            |c: &mut DeploymentRequest| {
                c.admission_redis_url = Some("redis://127.0.0.1:6379".to_string())
            },
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
        /// Accepted, and it classifies to exactly this posture. `None` for `Off`, which
        /// has no availability choice to make.
        Legal(Option<AdmissionAvailability>),
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
                Cell::Legal(_) => unreachable!("a legal cell has no refusal to identify"),
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
        let bounded = |secs: u64| {
            Some(AdmissionAvailability::BoundedDegraded {
                bound_secs: NonZeroU64::new(secs).expect("a positive test bound"),
            })
        };
        let fail_closed = Some(AdmissionAvailability::FailClosed);
        let cases: &[(bool, bool, i64, Cell)] = &[
            // gate off: nothing admission-specific may be configured
            (false, false, 0, Cell::Legal(None)),
            (false, false, 30, Cell::DanglingUnderOff),
            (false, false, -30, Cell::DanglingUnderOff),
            (false, true, 0, Cell::DanglingUnderOff),
            (false, true, 30, Cell::DanglingUnderOff),
            // gate on
            (true, false, 0, Cell::Legal(fail_closed)),
            (true, false, 30, Cell::UnreachableBound),
            (true, false, -30, Cell::UnreachableBound),
            (true, true, 0, Cell::InvalidWidth),
            (true, true, -30, Cell::InvalidWidth),
            (true, true, 30, Cell::Legal(bounded(30))),
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
            let Cell::Legal(posture) = expected else {
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
            let classified = match state {
                Some(state) => state.enforced().map(|gate| gate.availability()),
                None => panic!("{at}: accepted but named no state"),
            };
            assert_eq!(classified, posture, "{at}: classified to the wrong posture");
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
