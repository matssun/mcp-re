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
//! **`Off` has no parameters to forbid.** It used to forbid all five, and two of them
//! slipped through for a while. The gate's inputs are members of
//! [`AdmissionRequest`](crate::deployment_request::AdmissionRequest)'s enforcing forms now,
//! so an unenforced request has nowhere to carry them and the dangling clauses have no
//! configuration to examine (ADR-MCPRE-067 §7). `cli::admission_flags` answers the argv
//! forms, which are the only ones that survive.
//!
//! The degraded table went the same way: its two refused cells — a bound where nothing
//! reads it, and a window of zero width — are unrepresentable, because the availability is
//! one tagged value and the bound is a `NonZeroU64` carried by the arm that opens a window.

use crate::deployment_request::{
    AdmissionAvailabilityRequest, AdmissionRequest, DeploymentRequest,
};
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
    let authority = match validated_admission_authority(&config.admission) {
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
        return (
            Some(AdmissionState {
                kind: AdmissionKindState::Off,
            }),
            Vec::new(),
        );
    };
    let state = match config.admission {
        // `validated_admission_authority` yields an authority only for the enforcing forms,
        // so this arm is unreachable rather than a second reading of the selector.
        AdmissionRequest::NotEnforced => {
            return (
                Some(AdmissionState {
                    kind: AdmissionKindState::Off,
                }),
                Vec::new(),
            )
        }
        AdmissionRequest::Optional(_) => AdmissionState {
            kind: AdmissionKindState::Optional {
                authority_kid: kid,
                authority: key,
                redis_url,
                availability,
            },
        },
        AdmissionRequest::Required(_) => AdmissionState {
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
/// That argument is about a gate that EXISTS, which is why the window is a `NonZeroU64`
/// carried by the arm that opens one: every value the rule refused is a value the type no
/// longer admits, and the clause that stated it lives in `cli::admission_flags`, where a
/// flat command line can still say it.
pub(crate) fn validated_admission_authority(
    admission: &AdmissionRequest,
) -> Result<Option<AdmissionAuthority>, String> {
    // Clause order is the order these checks always ran in, so the diagnostic a
    // multiply-misconfigured deployment meets first does not change (§K1).
    let Some(gate) = admission.gate() else {
        // The unenforced form carries no gate inputs, so there is nothing to dangle. The
        // two clauses that refused a dangling authority and a dangling degraded window are
        // gone — a request cannot state either — and the argv forms are answered by
        // `cli::admission_flags` (ADR-MCPRE-067 §7).
        return Ok(None);
    };
    // What SURVIVES is every clause about what a supplied value says. The gate is
    // inhabited by its authority, so "enforcing with none" is unbuildable; an authority
    // that NAMES NOTHING is still writable, and is still the most dangerous of the states
    // because the deployment believes it has admission control.
    if gate.authority_pubkey_b64url.trim().is_empty() || gate.authority_kid.trim().is_empty() {
        return Err(MISSING_ADMISSION_AUTHORITY.to_string());
    }
    // Decoded HERE rather than where the verifier is built: an unusable authority key is a
    // property of the configuration, and catching it at materialization left the
    // composition root as the only thing between a programmatic config and a gate with no
    // usable issuer. The key travels onward from here, so this is the only decode.
    let Ok(key) = VerificationKey::from_b64url(&gate.authority_pubkey_b64url) else {
        return Err(
            "--admission-authority-pubkey is not a valid base64url-no-pad 32-byte \
             Ed25519 public key"
                .to_string(),
        );
    };
    let redis_url = gate.store.locator();
    if !redis_url.contains("://") {
        return Err(format!(
            "--admission-redis-url {redis_url:?} is not a URL: it names the shared \
             authoritative record currency is compared against, so a value that cannot name \
             a store leaves every call failing closed on an unreachable authority"
        ));
    }
    Ok(Some(AdmissionAuthority {
        kid: gate.authority_kid.clone(),
        key,
        redis_url: redis_url.to_string(),
        availability: match gate.availability {
            AdmissionAvailabilityRequest::FailClosed => AdmissionAvailability::FailClosed,
            AdmissionAvailabilityRequest::Degraded { bound_secs } => {
                AdmissionAvailability::BoundedDegraded { bound_secs }
            }
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut DeploymentRequest));

    /// A fully configured gate. Written through the request's own types, so a fixture
    /// cannot assemble a form the model forbids.
    fn gate() -> crate::deployment_request::AdmissionGateRequest {
        crate::deployment_request::AdmissionGateRequest {
            authority_kid: "authority-1".to_string(),
            authority_pubkey_b64url: valid_pubkey(),
            store: crate::deployment_request::SharedStoreRequest::redis("redis://127.0.0.1:6379"),
            availability: AdmissionAvailabilityRequest::FailClosed,
        }
    }

    fn enforcing(config: &mut DeploymentRequest, required: bool) {
        config.admission = if required {
            AdmissionRequest::Required(gate())
        } else {
            AdmissionRequest::Optional(gate())
        };
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
        let (state, violations) = run(|c| c.admission = AdmissionRequest::NotEnforced);
        assert!(violations.is_empty(), "{violations:?}");
        let state = state.expect("recognised");
        assert!(!state.is_enforced());
        assert!(state.enforced().is_none());

        for required in [false, true] {
            let (state, violations) = run(|c| enforcing(c, required));
            assert!(violations.is_empty(), "{required} refused: {violations:?}");
            let state = state.expect("recognised");
            assert_eq!(
                state.enforced().map(|gate| gate.posture()),
                Some(if required {
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
        let (state, _) = run(|c| enforcing(c, true));
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

    /// The availability travels as ONE value from the request to the state. Layer A owns
    /// the distinction between failing closed and tolerating a bounded window, so no
    /// consumer recombines a bool and an integer into a posture — and after Phase 6 the
    /// illegal combinations have no encoding on either side of the boundary.
    #[test]
    fn the_availability_posture_is_classified_from_the_two_flags() {
        let (state, _) = run(|c| {
            c.admission =
                AdmissionRequest::Required(crate::deployment_request::AdmissionGateRequest {
                    availability: AdmissionAvailabilityRequest::Degraded {
                        bound_secs: NonZeroU64::new(90).expect("90 is not zero"),
                    },
                    ..gate()
                });
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
        let state = run(|c| c.admission = AdmissionRequest::NotEnforced)
            .0
            .expect("off is a state");
        assert!(state.enforced().is_none());
    }

    /// A refused configuration yields NO state. An enforcing state that could be built
    /// beside a refusal would be a gate assembled from parts validation rejected.
    #[test]
    fn a_refused_configuration_recognises_no_state() {
        let (state, violations) = run(|c| {
            c.admission =
                AdmissionRequest::Required(crate::deployment_request::AdmissionGateRequest {
                    authority_pubkey_b64url: "not-a-key".to_string(),
                    ..gate()
                });
        });
        assert!(state.is_none(), "a state was built over a refusal");
        assert!(!violations.is_empty());
    }

    #[test]
    fn the_degraded_sub_state_is_accepted_with_a_positive_window() {
        let (_, violations) = run(|c| {
            c.admission =
                AdmissionRequest::Required(crate::deployment_request::AdmissionGateRequest {
                    availability: AdmissionAvailabilityRequest::Degraded {
                        bound_secs: NonZeroU64::new(30).expect("30 is not zero"),
                    },
                    ..gate()
                });
        });
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn an_enforcing_state_names_every_value_it_cannot_verify_without() {
        // The three values are MEMBERS of an applied gate, so "missing" is no longer a
        // state: what a request can still say is that one of them names nothing.
        let cases: Vec<Case> = vec![
            ("--admission-authority", |c| {
                c.admission =
                    AdmissionRequest::Required(crate::deployment_request::AdmissionGateRequest {
                        authority_pubkey_b64url: String::new(),
                        ..gate()
                    });
            }),
            ("--admission-authority", |c| {
                c.admission =
                    AdmissionRequest::Required(crate::deployment_request::AdmissionGateRequest {
                        authority_kid: String::new(),
                        ..gate()
                    });
            }),
            ("--admission-redis-url", |c| {
                c.admission =
                    AdmissionRequest::Required(crate::deployment_request::AdmissionGateRequest {
                        store: crate::deployment_request::SharedStoreRequest::redis(String::new()),
                        ..gate()
                    });
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
            c.admission =
                AdmissionRequest::Required(crate::deployment_request::AdmissionGateRequest {
                    authority_pubkey_b64url: "not-a-key".to_string(),
                    ..gate()
                });
        });
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--admission-authority-pubkey")),
            "{violations:?}"
        );
    }

    // Three tests left this module with the states they examined, and their absence is
    // the result:
    //
    // * every authority parameter refused beside an off gate;
    // * the complete degraded truth table, cell by cell, with each refusal identified;
    // * that no refusal under an off gate argues about window width.
    //
    // All three are about a SELECTION beside a value that belongs to another selection —
    // exactly what ADR-MCPRE-067 Phase 6 made unbuildable. The gate's inputs are members of
    // the enforcing forms and the degraded bound is a `NonZeroU64` on the arm that opens a
    // window, so none of those configurations can be constructed to be refused.
    //
    // The mistakes are still expressible on a flat command line, and the table moved there
    // whole: `cli::admission_flags::tests::the_degraded_truth_table_...` drives the same
    // cells through the adapter and pins the same per-mistake diagnostics.
}
