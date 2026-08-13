// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-058 §7.2 — the optional serving capabilities, as domain operations.
//!
//! # What lives here
//!
//! Each of the seven [`Seam`](crate::startup_posture::Seam)s the PEP can be assembled
//! with: read the configuration this capability owns, do whatever effectful work
//! establishing it requires, and produce both the artifact to attach and the line the
//! operator is told. One function per capability, each carrying its own `cfg` gating,
//! its own failure rule, and its own prose.
//!
//! They were seven blocks inside `run_validated`, roughly a third of it, differing only
//! in their domain and interleaved with the composition they were part of. Moving them
//! is not line relocation: the composition root can now state the ORDER capabilities are
//! established in without also stating what each one means, which is the difference
//! between a root and a procedure.
//!
//! # No `Capability` trait
//!
//! The blocks look alike; they are not alike. Retention opens a directory and refuses
//! startup if it cannot. The continuation store connects to Redis and ANNOUNCES its
//! absence instead of refusing. Admission connects to Redis and refuses. The transport
//! contract has no effect at all beyond a policy field. A trait over these would have to
//! be wide enough to say nothing, and ADR-MCPRE-058 §7.2 asks for a common LIFECYCLE
//! vocabulary, not a common interface. [`Established`] is that vocabulary: a data type,
//! not an abstraction over the domains.
//!
//! # Why the posture travels with the artifact
//!
//! `Established::on` cannot be constructed without the artifact, and
//! `Established::off` cannot carry one. So "the transcript says a security capability is
//! running" and "something was actually established" are one fact rather than two
//! statements that have to be kept in agreement — the distinction ADR-MCPRE-057 §18
//! draws between *requested* and *established*, made structural.
//!
//! The `declare` calls stay in `run_validated`. That is deliberate: the posture is the
//! composition root's statement about the deployment, `assert_complete` runs there, and
//! `scripts/seam_posture_gate.py` proves every seam is declared exactly once in that one
//! file. Hiding the declarations inside these functions would move the proof somewhere
//! the gate cannot see it.

use std::sync::Arc;

use crate::startup_posture::SeamState;

/// What materializing one optional capability produced: the artifact to attach, and the
/// posture line describing what this deployment now does or does not enforce.
///
/// The field is private and the two constructors are the only way in, which is what
/// makes an ON posture over nothing unrepresentable.
pub(crate) struct Established<T> {
    artifact: Option<T>,
    posture: SeamState,
}

impl<T> Established<T> {
    /// The capability is running, and here is what to attach.
    pub(crate) fn on(artifact: T, detail: impl Into<String>) -> Self {
        Established {
            artifact: Some(artifact),
            posture: SeamState::on(detail),
        }
    }

    /// The capability is not running. `detail` must say what that means for the calls
    /// this deployment serves, and name the flag that turns it on.
    pub(crate) fn off(detail: impl Into<String>) -> Self {
        Established {
            artifact: None,
            posture: SeamState::off(detail),
        }
    }

    /// Split into what to attach and what to declare. Consuming, so a caller cannot
    /// attach the artifact and then declare a posture built from something else.
    pub(crate) fn into_parts(self) -> (Option<T>, SeamState) {
        (self.artifact, self.posture)
    }
}

/// The OFF line for online OCSP, shared by the two arms below.
///
/// Both arms say the same thing on purpose. Usually "this build cannot do it" and "this
/// deployment did not ask for it" need different responses from an operator, but
/// `--client-ocsp require` is refused at parse time in EVERY build, so there is no
/// build-specific advice to give and inventing a distinction would be misleading.
///
/// It does NOT recommend `--client-ocsp require`, because validation refuses that flag
/// unconditionally, in every build: the check is implemented only on the blocking serve
/// loop, and the production data plane is the per-core async fleet. A diagnostic that
/// names a mode which always refuses sends an operator into a dead end, so this points at
/// `--client-crl`, which is what actually works on the serving path.
const OCSP_OFF: &str = "ONLINE OCSP client-cert revocation = OFF: no responder is \
     consulted, so a client certificate revoked at its issuing CA is still accepted unless \
     an offline CRL covers it. Online OCSP is unavailable on the async serving path \
     (--client-ocsp require is refused at startup); use --client-crl, with \
     --client-crl-reload-secs for restart-free refresh.";

/// #4030 — online OCSP client-certificate revocation.
///
/// The checker is attached to [`ServerOptions`](crate::ServerOptions) rather than to the
/// PEP, because revocation is decided during the TLS handshake.
/// Takes no configuration, because no legal deployment can change the answer.
///
/// `--client-ocsp require` is refused by [`crate::cli::online_ocsp_refusal`] from inside
/// `legality_violations`, which is on the only route to a `ValidatedConfig` — so every
/// validated deployment has `client_ocsp == Off`, `build_ocsp_checker` returns `None`, and
/// this posture is OFF. Taking a `&Config` implied a choice the legality model does not
/// offer.
///
/// The seam still DECLARES, because `Seam::ALL` does not vary by `cfg` and an undeclared
/// seam refuses startup. What went away is the input, not the declaration.
///
/// [`crate::cli::build_ocsp_checker`] and the `online_ocsp` feature are deliberately left in
/// place. Proving the `Require` arm unreachable under today's legality model is not a
/// decision to delete the implementation a future async OCSP would be built from.
#[cfg(feature = "online_ocsp")]
pub(crate) fn online_ocsp() -> Established<crate::ocsp::OcspChecker> {
    Established::off(OCSP_OFF)
}

/// The same seam in a build without the backend. Declared, not skipped: `Seam::ALL` does
/// not vary by `cfg`, because a capability compiled out is a state the transcript has to
/// be able to express.
#[cfg(not(feature = "online_ocsp"))]
pub(crate) fn online_ocsp() -> Established<std::convert::Infallible> {
    Established::off(OCSP_OFF)
}

/// §4.1 — the MCP transport/version contract.
///
/// Enforced only when the operator declares the protocol versions this deployment
/// serves. Absent the flag there is no contract to enforce, so required-header presence
/// and `Mcp-Name`/`params.name` agreement are not asserted — an explicit decision rather
/// than a default, because the failure it prevents is a signed request that names one
/// tool in its header and invokes another in its body.
pub(crate) fn mcp_transport_contract(
    state: &crate::config_state::McpTransportContractState,
) -> Established<mcp_re_http_profile::McpTransportPolicy> {
    let crate::config_state::McpTransportContractState::Enforced { versions } = state else {
        return Established::off(
            "MCP transport contract = OFF (no --mcp-protocol-version): the required \
             transport headers are not asserted and Mcp-Name is not checked against \
             params.name, so a signed request may name one tool in its header and invoke \
             another in its body. Declare the protocol version(s) this deployment serves \
             to enforce the contract.",
        );
    };
    let accepted: Vec<&str> = versions.iter().map(String::as_str).collect();
    Established::on(
        mcp_re_http_profile::McpTransportPolicy::mcp_2026_07_28(&accepted),
        format!(
            "MCP transport contract ENFORCED for protocol version(s) {versions:?} \
             (required transport headers covered; Mcp-Name must equal params.name)"
        ),
    )
}

/// ADR-MCPS-035 — the per-request accepted/rejected/signed attribution record.
///
/// Returns a pair rather than an [`Established`], because both arms attach a sink: the
/// OFF state is a real `NoAuditSink`, not the absence of one. Forcing it into the same
/// shape as the others would mean either an `Established::off` carrying an artifact —
/// which is exactly the invariant that type exists to hold — or the composition root
/// re-deriving which sink to install from the posture. The capabilities are not uniform,
/// and this is where that shows.
pub(crate) fn security_audit_record(
    state: crate::config_state::AuditState,
) -> (Arc<dyn crate::audit_sink::AuditSink>, SeamState) {
    match state {
        crate::config_state::AuditState::Stderr => (
            Arc::new(crate::audit_sink::StderrAuditSink),
            SeamState::on(
                "security audit record = STDERR (ADR-MCPS-035): one line per \
                 accepted / rejected / signed decision, carrying the verifier-resolved actor \
                 and the frozen mcp-re.* wire code.",
            ),
        ),
        crate::config_state::AuditState::None => (
            Arc::new(crate::audit_sink::NoAuditSink),
            SeamState::off(
                "security audit record = NONE: no per-request accepted/rejected \
                 record is emitted, so this deployment has no attribution surface for a later \
                 incident. Pass --audit-sink stderr to enable it.",
            ),
        ),
    }
}

/// ADR-MCPRE-054 — retention of the full request and response of accepted calls.
///
/// Opening the store is effectful and FAILS STARTUP. A deployment that cannot open it
/// would otherwise refuse every request with `evidence_retention_unavailable` while
/// appearing to have started, which is the least diagnosable shape the failure has.
/// Takes the classified state, not the deployment request: layer A already decided that
/// this deployment retains evidence, and `On` carries the directory that decided it. What
/// is left here is layer C — whether the directory can be opened — which is the one
/// question configuration cannot answer.
pub(crate) fn evidence_retention(
    state: &crate::config_state::RetentionState,
) -> Result<Established<crate::transparency::EvidenceRetention>, String> {
    let crate::config_state::RetentionState::On { directory: dir } = state else {
        return Ok(Established::off(
            "evidence retention = OFF: nothing is retained, so no SCITT \
             statement can later be issued about a call served here. Pass \
             --retained-evidence-dir <path> to enable it.",
        ));
    };
    let retention = crate::transparency::EvidenceRetention::open(dir)
        .map_err(|e| format!("--retained-evidence-dir {dir}: {e}"))?;
    Ok(Established::on(
        retention,
        format!(
            "evidence retention = ON at {dir} (ADR-MCPRE-054): the full \
             request and response messages of every ACCEPTED call are retained (rejected \
             requests are not), and a store failure refuses the exchange with \
             mcp-re.evidence_retention_unavailable. The store has NO expiry or quota — \
             a full volume is therefore a total outage. Put it on a dedicated volume \
             with a retention policy and free-space alerting."
        ),
    ))
}

/// #415 rev 2 §10 — the verified-context carrier.
///
/// Caller-seeded context is stripped regardless; this decides only whether the PEP
/// writes its OWN resolved actor in its place. `trusted` is an operator assertion about
/// the inner channel that nothing here can verify.
pub(crate) fn verified_context_carrier(
    state: crate::config_state::VerifiedContextState,
) -> Established<mcp_re_http_profile::VerifiedContextPolicy> {
    if state.asserts_inner_channel_isolation() {
        Established::on(
            mcp_re_http_profile::VerifiedContextPolicy::Trusted,
            "verified-context carrier = TRUSTED (#415 §10): the PEP writes its \
             resolved actor into the forwarded body. The carrier is UNSIGNED — this asserts \
             that nothing but this proxy can reach the inner server, and nothing here can \
             check that.",
        )
    } else {
        Established::off(
            "verified-context carrier = OFF (#415 §10): caller-seeded context is stripped \
             and the PEP writes nothing in its place, so the inner server receives no \
             resolved actor and must not make an authorization decision on identity. Pass \
             --verified-context trusted only where nothing but this proxy can reach the \
             inner server.",
        )
    }
}

/// The OFF line for the continuation store in a build without the backend.
#[cfg(not(feature = "redis_replay"))]
const CONTINUATION_STORE_NO_BACKEND: &str =
    "MRTR continuation store = OFF: this build lacks the `redis_replay` feature, so \
     multi-round-trip flows are SINGLE-REPLICA only regardless of configuration. A \
     client that receives an `input_required` reply from one replica and answers on \
     another is refused (mcp-re.continuation_binding_failed).";

/// The posture line for a build that HAS the shared-store backend but was not given a
/// URL for it. The feature-absent case says something different, because there the flag
/// this line recommends would not help.
///
/// Stated rather than left silent because an operator on the CP/linearizable replay
/// tier — the tier the claim matrix presents as strongest — otherwise loses every
/// human-approval / multi-round-trip flow with no indication why. The failure is closed,
/// but on the wire it reads as a client or attack signal.
#[cfg(feature = "redis_replay")]
const CONTINUATION_STORE_OFF: &str = "MRTR continuation store = OFF (no --replay-redis-url): \
     multi-round-trip flows are SINGLE-REPLICA only. A client that receives an \
     `input_required` reply from one replica and answers on another is refused \
     (mcp-re.continuation_binding_failed). Set --replay-redis-url for the shared store.";

/// ADR-MCPS-047 — the shared store that makes multi-round-trip flows cross-replica.
///
/// # Why absence is announced here and REFUSED for admission
///
/// The two look inconsistent until the difference is named. Admission is an EXPLICITLY
/// REQUESTED capability: a build that cannot provide it must fail closed rather than
/// serve a proxy that quietly does not enforce it. Cross-replica MRTR is OPPORTUNISTIC —
/// no flag asks for it; it appears when a shared Redis happens to be configured.
/// Refusing startup for its absence would make every single-store deployment
/// unstartable, and it is safe not to, because the dependent leg fails closed on its
/// own: an answer without a correlated continuation is rejected at the binding
/// (`mcp-re.continuation_binding_failed`), not admitted unbound.
///
/// The rule, for the next capability that has to choose: explicitly requested and
/// unavailable => refuse startup; opportunistic and unavailable => announce the absence,
/// and verify the dependent leg still fails closed without it.
#[cfg(feature = "redis_replay")]
pub(crate) fn mrtr_continuation_store(
    plan: &crate::startup_plan::ContinuationControlPlan,
    control: Option<&crate::control_runtime::ControlRuntime>,
) -> Result<Established<Arc<dyn crate::continuation_store::AsyncContinuationStore>>, String> {
    let crate::startup_plan::ContinuationControlPlan::Redis { endpoint: url } = plan else {
        return Ok(Established::off(CONTINUATION_STORE_OFF));
    };
    let handle = control
        .ok_or(
            "internal error: the plan declared the continuation store needs the control runtime",
        )?
        .handle();
    let store = handle
        .block_on(crate::redis_continuation_store::RedisContinuationStore::connect(url))
        .map_err(|e| format!("connect redis continuation store: {e}"))?;
    Ok(Established::on(
        Arc::new(store) as Arc<dyn crate::continuation_store::AsyncContinuationStore>,
        format!(
            "MRTR continuation store = shared (async Redis backend, TTL {}s)",
            crate::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS
        ),
    ))
}

/// The same seam in a build without the backend. A build that cannot be talked into the
/// shared store must not be told to set the flag that would enable it, so this arm names
/// the missing feature instead of the flag.
#[cfg(not(feature = "redis_replay"))]
pub(crate) fn mrtr_continuation_store(
    _plan: &crate::startup_plan::ContinuationControlPlan,
    _control: Option<&crate::control_runtime::ControlRuntime>,
) -> Result<Established<Arc<dyn crate::continuation_store::AsyncContinuationStore>>, String> {
    Ok(Established::off(CONTINUATION_STORE_NO_BACKEND))
}

/// The OFF line when the operator did not ask for the gate. Only the arm that CAN
/// enforce it says "pass --admission"; the build without the backend says something
/// different below, because that advice would not help there.
#[cfg(feature = "redis_replay")]
const ADMISSION_OFF: &str = "admission currency = OFF (--admission off): a call carrying a fresh, \
     correctly-bound assertion is served even after its workload has been revoked, \
     because currency is a comparison against state only the deployment can supply. \
     Pass --admission with --admission-redis-url to enforce it.";

/// Everything `HttpProfileProxy::with_admission` needs, kept together so the composition
/// root attaches one value rather than reassembling four.
///
/// Not `cfg`-gated, although only the `redis_replay` arm below can build one: every field
/// type exists in both profiles, and giving the two arms different return types would
/// push the `cfg` into the composition root, which is the one place that should not have
/// to know which backends this build has.
pub(crate) struct AdmissionGate {
    pub(crate) source: Arc<dyn crate::admission_source::AsyncAdmissionSource>,
    pub(crate) policy: mcp_re_http_profile::AdmissionPolicy,
    pub(crate) enforcement: crate::http_profile_serve::AdmissionEnforcement,
    pub(crate) resolve_authority: crate::http_profile_serve::AdmissionAuthorityResolver,
}

/// MCPRE-493 §7 — the admission-currency gate over the shared authoritative record.
///
/// Without a source the assertion and its binding are verified evidence that decides
/// nothing: a call carrying a fresh, correctly-bound assertion is served even after its
/// workload has been revoked, because currency is a comparison against state only the
/// deployment can supply.
///
/// # Why one scalar travels beside the state
///
/// `max_clock_skew` is a validated request parameter with three unrelated consumers — the
/// replay tier's skew-folded retain-until, the request `VerifierPolicy`, and this policy —
/// and no admission-specific rule. It belongs to no machine, so it is passed rather than
/// owned.
#[cfg(feature = "redis_replay")]
pub(crate) fn admission_currency(
    state: &crate::config_state::AdmissionState,
    max_clock_skew: i64,
    control: Option<&crate::control_runtime::ControlRuntime>,
) -> Result<Established<AdmissionGate>, String> {
    use crate::config_state::{AdmissionAvailability, AdmissionState};
    // The state names the posture AND carries what that posture cannot exist without, so
    // there is nothing here to reconstruct and no arm for a witness that went missing.
    let (enforcement, kid, key, url, availability) = match state {
        AdmissionState::Off => return Ok(Established::off(ADMISSION_OFF)),
        AdmissionState::Optional {
            authority_kid,
            authority,
            redis_url,
            availability,
        } => (
            crate::http_profile_serve::AdmissionEnforcement::Optional,
            authority_kid.clone(),
            authority.clone(),
            redis_url,
            availability,
        ),
        AdmissionState::Required {
            authority_kid,
            authority,
            redis_url,
            availability,
        } => (
            crate::http_profile_serve::AdmissionEnforcement::Required,
            authority_kid.clone(),
            authority.clone(),
            redis_url,
            availability,
        ),
    };
    // The two `AdmissionPolicy` flags are a PROJECTION of one posture rather than two
    // settings this seam could combine wrongly. `unwrap_or` is a saturation that cannot
    // fire: the bound was narrowed from a positive `i64` at layer A.
    let (allow_degraded_mode, degraded_propagation_bound) = match availability {
        AdmissionAvailability::FailClosed => (false, 0),
        AdmissionAvailability::BoundedDegraded { bound_secs } => {
            (true, i64::try_from(bound_secs.get()).unwrap_or(i64::MAX))
        }
    };
    // The admission record is an INDEPENDENT endpoint; it has nothing to do with which
    // replay tier the deployment chose. Coupling it to the replay control runtime made
    // admission unimplementable on the CP/linearizable tier — the operator supplied
    // `--admission-redis-url`, was told the flag was missing, and the natural resolution
    // was to turn a security control off.
    let handle = control
        .ok_or("internal error: the plan declared the admission source needs the control runtime")?
        .handle();
    let source = handle
        .block_on(crate::redis_admission_source::RedisAdmissionSource::connect(url))
        .map_err(|e| format!("connect redis admission source: {e}"))?;
    // Rendered before the resolver closure below moves `kid`.
    let line = format!(
        "admission currency = {} (authority {kid}, shared record over redis, degraded {})",
        match enforcement {
            crate::http_profile_serve::AdmissionEnforcement::Required => "REQUIRED",
            crate::http_profile_serve::AdmissionEnforcement::Optional => "optional",
        },
        match availability {
            AdmissionAvailability::FailClosed => {
                "OFF (an unreachable authority fails closed)".to_string()
            }
            AdmissionAvailability::BoundedDegraded { bound_secs } => {
                format!("allowed within P={bound_secs}s")
            }
        },
    );
    Ok(Established::on(
        AdmissionGate {
            source: Arc::new(source),
            policy: mcp_re_http_profile::AdmissionPolicy {
                max_assertion_age: 300,
                max_clock_skew,
                degraded_propagation_bound,
                allow_degraded_mode,
            },
            enforcement,
            resolve_authority: Arc::new(move |presented: &str| {
                (presented == kid).then(|| key.clone())
            }),
        },
        line,
    ))
}

/// The same seam in a build without the backend.
///
/// REFUSES startup when the gate was asked for — the opposite choice from the
/// continuation store above, and the difference is that admission was explicitly
/// requested. An operator who asked for it must not get a proxy that quietly does not do
/// it.
#[cfg(not(feature = "redis_replay"))]
pub(crate) fn admission_currency(
    state: &crate::config_state::AdmissionState,
    _max_clock_skew: i64,
    _control: Option<&crate::control_runtime::ControlRuntime>,
) -> Result<Established<AdmissionGate>, String> {
    if state.is_enforced() {
        return Err(
            "--admission requires a build with the `redis_replay` feature (the \
                    shared authoritative admission record)"
                .to_string(),
        );
    }
    Ok(Established::off(ADMISSION_NO_BACKEND))
}

/// The OFF line for a build that cannot enforce the gate at all.
#[cfg(not(feature = "redis_replay"))]
const ADMISSION_NO_BACKEND: &str =
    "admission currency = OFF: this build lacks the `redis_replay` feature (the \
     shared authoritative admission record), so --admission is refused at startup \
     rather than enforced. A workload revoked at the authority keeps being served \
     here until its assertion expires.";

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariant this module's type exists for: a posture cannot say ON over
    /// nothing, and cannot say OFF over something.
    ///
    /// The broken implementation this catches is the one that was there before —
    /// deciding the artifact and writing the posture line as two independent statements,
    /// so a capability whose construction was later made conditional keeps announcing
    /// itself as running. Here it cannot compile: `on` has no arm without an artifact
    /// and `off` has no parameter to put one in.
    #[test]
    fn an_on_posture_always_carries_an_artifact_and_an_off_posture_never_does() {
        let (artifact, posture) = Established::on(7u8, "thing = ON").into_parts();
        assert_eq!(artifact, Some(7));
        assert!(matches!(posture, SeamState::On { .. }));

        let (artifact, posture) = Established::<u8>::off("thing = OFF: pass --thing").into_parts();
        assert_eq!(artifact, None);
        assert!(matches!(posture, SeamState::Off { .. }));
    }

    /// Every OFF line names what turns the capability on, or why nothing can.
    ///
    /// An operator reading a transcript is deciding what to DO about the line. The
    /// posture module makes that a rule and the prose is the only place it can be
    /// broken, so it is asserted over the constants rather than left to review.
    #[test]
    fn every_off_line_tells_the_operator_what_to_do_about_it() {
        let lines: &[(&str, &str)] = &[
            ("OCSP_OFF", OCSP_OFF),
            #[cfg(feature = "redis_replay")]
            ("ADMISSION_OFF", ADMISSION_OFF),
            #[cfg(feature = "redis_replay")]
            ("CONTINUATION_STORE_OFF", CONTINUATION_STORE_OFF),
            #[cfg(not(feature = "redis_replay"))]
            ("ADMISSION_NO_BACKEND", ADMISSION_NO_BACKEND),
            #[cfg(not(feature = "redis_replay"))]
            (
                "CONTINUATION_STORE_NO_BACKEND",
                CONTINUATION_STORE_NO_BACKEND,
            ),
        ];
        for (name, line) in lines {
            assert!(
                line.contains("--") || line.contains("feature"),
                "{name} names neither a flag to set nor the missing feature: {line}"
            );
            assert!(
                line.contains("OFF"),
                "{name} does not say the capability is off: {line}"
            );
        }
    }
}
