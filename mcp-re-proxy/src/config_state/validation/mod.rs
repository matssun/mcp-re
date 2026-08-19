// SPDX-License-Identifier: Apache-2.0
//! Layer A's boundary: the one place a requested deployment is judged legal.
//!
//! Three responsibilities, and deliberately no fourth:
//!
//! - **assembly** — call each machine's classifier, run the cross-machine relations over
//!   the states they recognised, and build the [`DeploymentConfigState`] that planning
//!   projects from;
//! - **report-all** — collect every violation rather than returning at the first, so a
//!   command line wrong in four ways is answered about four;
//! - **precedence** — the ORDER an operator reads, pinned by
//!   `tests/integration/config_refusal_precedence_test.rs`.
//!
//! It does not own domain semantics. Each machine decides its own columns and each
//! relation its own pair; this module only asks them, in an order that is its own contract.
//! Where a rule still has no ruled owner it lives in [`residue`], enumerated rather than
//! inlined, so the remaining work is countable instead of hidden in a long function.
//!
//! It lives beside `config_state` rather than in `cli` because the request it judges can be
//! built without a parser — that was the bypass this boundary exists to close.

mod residue;

use crate::config_state::DeploymentConfigState;
use crate::deployment_request::DeploymentRequest;

/// A [`DeploymentRequest`] whose PURE guards have been checked.
///
/// The guards themselves are not new — [`unsafe_config_violations`] has always run at
/// the end of [`parse_args`]. What was missing is that passing through `parse_args` was
/// the ONLY thing that ran them. `DeploymentRequest` has 76 public fields, so any caller that built
/// one in code and handed it to `app::run` got a proxy with cn_legacy identity, a
/// non-durable replay tier or a disabled client-cert lifetime — every posture the
/// project refuses — with nothing to stop it. The guard was
/// at the wrong altitude: on one path into the runtime rather than on the runtime.
///
/// This type moves it onto the runtime. The serving path accepts only a
/// `ValidatedDeployment`, and the only way to obtain one is [`TryFrom`], so there is no
/// route past the check whether the config came from argv or from a caller's struct
/// literal.
///
/// **Purely knowable checks only.** These are deterministic and environment-independent:
/// ranges, mutually exclusive modes, required values missing from a selected mode. This
/// type makes NO claim about the environment — whether a file exists, whether a
/// certificate matches its key, whether a KMS answers, whether the clock is sane. Those
/// are observations, they can change between the check and the use, and they belong to
/// startup materialization (ADR-MCPRE-056 §5.1).
///
/// **It carries what validation recognised.** Deciding that a configuration is legal means
/// deciding which state it requests — `PushNetworked` rather than `PushInert`, `Delegated`
/// rather than `Exported` — and that decision is kept rather than recomputed downstream.
/// A stage that re-derived it from the same fields would be a second authority over one
/// deployment fact, free to disagree with the first (CF-10).
#[derive(Debug, Clone)]
pub struct ValidatedDeployment {
    config: DeploymentRequest,
    state: DeploymentConfigState,
}

impl ValidatedDeployment {
    /// The validated configuration. Named rather than a public field so the wrapper
    /// cannot be reconstructed around an unchecked `DeploymentRequest`.
    pub fn into_inner(self) -> DeploymentRequest {
        self.config
    }

    /// Which state each configuration machine was recognised to be in.
    ///
    /// Planning reads this together with the validated values; it does not ask again which
    /// state the deployment is in, because layer A has answered that once.
    pub fn state(&self) -> &DeploymentConfigState {
        &self.state
    }

    /// The validated values, for planning and composition.
    ///
    /// Named rather than a `Deref` because reading raw configuration is a statement about
    /// which layer the reader belongs to, not merely a question of safety. A shared
    /// `&DeploymentRequest` cannot undo the validation — but the two callers of this method are the
    /// two stages entitled to interpret configuration at all (startup planning, and the
    /// composition root that builds the plans), and a `Deref` made that boundary invisible
    /// at the call site. In particular it silently downgraded `&ValidatedDeployment` to
    /// `&DeploymentRequest` when forwarding into modules that establish runtime capabilities; written
    /// out, each such forward is visible in review and countable as work remaining.
    pub fn config(&self) -> &DeploymentRequest {
        &self.config
    }
}

impl TryFrom<DeploymentRequest> for ValidatedDeployment {
    type Error = String;

    fn try_from(config: DeploymentRequest) -> Result<Self, Self::Error> {
        match validate_configuration(&config) {
            Ok(state) => Ok(ValidatedDeployment { config, state }),
            Err(violations) => Err(format!(
                "mcp-re-proxy refuses unsafe configuration:\n  - {}",
                violations.join("\n  - ")
            )),
        }
    }
}

/// Collect the parse-time unsafe-configuration violations for `config`.
///
/// The proxy has NO security toggle — it always runs the maximal-security posture,
/// so this is applied unconditionally. This is the pure, black-box-testable core:
/// each returned string names the offending flag and how to fix it. It covers ONLY
/// the conditions knowable from the parsed [`DeploymentRequest`] — the group/world-readable
/// key-file check is filesystem-dependent and lives in `main.rs` (which reads the
/// file mode and reuses the same fail-closed posture).
///
/// ADR-MCPS-023 §A1 (v0.9, MCPS-57): a `--max-client-cert-lifetime` GREATER than
/// [`crate::config_state::transport::MAX_CLIENT_CERT_LIFETIME`] is rejected. Mode-A's entire certificate-revocation
/// posture is short-lived certificates (on GCP the online-OCSP path is a no-op and
/// CAS is CRL-only), so a long-lived cert cannot honestly be audited as
/// `short_lived_cert`. DISABLED enforcement (`none`/`0`, i.e.
/// `max_client_cert_lifetime == None`) is likewise rejected.
///
/// The postures rejected here are the pure-config, platform-independent fail-open
/// ones: a non-durable/weak replay tier (#90/ADR-MCPS-020), lb-assertion binding, and
/// cn_legacy identity.
///
/// The violations alone. [`validate_configuration`] is the boundary proper — it runs the
/// same single pass and additionally returns what that pass RECOGNISED, which is what the
/// runtime needs. This wrapper exists for callers that only ask whether a config is legal.
pub fn unsafe_config_violations(config: &DeploymentRequest) -> Vec<String> {
    validate_configuration(config).err().unwrap_or_default()
}

/// Decide whether a requested deployment state is legal, and say which state it is.
///
/// One pass, two products. A validator that recognises `TrustRevocation::PushNetworked`,
/// checks it, and throws the recognition away leaves every downstream stage to re-derive
/// the same fact from the same fields — one deployment fact with two derivations, free to
/// disagree. So the classification is returned (`work/CONFIG-STATE-ATLAS.md` CF-10) and
/// becomes what plans project from.
///
/// **Order is a separate contract.** Every violation is reported, not the first, and the
/// sequence is what an operator reads. It is pinned by
/// `tests/integration/config_refusal_precedence_test.rs` so that reorganising this
/// function cannot
/// silently reorder the diagnosis: machine validators are called at the position their
/// clauses already occupied.
pub fn validate_configuration(
    config: &DeploymentRequest,
) -> Result<DeploymentConfigState, Vec<String>> {
    // PASS 1 — each machine recognises its own state and checks that state's columns.
    let (continuation_control, continuation_violations) =
        crate::config_state::continuation_control::classify_and_validate(config);
    let (custody, custody_violations) = crate::config_state::custody::classify_and_validate(config);
    let (delegated_signing, delegated_signing_violations) =
        crate::config_state::delegated_signing::classify_and_validate(config);
    let (replay, replay_violations) = crate::config_state::replay::classify_and_validate(config);
    let (tls_custody, tls_custody_violations) =
        crate::config_state::tls_custody::classify_and_validate(config);
    let (trust_revocation, trust_violations) =
        crate::config_state::trust_revocation::classify_and_validate(config);
    let (admission, admission_violations) =
        crate::config_state::admission::classify_and_validate(config);
    let (channel_binding, binding_violations) =
        crate::config_state::transport::classify_and_validate_binding(config);
    let (crl_revocation, crl_violations) =
        crate::config_state::transport::classify_and_validate_crl(config);
    let (freshness, freshness_violations) =
        crate::config_state::freshness::classify_and_validate(config);
    let (trust_document, trust_document_violations) =
        crate::config_state::trust_document::classify_and_validate(config);
    let (client_credential_window, credential_window_violations) =
        crate::config_state::client_credential_window::classify_and_validate(config);
    // This deployment's own actor identity. It takes the RESOLVED issuer kid rather than
    // re-reading the primitives it defaults from, so the keyid on the identity and the kid
    // the credential chains to are one value (CF-10).
    let (server_identity, server_identity_violations) =
        crate::config_state::server_identity::classify_and_validate(
            config,
            delegated_signing.as_ref(),
        );
    let (audit, retention, verified_context) = crate::config_state::evidence::classify(config);
    let mcp_transport_contract = crate::config_state::mcp_transport_contract::classify(config);
    // Infallible: the request states one of three things and the default makes the third
    // a basis too. Nothing to refuse — the illegal combination is not representable.
    let in_flight_limit = crate::config_state::in_flight_limit::classify(config);
    // PASS 2 — the relations between machines, asked of the RECOGNISED states rather than
    // of the fields again.
    let cross = crate::config_state::cross_machine::validate(
        config.key_source,
        tls_custody.as_ref(),
        trust_revocation.as_ref(),
        config,
    );
    let decided = MachineViolations {
        admission: admission_violations,
        channel_binding: binding_violations,
        continuation_control: continuation_violations,
        crl_revocation: crl_violations,
        custody: custody_violations,
        delegated_signing: delegated_signing_violations,
        freshness: freshness_violations,
        replay: replay_violations,
        trust_document: trust_document_violations,
        client_credential_window: credential_window_violations,
        server_identity: server_identity_violations,
        tls_custody: tls_custody_violations,
        trust_revocation: trust_violations,
        cross,
    };
    let violations = legality_violations(config, decided);
    // Seven owners can name NOTHING: `Replay` (`memory` and `file` are input forms, not
    // deployments), `ChannelBinding` (three undeployable binding kinds, one deprecated
    // identity source), `DelegatedSigning` (the §7 epoch has no default, so without it there
    // is no posture to resolve), `TrustRevocation` (three of its four states require a
    // reload cadence), `Admission` (its two enforcing states require an authority and a
    // record locator), `Custody` (every state requires the material it signs with) and
    // `TlsCustody` (its exported state requires the key it exports) — a state cannot be
    // built without the witnesses that make it inhabitable. Each has already
    // pushed its refusal when that happens, so the arms below are unreachable — stated
    // one machine at a time, so an owner that forgets to refuse fails loudly and NAMES
    // itself instead of hiding inside a wildcard over a widening tuple.
    if !violations.is_empty() {
        return Err(violations);
    }
    let unrecognised = |machine: &str| {
        vec![format!(
            "internal error: the {machine} configuration machine recognised no state and \
             raised no refusal"
        )]
    };
    let Some(replay) = replay else {
        return Err(unrecognised("replay"));
    };
    let Some(channel_binding) = channel_binding else {
        return Err(unrecognised("channel-binding"));
    };
    let Some(delegated_signing) = delegated_signing else {
        return Err(unrecognised("delegated-signing"));
    };
    let Some(trust_revocation) = trust_revocation else {
        return Err(unrecognised("trust-revocation"));
    };
    let Some(admission) = admission else {
        return Err(unrecognised("admission"));
    };
    let Some(custody) = custody else {
        return Err(unrecognised("custody"));
    };
    let Some(tls_custody) = tls_custody else {
        return Err(unrecognised("tls-custody"));
    };
    let Some(server_identity) = server_identity else {
        return Err(unrecognised("server-identity"));
    };
    let Some(freshness) = freshness else {
        return Err(unrecognised("freshness"));
    };
    let Some(trust_document) = trust_document else {
        return Err(unrecognised("trust-document"));
    };
    let Some(client_credential_window) = client_credential_window else {
        return Err(unrecognised("client-credential-window"));
    };
    Ok(DeploymentConfigState::new(
        crate::config_state::RecognisedStates {
            admission,
            audit,
            channel_binding,
            client_credential_window,
            freshness,
            continuation_control,
            crl_revocation,
            custody,
            delegated_signing,
            in_flight_limit,
            mcp_transport_contract,
            replay,
            retention,
            server_identity,
            tls_custody,
            trust_document,
            trust_revocation,
            verified_context,
        },
    ))
}

/// What the two passes decided, kept apart by owner so the clause list can splice each
/// where it has always been read.
struct MachineViolations {
    admission: Vec<String>,
    channel_binding: Vec<String>,
    continuation_control: Vec<String>,
    crl_revocation: Vec<String>,
    custody: Vec<String>,
    delegated_signing: Vec<String>,
    freshness: Vec<String>,
    replay: Vec<String>,
    trust_document: Vec<String>,
    client_credential_window: Vec<String>,
    server_identity: Vec<String>,
    tls_custody: Vec<String>,
    trust_revocation: Vec<String>,
    cross: crate::config_state::cross_machine::CrossMachineViolations,
}

/// The clause list, in the order an operator reads it.
///
/// Nothing here decides anything about a machine that has one: `decided` arrives already
/// checked, and this function only places each result where its clauses were read before
/// the machine owned them — see [`validate_configuration`] on why the position is
/// load-bearing. Clauses still stated inline belong to machines not yet implemented.
fn legality_violations(config: &DeploymentRequest, decided: MachineViolations) -> Vec<String> {
    let mut violations = Vec::new();
    // Online OCSP cannot be honored on the production data plane. Checked HERE, because
    // this is the boundary the runtime actually goes through: `client_ocsp` is one of
    // `DeploymentRequest`'s public fields, so a caller that builds the struct in code
    // reaches the serving path without ever meeting a parser.
    violations.extend(residue::ocsp_mode_violations(config));
    // The mode's one parameter, immediately after it.
    violations.extend(residue::ocsp_responder_url_violations(config));
    // Same shape, second instance: a deny-list nothing enforces, on a public field.
    violations.extend(decided.cross.x6_unenforceable_deny_list);
    // Third instance of the same shape. This one was not a bypass — the composition root
    // refused it too — but it was stated twice, in two places, with two messages.
    violations.extend(residue::authz_profile_violations(config));
    // X2b — TlsCustody × Tls. A delegated handshake key and an exported copy of it are
    // contradictory rather than redundant, and the contradiction is between two machines,
    // so it is decided in pass 2 and only placed here.
    violations.extend(decided.cross.x2b_exclusive_tls_custody);
    // The `ChannelBinding` machine: which binding kinds are deployments at all, and which
    // identity source names a live state. Its `binding == none` and `== lb-assertion`
    // clauses used to sit at the END of this list; they are emitted here now, which is a
    // DELIBERATE precedence change — the mode's own undeployability is what an operator
    // needs first, and it was previously reported after every unrelated limit.
    violations.extend(decided.freshness);
    violations.extend(decided.channel_binding);
    // The deployment's own identity coordinates, immediately before `--target-uri`, which is
    // one of them and was the only one checked here. Each is a REQUIRED `String` that
    // nothing downstream ever dereferences — they are minted into what the proxy signs and
    // compared by verifiers,
    // never opened. An empty one is therefore not a startup failure but a coordinate that
    // silently stops distinguishing this deployment from another that also set none. They
    // are stated one field at a time, in the order an operator meets them, rather than as a
    // single "required strings" clause: they belong to a machine layer A does not yet have,
    // and collapsing them would fix the ordering of that machine's diagnostics in advance.
    // The `ServerIdentity` owner's two coordinates, at the position the identity clauses
    // have always been read.
    violations.extend(decided.server_identity);
    // `--audience` is not one of them: it is consumed as an audience parameter, not as part
    // of the identity, so its guard stays where no owner claims it. `--server-key-id` is not
    // guarded here at all — `DelegatedSigning` owns the resolved issuer kid, and the
    // fallback is only required when the resolution actually reads it.
    violations.extend(residue::audience_violations(config));
    // The required locators, in the same shape and immediately after. Each of these IS
    // dereferenced at startup, so an empty one eventually fails — but that failure is an
    // observation about the environment, and "this string names nothing" is knowable without
    // one. ADR-MCPRE-056 §5.1 puts the purely-knowable half here, which is also the half
    // that reads as a configuration defect rather than a missing file.
    violations.extend(residue::required_locator_violations(config));
    // Sixth instance, and the one that reaches furthest into a served request: an empty or
    // scheme-less `--target-uri` does not weaken the request-target reconstruction check,
    // it disables it for every request.
    violations.extend(residue::target_uri_violations(config));
    // Seventh, and it arrives here from the TRUST plane, where it had no business being:
    // whether a deployment names an inner server is a statement about the request, not
    // about trust, and refusing it there meant the trust plane could reject a
    // configuration after two other planes had already established resources. It is the
    // same class as the clause above — a required locator — so it takes the position next
    // to it.
    violations.extend(residue::inner_plane_presence_violations(config));
    // Structure of that list, immediately after its presence: a list holding `""` is not an
    // empty list, so it satisfies the clause above and then contributes a backend the pool
    // will never reach. A trailing comma on the command line produces exactly that.
    violations.extend(residue::inner_plane_structure_violations(config));
    // The admission gate. Its four clauses were the LAST parse-only invariants of this
    // shape, and one of them was a genuine bypass rather than a misplacement: nothing
    // downstream re-checked the degraded window, so a programmatic config reached the
    // serving path with `allow_degraded` on and P zero — a revoked workload served for
    // the clock-skew tolerance on a deployment that configured no window at all.
    violations.extend(decided.admission);
    // The KMS/STS endpoint overrides. These carry the root-key trust bootstrap: the
    // `GetPublicKey` answer from the named host becomes the ROOT verify key the
    // verify-before-return guardrail is measured against, so a substituted endpoint
    // substitutes the root authority self-consistently, and the GCP path posts a live
    // workload-identity bearer token to it in the clear over `http://`.
    // The `Custody` machine: which key material this deployment claims to hold, and every
    // parameter that claim requires or excludes. Its endpoint guards come first because an
    // overridden KMS endpoint substitutes the root verify key itself.
    violations.extend(decided.custody);
    // X2a — Custody × TlsCustody: a delegated selector names a key object in one specific
    // backend, so which one is legal depends on the custody state.
    violations.extend(decided.cross.x2a_delegated_selector);
    // The `TlsCustody` machine's own column: the exported state has no key without one.
    violations.extend(decided.tls_custody);
    // Ingress-assertion coherence: whether the operator's belief about a request-binding
    // ingress control matches what runs.
    if let Some(refusal) = crate::config_state::transport::ingress_assertion_violation(config) {
        violations.push(refusal);
    }
    // The `CrlRevocation` machine: whether offline revocation is off, loaded once, or
    // re-read, and what each of those states requires.
    violations.extend(decided.crl_revocation);
    // ADR-MCPRE-052 delegated custody, decided by its own owner. The epoch was refused in
    // `delegated_wiring` — the last deterministic layer-A invalidity left, raised after two
    // planes had already established resources — while its two siblings were checked here,
    // so the family was split across two layers with no reason beyond history. It is one
    // owner now, and this is where an operator has always read it.
    violations.extend(decided.delegated_signing);
    // ADR-MCPS-023 §A1 (MCPS-57) and the old relation X5, now one owner: `None` disables
    // enforcement on either side, a lifetime above the ceiling would let a NOT-short-lived
    // cert be audited as `short_lived_cert`, and a connection age above the lifetime means
    // a connection outlives the credential that authenticated it. All fail closed, and
    // they are spliced where the two clause groups have always been read.
    violations.extend(decided.client_credential_window);
    // The trust locator, immediately before the posture over it. It left the required-
    // locator group when it acquired an owner: `TrustDocumentSource` is what a `TrustPlan`
    // now carries instead of a bare string, so the refusal belongs where the trust plane's
    // other clauses are rather than among three locators it shares nothing else with.
    violations.extend(decided.trust_document);
    // The `TrustRevocation` machine (ADR-MCPS-021 Axis 2): the declared tier, the reload
    // cadence that IS its revocation window, and the epoch source that splits Push into
    // its inert and networked states. Spliced here because this is where its clauses have
    // always been read.
    violations.extend(decided.trust_revocation);
    // MCPS-093/094: the socket timeouts and the aggregate read-phase deadline ARE the
    // slow-loris defense — a peer trickling bytes just under `read_timeout` is stopped by
    // `request_deadline`, and with either gone a handful of connections pin serve slots up
    // to `max_concurrent_connections` with nothing to drop them.
    //
    // An out-of-range value was already rejected LOUDLY, with the stated reason that "the
    // control can never be turned off by out-of-range input". `0` turned the same control
    // off silently, which left the binary asserting a maximal-security posture while its
    // own defense was disabled. Each default is `Some(30s)`, so `None` here only ever comes
    // from an operator explicitly passing `0`.
    // The freshness tolerance moved to `config_state::freshness`, which owns the fact and
    // its two projections; its violations arrive with every other owner's below.
    // The two `ServerLimits` quantities that are legally PRESENT but illegally zero, stated
    // ahead of the timeout clauses because they are the same class — a limit that disables
    // the control it bounds — and an operator reading about limits should meet them together.
    // Neither is `Option`, so absence is not the question and a fail-safe default already
    // applies; only an explicit zero reaches here.
    violations.extend(residue::connection_ceiling_violations(config));
    violations.extend(residue::drain_window_violations(config));
    violations.extend(residue::slow_loris_timeout_violations(config));
    // The `Replay` machine: which shared store holds admitted nonces, and every locator
    // that store requires or excludes. Spliced where the `memory` refusal and the
    // tier-strength refusal were read, in that order — the machine emits the input-form
    // refusal first for exactly that reason.
    violations.extend(decided.replay);
    // The `ContinuationControl` machine (CF-12). A NEW position: this clause has no
    // predecessor to preserve, because until the alias was split there was no
    // configuration of its own to refuse. Placed beside Replay because that is where an
    // operator reading about shared stores is looking, not because the two are related.
    violations.extend(decided.continuation_control);
    // MCPS-79 (ADR-MCPS-049 clause 1) needed a clause here while a replay store could be
    // node-local: `--fleet` had to reject the kinds a peer verifier could not see. No such
    // kind is representable now — every classifiable replay state is shared, and a request
    // that declares no durability tier names no state at all — so the fleet posture needs
    // no replay clause of its own. The tier's own strength requirement is enforced above.
    // X9 — TrustRevocation × DelegatedSigning. The epoch posture is decided once, by the
    // `TrustRevocation` machine, and carried in the classification; nothing is re-derived
    // here (CF-09).
    violations.extend(decided.cross.x9_trust_epoch_posture);
    violations
}
