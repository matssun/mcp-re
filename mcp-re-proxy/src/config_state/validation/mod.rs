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

use crate::config_state::DeploymentConfigState;
use crate::deployment_request::{AuthzKind, DeploymentRequest, OcspKind};

/// A [`DeploymentRequest`] whose PURE guards have been checked.
///
/// The guards themselves are not new — [`unsafe_config_violations`] has always run at
/// the end of [`parse_args`]. What was missing is that passing through `parse_args` was
/// the ONLY thing that ran them. `DeploymentRequest` has 76 public fields, so any caller that built
/// one in code and handed it to `app::run` got a proxy with cn_legacy identity, a
/// non-durable replay tier, a disabled client-cert lifetime or reverse-proxy header
/// ingress — every posture the project refuses — with nothing to stop it. The guard was
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

/// The `--target-uri` shape the request-target reconstruction check depends on, as a pure
/// rule over the configured value.
///
/// ADR-MCPRE-058 §8.3, and the member of this file's former parser-only family with the
/// most direct effect on a served request.
///
/// `async_serve` compares the origin-form of the configured target against the one the
/// request arrived at, and refuses to serve where they differ. That comparison is
/// answerable only for an ABSOLUTE target: `origin_form_of` finds `://` or returns `None`,
/// and `target_uri_mismatch` propagates that `None` as "no mismatch". A blank target
/// short-circuits to `None` one line earlier. So a configured target that is empty or
/// scheme-less does not weaken the check — it disables it, silently, for every request,
/// and the deployment goes on reporting that the binding is in force.
///
/// Both functions say in their own docs that the parser guarantees the shape. It did, and
/// only for argv: `target_uri` is a public `DeploymentRequest` field, so a programmatically built
/// config reaches the serving path having met no parser. An ingress fanning several paths
/// into one process would then verify signatures over a `@target-uri` the request never
/// arrived at, which is the exact scenario the parse-time diagnostic describes.
///
/// The validation boundary is the one caller, so a command line and a struct literal are
/// held to the shape by the same clause.
pub(crate) fn target_uri_violation(uri: &str) -> Option<String> {
    if uri.trim().is_empty() {
        return Some(
            "--target-uri must not be empty: an empty target makes the audience/target \
             binding a tautology (both sides compare equal) instead of binding this \
             deployment's dispatch boundary"
                .to_string(),
        );
    }
    if !uri.contains("://") {
        return Some(format!(
            "--target-uri {uri:?} is not an absolute URI: it must be \
             <scheme>://<authority><path> (e.g. https://proxy.internal:8600/mcp). \
             A scheme-less target disables the request-target reconstruction check \
             entirely, so an ingress fanning several paths into one process would \
             verify signatures over a @target-uri the request never arrived at"
        ));
    }
    None
}

/// The one decision about whether a configured authorization profile can be honored.
///
/// `Some(diagnostic)` means it cannot. Two independent facts make it so, and the
/// diagnostic carries both because an operator needs both to know what to do:
///
/// - the reference profile is a CONFORMANCE implementation, never accepted as the
///   production authorization authority (ADR-MCPS-013; Biscuit is the intended one);
/// - authorization enforcement is not wired on the RFC 9421 serving path at all — the
///   evaluator has not been rebuilt on the HTTP-profile request evidence.
///
/// Either alone is sufficient to refuse. A configured policy that would silently not
/// enforce is the forbidden-claim shape (security-boundary §2).
///
/// One function because this prohibition was once stated TWICE, in two places, with two
/// different messages: in `parse_args` and in the composition root. Neither was at the
/// validation boundary. That was not a bypass — the composition root did catch a
/// programmatically built `DeploymentRequest` — but two independent statements of one prohibition can
/// drift, and a policy decision does not belong in a composition root (ADR-MCPRE-056 §12).
pub(crate) fn unaccepted_authz_profile_refusal(authz: AuthzKind) -> Option<String> {
    (authz == AuthzKind::Reference).then(|| {
        "--authz reference selects the reference/conformance signed-authorization \
         profile, which is NOT accepted as the production authorization authority \
         (ADR-MCPS-013; Biscuit is the intended production profile), and authorization \
         enforcement is not wired on the RFC 9421 serving path in any case — the evaluator \
         must be rebuilt on the HTTP-profile request evidence first. Run --authz off."
            .to_string()
    })
}

/// The one decision about whether `--client-ocsp require` can be honored.
///
/// `Some(diagnostic)` means it cannot. Today that is unconditional, and the reason is a
/// property of the SERVING PATH rather than of the build: `ocsp_rejection` is reached only
/// from `connection_rejection`, which only the blocking serve loops call. The production
/// data plane is the per-core async fleet (ADR-MCPRE-051 §1), which calls
/// `connection_rejection_for_chain` and performs only the offline cert-lifetime and CRL
/// checks. So the responder round trip never happens, with or without the `online_ocsp`
/// feature — without it the code is absent, with it the code is present but never called.
///
/// Accepting it would announce `ONLINE OCSP client-cert revocation enabled` at startup on
/// a deployment that admits every revoked client certificate: the forbidden-claim shape
/// (security-boundary §2). The refusal lifts when the async path performs the round trip
/// off the runtime worker, and this is the single place that would have to change.
///
/// A function rather than an inline condition because it is what
/// [`unsafe_config_violations`] consults, and that is what a programmatically built
/// `DeploymentRequest` meets. Two copies is how the two drifted in the first place: the
/// parser refused, the validation boundary did not, and a caller that skipped the parser
/// reached the serving path with the claim intact.
pub(crate) fn online_ocsp_refusal(client_ocsp: OcspKind) -> Option<String> {
    (client_ocsp == OcspKind::Require).then(|| {
        "--client-ocsp require cannot be honored: online OCSP is implemented only on \
         the blocking serve loop, while the production data plane is the per-core \
         async fleet, which performs no OCSP revocation check. Accepting it would \
         announce enforcement that does not happen. Use --client-crl (with \
         --client-crl-reload-secs for restart-free refresh) for client-certificate \
         revocation on the async serving path."
            .to_string()
    })
}

/// The AIA-override responder, held to its own shape and then to the mode that reads it.
///
/// `--ocsp-responder-url` is the one OCSP parameter, and it parameterizes a mode rather
/// than naming a state, so it has no machine of its own; these are its two columns in the
/// order semantic dependency puts them. A responder that names nothing is a defect in the
/// value; a responder no mode will read is a defect in the combination, and only the second
/// depends on `client_ocsp`.
///
/// The second clause matters even though [`online_ocsp_refusal`] refuses `require`
/// unconditionally: the surviving case is a responder configured beside `--client-ocsp off`,
/// which no clause reaches, and which leaves an operator believing a revocation authority is
/// configured while every certificate is admitted unchecked.
fn ocsp_responder_violations(config: &DeploymentRequest) -> Vec<String> {
    let Some(url) = config.ocsp_responder_url.as_deref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if url.trim().is_empty() {
        out.push(
            "--ocsp-responder-url is empty: it overrides the responder named by the \
             certificate's AIA extension, so an empty value replaces a resolvable authority \
             with none"
                .to_string(),
        );
    }
    if config.client_ocsp != OcspKind::Require {
        out.push(
            "--ocsp-responder-url has no effect without --client-ocsp require: nothing \
             consults a responder in this mode, so the deployment would carry a revocation \
             authority it never asks"
                .to_string(),
        );
    }
    out
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
/// ones: reverse-proxy header ingress (M10/M22), a non-durable/weak replay tier
/// (#90/ADR-MCPS-020), lb-assertion binding, and cn_legacy identity.
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
        replay: replay_violations,
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
    Ok(DeploymentConfigState::new(
        crate::config_state::RecognisedStates {
            admission,
            audit,
            channel_binding,
            continuation_control,
            crl_revocation,
            custody,
            delegated_signing,
            in_flight_limit,
            mcp_transport_contract,
            replay,
            retention,
            tls_custody,
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
    replay: Vec<String>,
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
    if let Some(refusal) = online_ocsp_refusal(config.client_ocsp) {
        violations.push(refusal);
    }
    // The mode's one parameter, immediately after it.
    violations.extend(ocsp_responder_violations(config));
    // Same shape, second instance: a deny-list nothing enforces, on a public field.
    violations.extend(decided.cross.x6_unenforceable_deny_list);
    // Third instance of the same shape. This one was not a bypass — the composition root
    // refused it too — but it was stated twice, in two places, with two messages.
    if let Some(refusal) = unaccepted_authz_profile_refusal(config.authz) {
        violations.push(refusal);
    }
    // X2b — TlsCustody × Tls. A delegated handshake key and an exported copy of it are
    // contradictory rather than redundant, and the contradiction is between two machines,
    // so it is decided in pass 2 and only placed here.
    violations.extend(decided.cross.x2b_exclusive_tls_custody);
    // The `ChannelBinding` machine: which binding kinds are deployments at all, and which
    // identity source names a live state. Its `binding == none` and `== lb-assertion`
    // clauses used to sit at the END of this list; they are emitted here now, which is a
    // DELIBERATE precedence change — the mode's own undeployability is what an operator
    // needs first, and it was previously reported after every unrelated limit.
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
    for (value, message) in [
        (
            config.trust_domain.as_str(),
            "--trust-domain is empty: it is a component of every actor identity \
             (role:trust_domain:subject:keyid), so an empty domain removes a coordinate \
             from every actor this deployment names",
        ),
        (
            config.audience.as_str(),
            "--audience is empty: it is the audience verifiers bind a response to, so an \
             empty one makes this deployment's evidence indistinguishable from that of any \
             other deployment that also set none",
        ),
        (
            config.server_signer.as_str(),
            "--server-signer is empty: it is minted as the issuer of every response, and an \
             empty issuer names nobody for a verifier to resolve",
        ),
        (
            config.server_key_id.as_str(),
            "--server-key-id is empty: it names the response key in the trust store and is \
             the default the delegation credential chains to, so an empty value leaves both \
             lookups searching for nothing",
        ),
    ] {
        if value.trim().is_empty() {
            violations.push(message.to_string());
        }
    }
    // The required locators, in the same shape and immediately after. Each of these IS
    // dereferenced at startup, so an empty one eventually fails — but that failure is an
    // observation about the environment, and "this string names nothing" is knowable without
    // one. ADR-MCPRE-056 §5.1 puts the purely-knowable half here, which is also the half
    // that reads as a configuration defect rather than a missing file.
    for (value, message) in [
        (
            config.bind.as_str(),
            "--bind is empty: it names the address this proxy listens on, and an empty value \
             resolves to no address rather than to a default",
        ),
        (
            config.tls_cert.as_str(),
            "--tls-cert is empty: it names the server certificate chain presented on every \
             handshake",
        ),
        (
            config.client_ca.as_str(),
            "--client-ca is empty: it names the roots every client certificate is verified \
             against, which is the whole of who may connect",
        ),
        (
            config.trust_path.as_str(),
            "--trust is empty: it names the trust document the request-signer set is read \
             from, so an empty path leaves no signer trusted and no file to say so",
        ),
    ] {
        if value.trim().is_empty() {
            violations.push(message.to_string());
        }
    }
    // Sixth instance, and the one that reaches furthest into a served request: an empty or
    // scheme-less `--target-uri` does not weaken the request-target reconstruction check,
    // it disables it for every request.
    if let Some(refusal) = target_uri_violation(&config.target_uri) {
        violations.push(refusal);
    }
    // Seventh, and it arrives here from the TRUST plane, where it had no business being:
    // whether a deployment names an inner server is a statement about the request, not
    // about trust, and refusing it there meant the trust plane could reject a
    // configuration after two other planes had already established resources. It is the
    // same class as the clause above — a required locator — so it takes the position next
    // to it.
    if config.inner_http_urls.is_empty() {
        violations.push(
            "the proxy serves over an async HTTP inner plane: pass --inner-http-url <url>. To \
             protect a local stdio MCP server, run it behind the mcp-re-stdio-bridge adapter \
             and point --inner-http-url at the bridge."
                .to_string(),
        );
    }
    // Structure of that list, immediately after its presence: a list holding `""` is not an
    // empty list, so it satisfies the clause above and then contributes a backend the pool
    // will never reach. A trailing comma on the command line produces exactly that.
    if config
        .inner_http_urls
        .iter()
        .any(|url| url.trim().is_empty())
    {
        violations.push(
            "--inner-http-url contains an empty URL: every backend in the inner plane must \
             name one, or the pool carries a member no request can be forwarded to"
                .to_string(),
        );
    }
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
    // ADR-MCPS-023 §A1 (MCPS-57): `None` disables enforcement outright; a lifetime
    // above the ceiling would let a NOT-short-lived cert be audited as
    // `short_lived_cert`. Both fail closed.
    match config.max_client_cert_lifetime {
        None => violations.push(
            "--max-client-cert-lifetime none/0 disables client-cert lifetime enforcement; \
             set a bounded lifetime (default 1h)"
                .to_string(),
        ),
        Some(lifetime) if lifetime > crate::config_state::transport::MAX_CLIENT_CERT_LIFETIME => {
            violations.push(format!(
                "--max-client-cert-lifetime {}s exceeds the ceiling of {}s: Mode-A's \
             revocation posture is short-lived certificates, so a longer lifetime cannot be \
             audited as short_lived_cert; set a lifetime <= {}s",
                lifetime.as_secs(),
                crate::config_state::transport::MAX_CLIENT_CERT_LIFETIME.as_secs(),
                crate::config_state::transport::MAX_CLIENT_CERT_LIFETIME.as_secs(),
            ))
        }
        Some(_) => {}
    }
    // X5 — Limits × Tls: a connection may not outlive the credential that authenticated
    // it, because the client certificate is checked at the handshake and never again.
    violations.extend(decided.cross.x5_connection_outlives_credential);
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
    // The freshness tolerance, held to the bound `VerifierPolicy::new` re-checks. It is a
    // range over a number, which is knowable here,
    // and leaving it to the verifier's constructor meant a deployment learned about it after
    // two planes had established resources. A negative skew narrows the window
    // asymmetrically; one above the bound stops the freshness gate being a freshness gate.
    if !(0..=mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND)
        .contains(&config.max_clock_skew)
    {
        violations.push(format!(
            "--max-clock-skew must be 0..={} seconds (§5.1 bounded skew), got {}: it is the \
             tolerance applied to every verified request AND the replay retain_until, so \
             outside this range the freshness gate stops bounding anything",
            mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
            config.max_clock_skew
        ));
    }
    // The two `ServerLimits` quantities that are legally PRESENT but illegally zero, stated
    // ahead of the timeout clauses because they are the same class — a limit that disables
    // the control it bounds — and an operator reading about limits should meet them together.
    // Neither is `Option`, so absence is not the question and a fail-safe default already
    // applies; only an explicit zero reaches here.
    if config.limits.max_concurrent_connections == 0 {
        violations.push(
            "--max-connections 0 accepts no connection at all: there is no \"unlimited\" \
             spelling, because an unbounded connection count is attacker-controlled \
             buffering ahead of the verify gate. Set a positive ceiling"
                .to_string(),
        );
    }
    if config.limits.drain_grace.is_zero() {
        violations.push(
            "--drain-grace-secs 0 abandons every in-flight request on SIGTERM: the drain \
             window is what lets an admitted request finish before the listener goes away, \
             and the k8s invariant request_deadline <= drain_grace < \
             terminationGracePeriodSeconds cannot hold with a zero window. Set a positive \
             window (default 30s)"
                .to_string(),
        );
    }
    for (value, flag) in [
        (config.limits.read_timeout, "--read-timeout-secs"),
        (config.limits.write_timeout, "--write-timeout-secs"),
        (config.limits.request_deadline, "--request-deadline-secs"),
    ] {
        if value.is_none() {
            violations.push(format!(
                "{flag} 0 disables a slow-loris defense: a peer that trickles bytes then \
                 holds a serve slot indefinitely, up to --max-connections, with no \
                 fail-closed drop. Set a bounded value (default 30s)"
            ));
        }
    }
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
    // X7 — ChannelBinding × Tls: mTLS is terminated locally XOR a forwarded identity is
    // trusted. The two binding-kind clauses that used to close this list moved up into the
    // `ChannelBinding` machine's own position.
    violations.extend(decided.cross.x7_local_mtls_xor_forwarded);
    // X9 — TrustRevocation × DelegatedSigning. The epoch posture is decided once, by the
    // `TrustRevocation` machine, and carried in the classification; nothing is re-derived
    // here (CF-09).
    violations.extend(decided.cross.x9_trust_epoch_posture);
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-MCPRE-058 §8.3: the rule the request-target reconstruction check depends on,
    /// asserted directly on the pure predicate.
    ///
    /// The shapes that matter are the ones `origin_form_of` cannot answer for. A
    /// scheme-less or empty target makes `target_uri_mismatch` return `None` for every
    /// request, which reads as "consistent" — so the check does not weaken, it disappears.
    #[test]
    fn a_target_uri_that_would_disable_the_reconstruction_check_is_refused() {
        for absolute in [
            "https://proxy.internal:8600/mcp",
            "http://127.0.0.1:8600/",
            "https://proxy.internal",
        ] {
            assert!(
                target_uri_violation(absolute).is_none(),
                "an absolute target is the supported shape: {absolute}"
            );
        }
        for unusable in [
            "",
            "   ",
            "/mcp",
            "proxy.internal:8600/mcp",
            "proxy.internal",
        ] {
            let refusal = target_uri_violation(unusable)
                .unwrap_or_else(|| panic!("{unusable:?} leaves the check unanswerable"));
            assert!(
                refusal.contains("--target-uri"),
                "the refusal must name the flag, got: {refusal}"
            );
        }
    }
}
