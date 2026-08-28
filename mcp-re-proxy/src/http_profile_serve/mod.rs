// SPDX-License-Identifier: Apache-2.0
//! The production RFC 9421 serving handler (ADR-MCPRE-050 sole carrier,
//! ADR-MCPRE-051 §1–§4 per-core async data plane).
//!
//! [`HttpProfileProxy`] is the server-side PEP the async fleet runs per request. It
//! is the production promotion of the proven `examples/http_profile_proxy.rs`
//! pipeline onto the per-core async data plane, verifying/signing the **RFC 9421 +
//! RFC 9530 HTTP evidence carrier** — the signature rides in the RFC 9421 HTTP
//! headers, not a JSON-RPC `_meta` block, on the served path.
//!
//! The per-request stage sequence is stated once, in [`crate::exchange_state`], as the
//! transition relation itself rather than as prose. Its one irreversible effect and the
//! typed boundary carried across it are in [`crate::request_stages`]. This module does not
//! restate either as a numbered list: the list that used to be here had drifted out of
//! execution order, which is what a hand-maintained sequence does, and two copies of an
//! ordering is how the second one stops being true.
//!
//! [`handle`](HttpProfileProxy::handle) advances an [`ExchangeProgress`] as each operation
//! establishes its state, and every refusal reads that value rather than inferring from its
//! own position in the function. What the exchange may claim about its effects — did the
//! backend act, was a human's approval spent — is a fact about the machines, not about
//! which line refused.
//!
//! **Nothing irreversible happens on a request's behalf until it is both admitted and
//! answerable.** The continuation read and the delegated-key snapshot are ordered the way
//! they are for that reason: a destructive continuation read before admission let an
//! about-to-be-rejected request destroy a live approval leg, and discovering a missing
//! delegated key only at signing time meant the backend had already run — and 503 is a
//! status clients retry, so the action ran twice.
//!
//! Any fail-closed step emits a delegated-signed rejection receipt instead. A
//! one-way notification (a `method` with no `id`) is answered with a delegated
//! bodyless 202 whose credential rides in the covered `mcp-re-delegation` header
//! (#424).

use std::sync::Arc;

use mcp_re_core::McpReError;

use crate::refusal::Refusal;
use crate::refusal::RefusalCause;

/// The validity a signed response may advertise — obtained here, derived only there.
pub(crate) mod signing_window;

/// What the proxy asserts under its own credential when it refuses. The assembly asks
/// this owner for a receipt; it does not assemble one.
pub(crate) mod receipt;

/// The PEP's read/write boundary inside the client's JSON-RPC body: what it reads out,
/// what it strips because it owns it, and what it writes because it is entitled to.
mod body_boundary;

/// The ADR-MCPS-047 continuation plane: a human's approval opened, read without being
/// spent, spent exactly once, and recorded so any replica can answer it.
mod continuation;

/// What the backend's reply IS: read once, here, so no later authority re-reads it.
mod reply;

/// The backend seam, and what the exchange may claim about execution given what it
/// managed to do.
mod inner_plane;

/// Durable responsibility for a served exchange: taken before the side effects run, and
/// discharged with what was actually served.
mod retention;

/// What makes an inbound message a request this deployment reads at all: whose it is,
/// whether it is addressed here, and whether it is legal MCP.
mod request_admission;
pub use body_boundary::extract_request_state;
use body_boundary::ForwardedBody;
use continuation::Retirement;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ExecutionDisposition;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::RetainedContinuation;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedContextPolicy;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::VerifierPolicy;
use reply::ReplyClass;
use reply::ValidatedReply;

use crate::admission_enforcer::AdmissionEnforcement;
use crate::admission_enforcer::AdmissionEnforcer;
use crate::admission_source::AsyncAdmissionSource;
use crate::async_inner::AsyncInnerServer;
use crate::async_serve::ServedHttpRequest;
use crate::async_serve::ServedHttpResponse;
use crate::authorization::AuthorizationEvaluator;
use crate::authorization::AuthorizationPosture;
use crate::authorization::AuthorizationStage;
use crate::communication_assurance::request_peer_binding::http_profile_adapter::verified_request_subject;
use crate::communication_assurance::RequestPeerBindingFacts;
use crate::continuation_store::AsyncContinuationStore;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::exchange_state::ContinuationState;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::exchange_state::OpenLeg;
use crate::exchange_state::RetrySemantics;
use crate::http_profile_dispatch::dispatch_request_with_async_tier;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::request_stages::ReadyForDispatch;
use crate::request_stages::RetentionDisposition;
use crate::transport::TransportBinding;
use signing_window::SigningWindow;

/// Default lifetime of a recorded MRTR continuation in the shared correlation store
/// (ADR-MCPS-047): long enough for a client to answer an `InputRequiredResult`,
/// bounded so an unanswered continuation does not linger. Overridable via
/// [`HttpProfileProxy::with_continuation_store`].
pub const DEFAULT_CONTINUATION_TTL_SECS: i64 = 300;

/// The trust seam: resolve a presented keyid FOR a signing slot to a structured
/// actor (identity + verification key). A key not trusted for `slot` resolves to
/// `None` (fail closed). `Send + Sync` so one `HttpProfileProxy` serves every core.
/// The proxy's trust seam. Returns a [`ResolverOutcome`] rather than an `Option` so a
/// store OUTAGE is distinguishable from an UNKNOWN KEYID (C079): both fail closed, but
/// only one of them is a statement about the caller's key.
pub type ActorResolver = Box<dyn Fn(&str, SignerSlot) -> ResolverOutcome + Send + Sync>;

/// Resolves an admission assertion's `issuer_kid` to the admission authority's root
/// key. `None` means the issuer is not one this deployment trusts to admit anything —
/// a kid never introduces trust, so an assertion naming an unresolvable issuer is
/// refused exactly as an unknown request keyid is.
///
/// Separate from [`ActorResolver`] because admitting a workload and signing a message
/// are different authorities: a key trusted for one must not be usable for the other
/// by sharing a seam.
pub type AdmissionAuthorityResolver = Arc<dyn Fn(&str) -> Option<VerificationKey> + Send + Sync>;

/// One exchange's identity, as every stage past VERIFIED needs it.
///
/// Grouped because these four travel together and never independently: the request a
/// refusal binds to, the evidence that makes binding possible, the actor it is attributed
/// to, and the instant the whole exchange is judged at. `now` is fixed for the exchange, so
/// a key valid at ANSWERABLE is still valid at RESPONSE-SIGNED.
pub(super) struct Exchange<'a> {
    http_req: &'a HttpRequest,
    verified: &'a VerifiedMcpRequest,
    actor_id: &'a str,
    now: i64,
    /// The delegated key snapshotted at ANSWERABLE, once the exchange has one.
    ///
    /// `None` only before that stage. Every refusal from ANSWERABLE onward signs with this
    /// snapshot rather than re-asking the signer: `now` is fixed for the exchange, so a key
    /// valid there is valid here, while a signer retired in between makes the re-ask return
    /// nothing and degrades the refusal to an unsigned error — on exactly the exits that
    /// most need to state, under signature, that the backend may have acted.
    key: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
}

/// The RFC 9421 server-side PEP run by the async fleet (ADR-MCPRE-051).
///
/// Holds ONLY the RFC 9421 serving state — the verifier, signer, and evidence all
/// operate on the HTTP message, not a JSON-RPC `_meta` envelope. `Send + Sync`
/// (MCPRE-111): one instance is
/// shared across all per-core runtimes.
pub struct HttpProfileProxy {
    /// Who may speak, to whom, and under what acceptance policy — the three inputs that
    /// decide whether an inbound message is a request this deployment reads at all.
    requests: request_admission::RequestAdmission,
    /// The response-signing authority: the delegated credential, the configured validity,
    /// and the receipt a refusal is served as. Held as one owner so the reply path and the
    /// refusal path cannot drift apart in what they sign under.
    responses: receipt::ResponseSigning,
    /// The authoritative async replay tier (ADR-MCPRE-051 §4).
    replay_async: crate::async_replay::AsyncReplayTier,
    /// Deployment replay-durability posture (fleet-strict + declared tier).
    dispatch_cfg: ProxyDispatchConfig,
    /// The backend seam, and the reading of every answer it can give.
    inner_async: inner_plane::InnerPlane,
    /// Optional Mode-A transport binding: bind the verified request actor to the
    /// mTLS peer identity. `None` disables the channel binding.
    transport_binding: Option<TransportBinding>,
    /// What this deployment decides authorization with (ADR-MCPRE-065). Deciding with
    /// nothing is one of its states, and it claims nothing rather than permitting.
    authorization: AuthorizationStage,
    /// The ADR-MCPS-047 continuation plane: the shared correlation tier and the bounded
    /// lifetime its entries run under, held as one owner so a TTL never outlives the
    /// question of whether there is a store to apply it to.
    continuations: continuation::ContinuationPlane,
    /// Whether to carry verified context to the inner server (#415 rev 2 §10).
    /// Default `Disabled`: the context is the PEP's conclusion, unsigned by
    /// design, so it is only meaningful over a channel the PEP alone can write to
    /// — an operator asserts that, and nothing here can check it.
    verified_context_policy: VerifiedContextPolicy,
    /// The ADR-MCPS-035 security-audit sink. `None` is the explicit no-emission
    /// posture; a sink failure never fails a request (see [`crate::audit_sink`]).
    audit: crate::audit_sink::MaybeAuditSink,
    /// The §7 admission-currency gate (ADR-MCPRE-053). `None` disables admission
    /// entirely: the binding, if a call carries one, is verified evidence that
    /// decides nothing.
    admission: Option<AdmissionEnforcer>,
    /// ADR-MCPRE-054 evidence retention. `None` is the default: nothing is retained
    /// and the request path is unchanged. When present, every served exchange is
    /// retained BEFORE the response is handed back, and a retention failure refuses the
    /// exchange — a deployment that has turned this on is asserting it can account for
    /// what it served.
    retention: retention::Retention,
}

impl HttpProfileProxy {
    /// Install the ADR-MCPS-035 audit sink. Without one the serving path emits no
    /// security record — which is what `docs/spec/security-boundary.md` S9 describes as
    /// delivered, so a deployment relying on that surface must install one.
    pub fn with_audit_sink(
        mut self,
        sink: std::sync::Arc<dyn crate::audit_sink::AuditSink>,
    ) -> Self {
        self.audit = Some(sink);
        self
    }

    /// Install ADR-MCPRE-054 evidence retention.
    ///
    /// Turning this on changes what the deployment STORES about every call — the full
    /// request and response messages, which is what a later SCITT statement commits to
    /// and what an auditor recomputes the handles from. It is off unless installed, and
    /// once installed a retention failure refuses the exchange rather than serving a
    /// call the deployment cannot account for.
    pub fn with_evidence_retention(
        mut self,
        retention: Arc<crate::transparency::EvidenceRetention>,
    ) -> Self {
        self.retention = retention::Retention::to(retention);
        self
    }

    /// Construct the serving PEP (ADR-MCPRE-052 delegated-signing — the only response-
    /// signing mode). `resolve_actor` is the trust seam; `expected_audience` the
    /// verifier audience; `dispatch_cfg`/`inner_async` the replay/inner planes. There
    /// is no directly-held server key on the serving struct — only the shared
    /// [`DelegatedServerSigner`] whose snapshot the cold-path rotor keeps fresh. Every
    /// response and rejection is signed by the active delegated key + inline
    /// credential, failing closed when none is valid.
    #[allow(clippy::too_many_arguments)]
    pub fn new_delegated(
        resolve_actor: ActorResolver,
        expected_audience: AudienceTuple,
        replay_async: crate::async_replay::AsyncReplayTier,
        dispatch_cfg: ProxyDispatchConfig,
        inner_async: Box<dyn AsyncInnerServer>,
        sig_ttl_secs: i64,
        delegated_signer: Arc<DelegatedServerSigner>,
    ) -> Self {
        HttpProfileProxy {
            requests: request_admission::RequestAdmission::new(resolve_actor, expected_audience),
            responses: receipt::ResponseSigning::new(delegated_signer, sig_ttl_secs),
            replay_async,
            dispatch_cfg,
            inner_async: inner_plane::InnerPlane::over(inner_async),
            transport_binding: None,
            continuations: continuation::ContinuationPlane::disabled(),
            verified_context_policy: VerifiedContextPolicy::default(),
            authorization: AuthorizationStage::default(),
            audit: None,
            admission: None,
            retention: retention::Retention::none(),
        }
    }

    /// Attach a verifier-local acceptance policy (§4.1 MCP transport contract,
    /// §5.1 clock skew, §13.1 algorithm registry). A deployment on MCP 2026-07-28
    /// passes `VerifierPolicy::default().with_mcp_transport(McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"]))`
    /// to enforce required-header presence and version policy on the served path.
    pub fn with_verifier_policy(mut self, policy: VerifierPolicy) -> Self {
        self.requests.under(policy);
        self
    }

    /// Carry verified context to the inner server over an EXPLICITLY TRUSTED
    /// channel (#415 rev 2 §10, MCPRE-429).
    ///
    /// Calling this asserts that only this PEP can write to the inner server —
    /// loopback, a same-pod sidecar, a UNIX socket. The carrier has no signature
    /// (the inner server is not meant to re-evaluate trust), so if anything else
    /// can reach that server, it can assert any context it likes and the inner
    /// server cannot tell. There is no cryptographic fallback: the channel IS the
    /// trust, which is why this is an explicit call and never a default.
    ///
    /// The reserved-field guard runs regardless of this setting — caller-seeded
    /// context is stripped whether or not the carrier is on.
    pub fn with_verified_context_carrier(mut self, policy: VerifiedContextPolicy) -> Self {
        self.verified_context_policy = policy;
        self
    }

    /// Bind the verified request actor to the mTLS peer identity (Mode A, ADR-MCPS-014).
    ///
    /// A named capability rather than a policy parameter. The caller chooses whether the
    /// channel is bound; it does not get to supply the rule that decides, because a
    /// supplied rule can admit everything while the serving path still records the
    /// exchange as bound. See [`TransportBinding`].
    pub fn with_exact_match_transport_binding(mut self) -> Self {
        self.transport_binding = Some(TransportBinding::exact_match());
        self
    }

    /// Install a binding the configuration owner recognised.
    ///
    /// `pub(crate)`, so the composition root can pass the binding derived from the
    /// deployment's channel-binding state while no crate outside can install one at all.
    pub(crate) fn with_transport_binding(mut self, binding: TransportBinding) -> Self {
        self.transport_binding = Some(binding);
        self
    }

    /// Install the authorization mechanism this deployment decides under
    /// (ADR-MCPRE-065).
    ///
    /// A named capability, not a policy parameter, for the same reason the transport
    /// binding is one: the caller chooses WHETHER a policy decides, and supplies the
    /// mechanism whole. Without this call the deployment authorizes nothing and says so —
    /// it does not quietly permit.
    pub fn with_authorization(mut self, evaluator: Arc<dyn AuthorizationEvaluator>) -> Self {
        self.authorization = AuthorizationStage::under(evaluator);
        self
    }

    /// AUTHORIZED — may this actor perform this action (ADR-MCPRE-065)?
    ///
    /// ```text
    /// ensures   Ok  => a policy permitted this action, or no policy is deployed
    ///           Err => 403, bound
    /// forbids   burning a nonce, running the backend
    /// refusal   free — nothing has happened
    /// ```
    ///
    /// Ordered after admission and before everything irreversible. Admission's facts are an
    /// input to the decision, and running a tool for an action no policy permits is exactly
    /// what a free refusal here prevents.
    ///
    /// The posture it returns is not advisory: [`ReadyForDispatch`] carries a body that only
    /// `AuthorizationPosture::release` can produce, so a pipeline that dropped this stage
    /// would not compile at the dispatch. What the DECISION means is
    /// [`AuthorizationStage`]'s; what a refusal costs the client is the machine's.
    fn authorization_stage(
        &self,
        ex: &Exchange<'_>,
        bound: Option<&RequestPeerBindingFacts>,
    ) -> Result<AuthorizationPosture, Refusal> {
        self.authorization
            .decide(ex.verified, &ex.http_req.body, bound)
            .map_err(|refusal| Refusal::before_admission(refusal, 403))
    }

    /// Wire the MRTR continuation correlation store (ADR-MCPS-047) with a bounded
    /// entry TTL. The open leg records `{previous_request_base,
    /// input_required_response_base}` under `H(requestState)`; the answer leg — on
    /// ANY replica — takes them one-shot to drive the pure continuation binding.
    pub fn with_continuation_store(
        mut self,
        store: Arc<dyn AsyncContinuationStore>,
        ttl_secs: i64,
    ) -> Self {
        self.continuations = continuation::ContinuationPlane::wired(store, ttl_secs);
        self
    }

    /// Enforce §7 admission currency (ADR-MCPRE-053) against an authoritative source.
    ///
    /// Without this the assertion and its binding are verified evidence that decides
    /// nothing: a call carrying a fresh, correctly-bound assertion is served even
    /// after the workload's admission has been superseded or revoked, because
    /// currency is a comparison against state only the deployment can supply.
    ///
    /// `enforcement` decides what an admission-free request means. It is a
    /// deployment's call, not a default: `Required` on a fleet that does not issue
    /// assertions refuses every call, and `Optional` on one that does silently
    /// accepts a caller who simply omits the evidence.
    pub fn with_admission(
        mut self,
        source: Arc<dyn AsyncAdmissionSource>,
        policy: AdmissionPolicy,
        enforcement: AdmissionEnforcement,
        resolve_authority: AdmissionAuthorityResolver,
    ) -> Self {
        self.admission = Some(AdmissionEnforcer::new(
            source,
            policy,
            enforcement,
            resolve_authority,
        ));
        self
    }

    /// ADMISSION-CHECKED — the §7 currency gate (ADR-MCPRE-053).
    ///
    /// ```text
    /// ensures   Ok  => this call acts under an admission this deployment accepts, or
    ///                  admission is not enforced here
    ///           Err => 403, bound
    /// forbids   burning a nonce, running the backend
    /// refusal   free — nothing has happened
    /// ```
    ///
    /// Placed before replay admission and the inner round trip, because both are
    /// irreversible: burning a nonce and running a tool on behalf of a workload whose
    /// admission has been revoked is precisely what this exists to prevent.
    ///
    /// The DECISION belongs to [`AdmissionEnforcer`], next door, which owns the
    /// deployment's posture and the degraded-window arithmetic. What is here is the
    /// ordering and the prerequisite: `bound` — the ADR-MCPRE-064 §16 predecessor, never an
    /// identity source — travels WITH the decision, so an authority downstream receives
    /// what the decision was taken over instead of re-deriving it, and the
    /// *bound* / *not claimed* distinction survives the stage that consumed it.
    ///
    /// Names its refusal like every other stage rather than minting one. The retry contract
    /// is a fact about the whole exchange, which no stage can state; the machine states it,
    /// once, where [`HttpProfileProxy::refuse`] signs.
    async fn admission_stage(
        &self,
        ex: &Exchange<'_>,
        bound: Option<&RequestPeerBindingFacts>,
    ) -> Result<Established<Option<RequestPeerBindingFacts>>, Refusal> {
        let admitted = || Established::new(bound.cloned(), ExchangeEvent::AdmissionCurrencyChecked);
        let Some(enforcer) = self.admission.as_ref() else {
            return Ok(admitted());
        };
        match enforcer
            .decide(
                ex.verified,
                ex.actor_id,
                self.requests.audience_id(),
                ex.now,
            )
            .await
        {
            Ok(()) => Ok(admitted()),
            Err(e) => Err(Refusal::before_admission(e, 403)),
        }
    }

    /// Turn a stage's decision into the signed refusal the client receives.
    ///
    /// The assembly's only contribution is the exchange machine's verdict: the retry
    /// contract is a fact about the whole exchange, so a stage could not state it even if it
    /// tried. WHICH receipt that becomes belongs to [`receipt::ResponseSigning`].
    fn refuse(
        &self,
        ex: &Exchange<'_>,
        refusal: Refusal,
        progress: &ExchangeProgress,
    ) -> ServedHttpResponse {
        self.responses
            .refuse(&self.audit, ex, refusal, Self::disposition(progress))
    }

    /// Serve one request end to end on the async data plane. Always returns a
    /// [`ServedHttpResponse`] — a signed reply on success, a signed rejection receipt
    /// on any fail-closed step. Only the replay admission and the inner round-trip
    /// are awaited; the RFC 9421 verify/sign are inline CPU (ADR-MCPRE-051 §2).
    /// The NOTIFICATION arm: a signed bodyless 202 for a message with no JSON-RPC `id`.
    ///
    /// ADR-MCPRE-058 §9.2 — lifted out of `handle` whole, and it is a whole arm: every path
    /// through it returns, so extracting it removes a terminal branch rather than a slice of
    /// the pipeline. The stage's position in `handle` is unchanged.
    ///
    /// This runs AFTER the backend has acted. The 202 states that the enforcement boundary
    /// authenticated and accepted the message — never that any action completed (#418).
    ///
    /// Retention covers this exit on the same terms as a bodied reply. Leaving it out let a
    /// client decide whether a call it had already executed was accountable, by the single
    /// act of omitting the `id`.
    #[allow(clippy::too_many_arguments)]
    async fn answer_notification(
        &self,
        http_req: &HttpRequest,
        window: &SigningWindow,
        now: i64,
        verified: &mcp_re_http_profile::VerifiedMcpRequest,
        actor_id: String,
        retention: &RetentionDisposition,
        execution: ExecutionDisposition,
    ) -> ServedHttpResponse {
        let a = window.key();
        match sign_delegated_accepted_202(
            http_req,
            &a.credential,
            a.key.as_ref(),
            &a.delegated_kid,
            now,
            window.expires(),
        ) {
            Ok(ack) => {
                // Retention covers this exit on the SAME terms as the bodied reply.
                // The backend has already run by here, so leaving it out let a
                // client decide whether a call it had executed was accountable, by
                // the single act of omitting the JSON-RPC `id`.
                if let Some(rejection) = self
                    .retain_accepted(
                        http_req,
                        &ack,
                        now,
                        Some(verified.evidence()),
                        actor_id.clone(),
                        retention,
                        execution,
                        Some(window.shared()),
                    )
                    .await
                {
                    return rejection;
                }
                // The signed bodyless 202 IS the signed response for a notification,
                // and it is returned on this line — so the record describes bytes the
                // client actually receives.
                crate::audit_record::record_to(
                    &self.audit,
                    crate::audit_record::AuditSubject::response(
                        mcp_re_core::audit::AuditEvent::response_signed(),
                    ),
                    Some(actor_id),
                    202,
                    now,
                );
                served(ack)
            }
            Err(e) => self.responses.response_rejection(
                &self.audit,
                http_req,
                &RefusalCause::from(e),
                500,
                now,
                Some(verified.evidence()),
                Some(actor_id),
                execution,
                Some(window.shared()),
            ),
        }
    }

    /// What the exchange machine's cross-machine state means on the wire.
    ///
    /// The only place the two vocabularies meet, and now a total map: every consequence the
    /// machine can derive is stated.
    ///
    /// `NotRetrySafe` used to map to `Unstated`, on the reasoning that past the threshold the
    /// frozen wire code already carried the contract. It did not. Exactly ONE post-dispatch
    /// code said anything — `evidence_retention_indeterminate`, which `retry_semantics`
    /// special-cased by name — so an illegal upstream response, a signing failure and a
    /// continuation-record failure at **HTTP 503** all returned a bare status after the tool
    /// had run, and 503 is the status clients retry (ADR-MCPRE-058 §10, ruling D1). Deriving
    /// it from the machine rather than from an allowlist of tokens is what stops the next
    /// post-dispatch exit from silently not being on the list.
    fn disposition(progress: &ExchangeProgress) -> ExecutionDisposition {
        match progress.retry_semantics() {
            RetrySemantics::SafeNothingExecuted => ExecutionDisposition::NothingExecuted,
            RetrySemantics::RequiresNewElicitation => {
                ExecutionDisposition::ApprovalSpentNothingExecuted
            }
            RetrySemantics::NotRetrySafe => ExecutionDisposition::PossiblyExecuted,
        }
    }

    // ===================== THE REQUEST PIPELINE, STAGE BY STAGE =====================
    //
    // ADR-MCPRE-058 §9.2 + ADR-MCPRE-057 §4. One function per transition of the request
    // machine, each with an explicit contract: what it ensures, what it may not do, and
    // whether its refusal is free.
    //
    // A stage that SUCCEEDS returns an `Established<T>` naming the event it justifies, so
    // the state a stage requires is not written here at all: it is the relation's, and
    // `transition` refuses the event from anywhere else. `handle` cannot state an event,
    // and cannot reach a stage's value without the machine learning the stage ran.
    //
    // The point is not fewer lines. It is that each transition can be tested — and
    // eventually PROVED — on its own, rather than only as a property of the whole
    // pipeline. A stage that returns `Err` names its refusal and never signs one.
    //
    // Refusals take their retry contract from the machine, never from their own position:
    // every one of them passes `Self::disposition(progress)`.

    /// TRANSPORT-BOUND — Mode-A: the verified request actor must be the mTLS peer.
    /// ```text
    /// ensures   Ok  => authenticated peer == resolved actor's SUBJECT (never `actor_id()`)
    ///           Err => 403, bound to the request via `;req`
    /// forbids   any effect on the request's behalf
    /// refusal   free
    /// ```
    /// No policy installed passes: the channel is then not CLAIMED to be bound.
    fn transport_binding_stage(
        &self,
        ex: &Exchange<'_>,
        peer: Option<&crate::communication_assurance::AuthenticatedChannelPeer>,
    ) -> Result<Established<Option<RequestPeerBindingFacts>>, Refusal> {
        let checked = ExchangeEvent::TransportBindingChecked;
        let Some(binding) = &self.transport_binding else {
            return Ok(Established::new(None, checked)); // NOT CLAIMED to be bound
        };
        let subject = verified_request_subject(ex.verified.resolved_actor());
        let Ok(bound) = binding.bind(peer, subject) else {
            return Err(Refusal::before_admission(
                McpReError::TransportBindingFailed,
                403,
            ));
        };
        Ok(Established::new(Some(bound), checked))
    }

    /// REPLAY-ADMITTED — async §4 replay admission plus the continuation binding.
    ///
    /// ```text
    /// ensures   Ok  => this exact request has never been admitted before, and any
    ///                  continuation it carries binds to the retained bases
    ///           Err => 409, bound
    /// forbids   running the backend
    /// refusal   free — the nonce is burned strictly last
    /// ```
    async fn replay_admission_stage(
        &self,
        ex: &Exchange<'_>,
        continuation: Option<RetainedContinuation<'_>>,
    ) -> Result<Established<()>, Refusal> {
        // The outcome value is not consulted: admission is the property, and a stage that
        // read the outcome to decide something would be making a second decision the
        // pipeline does not have a state for.
        dispatch_request_with_async_tier(
            ex.verified,
            &self.replay_async,
            continuation,
            &self.dispatch_cfg,
            ex.now,
        )
        .await
        .map(|_| Established::new((), ExchangeEvent::ReplayAdmitted))
        .map_err(|e| Refusal::before_admission(e, 409))
    }

    /// ANSWERABLE — can this request be answered AT ALL?
    ///
    /// ```text
    /// ensures   Ok  => a delegated key exists, so a reply can be signed later
    ///           Err => 503, bound
    /// forbids   retiring a continuation, running the backend
    /// refusal   free — and this is the whole point of asking here
    /// ```
    ///
    /// Asked BEFORE the two irreversible steps. Discovering a missing key only at signing
    /// time meant the tool call had already executed and the client got a 503 — a
    /// transient-looking status it retries, so the action runs twice.
    fn answerable_stage(&self, ex: &Exchange<'_>) -> Result<Established<SigningWindow>, Refusal> {
        // The snapshot is taken ONCE and signs the reply below: `now` is fixed for the
        // whole request, so a key valid here is valid there. The window it opens is what
        // the reply may advertise — this stage does not compute that, the window is it.
        match self.responses.window(ex.now) {
            Some(window) => Ok(Established::new(
                window,
                ExchangeEvent::DelegatedKeySnapshotted,
            )),
            None => Err(Refusal::before_admission(
                McpReError::DelegatedSigningUnavailable,
                503,
            )),
        }
    }

    /// FORWARDED — strip the proxy-owned `_meta` so the backend sees clean MCP.
    ///
    /// ```text
    /// ensures   Ok  => a body the inner server may receive, carrying verified context
    ///                  the caller did not author
    ///           Err => 500, bound
    /// forbids   running the backend
    /// refusal   free of execution; the approval may already be spent
    /// ```
    ///
    /// Fails closed when the trusted carrier is on but the context could not be written:
    /// the inner server would otherwise get an ordinary-looking request with no verified
    /// context, which is a silent downgrade to an unauthenticated call.
    fn forward_body_stage(&self, ex: &Exchange<'_>) -> Result<Established<Vec<u8>>, Refusal> {
        let forwarded = ForwardedBody::prepare(
            &ex.http_req.body,
            ex.verified,
            self.verified_context_policy,
            ex.now,
        )
        .map_err(|e| Refusal::after_admission(e, 500))?;
        Ok(Established::new(
            forwarded.into_bytes_for_inner(ex.actor_id),
            ExchangeEvent::ForwardBodyPrepared,
        ))
    }

    /// RESPONSE-SIGNED — the enforcement boundary puts its signature on the reply.
    ///
    /// ```text
    /// ensures   Ok  => `response` carries the delegated signature bound to THIS request,
    ///                  and the returned bytes are its signature base
    ///           Err => 500, bound
    /// refusal   NOT free
    /// ```
    #[allow(clippy::too_many_arguments)]
    fn sign_reply_stage(
        &self,
        ex: &Exchange<'_>,
        response: &mut HttpResponse,
        a: &mcp_re_http_profile::ActiveDelegatedKey,
        expires: i64,
    ) -> Result<Established<Vec<u8>>, Refusal> {
        // Scoped so the timer covers the signature and nothing after it.
        let sign_result = {
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Sign);
            sign_delegated_response_full(
                response,
                ex.http_req,
                ex.verified.evidence(),
                &a.server_signer,
                &a.credential,
                a.key.as_ref(),
                &a.delegated_kid,
                ex.now,
                expires,
            )
        };
        sign_result
            .map(|base| Established::new(base, ExchangeEvent::ResponseSigned))
            .map_err(|e| Refusal::after_admission(e, 500))
    }

    /// Serve one request end to end on the async data plane.
    ///
    /// This function is the ASSEMBLY, not the work. It composes the stages above and
    /// nothing else; each stage carries its own contract, so what is visible here is the
    /// pipeline itself — which step follows which, and where the execution threshold lies.
    ///
    /// It does not advance the request machine. A stage's success arrives as an
    /// [`Established`], and `progress.establish` is the only way to open one — so the
    /// machine learns that a step ran by the assembly CONSUMING its result, not by the
    /// assembly remembering to say so afterwards. The events written out below are the
    /// assembly's own facts: the dispatch, the retirement decided from a `Retirement`, and
    /// the terminals.
    ///
    /// Every refusal is minted by `refuse` from a `Refusal` the stage named. `handle` never
    /// re-decides what a failure means, which is why no exit here has to know how far the
    /// exchange had got: the machine already does.
    pub async fn handle(&self, req: ServedHttpRequest, now: i64) -> ServedHttpResponse {
        // The request machine (ADR-MCPRE-057 §4), advanced by each stage as it establishes
        // its state. Every refusal reads its cross-machine state to decide what the client
        // may safely do — which no single stage knows on its own.
        let mut progress = ExchangeProgress::new();
        let http_req = HttpRequest {
            method: req.method,
            target_uri: req.target_uri,
            headers: req.headers,
            body: req.body,
        };

        let verified = match self.requests.verify(&http_req, now) {
            Ok(v) => progress.establish(v),
            // Signed inline rather than through `refuse`: there is no `Exchange` yet,
            // because nothing about the request is trusted.
            Err(refusal) => {
                return self.responses.rejection(
                    &self.audit,
                    &http_req,
                    &refusal.cause,
                    refusal.status,
                    now,
                    None,
                    None,
                    Self::disposition(&progress),
                    None,
                )
            }
        };

        // The verifier-resolved actor, carried into every audit record from here on: a
        // denial after resolution knows who was denied, and dropping that is dropping the
        // attribution this surface exists to provide.
        let actor_id = verified.resolved_actor().actor_id();
        let mut ex = Exchange {
            http_req: &http_req,
            verified: &verified,
            actor_id: &actor_id,
            now,
            key: None,
        };

        // What this request IS, decided once and carried: a legal JSON-RPC 2.0 request, and
        // the outstanding id that selects its terminal.
        let outstanding = match self.requests.validate_envelope(&http_req) {
            Ok(id) => id,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        let bound = match self.transport_binding_stage(&ex, req.peer.as_ref()) {
            Ok(bound) => progress.establish(bound),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        // The prerequisite chain, carried rather than re-derived: the binding reaches
        // admission, and what admission DECIDED OVER reaches authorization. Authorization
        // receives the ADR-MCPRE-064 product whole; it never reopens it.
        let decided_over = match self.admission_stage(&ex, bound.as_ref()).await {
            Ok(admitted) => progress.establish(admitted),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        // AUTHORIZED. This deployment's honest posture — a policy's grant, or the fact
        // that no policy is deployed. Held across the stages below because the dispatch
        // consumes it: the body `ReadyForDispatch` carries has exactly one producer, and
        // that producer is this value.
        let authorized = match self.authorization_stage(&ex, decided_over.as_ref()) {
            Ok(posture) => posture,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        let prep = match self
            .continuations
            .prepare(&ex, self.requests.audience_id())
            .await
        {
            Ok(prep) => progress.establish(prep),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        if prep.was_peeked() {
            // A `peek`, so nothing is spent yet — a refusal from here is still an ordinary
            // retry, which is the whole reason the read is not a `consume`.
            progress.observe_continuation(ContinuationState::Peeked);
        }

        match self.replay_admission_stage(&ex, prep.binding()).await {
            Ok(admitted) => progress.establish(admitted),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        }

        let window = match self.answerable_stage(&ex) {
            Ok(established) => progress.establish(established),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        // Carried on the exchange so every refusal below signs with the key the reply
        // itself would have used, rather than re-asking a signer that may have been
        // retired in between and degrading to an unsigned error.
        ex.key = Some(window.shared());

        match self.continuations.retire(prep.answer_key()).await {
            Retirement::NotInvolved => {}
            // The human's approval is now spent. Every refusal from here to the dispatch
            // must say so: the action did not run, but an ordinary retry cannot make it run
            // either.
            Retirement::Retired => progress.observe_continuation(ContinuationState::Consumed),
            // The store answered: there was nothing live under this key. A replayed or
            // spliced continuation, and a statement about the caller.
            Retirement::AlreadyAnswered => {
                return self.refuse(
                    &ex,
                    Refusal::before_admission(McpReError::ContinuationBindingFailed, 409),
                    &progress,
                )
            }
            // The store did not answer, so the `DEL` may have executed with its reply lost.
            // The approval is recorded as spent BEFORE the refusal is signed: a new
            // elicitation is the correct remedy whether or not the entry survived, whereas
            // the ordinary retry the alternative implies passes replay admission on a fresh
            // nonce and then fails as already-answered, with nothing left to answer. The
            // refusal names the shared tier rather than the caller's continuation, because
            // the fault is this deployment's.
            Retirement::Indeterminate => {
                progress.observe_continuation(ContinuationState::Consumed);
                return self.refuse(
                    &ex,
                    Refusal::before_admission(McpReError::ReplayCacheUnavailable, 503),
                    &progress,
                );
            }
        }
        progress.advance(ExchangeEvent::ContinuationRetired);

        // ADR-MCPS-035: the request is now ADMITTED. Emitted here rather than at signature
        // verification so `accepted` and `rejected` are MUTUALLY EXCLUSIVE per request: a
        // signature-valid request that then loses replay admission is a rejection, and a
        // record claiming both would make the surface useless for attribution.
        //
        // Every exit BELOW this line records `mcp-re.response.rejected` instead — the
        // request was admitted, so a `request.rejected` record would contradict this one,
        // and the fault is on the response side anyway.
        crate::audit_record::record_to(
            &self.audit,
            crate::audit_record::AuditSubject::request(
                mcp_re_core::audit::AuditEvent::request_accepted(),
                // The live product, asked for its own projection. Nothing here reconstructs
                // an authorization fact, and an unconfigured deployment says so rather than
                // reading as an allow (ADR-MCPRE-066 §1.1, invariant 5).
                authorized.audit_facet(),
            ),
            Some(actor_id.clone()),
            200,
            now,
        );

        let forwarded = match self.forward_body_stage(&ex) {
            Ok(body) => progress.establish(body),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        // The inner plane is asked FIRST. Local saturation and a fully-ejected backend set
        // are facts about this proxy, knowable without writing anything, and refusing on
        // them after the reservation leaves a durable marker asserting that this request
        // crossed the execution threshold — for a request that provably never reached a
        // backend. The reservation is therefore the last refusal of any kind before the
        // dispatch, and the relation says so: `RetentionReserved` is the last pre-dispatch
        // state, so a pipeline that asked in the other order would be refused rather than
        // recorded in whichever order the relation happened to prefer.
        match self.inner_async.admit() {
            Ok(accepted) => progress.establish(accepted),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        }
        let retention = match self.retention.reserve(ex.http_req).await {
            Ok(disposition) => progress.establish(disposition),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        // ===================== IRREVERSIBLE INNER DISPATCH =====================
        //
        // Every pre-dispatch prerequisite is now in hand, and `ReadyForDispatch` is what
        // says so: it cannot be built without them, and the dispatch consumes it. Past this
        // line no exit can claim nothing happened — which is why every one of them is a
        // `response_rejection` rather than a `rejection`.
        let ready = ReadyForDispatch::new(authorized.release(forwarded), window, retention);
        // BEFORE the await, not after it. Once the request is committed to the backend the
        // exchange must read as possibly-executed, whatever the dispatch goes on to return:
        // a state entered only on the way out would leave a cancelled or panicking dispatch
        // claiming nothing happened.
        progress.advance(ExchangeEvent::BackendDispatched);
        let outcome = self.inner_async.dispatch(ready.forwarded()).await;
        let (outcome, window, retention) = ready.dispatched(outcome).into_parts();

        // NOTIFICATION — a one-way message with no JSON-RPC `id` is answered with a signed
        // bodyless 202 rather than a bodied reply (#424 / #418). The branch is here because
        // everything below assumes a bodied reply, and the 202 is its own terminal: it says
        // the boundary accepted the message, never that anything completed.
        //
        // Decided from the REQUEST, which is where the fact lives — a notification is a
        // message the client sent with no `id`, and no reply can make it one or stop it
        // being one. Whatever the backend returned for it is discarded unread, as JSON-RPC
        // requires.
        //
        // The reply itself is discarded, as JSON-RPC requires — but not the fact of whether
        // the inner plane received the message at all. A 202 minted for a message that was
        // never transmitted, or whose transport failed after transmission, is a signed
        // statement from the enforcement boundary that a backend accepted something no
        // backend has seen, and it is the one exit a client could select by omitting `id`.
        if matches!(
            outstanding,
            mcp_re_http_profile::OutstandingId::Notification
        ) {
            match self
                .inner_async
                .observe_acknowledgement(&mut progress, &outcome)
            {
                Ok(acknowledged) => progress.establish(acknowledged),
                Err(refusal) => return self.refuse(&ex, refusal, &progress),
            }
            debug_assert!(progress.state().is_terminal());
            debug_assert!(progress.invariant_violation().is_none());
            return self
                .answer_notification(
                    &http_req,
                    &window,
                    now,
                    &verified,
                    actor_id,
                    &retention,
                    Self::disposition(&progress),
                )
                .await;
        }

        let inner_bytes = match self.inner_async.observe_reply(&mut progress, outcome) {
            Ok(bytes) => progress.establish(bytes),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: inner_bytes,
        };

        let validated = match ValidatedReply::of(&response, &outstanding) {
            Ok(validated) => progress.establish(Established::new(
                validated,
                ExchangeEvent::EnvelopeValidated,
            )),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        let class = match validated.classify() {
            Ok(class) => {
                progress.establish(Established::new(class, ExchangeEvent::ResponseClassified))
            }
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        // The obligation is incurred HERE, before the reply is signed and long before it is
        // served. It latches: nothing downstream can decide this exchange opens no leg after
        // the classifier decided it does.
        progress.observe_open_leg(match class {
            ReplyClass::Terminal => OpenLeg::NotApplicable,
            ReplyClass::Open(_) => OpenLeg::Required,
        });

        let response_base =
            match self.sign_reply_stage(&ex, &mut response, window.key(), window.expires()) {
                Ok(base) => progress.establish(base),
                Err(refusal) => return self.refuse(&ex, refusal, &progress),
            };

        match &class {
            ReplyClass::Terminal => progress.advance(ExchangeEvent::ContinuationNotRequired),
            ReplyClass::Open(state) => {
                match self
                    .continuations
                    .record_open_leg(&ex, self.requests.audience_id(), state, response_base)
                    .await
                {
                    Ok(recorded) => {
                        progress.observe_open_leg(OpenLeg::Recorded);
                        progress.establish(recorded);
                    }
                    Err(refusal) => return self.refuse(&ex, refusal, &progress),
                }
            }
        }

        if let Some(rejection) = self
            .retain_accepted(
                &http_req,
                &response,
                now,
                Some(verified.evidence()),
                actor_id.clone(),
                &retention,
                Self::disposition(&progress),
                ex.key.clone(),
            )
            .await
        {
            return rejection;
        }
        progress.advance(ExchangeEvent::EvidenceRetained);

        // Emitted HERE, not at signing time: everything above can still discard this
        // response, and a `response.signed` record for bytes the client never received is
        // exactly the kind of contradiction that makes an audit stream unusable.
        crate::audit_record::record_to(
            &self.audit,
            crate::audit_record::AuditSubject::response(
                mcp_re_core::audit::AuditEvent::response_signed(),
            ),
            Some(actor_id),
            response.status,
            now,
        );
        // Two terminals, because the exchange makes a different claim in each: one says the
        // call is over, the other says the client may continue — and the second is only
        // reachable now that the continuation it depends on is durable.
        progress.advance(match class {
            ReplyClass::Terminal => ExchangeEvent::TerminalResponseServed,
            ReplyClass::Open(_) => ExchangeEvent::OpenLegResponseServed,
        });
        debug_assert!(progress.state().is_terminal());
        debug_assert!(progress.invariant_violation().is_none());
        served(response)
    }

    /// Retain one ACCEPTED exchange (ADR-MCPRE-054), or produce the refusal.
    ///
    /// `Some(rejection)` means the evidence could not be kept and the exchange must be
    /// refused; `None` means it is retained, or retention is not configured, and the
    /// caller may serve.
    ///
    /// EVERY accepted exit goes through here — the bodied reply and the bodyless 202
    /// alike. Retention wired onto only one of them is not a weaker guarantee, it is a
    /// client-selectable one: the notification form reaches the same backend and runs
    /// the same side effects, so a hostile-but-enrolled caller could choose to leave no
    /// reconstructible hop by dropping the `id`. A new success path must call this too,
    /// which is why it is one function and not a block copied twice.
    ///
    /// Retention runs BEFORE the response goes out and before its `response.signed`
    /// record, for the same reason the audit record is emitted late: everything above
    /// can still discard this response, and retaining an exchange the client never
    /// received would put a record in the store that no receipt should be issued about.
    /// A deployment with retention on asserts it can account for what it served, and
    /// refusing when the evidence cannot be kept is the only thing that keeps that true.
    ///
    /// The obligation arrives as a [`RetentionDisposition`], so this discharges it by
    /// EXHAUSTIVE MATCH rather than by checking whether an earlier step ran. There used
    /// to be a guard here for "retention is configured but no reservation arrived", which
    /// existed only because `Option<RetentionReservation>` could not distinguish that from
    /// "this deployment retains nothing". With the two cases separate there is no third to
    /// detect (ADR-MCPRE-058 §9.5, §9.6).
    #[allow(clippy::too_many_arguments)]
    async fn retain_accepted(
        &self,
        request: &HttpRequest,
        response: &HttpResponse,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: String,
        retention_owed: &RetentionDisposition,
        execution: ExecutionDisposition,
        snapshot: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ) -> Option<ServedHttpResponse> {
        let Err(refusal) = self
            .retention
            .complete(retention_owed, request, response)
            .await
        else {
            return None;
        };
        Some(self.responses.response_rejection(
            &self.audit,
            request,
            &refusal.cause,
            refusal.status,
            now,
            bound,
            Some(actor_id),
            execution,
            snapshot,
        ))
    }
}

/// Wrap a fully-built [`HttpResponse`] as a [`ServedHttpResponse`].
pub(super) fn served(resp: HttpResponse) -> ServedHttpResponse {
    ServedHttpResponse {
        status: resp.status,
        headers: resp.headers,
        body: resp.body,
    }
}

#[cfg(test)]
mod admission_prerequisite_tests {
    //! ADR-MCPRE-064 Slice 5 (#625) — admission CONSUMES the request↔peer binding.
    //!
    //! # What changed, stated precisely
    //!
    //! The exchange machine already refused an out-of-order transition: advancing
    //! `AdmissionCurrencyChecked` before `TransportBindingChecked` latches an anomaly. So
    //! stage ORDER was never the gap.
    //!
    //! What was discarded is the binding's CONTENT. `TransportBinding::bind` built a
    //! `RequestPeerBindingFacts` and the stage returned `Established<()>`, so no later
    //! authority could condition on whether binding had been claimed at all — the
    //! `Some`/`None` distinction died at the stage that made it.
    //!
    //! # What the prerequisite says
    //!
    //! `Required` is the only enforcement under which *every served call acted under a
    //! current admission* is a true statement about the deployment. It is only true if the
    //! caller was also shown to be the peer of the channel it arrived over; otherwise the
    //! assertion was matched against an actor whose channel nobody checked, and the
    //! sentence quietly weakens to *every call presented a current admission*.
    //!
    //! # What is deliberately NOT changed
    //!
    //! The assertion match stays on `actor_id()`. An admission assertion is issued to the
    //! full resolved signing actor — role, trust domain, subject AND keyid — so the
    //! composite is the correct coordinate here, and the ADR-MCPRE-064 Slice 4 ruling does
    //! NOT extend to it. Narrowing this to the subject would let an assertion issued for
    //! one signing key be presented under another. The control below pins that.

    use super::*;

    #[test]
    fn the_binding_stage_hands_on_the_fact_rather_than_a_unit() {
        // What the slice actually changed. Ordering was never the gap — the exchange
        // machine latches an anomaly on an out-of-order transition — so the measurable
        // difference is that the stage's established value now HAS content, and the
        // *bound* / *no policy installed* distinction survives it.
        //
        // The two shapes are asserted through `Established`'s own type, which is the point:
        // a stage returning `Established<()>` cannot hand anything to its successor, and no
        // amount of call-site discipline changes that.
        let not_claimed: Established<Option<RequestPeerBindingFacts>> =
            Established::new(None, ExchangeEvent::TransportBindingChecked);
        let mut progress = ExchangeProgress::new();
        assert!(
            progress.establish(not_claimed).is_none(),
            "no binding policy installed is NOT CLAIMED to be bound, and says so"
        );
    }

    #[test]
    fn the_binding_prerequisite_and_the_assertion_coordinate_are_different_facts() {
        // THE CONTROL THAT KEEPS THE TWO RULINGS APART. A reader applying Slice 4's ruling
        // by analogy would narrow the admission match from `actor_id()` to the subject —
        // and an assertion issued for one signing key would then be presentable under
        // another key of the same subject.
        //
        //   request <-> peer :  authenticated peer identity == resolved actor SUBJECT
        //   assertion <-> actor:  admitted_actor            == resolved actor ACTOR_ID
        use mcp_re_http_profile::ActorIdentity;

        let actor = ActorIdentity {
            role: "client".into(),
            trust_domain: "example.org".into(),
            subject: "spiffe://example.org/agent-1".into(),
            keyid: "key-a".into(),
        };
        let rotated = ActorIdentity {
            keyid: "key-b".into(),
            ..actor.clone()
        };

        assert_eq!(
            actor.subject, rotated.subject,
            "one principal — which is why the TRANSPORT binding survives a key rotation"
        );
        assert_ne!(
            actor.actor_id(),
            rotated.actor_id(),
            "two signing actors — which is why an ADMISSION assertion issued to the first \
             must not be presentable under the second. Collapsing this to subject equality \
             is the mistake this control exists to catch."
        );
    }
}
