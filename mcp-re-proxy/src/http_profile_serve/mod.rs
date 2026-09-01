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

use crate::refusal::Refusal;

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

// ===================== THE REQUEST PIPELINE, REGION BY REGION =====================
//
// ADR-MCPRE-058 §9.2 + ADR-MCPRE-057 §4. One module per REGION of the exchange, and inside
// it one function per transition of the request machine, each with an explicit contract:
// what it ensures, what it may not do, and whether its refusal is free.
//
// The regions are the coarse facts `handle` composes, and each one is a different answer to
// *what has this deployment spent yet* — nothing, a nonce and an approval, a durable
// marker, the backend. A stage that SUCCEEDS returns an `Established<T>` naming the event
// it justifies, so the state a stage requires is not written in the assembly at all: it is
// the relation's, and `transition` refuses the event from anywhere else.
//
// The point is not fewer lines. It is that each transition can be tested — and eventually
// PROVED — on its own, rather than only as a property of the whole pipeline. A stage that
// returns `Err` names its refusal and never signs one; refusals take their retry contract
// from the machine, never from their own position.

/// Everything asked before this deployment will spend anything, and the two facts that
/// outlive it.
mod pre_admission;

/// Reaching *answerable and committed*: the continuation read, replay admission, the
/// signing window, and the retirement that spends the approval.
mod answering_commitment;

/// The last three questions before the backend is reached, in the order that keeps the
/// durable record honest.
mod dispatch_commitment;

/// Everything after the backend has acted — where no exit can claim nothing happened.
mod reply_assembly;
pub use body_boundary::extract_request_state;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ExecutionDisposition;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::OutstandingId;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedContextPolicy;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::VerifierPolicy;

use crate::admission_enforcer::AdmissionEnforcement;
use crate::admission_enforcer::AdmissionEnforcer;
use crate::admission_source::AsyncAdmissionSource;
use crate::async_inner::AsyncInnerServer;
use crate::async_serve::ServedHttpRequest;
use crate::async_serve::ServedHttpResponse;
use crate::authorization::AuthorizationEvaluator;
use crate::authorization::AuthorizationStage;
use crate::continuation_store::AsyncContinuationStore;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::exchange_state::RetrySemantics;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::request_stages::ReadyForDispatch;
use crate::transport::TransportBinding;

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

    /// Serve one request end to end on the async data plane.
    ///
    /// This function is the ASSEMBLY, not the work. It composes the regions above and
    /// nothing else; each region carries its own contract, so what is visible here is the
    /// pipeline itself — which step follows which, and where the execution threshold lies.
    ///
    /// It does not advance the request machine except at its own three facts: the dispatch,
    /// and the two terminals. A stage's success arrives as an
    /// [`Established`](crate::exchange_state::Established), and `progress.establish` is the
    /// only way to open one — so the machine learns that a step ran by the value being
    /// CONSUMED, not by anyone remembering to say so afterwards.
    ///
    /// Every refusal is minted by `refuse` from a `Refusal` the stage named. `handle` never
    /// re-decides what a failure means, which is why no exit has to know how far the
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
        let verified = match self.verify_stage(&http_req, now, &mut progress) {
            Ok(verified) => verified,
            Err(rejection) => return rejection,
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

        // Nothing irreversible happens on a request's behalf until it is both admitted and
        // answerable. These two regions are in this order for that reason: a destructive
        // continuation read before admission let an about-to-be-rejected request destroy a
        // live approval leg.
        let admitted = match self
            .admit_request(&ex, req.peer.as_ref(), &mut progress)
            .await
        {
            Ok(admitted) => admitted,
            Err(rejection) => return rejection,
        };
        let window = match self.commit_to_answering(&mut ex, &mut progress).await {
            Ok(window) => window,
            Err(rejection) => return rejection,
        };
        self.record_request_accepted(&admitted, &actor_id, now);
        let commitment = self.commit_to_dispatch(&ex, admitted.authorized, &mut progress);
        let (prepared, retention) = match commitment.await {
            Ok(committed) => committed,
            Err(rejection) => return rejection,
        };

        // ===================== IRREVERSIBLE INNER DISPATCH =====================
        //
        // Every pre-dispatch prerequisite is now in hand, and `ReadyForDispatch` is what
        // says so: it cannot be built without them, and transmitting consumes it. Past this
        // line no exit can claim nothing happened — which is why every one of them is a
        // `response_rejection` rather than a `rejection`.
        let ready = ReadyForDispatch::new(prepared, window, retention);
        // BEFORE the await, not after it. Once the request is committed to the backend the
        // exchange must read as possibly-executed, whatever the dispatch goes on to return:
        // a state entered only on the way out would leave a cancelled or panicking dispatch
        // claiming nothing happened.
        progress.advance(ExchangeEvent::BackendDispatched);
        let (outcome, window, retention) = ready.dispatch().await.into_parts();

        // NOTIFICATION — a one-way message with no JSON-RPC `id` is its own terminal: it
        // says the boundary accepted the message, never that anything completed. Decided
        // from the REQUEST, which is where the fact lives.
        if matches!(admitted.outstanding, OutstandingId::Notification) {
            return self
                .answer_notification_terminal(&ex, &mut progress, &outcome, &window, &retention)
                .await;
        }
        let reply = match self
            .assemble_reply(&ex, &mut progress, outcome, &admitted.outstanding, &window)
            .await
        {
            Ok(reply) => reply,
            Err(rejection) => return rejection,
        };
        self.serve_retained(&ex, &mut progress, reply, &retention)
            .await
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
