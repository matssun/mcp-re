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
use crate::refusal::RefusalPosture;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::build_delegated_rejection;
use mcp_re_http_profile::build_delegated_rejection_preflight;
use mcp_re_http_profile::insert_verified_context;
use mcp_re_http_profile::parse_response_body;
use mcp_re_http_profile::result_class::classify_result_type;
use mcp_re_http_profile::result_class::input_required_state_of;
use mcp_re_http_profile::result_class::ResultTypeClass;
use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::strip_proxy_owned_meta;
use mcp_re_http_profile::validate_response_envelope;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ExecutionDisposition;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RejectionReason;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::RetainedContinuation;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedContext;
use mcp_re_http_profile::VerifiedContextPolicy;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use crate::admission_enforcer::AdmissionEnforcement;
use crate::admission_enforcer::AdmissionEnforcer;
use crate::admission_source::AsyncAdmissionSource;
use crate::async_inner::AsyncInnerServer;
use crate::async_inner::InnerOutcome;
use crate::async_serve::ServedHttpRequest;
use crate::async_serve::ServedHttpResponse;
use crate::authorization::AuthorizationEvaluator;
use crate::authorization::AuthorizationPosture;
use crate::authorization::AuthorizationStage;
use crate::communication_assurance::request_peer_binding::http_profile_adapter::verified_request_subject;
use crate::communication_assurance::RequestPeerBindingFacts;
use crate::continuation_store::continuation_key;
use crate::continuation_store::AsyncContinuationStore;
use crate::continuation_store::RetainedBases;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::exchange_state::ContinuationState;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::exchange_state::OpenLeg;
use crate::exchange_state::ResponseOrigin;
use crate::exchange_state::RetrySemantics;
use crate::http_profile_dispatch::dispatch_request_with_async_tier;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::request_stages::ReadyForDispatch;
use crate::request_stages::RetentionDisposition;
use crate::transport::TransportBinding;

/// Default lifetime of a recorded MRTR continuation in the shared correlation store
/// (ADR-MCPS-047): long enough for a client to answer an `InputRequiredResult`,
/// bounded so an unanswered continuation does not linger. Overridable via
/// [`HttpProfileProxy::with_continuation_store`].
pub const DEFAULT_CONTINUATION_TTL_SECS: i64 = 300;

/// How many times the CONTINUATION-RECORDED open-leg record is attempted before the leg is failed.
///
/// Bounded and small: the shared tier answered the replay admission moments earlier,
/// so the only failure this can absorb is a transient one, and retrying past that
/// would put an unbounded stall in front of a response the backend has already
/// produced.
const CONTINUATION_RECORD_ATTEMPTS: usize = 3;

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
struct Exchange<'a> {
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

/// What CONTINUATION-PREPARED recovered.
///
/// The owned `retained` and `answer_state` outlive the borrowed [`RetainedContinuation`]
/// handed to replay admission, which is why the borrow is produced on demand by
/// [`ContinuationPrep::binding`] rather than stored.
struct ContinuationPrep {
    answer_state: Option<String>,
    answer_key: Option<String>,
    retained: Option<RetainedBases>,
}

impl ContinuationPrep {
    /// The binding to check the answer leg against, when there is one to check.
    ///
    /// `None` covers every way the bases can be absent — no store, no `requestState`, a
    /// store miss, an expired or already-answered entry, a store outage — because the
    /// dispatcher must fail closed on `continuation_binding_failed` in all of them. A
    /// continuation that was signed but cannot be bound is never admitted.
    fn binding(&self) -> Option<RetainedContinuation<'_>> {
        match (&self.retained, &self.answer_state) {
            (Some(bases), Some(state)) => Some(RetainedContinuation {
                previous_request_base: &bases.previous_request_base,
                input_required_response_base: &bases.input_required_response_base,
                request_state: state.as_bytes(),
            }),
            _ => None,
        }
    }
}

/// What the shared tier reported when this exchange tried to retire the approval it
/// answers.
///
/// Four values, because the store's `Err` is not the store's `Ok(false)`. A `DEL` whose
/// reply was never read may well have executed, so "there was definitely nothing to
/// retire" and "the entry may or may not be gone" are different facts about a human's
/// approval: they warrant different wire codes, and — the load-bearing part — different
/// claims about whether an ordinary retry can still succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retirement {
    /// This deployment runs no store, or this request answers nothing. No approval is at
    /// stake.
    NotInvolved,
    /// THIS call removed the live entry. **The approval is spent.**
    Retired,
    /// The store ANSWERED, and there was no live entry to remove: already answered,
    /// expired, or a splice. A statement about the caller.
    AlreadyAnswered,
    /// The store did not answer. The entry may or may not be gone, and nothing downstream
    /// can find out — the answer leg is the only thing that would have consumed it.
    Indeterminate,
}

/// The RFC 9421 server-side PEP run by the async fleet (ADR-MCPRE-051).
///
/// Holds ONLY the RFC 9421 serving state — the verifier, signer, and evidence all
/// operate on the HTTP message, not a JSON-RPC `_meta` envelope. `Send + Sync`
/// (MCPRE-111): one instance is
/// shared across all per-core runtimes.
pub struct HttpProfileProxy {
    /// Trust resolution for request (client) and response (server) signing slots.
    resolve_actor: ActorResolver,
    /// The verifier's expected audience tuple (audience id + `@target-uri` + route);
    /// `target_uri` must equal the request `@target-uri` (enforced in verify).
    expected_audience: AudienceTuple,
    /// The ADR-MCPRE-052 delegated-signing custody — the ONLY response-signing mode.
    /// Every response and rejection is signed by the active short-TTL delegated key +
    /// inline credential; the root is never on the request path, and the proxy fails
    /// closed when no valid delegated key is available. There is no direct-root mode.
    signer: Arc<DelegatedServerSigner>,
    /// The authoritative async replay tier (ADR-MCPRE-051 §4).
    replay_async: crate::async_replay::AsyncReplayTier,
    /// Deployment replay-durability posture (fleet-strict + declared tier).
    dispatch_cfg: ProxyDispatchConfig,
    /// The async inner-plane client to the stateless Streamable-HTTP backend.
    inner_async: Box<dyn AsyncInnerServer>,
    /// Optional Mode-A transport binding: bind the verified request actor to the
    /// mTLS peer identity. `None` disables the channel binding.
    transport_binding: Option<TransportBinding>,
    /// What this deployment decides authorization with (ADR-MCPRE-065). Deciding with
    /// nothing is one of its states, and it claims nothing rather than permitting.
    authorization: AuthorizationStage,
    /// Response-signature validity window (seconds added to `created`).
    sig_ttl_secs: i64,
    /// Optional MRTR continuation correlation store (ADR-MCPS-047) — the fleet-shared
    /// tier that carries a multi-round-trip continuation across a replica switch.
    /// `None` disables MRTR: an `InputRequiredResult` is still returned, but a later
    /// answer leg carrying a continuation fails closed (no retained bases). A fleet
    /// wires the Redis store; single-replica runs may wire the in-memory one.
    continuation_store: Option<Arc<dyn AsyncContinuationStore>>,
    /// Lifetime of a recorded continuation (seconds); see
    /// [`DEFAULT_CONTINUATION_TTL_SECS`].
    continuation_ttl_secs: i64,
    /// Whether to carry verified context to the inner server (#415 rev 2 §10).
    /// Default `Disabled`: the context is the PEP's conclusion, unsigned by
    /// design, so it is only meaningful over a channel the PEP alone can write to
    /// — an operator asserts that, and nothing here can check it.
    verified_context_policy: VerifiedContextPolicy,
    /// The verifier-local acceptance policy: algorithm registry, bounded skew, and
    /// the optional MCP transport/version contract (§4.1, §5.1, §13.1). Default is
    /// `VerifierPolicy::default()` — Ed25519, 30s skew, no transport contract — so
    /// serving behaves as before unless a deployment attaches a stricter policy.
    verifier_policy: VerifierPolicy,
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
    retention: Option<Arc<crate::transparency::EvidenceRetention>>,
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
        self.retention = Some(retention);
        self
    }

    /// Emit one audit record, if a sink is installed.
    ///
    /// `subject` decides which authorities the record carries: a request record states an
    /// authorization outcome, a response record has none to state (ADR-MCPRE-066 R5). The
    /// choice is made by the caller that knows which half of the exchange it is reporting,
    /// and the type refuses the other combination.
    fn audit(
        &self,
        subject: crate::audit_record::AuditSubject,
        actor_id: Option<String>,
        status: u16,
        now: i64,
    ) {
        if let Some(sink) = &self.audit {
            sink.record(&crate::audit_record::AuditRecord {
                subject,
                actor_id,
                status,
                at_unix: now,
            });
        }
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
            resolve_actor,
            expected_audience,
            signer: delegated_signer,
            replay_async,
            dispatch_cfg,
            inner_async,
            transport_binding: None,
            sig_ttl_secs,
            continuation_store: None,
            continuation_ttl_secs: DEFAULT_CONTINUATION_TTL_SECS,
            verified_context_policy: VerifiedContextPolicy::default(),
            verifier_policy: VerifierPolicy::default(),
            authorization: AuthorizationStage::default(),
            audit: None,
            admission: None,
            retention: None,
        }
    }

    /// Attach a verifier-local acceptance policy (§4.1 MCP transport contract,
    /// §5.1 clock skew, §13.1 algorithm registry). A deployment on MCP 2026-07-28
    /// passes `VerifierPolicy::default().with_mcp_transport(McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"]))`
    /// to enforce required-header presence and version policy on the served path.
    pub fn with_verifier_policy(mut self, policy: VerifierPolicy) -> Self {
        self.verifier_policy = policy;
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
        self.continuation_store = Some(store);
        self.continuation_ttl_secs = ttl_secs;
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
        self.admission = Some(AdmissionEnforcer {
            source,
            policy,
            enforcement,
            resolve_authority,
            last_authoritative_read: std::sync::atomic::AtomicI64::new(i64::MIN),
        });
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
                &self.expected_audience.audience_id,
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
    /// The ONLY place in the pipeline that signs. It is also the only place that consults
    /// the exchange machine, which is the point: the retry contract is a fact about the whole
    /// exchange, so a stage could not state it correctly even if it tried. The stage says
    /// WHAT was refused; the machine says what the client may still assume.
    fn refuse(
        &self,
        ex: &Exchange<'_>,
        refusal: Refusal,
        progress: &ExchangeProgress,
    ) -> ServedHttpResponse {
        let execution = Self::disposition(progress);
        let (bound, actor) = match refusal.posture {
            // An unverified request has no trustworthy hash to bind to and no resolved actor
            // to attribute the denial to.
            RefusalPosture::Preflight => (None, None),
            _ => (Some(ex.verified.evidence()), Some(ex.actor_id.to_owned())),
        };
        if refusal.posture == RefusalPosture::AfterAdmission {
            return self.response_rejection(
                ex.http_req,
                &refusal.cause,
                refusal.status,
                ex.now,
                bound,
                actor,
                execution,
                ex.key.clone(),
            );
        }
        self.rejection(
            ex.http_req,
            &refusal.cause,
            refusal.status,
            ex.now,
            bound,
            actor,
            execution,
            ex.key.clone(),
        )
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
        a: &Arc<mcp_re_http_profile::ActiveDelegatedKey>,
        now: i64,
        expires: i64,
        verified: &mcp_re_http_profile::VerifiedMcpRequest,
        actor_id: String,
        retention: &RetentionDisposition,
        execution: ExecutionDisposition,
    ) -> ServedHttpResponse {
        match sign_delegated_accepted_202(
            http_req,
            &a.credential,
            a.key.as_ref(),
            &a.delegated_kid,
            now,
            expires,
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
                        Some(Arc::clone(a)),
                    )
                    .await
                {
                    return rejection;
                }
                // The signed bodyless 202 IS the signed response for a notification,
                // and it is returned on this line — so the record describes bytes the
                // client actually receives.
                self.audit(
                    crate::audit_record::AuditSubject::response(
                        mcp_re_core::audit::AuditEvent::response_signed(),
                    ),
                    Some(actor_id),
                    202,
                    now,
                );
                served(ack)
            }
            Err(e) => self.response_rejection(
                http_req,
                &RefusalCause::from(e),
                500,
                now,
                Some(verified.evidence()),
                Some(actor_id),
                execution,
                Some(Arc::clone(a)),
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

    /// VERIFIED — RFC 9421 + RFC 9530 + the evidence block.
    ///
    /// ```text
    /// ensures   Ok  => the signature verified and an actor is resolved
    ///           Err => 403, signed UNBOUND (no trustworthy request hash exists yet)
    /// forbids   any effect on the request's behalf
    /// refusal   free — nothing has happened
    /// ```
    ///
    /// DPoP artifact bindings derive their credential from the covered Authorization
    /// header, so no external material is supplied; a binding lacking one fails closed.
    fn verify_stage(
        &self,
        http_req: &HttpRequest,
        now: i64,
    ) -> Result<Established<VerifiedMcpRequest>, Refusal> {
        let no_material = |_b: &ArtifactBinding| None;
        // Scoped so the timer covers the verification and nothing after it.
        let verify_result = {
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Verify);
            Verifier::new(&self.verifier_policy, self.resolve_actor.as_ref()).verify_request(
                http_req,
                &self.expected_audience,
                &no_material,
                now,
            )
        };
        // The request never verified, so there is no trustworthy request hash to bind to
        // and no resolved actor to attribute the denial to.
        verify_result
            .map(|v| Established::new(v, ExchangeEvent::SignatureVerified))
            .map_err(|e| Refusal::preflight(e, 403))
    }

    /// REQUEST-ENVELOPE-VALIDATED — is this body a legal JSON-RPC request at all?
    ///
    /// ```text
    /// ensures   Ok  => the body is a legal JSON-RPC 2.0 request, and the outstanding id
    ///                  it establishes is decided ONCE, here
    ///           Err => 400, bound to the request via `;req`
    /// forbids   any effect on the request's behalf
    /// refusal   free — nothing has happened
    /// ```
    ///
    /// Asked here, before anything reads the body for meaning, because everything below
    /// does: the continuation stage reads `params.requestState`, the forwarded body strips
    /// `_meta`, and the terminal arm is chosen by the presence of `id`. Deciding the shape
    /// after admission would burn a nonce, spend an approval and write a durable retention
    /// marker on behalf of a document that is not an MCP message.
    ///
    /// The returned [`OutstandingId`](mcp_re_http_profile::OutstandingId) is the exchange's
    /// single answer to "what is this request": the notification arm and the response
    /// envelope validator are both given this value rather than re-reading the body. Two
    /// readers of one document can disagree, and the disagreement that mattered here is a
    /// body dispatched as a request and acknowledged as a notification.
    fn validate_request_stage(
        &self,
        http_req: &HttpRequest,
    ) -> Result<mcp_re_http_profile::OutstandingId, Refusal> {
        mcp_re_http_profile::validate_request_envelope(&http_req.body)
            .map_err(|e| Refusal::before_admission(e, 400))
    }

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

    /// CONTINUATION-PREPARED — recover the retained open-leg bases for an ANSWER leg.
    ///
    /// ```text
    /// ensures   Ok  => the continuation machine is NotInvolved or Peeked — never Consumed
    ///           Err => 503, bound: the shared tier did not answer
    /// forbids   consuming anything
    /// refusal   free — `peek` has no side effect, so nothing is spent
    /// ```
    ///
    /// Keyed by the actor the VERIFIER resolved, never by anything the request asserts, so
    /// one peer cannot name another's continuation at all. `peek` has no side effect, which
    /// is what lets a request that is about to be refused leave a live approval intact.
    ///
    /// A store MISS and a store OUTAGE are different facts and are refused differently. A
    /// miss — never opened, expired, already answered — leaves no bases, and the binding
    /// then fails closed `continuation_binding_failed`, which is a statement about the
    /// CALLER. An outage is a statement about this DEPLOYMENT, so it is named as one:
    /// flattening the two reports a forged continuation every time the shared tier blips,
    /// and hides a genuine splice attempt inside an outage.
    async fn prepare_continuation_stage(
        &self,
        ex: &Exchange<'_>,
    ) -> Result<Established<ContinuationPrep>, Refusal> {
        let has_continuation = ex.verified.request_block().continuation.is_some();
        let answer_state = if has_continuation {
            extract_request_state(&ex.http_req.body)
        } else {
            None
        };
        let answer_key = answer_state.as_ref().map(|state| {
            continuation_key(
                &self.expected_audience.audience_id,
                ex.actor_id,
                state.as_bytes(),
            )
        });
        let retained = match (&self.continuation_store, &answer_key) {
            (Some(store), Some(key)) => match store.peek(key).await {
                Ok(bases) => bases,
                Err(_) => {
                    return Err(Refusal::before_admission(
                        McpReError::ReplayCacheUnavailable,
                        503,
                    ))
                }
            },
            _ => None,
        };
        Ok(Established::new(
            ContinuationPrep {
                answer_state,
                answer_key,
                retained,
            },
            ExchangeEvent::ContinuationPrepared,
        ))
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
    ///
    /// The returned window never outlives the credential authorizing it: `sig_ttl_secs`
    /// alone would let a response claim a validity the verifier refuses seconds later.
    fn answerable_stage(
        &self,
        ex: &Exchange<'_>,
    ) -> Result<Established<(Arc<mcp_re_http_profile::ActiveDelegatedKey>, i64)>, Refusal> {
        match self.signer.current(ex.now) {
            // The snapshot is taken ONCE and signs the reply below: `now` is fixed for the
            // whole request, so a key valid here is valid there.
            Some(a) => {
                let expires = (ex.now + self.sig_ttl_secs).min(a.exp);
                Ok(Established::new(
                    (a, expires),
                    ExchangeEvent::DelegatedKeySnapshotted,
                ))
            }
            None => Err(Refusal::before_admission(
                McpReError::DelegatedSigningUnavailable,
                503,
            )),
        }
    }

    /// CONTINUATION-RETIRED — spend the approval, exactly once.
    ///
    /// ```text
    /// ensures   what the shared tier reported, as a [`Retirement`]
    /// forbids   running the backend
    /// refusal   minted by the CALLER — see [`Retirement`]
    /// ```
    ///
    /// One-shot is enforced here, by the store's atomic `consume`: of two concurrent answer
    /// legs that both bound successfully, exactly one proceeds. The other three outcomes do
    /// not proceed, and they are not the same fact, so the stage reports what happened and
    /// the caller — which holds the continuation machine — decides both the refusal and
    /// what the exchange may claim about the approval. A stage cannot do the second, and a
    /// stage that refused without it would be stating a retry contract it cannot know.
    async fn retire_continuation_stage(&self, answer_key: Option<&String>) -> Retirement {
        let (Some(store), Some(key)) = (&self.continuation_store, answer_key) else {
            return Retirement::NotInvolved;
        };
        match store.consume(key).await {
            Ok(true) => Retirement::Retired,
            Ok(false) => Retirement::AlreadyAnswered,
            Err(_) => Retirement::Indeterminate,
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
        match forwarded_body(
            &ex.http_req.body,
            ex.verified,
            self.verified_context_policy,
            ex.now,
        ) {
            Ok(Forwarded { body, seeded }) => {
                if seeded {
                    // A deliberate attempt to assert one's own authentication context to
                    // the inner server is exactly what this surface exists to detect. The
                    // frozen audit vocabulary has no event for it (ADR-MCPS-035 §3 admits
                    // no third success event), so it is named on the diagnostic channel
                    // rather than left with no trace at all.
                    eprintln!(
                        "mcp-re-proxy: warning: request from actor {} seeded the reserved \
                         verified-context `_meta` key; stripped before forwarding (the inner \
                         server never saw it)",
                        ex.actor_id
                    );
                }
                Ok(Established::new(body, ExchangeEvent::ForwardBodyPrepared))
            }
            Err(e) => Err(Refusal::after_admission(e, 500)),
        }
    }

    /// RETENTION-RESERVED — take durable responsibility BEFORE the side effects run.
    ///
    /// ```text
    /// ensures   Ok  => the crossing of the execution threshold is itself durable
    ///           Err => 503, bound
    /// forbids   running the backend
    /// refusal   THE LAST FREE ONE — nothing between it and the dispatch can refuse, and
    ///           past the dispatch no refusal can say nothing happened
    /// ```
    ///
    /// Ordered AFTER the inner-plane question for that reason. The marker this writes is
    /// durable and is erased only by `complete`, so a free refusal downstream of it would
    /// leave on disk the record that a request crossed the execution threshold when it
    /// provably never reached a backend — and one such file per refusal, in a store with
    /// no expiry, for as long as the plane stays saturated.
    ///
    /// NOT a probe: it does not claim the later write will succeed, because nothing can —
    /// the backend and the store share no transaction. The write runs on the retention
    /// writer thread and this future AWAITS its acknowledgement, so the core keeps serving
    /// while the fsync is in progress. Awaiting is not optional: dispatching before the
    /// marker is durable would make the reservation a hint rather than a record.
    ///
    /// Returns a `RetentionDisposition`, not an `Option`: "this deployment retains nothing"
    /// and "a reservation is missing" are different facts, and collapsing them is what used
    /// to require a guard on the completion path to tell them apart (ADR-MCPRE-058 §9.6).
    async fn reserve_retention_stage(
        &self,
        ex: &Exchange<'_>,
    ) -> Result<Established<RetentionDisposition>, Refusal> {
        let reserved =
            |d: RetentionDisposition| Established::new(d, ExchangeEvent::RetentionReserved);
        let Some(retention) = self.retention.as_ref() else {
            return Ok(reserved(RetentionDisposition::NotConfigured));
        };
        match retention.reserve(ex.http_req).await {
            Ok(reservation) => Ok(reserved(RetentionDisposition::Reserved(reservation))),
            Err(e) => {
                eprintln!(
                    "evidence retention could not accept the exchange, refusing before \
                     dispatch: {e}"
                );
                Err(Refusal::after_admission(
                    McpReError::EvidenceRetentionUnavailable,
                    503,
                ))
            }
        }
    }

    /// INNER-PLANE-ACCEPTED — can a dispatch begin at all?
    ///
    /// ```text
    /// ensures   Ok  => the inner plane has a permit and a live backend
    ///           Err => 503, bound
    /// forbids   transmitting anything
    /// refusal   free, and free of DURABLE consequence — asked before the retention
    ///           reservation, so a saturated plane leaves nothing behind on disk
    /// ```
    ///
    /// Local saturation and a fully-ejected backend set are facts about THIS proxy, knowable
    /// without putting a byte on the wire. Discovering them from the far side of the
    /// threshold — which is what a seam returning only bytes forces — turned a
    /// definitely-not-executed outage into an exchange that must claim `possibly_executed`
    /// forever after, and served it as a signed HTTP 200 carrying an error body.
    fn inner_plane_stage(&self) -> Result<Established<()>, Refusal> {
        self.inner_async
            .admit()
            .map(|_| Established::new((), ExchangeEvent::InnerPlaneAccepted))
            .map_err(|_| Refusal::after_admission(McpReError::InnerPlaneUnavailable, 503))
    }

    /// RESPONSE-OBSERVED — what did the inner plane actually manage to do?
    ///
    /// ```text
    /// ensures   Ok  => bytes authored by the BACKEND
    ///           Err => 503 / 504 / 502, bound, recorded as a RESPONSE-side fault
    /// refusal   NOT free — every arm below reports possibly-executed
    /// ```
    ///
    /// The three failing arms are three different facts and get three different codes. The
    /// one that matters most is the middle: a timeout means the request was transmitted and
    /// the answer never came, so whether the tool ran is genuinely unknown, and the previous
    /// behaviour — a synthesized `-32603` signed at HTTP 200 — was the strongest available
    /// statement that the exchange completed normally.
    fn observe_inner_stage(
        &self,
        progress: &mut ExchangeProgress,
        outcome: InnerOutcome,
    ) -> Result<Established<Vec<u8>>, Refusal> {
        match outcome {
            InnerOutcome::Replied(bytes) => {
                progress.observe_origin(ResponseOrigin::BackendReplied);
                Ok(Established::new(bytes, ExchangeEvent::ResponseObserved))
            }
            // A lost race against `admit`: the last permit went to another core between the
            // question and the dispatch. Reported as what it is, at the consequence the
            // exchange has already crossed — the floor does not move back for a more
            // precise late observation.
            InnerOutcome::NotDispatched(_) => Err(Refusal::after_admission(
                McpReError::InnerPlaneUnavailable,
                503,
            )),
            InnerOutcome::Indeterminate(_) => {
                progress.observe_origin(ResponseOrigin::DispatchIndeterminate);
                Err(Refusal::after_admission(
                    McpReError::InnerDispatchIndeterminate,
                    504,
                ))
            }
            InnerOutcome::InvalidUpstream(clause) => Err(Refusal::after_admission(
                HttpProfileError::UpstreamResponseInvalid(clause),
                502,
            )),
        }
    }

    /// NOTIFICATION-OBSERVED — may a 202 be minted for what the inner plane managed to do?
    ///
    /// ```text
    /// ensures   Ok  => the backend RECEIVED the message
    ///           Err => 503 (nothing was transmitted) / 504 (transmitted, no answer)
    /// refusal   NOT free — the exchange has crossed the threshold either way
    /// ```
    ///
    /// Two outcomes acknowledge and two refuse, split on whether the backend ANSWERED. The
    /// 202 says the enforcement boundary authenticated and accepted the message and the
    /// inner plane received it; it never says any action completed (#418). What the backend
    /// answered is discarded unread, as JSON-RPC requires — but WHETHER it was reached is
    /// not a detail of the answer, and a message that never left the proxy has been
    /// accepted by nothing.
    ///
    /// [`InnerOutcome::InvalidUpstream`] acknowledges, and that is not a concession: a
    /// conformant Streamable-HTTP backend answers a notification with `202 Accepted` and no
    /// body, which carries no `application/json` content type and therefore arrives here as
    /// an unusable answer FROM A BACKEND THAT RECEIVED THE MESSAGE
    /// ([`crate::http_inner`]). The two refused outcomes are the two that say the message
    /// did not get there, or may not have.
    fn observe_notification_stage(
        &self,
        progress: &mut ExchangeProgress,
        outcome: &InnerOutcome,
    ) -> Result<Established<()>, Refusal> {
        match outcome {
            InnerOutcome::Replied(_) | InnerOutcome::InvalidUpstream(_) => {
                progress.observe_origin(ResponseOrigin::BackendReplied);
                Ok(Established::new(
                    (),
                    ExchangeEvent::NotificationAcknowledged,
                ))
            }
            InnerOutcome::NotDispatched(_) => Err(Refusal::after_admission(
                McpReError::InnerPlaneUnavailable,
                503,
            )),
            InnerOutcome::Indeterminate(_) => {
                progress.observe_origin(ResponseOrigin::DispatchIndeterminate);
                Err(Refusal::after_admission(
                    McpReError::InnerDispatchIndeterminate,
                    504,
                ))
            }
        }
    }

    /// RESPONSE-VALIDATED — the JSON-RPC control envelope must be legal before anything
    /// treats these bytes as a response.
    ///
    /// ```text
    /// ensures   Ok  => syntax, `jsonrpc`, `id` correlation and `result` XOR `error` all hold
    ///           Err => 502, bound
    /// refusal   NOT free — the action already ran
    /// ```
    ///
    /// Unconditional, which is the whole change (ruling D2). This used to happen only inside
    /// the MRTR open-leg recorder, so whether MCP-RE refused a malformed protocol response
    /// depended on whether an operator had wired Redis — a capability with no relationship
    /// to protocol legality. A deployment without it signed unparseable bodies as opaque
    /// payload and the client's own verifier then rejected a message the enforcement
    /// boundary had vouched for.
    ///
    /// Stops at the control envelope. Everything inside `result` beyond the MCP lifecycle
    /// members is application data that MCP-RE carries and signs without reading.
    fn validate_envelope_stage(
        &self,
        response: &HttpResponse,
        outstanding: &mcp_re_http_profile::OutstandingId,
    ) -> Result<Established<serde_json::Value>, Refusal> {
        let invalid = |clause| {
            Refusal::after_admission(HttpProfileError::UpstreamResponseInvalid(clause), 502)
        };
        let parsed = parse_response_body(&response.body).map_err(|e| match e {
            HttpProfileError::UpstreamResponseInvalid(clause) => invalid(clause),
            _ => invalid("response body"),
        })?;
        match validate_response_envelope(&parsed, outstanding) {
            Ok(_) => Ok(Established::new(parsed, ExchangeEvent::EnvelopeValidated)),
            Err(HttpProfileError::UpstreamResponseInvalid(clause)) => Err(invalid(clause)),
            Err(e) => Err(Refusal::after_admission(e, 502)),
        }
    }

    /// RESPONSE-CLASSIFIED — which MCP lifecycle transition is this reply?
    ///
    /// ```text
    /// ensures   Ok  => the reply is a terminal answer, or an open leg with usable state
    ///           Err => 502, bound
    /// refusal   NOT free — the action already ran
    /// ```
    ///
    /// The state this stage separates from validation is the point of having two: a
    /// perfectly well-formed JSON-RPC response can still be one whose MCP meaning this
    /// reader cannot determine. MCP 2026-07-28 closes the `resultType` set and requires an
    /// unrecognized one be considered invalid — signing it anyway would produce a verifiable
    /// message whose continuation semantics nobody can read, and a client failing closed on
    /// it would be told the PEP had vouched for it.
    ///
    /// A JSON-RPC error classifies as [`ReplyClass::Terminal`]: it is a legal terminal
    /// protocol response, not a malformed one and not a transport failure.
    fn classify_reply_stage(
        &self,
        parsed: &serde_json::Value,
    ) -> Result<Established<ReplyClass>, Refusal> {
        let classified = |c: ReplyClass| Established::new(c, ExchangeEvent::ResponseClassified);
        let result = parsed.get("result");
        match classify_result_type(result) {
            ResultTypeClass::Complete => Ok(classified(ReplyClass::Terminal)),
            ResultTypeClass::Unrecognized => Err(Refusal::after_admission(
                HttpProfileError::UnrecognizedResultType,
                502,
            )),
            ResultTypeClass::InputRequired => match input_required_state_of(result) {
                Ok(Some(state)) => Ok(classified(ReplyClass::Open(state))),
                // Classified as non-terminal and then failed to yield its state: the two
                // arms cannot both be right, and the only safe reading is that the message
                // is invalid.
                _ => Err(Refusal::after_admission(
                    HttpProfileError::UpstreamResponseInvalid("input_required requestState"),
                    502,
                )),
            },
        }
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

    /// CONTINUATION-RECORDED — make an open leg answerable on any replica.
    ///
    /// ```text
    /// ensures   Ok(true)  => the retained bases are in the shared tier
    ///           Ok(false) => this reply opens no leg, so there is nothing to record
    ///           Err       => 502 (unreadable reply) or 503 (shared tier), bound
    /// refusal   NOT free
    /// ```
    ///
    /// Retried briefly before failing the leg. Reaching here means the backend has ALREADY
    /// run, and the shared tier answered the replay admission microseconds ago — so a
    /// failure now is a transient blip rather than the outage REPLAY-ADMITTED already fails
    /// closed on. Absorbing it is what keeps a retryable 503, which re-executes the tool
    /// call, off a path that has side effects.
    async fn record_open_leg_stage(
        &self,
        ex: &Exchange<'_>,
        state: &str,
        response_base: Vec<u8>,
    ) -> Result<Established<()>, Refusal> {
        // D3. A deployment with no shared store cannot make this leg answerable ON ANY
        // REPLICA, and it has known that since startup. Serving the elicitation anyway
        // hands the client a signed, verified instruction to continue an exchange nothing
        // has been kept for — and the failure surfaces one leg later, as
        // `continuation_binding_failed`, which on the wire reads like an attack signal.
        //
        // The dependent leg does fail closed either way. What it cannot do is fail closed
        // in TIME, which is why the refusal belongs here.
        let Some(store) = &self.continuation_store else {
            return Err(Refusal::after_admission(
                McpReError::ReplayCacheUnavailable,
                503,
            ));
        };
        let bases = RetainedBases {
            previous_request_base: ex.verified.request_signature_base().to_vec(),
            input_required_response_base: response_base,
        };
        let key = continuation_key(
            &self.expected_audience.audience_id,
            ex.actor_id,
            state.as_bytes(),
        );
        for _ in 0..CONTINUATION_RECORD_ATTEMPTS {
            if store
                .store(&key, &bases, self.continuation_ttl_secs)
                .await
                .is_ok()
            {
                return Ok(Established::new((), ExchangeEvent::OpenLegRecorded));
            }
        }
        Err(Refusal::after_admission(
            McpReError::ReplayCacheUnavailable,
            503,
        ))
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

        let verified = match self.verify_stage(&http_req, now) {
            Ok(v) => progress.establish(v),
            // Signed inline rather than through `refuse`: there is no `Exchange` yet,
            // because nothing about the request is trusted.
            Err(refusal) => {
                return self.rejection(
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
        let outstanding = match self.validate_request_stage(&http_req) {
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

        let prep = match self.prepare_continuation_stage(&ex).await {
            Ok(prep) => progress.establish(prep),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        if prep.retained.is_some() {
            // A `peek`, so nothing is spent yet — a refusal from here is still an ordinary
            // retry, which is the whole reason the read is not a `consume`.
            progress.observe_continuation(ContinuationState::Peeked);
        }

        match self.replay_admission_stage(&ex, prep.binding()).await {
            Ok(admitted) => progress.establish(admitted),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        }

        let (a, expires) = match self.answerable_stage(&ex) {
            Ok(pair) => progress.establish(pair),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        // Carried on the exchange so every refusal below signs with the key the reply
        // itself would have used, rather than re-asking a signer that may have been
        // retired in between and degrading to an unsigned error.
        ex.key = Some(Arc::clone(&a));

        match self
            .retire_continuation_stage(prep.answer_key.as_ref())
            .await
        {
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
        self.audit(
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
        match self.inner_plane_stage() {
            Ok(accepted) => progress.establish(accepted),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        }
        let retention = match self.reserve_retention_stage(&ex).await {
            Ok(disposition) => progress.establish(disposition),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        // ===================== IRREVERSIBLE INNER DISPATCH =====================
        //
        // Every pre-dispatch prerequisite is now in hand, and `ReadyForDispatch` is what
        // says so: it cannot be built without them, and the dispatch consumes it. Past this
        // line no exit can claim nothing happened — which is why every one of them is a
        // `response_rejection` rather than a `rejection`.
        let ready = ReadyForDispatch::new(authorized.release(forwarded), a, expires, retention);
        // BEFORE the await, not after it. Once the request is committed to the backend the
        // exchange must read as possibly-executed, whatever the dispatch goes on to return:
        // a state entered only on the way out would leave a cancelled or panicking dispatch
        // claiming nothing happened.
        progress.advance(ExchangeEvent::BackendDispatched);
        let outcome = self.inner_async.dispatch(ready.forwarded()).await;
        let (outcome, a, expires, retention) = ready.dispatched(outcome).into_parts();

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
            match self.observe_notification_stage(&mut progress, &outcome) {
                Ok(acknowledged) => progress.establish(acknowledged),
                Err(refusal) => return self.refuse(&ex, refusal, &progress),
            }
            debug_assert!(progress.state().is_terminal());
            debug_assert!(progress.invariant_violation().is_none());
            return self
                .answer_notification(
                    &http_req,
                    &a,
                    now,
                    expires,
                    &verified,
                    actor_id,
                    &retention,
                    Self::disposition(&progress),
                )
                .await;
        }

        let inner_bytes = match self.observe_inner_stage(&mut progress, outcome) {
            Ok(bytes) => progress.establish(bytes),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: inner_bytes,
        };

        let parsed = match self.validate_envelope_stage(&response, &outstanding) {
            Ok(parsed) => progress.establish(parsed),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        let class = match self.classify_reply_stage(&parsed) {
            Ok(class) => progress.establish(class),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        // The obligation is incurred HERE, before the reply is signed and long before it is
        // served. It latches: nothing downstream can decide this exchange opens no leg after
        // the classifier decided it does.
        progress.observe_open_leg(match class {
            ReplyClass::Terminal => OpenLeg::NotApplicable,
            ReplyClass::Open(_) => OpenLeg::Required,
        });

        let response_base = match self.sign_reply_stage(&ex, &mut response, a.as_ref(), expires) {
            Ok(base) => progress.establish(base),
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };

        match &class {
            ReplyClass::Terminal => progress.advance(ExchangeEvent::ContinuationNotRequired),
            ReplyClass::Open(state) => {
                match self.record_open_leg_stage(&ex, state, response_base).await {
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
        self.audit(
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
        let reservation = match retention_owed {
            RetentionDisposition::NotConfigured => return None,
            RetentionDisposition::Reserved(reservation) => reservation,
        };
        // A disposition can only be `Reserved` if `self.retention` was present when it was
        // built, and the store is owned for the proxy's whole life.
        let retention = self.retention.as_ref()?;
        match retention.complete(reservation, request, response).await {
            Ok(_) => None,
            Err(e) => {
                // The backend has already run. Answering 503 here is what made a
                // transient store fault into repeated execution: 503 is the status
                // clients retry, and the retry's fresh nonce passes replay admission.
                eprintln!(
                    "evidence retention failed AFTER the call executed; the exchange is \
                     indeterminate and MUST NOT be blindly retried: {e}"
                );
                Some(self.response_rejection(
                    request,
                    &RefusalCause::from(McpReError::EvidenceRetentionIndeterminate),
                    500,
                    now,
                    bound,
                    Some(actor_id),
                    execution,
                    snapshot,
                ))
            }
        }
    }

    /// A PRE-ACCEPTANCE rejection — recorded as `mcp-re.request.rejected`.
    ///
    /// Used by every exit that runs BEFORE the `mcp-re.request.accepted` record is
    /// emitted, so `accepted` and `request.rejected` stay mutually exclusive per
    /// request (ADR-MCPS-035). `wire_code` is already the frozen token; the record
    /// carries it verbatim, never a parallel sub-name.
    ///
    /// `actor_id` is the VERIFIER-RESOLVED actor when one was established before this
    /// exit, and `None` when the request was refused before resolution — the
    /// distinction `AuditRecord` documents, and the reason a denial that carries
    /// attribution must not discard it.
    #[allow(clippy::too_many_arguments)]
    fn rejection(
        &self,
        request: &HttpRequest,
        cause: &RefusalCause,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: Option<String>,
        execution: ExecutionDisposition,
        snapshot: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ) -> ServedHttpResponse {
        self.audit(
            crate::audit_record::AuditSubject::request(
                match cause.core_verdict() {
                    Some(e) => mcp_re_core::audit::AuditEvent::request_rejected(&e),
                    // Core reached no verdict: a policy did. Its token belongs in the
                    // authorization coordinate below, never in Core's `reason`.
                    None => mcp_re_core::audit::AuditEvent::request_rejected_elsewhere(),
                },
                cause.authorization_facet(),
            ),
            actor_id,
            status,
            now,
        );
        self.signed_rejection(
            request,
            cause.wire_code(),
            status,
            now,
            bound,
            execution,
            snapshot,
        )
    }

    /// A POST-ACCEPTANCE rejection — recorded as `mcp-re.response.rejected`.
    ///
    /// The request was admitted (an `accepted` record already names it) and the fault
    /// is on the RESPONSE side: the forwarded body, the backend's reply class, the
    /// response signature, or recording the continuation that makes the reply
    /// answerable. Emitting `request.rejected` here would contradict the `accepted`
    /// record for the same request and attribute a backend fault to the caller;
    /// `mcp-re.response.rejected` is the frozen token the §9 taxonomy splits out for
    /// exactly this.
    #[allow(clippy::too_many_arguments)]
    fn response_rejection(
        &self,
        request: &HttpRequest,
        cause: &RefusalCause,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: Option<String>,
        execution: ExecutionDisposition,
        snapshot: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ) -> ServedHttpResponse {
        self.audit(
            crate::audit_record::AuditSubject::response(match cause.core_verdict() {
                Some(e) => mcp_re_core::audit::AuditEvent::response_rejected(&e),
                None => mcp_re_core::audit::AuditEvent::response_rejected_elsewhere(),
            }),
            actor_id,
            status,
            now,
        );
        self.signed_rejection(
            request,
            cause.wire_code(),
            status,
            now,
            bound,
            execution,
            snapshot,
        )
    }

    /// Build a signed rejection receipt bound to `request` (or preflight-unbound),
    /// with the injected `now` for the signature window (fail-closed freshness).
    ///
    /// Signs the rejection with the active delegated key and the inline credential
    /// (ADR-MCPRE-052) — request-bound when `bound` is `Some` (the request verified),
    /// preflight-unbound when `None` (the request never earned a trustworthy hash).
    /// Never root-signed. If no valid delegated key exists, a last-resort UNSIGNED
    /// error is emitted rather than a bogus signature.
    ///
    /// `snapshot` is the key the exchange took at ANSWERABLE, when it had got that far. It
    /// is preferred over re-asking the signer, and that preference is the whole reason it
    /// is threaded here: `current` returns `None` for a retired signer, so a drain or a
    /// failed rotation between ANSWERABLE and a post-dispatch refusal turned the one
    /// receipt that must state "the backend may have acted" into an unsigned body a client
    /// cannot tell from an on-path forgery. The same snapshot signs the successful reply,
    /// so no refusal claims a validity the reply would not have had.
    ///
    /// Carries no audit emission of its own: the two callers above choose the frozen
    /// event type, because which one is correct depends on whether the request had
    /// already been admitted.
    #[allow(clippy::too_many_arguments)]
    fn signed_rejection(
        &self,
        request: &HttpRequest,
        wire_code: &'static str,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        execution: ExecutionDisposition,
        snapshot: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ) -> ServedHttpResponse {
        let reason = RejectionReason::new(
            wire_code,
            format!("mcp-re http-profile proxy rejected: {wire_code}"),
        )
        .with_execution(execution);
        let resp = match snapshot.or_else(|| self.signer.current(now)) {
            Some(a) => {
                // Never advertise validity past the credential that authorizes the
                // signature: a verifier refuses the whole receipt once the delegated
                // credential's own window closes.
                let expires = (now + self.sig_ttl_secs).min(a.exp);
                let built = match bound {
                    Some(ev) => build_delegated_rejection(
                        request,
                        ev,
                        &reason,
                        status,
                        &a.server_signer,
                        &a.credential,
                        a.key.as_ref(),
                        &a.delegated_kid,
                        now,
                        expires,
                    ),
                    None => build_delegated_rejection_preflight(
                        Some(request),
                        &reason,
                        status,
                        &a.server_signer,
                        &a.credential,
                        a.key.as_ref(),
                        &a.delegated_kid,
                        now,
                        expires,
                    ),
                };
                built.unwrap_or_else(|_| unsigned_error(status, wire_code, execution))
            }
            None => unsigned_error(status, wire_code, execution),
        };
        served(resp)
    }
}

/// Which MCP lifecycle transition a validated reply is.
///
/// Carries the `requestState` for an open leg because the classifier is the only place that
/// reads it out of the body, and passing the body along instead would invite a second reader
/// to walk the same JSON and reach its own conclusion.
///
/// A JSON-RPC error is [`Terminal`](ReplyClass::Terminal): a legal terminal protocol
/// response, distinct from a malformed one and from a transport failure.
enum ReplyClass {
    /// The exchange ends here — an ordinary result, or a JSON-RPC error.
    Terminal,
    /// An `InputRequiredResult`. The state is the one an answer leg re-presents.
    Open(String),
}

/// Wrap a fully-built [`HttpResponse`] as a [`ServedHttpResponse`].
fn served(resp: HttpResponse) -> ServedHttpResponse {
    ServedHttpResponse {
        status: resp.status,
        headers: resp.headers,
        body: resp.body,
    }
}

/// Read `params.requestState` (a string) from a JSON-RPC request body — the opaque
/// MRTR state an answer leg re-presents (ADR-MCPS-047). `None` if the body is not
/// JSON, has no `params.requestState`, or it is not a string.
///
/// The value is read only to KEY the correlation store; it is never interpreted, and
/// what it binds to is settled by digest equality against the retained bases.
pub fn extract_request_state(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("params")?
        .get("requestState")?
        .as_str()
        .map(str::to_owned)
}

/// Compose the body forwarded to the inner server (#415 rev 2 §10, MCPRE-429).
///
/// Two steps, in this order:
///
/// 1. **Strip the PEP-owned `_meta` keys** — the request-evidence block the PEP
///    just consumed, and the reserved verified-context key. This is the §10 guard
///    and it runs on EVERY request regardless of policy: a caller that could seed
///    the reserved key would be asserting its own verified context to a server
///    that trusts the block implicitly, which is an authentication bypass rather
///    than a spoofing nuisance. A deployment with the carrier disabled must not be
///    one config flip away from forwarding attacker-authored context.
///
///    Only PEP-owned keys are removed. Application and MCP `_meta` entries are
///    none of the enforcement boundary's business — deleting the whole `_meta`
///    would not be caution, it would be destroying data the PEP was asked to pass
///    through.
///
/// 2. **Write the PEP's own context**, only under an explicitly trusted channel.
///
/// Returns `Err` if the trusted carrier is enabled and the context could not be
/// written. That is deliberate: under `Trusted` the inner server is entitled to
/// assume the PEP speaks, and silently forwarding a request WITHOUT the context it
/// expects would degrade into an unauthenticated call that looks ordinary. Fail
/// closed instead.
fn forwarded_body(
    body: &[u8],
    verified: &VerifiedMcpRequest,
    policy: VerifiedContextPolicy,
    now: i64,
) -> Result<Forwarded, HttpProfileError> {
    // The forwarded bytes are re-serialized below, which cannot carry a duplicate
    // member name or a number the f64 carrier alters. Refuse those on the ORIGINAL
    // bytes, using the same scan the response path applies, so the backend never sees
    // a body that differs from what the client signed.
    mcp_re_http_profile::reject_unrepresentable_json(body)?;
    let mut seeded = false;
    let stripped = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut v) => {
            seeded = strip_proxy_owned_meta(&mut v);
            serde_json::to_vec(&v)
                .map_err(|_| HttpProfileError::MalformedEvidence("body reserialize"))?
        }
        // A non-object body never verified as a full-profile request, so this is
        // unreachable on the served path; pass it through rather than invent bytes.
        Err(_) => body.to_vec(),
    };
    let body = match policy {
        VerifiedContextPolicy::Disabled => stripped,
        VerifiedContextPolicy::Trusted => {
            let ctx = VerifiedContext::from_verified(verified, now);
            insert_verified_context(&stripped, &ctx)?
        }
    };
    Ok(Forwarded { body, seeded })
}

/// The body forwarded to the inner server, plus the §10 guard's detection signal.
struct Forwarded {
    /// The clean JSON-RPC bytes the inner server receives.
    body: Vec<u8>,
    /// Whether the caller had seeded the reserved verified-context key. The value was
    /// stripped either way; this is the only trace the attempt leaves, so the serving
    /// path names it rather than discarding it.
    seeded: bool,
}

/// A last-resort unsigned error body when even the signed rejection cannot be built
/// (a server-key failure). Never a silent allow — an explicit error status.
///
/// It still states what the exchange knows about effects. That claim is the one thing a
/// client cannot infer from what is left: an unsigned 504 with an empty error object reads
/// as an ordinary transport failure, i.e. as did-not-run, on the exits where the proxy
/// knows the backend was dispatched.
fn unsigned_error(status: u16, wire_code: &str, execution: ExecutionDisposition) -> HttpResponse {
    let mut mcp_re_error = serde_json::json!({ "wire_code": wire_code });
    // The SAME projection the signed rejection uses. Both inputs are handed over, so this
    // receipt can state the wire-code-dependent cases — a retention failure the client must
    // reconcile against a store that has no record of the call — and not merely what the
    // disposition alone knows.
    if let Some(claim) = mcp_re_http_profile::retry_semantics(wire_code, execution) {
        if let (Some(target), Some(extra)) = (mcp_re_error.as_object_mut(), claim.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
    }
    HttpResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE,
                "message": wire_code,
                "data": { "mcp_re_error": mcp_re_error },
            },
            "id": serde_json::Value::Null,
        }))
        .unwrap_or_default(),
    }
}

#[cfg(test)]
mod admission_window_tests {
    use super::*;

    fn enforcer(bound: i64, skew: i64, allow_degraded: bool) -> AdmissionEnforcer {
        AdmissionEnforcer {
            source: Arc::new(crate::admission_source::InMemoryAdmissionSource::new()),
            policy: AdmissionPolicy {
                max_assertion_age: 300,
                max_clock_skew: skew,
                degraded_propagation_bound: bound,
                allow_degraded_mode: allow_degraded,
            },
            enforcement: AdmissionEnforcement::Required,
            resolve_authority: Arc::new(|_kid: &str| None),
            last_authoritative_read: std::sync::atomic::AtomicI64::new(i64::MIN),
        }
    }

    /// A replica that has never reached the authority has no last-known state to serve
    /// on, so startup is not a confirmation.
    #[test]
    fn a_replica_that_never_reached_the_authority_has_no_window() {
        assert!(enforcer(60, 5, true).degraded_window_exhausted(1_000));
    }

    /// R7-C093: the degraded window is elapsed OUTAGE time, not assertion freshness.
    ///
    /// The revocation channel is the store, so during a store outage the issuer never
    /// learns of a revocation and keeps minting assertions with a current `iat`. A
    /// caller that simply keeps fetching them was therefore served for the whole
    /// outage, however long, while the operator was told degraded serving is bounded
    /// by P. Nothing the caller can do moves this clock.
    #[test]
    fn the_degraded_window_closes_p_after_the_last_successful_read() {
        let enforcer = enforcer(60, 5, true);
        enforcer.record_authoritative_read(1_000);

        assert!(
            !enforcer.degraded_window_exhausted(1_060),
            "inside P + skew the last-known state is still usable"
        );
        assert!(
            !enforcer.degraded_window_exhausted(1_065),
            "the skew allowance is on the same clock"
        );
        assert!(
            enforcer.degraded_window_exhausted(1_066),
            "past P + skew an unreachable authority fails closed, however fresh the \
             assertion the caller presents"
        );
    }

    /// The clock only moves forward: a stale read cannot re-open a window a later one
    /// closed.
    #[test]
    fn an_out_of_order_read_does_not_rewind_the_window() {
        let enforcer = enforcer(60, 0, true);
        enforcer.record_authoritative_read(2_000);
        enforcer.record_authoritative_read(1_000);
        assert!(!enforcer.degraded_window_exhausted(2_050));
    }

    /// Degraded mode is opt-in; without it an unreachable authority fails closed at
    /// once, whatever was last read.
    #[test]
    fn without_the_opt_in_there_is_no_window_at_all() {
        let enforcer = enforcer(3_600, 30, false);
        enforcer.record_authoritative_read(1_000);
        assert!(enforcer.degraded_window_exhausted(1_001));
    }
}

/// The last-resort unsigned receipt states what the signed one would have stated.
///
/// This is the exit where a client has least to go on: no signature, no binding, and an
/// error object it would otherwise read as an ordinary transport failure. What it must
/// still carry is the execution claim — and the claim is a function of the wire code as
/// well as the disposition, which is why this receipt consumes the canonical projection
/// rather than a local copy of it.
#[cfg(test)]
mod last_resort_receipt_tests {
    use super::*;

    /// Read the `mcp_re_error` object out of an unsigned last-resort body.
    fn claim(status: u16, wire_code: &str, execution: ExecutionDisposition) -> serde_json::Value {
        let resp = unsigned_error(status, wire_code, execution);
        let body: serde_json::Value =
            serde_json::from_slice(&resp.body).expect("the last-resort body is JSON");
        body["error"]["data"]["mcp_re_error"].clone()
    }

    /// The negative control for the duplicated-authority defect.
    ///
    /// A local projection taking only the disposition CANNOT produce `retention_status`,
    /// because that case is selected by the wire code. Before the duplicate was deleted
    /// this assertion failed on the missing field while every other field passed — the
    /// client was told to reconcile without being told the evidence store has no record of
    /// the call it must reconcile.
    #[test]
    fn a_retention_indeterminate_last_resort_receipt_still_names_the_failed_obligation() {
        let e = claim(
            500,
            mcp_re_core::McpReError::EvidenceRetentionIndeterminate.wire_code(),
            ExecutionDisposition::PossiblyExecuted,
        );
        assert_eq!(e["execution_status"], "possibly_executed");
        assert_eq!(
            e["retention_status"], "failed",
            "the unsigned receipt must state WHICH obligation failed: {e}"
        );
        assert_eq!(e["retry_safety"], "unsafe_without_reconciliation");
    }

    /// The field is selected by the wire code, not added to every possibly-executed exit.
    #[test]
    fn an_ordinary_post_dispatch_failure_claims_no_retention_status() {
        let e = claim(
            502,
            mcp_re_core::McpReError::TrustResolverUnavailable.wire_code(),
            ExecutionDisposition::PossiblyExecuted,
        );
        assert_eq!(e["execution_status"], "possibly_executed");
        assert!(
            e.get("retention_status").is_none(),
            "no retention obligation failed here: {e}"
        );
    }

    /// The spent-approval case is disposition-selected and survives the same path.
    #[test]
    fn a_spent_approval_last_resort_receipt_names_the_consumed_continuation() {
        let e = claim(
            503,
            mcp_re_core::McpReError::ReplayCacheUnavailable.wire_code(),
            ExecutionDisposition::ApprovalSpentNothingExecuted,
        );
        assert_eq!(e["execution_status"], "not_executed");
        assert_eq!(e["continuation_status"], "consumed");
        assert_eq!(e["retry_safety"], "unsafe_without_new_elicitation");
    }

    /// An exchange that states nothing adds nothing: the frozen vectors keep their bytes.
    #[test]
    fn an_unstated_disposition_adds_no_claim() {
        let e = claim(
            400,
            mcp_re_core::McpReError::MalformedEnvelope.wire_code(),
            ExecutionDisposition::Unstated,
        );
        assert_eq!(
            e.as_object().expect("an object").len(),
            1,
            "only the wire code: {e}"
        );
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
