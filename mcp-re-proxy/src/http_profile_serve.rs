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
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::build_delegated_rejection;
use mcp_re_http_profile::build_delegated_rejection_preflight;
use mcp_re_http_profile::check_admission;
use mcp_re_http_profile::insert_verified_context;
use mcp_re_http_profile::outstanding_id;
use mcp_re_http_profile::parse_response_body;
use mcp_re_http_profile::result_class::classify_result_type;
use mcp_re_http_profile::result_class::input_required_state_of;
use mcp_re_http_profile::result_class::ResultTypeClass;
use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::strip_proxy_owned_meta;
use mcp_re_http_profile::validate_response_envelope;
use mcp_re_http_profile::verify_request_full_with_policy;
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
use mcp_re_http_profile::VerifiedHttpRequestEvidence;
use mcp_re_http_profile::VerifierPolicy;

use crate::admission_source::AsyncAdmissionSource;
use crate::async_inner::AsyncInnerServer;
use crate::async_inner::InnerOutcome;
use crate::async_serve::ServedHttpRequest;
use crate::async_serve::ServedHttpResponse;
use crate::continuation_store::continuation_key;
use crate::continuation_store::AsyncContinuationStore;
use crate::continuation_store::RetainedBases;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::exchange_state::ContinuationState;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::exchange_state::OpenLeg;
use crate::exchange_state::ResponseOrigin;
use crate::exchange_state::RetrySemantics;
use crate::http_profile_dispatch::dispatch_request_with_async_tier;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::request_stages::ReadyForDispatch;
use crate::request_stages::RetentionDisposition;
use crate::transport::TransportBindingPolicy;

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

/// How a refusal must be signed and recorded.
///
/// Not a detail of presentation: each posture is a different claim. Preflight says no
/// trustworthy request hash exists; the other two say one does, and differ on whether the
/// request had already been ADMITTED — which decides whether the fault is attributed to the
/// caller or to the response side (ADR-MCPS-035 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalPosture {
    /// The request never verified. Signed response-only, no actor to attribute it to.
    Preflight,
    /// The request verified but was not yet admitted. Bound via `;req`, recorded as
    /// `mcp-re.request.rejected`.
    BeforeAdmission,
    /// The request was admitted, so the fault is on the response side. Bound, recorded as
    /// `mcp-re.response.rejected` — a `request.rejected` here would contradict the
    /// `accepted` record already emitted for the same request.
    AfterAdmission,
}

/// What a stage DECIDED, before anything is signed.
///
/// A stage names its refusal; it does not produce one. Two reasons, and the second is the
/// load-bearing one:
///
/// * signing is authority, and the eleven stages have no business exercising it;
/// * a refusal that is a VALUE can be asserted on directly, so a stage's contract can be
///   tested without standing up a signer, a credential, or a clock.
///
/// Note what is absent: the retry contract. A stage cannot state it, because it is a fact
/// about the whole exchange rather than about the step that failed. It is derived once, from
/// the exchange machine, where [`HttpProfileProxy::refuse`] signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal {
    wire_code: &'static str,
    status: u16,
    posture: RefusalPosture,
}

impl Refusal {
    /// The request never verified.
    fn preflight(wire_code: &'static str, status: u16) -> Self {
        Refusal {
            wire_code,
            status,
            posture: RefusalPosture::Preflight,
        }
    }

    /// The request verified but had not been admitted.
    fn before_admission(wire_code: &'static str, status: u16) -> Self {
        Refusal {
            wire_code,
            status,
            posture: RefusalPosture::BeforeAdmission,
        }
    }

    /// The request was admitted; the fault is on the response side.
    fn after_admission(wire_code: &'static str, status: u16) -> Self {
        Refusal {
            wire_code,
            status,
            posture: RefusalPosture::AfterAdmission,
        }
    }
}

/// One exchange's identity, as every stage past VERIFIED needs it.
///
/// Grouped because these four travel together and never independently: the request a
/// refusal binds to, the evidence that makes binding possible, the actor it is attributed
/// to, and the instant the whole exchange is judged at. `now` is fixed for the exchange, so
/// a key valid at ANSWERABLE is still valid at RESPONSE-SIGNED.
struct Exchange<'a> {
    http_req: &'a HttpRequest,
    verified: &'a VerifiedHttpRequestEvidence,
    actor_id: &'a str,
    now: i64,
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
    transport_binding: Option<Box<dyn TransportBindingPolicy + Send + Sync>>,
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

/// What a request that carries NO admission evidence means to this deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionEnforcement {
    /// Serve it. For a deployment that has not rolled admission out to every client
    /// yet — the binding is honoured when present and absent is not an error.
    Optional,
    /// Refuse it. The only setting under which "every served call acted under a
    /// current admission" is a true statement about the deployment.
    Required,
}

/// The §7 admission gate's collaborators, held together because none of them is
/// meaningful alone.
struct AdmissionEnforcer {
    /// The authoritative state this PEP consults per call.
    source: Arc<dyn AsyncAdmissionSource>,
    /// The N/P/TTL freshness budget and the degraded-mode opt-in (§5.2).
    policy: AdmissionPolicy,
    /// What an admission-free request means here.
    enforcement: AdmissionEnforcement,
    /// Resolves an assertion's `issuer_kid` to the admission authority's root key.
    /// A kid never introduces trust: an assertion signed by an unresolvable issuer
    /// is refused, exactly as an unknown request keyid is.
    resolve_authority: AdmissionAuthorityResolver,
    /// When the authoritative source was last READ successfully, in unix seconds.
    ///
    /// P bounds how long this PEP may serve on last-known state while the authority is
    /// unreachable. Applied to the presented assertion's `iat`, it bounds the wrong
    /// thing: the revocation channel is the STORE, so during a store outage the
    /// assertion issuer never learns of a revocation and keeps minting assertions with
    /// a current `iat` — and a caller that simply keeps fetching them is served for the
    /// whole outage, however long. Bounding elapsed time since the last successful read
    /// is what makes "degraded serving is bounded by P" a true statement about the
    /// deployment.
    ///
    /// `i64::MIN` until the first successful read: a replica that has never reached the
    /// authority has no last-known state to serve on, so it fails closed rather than
    /// treating startup as a confirmation.
    last_authoritative_read: std::sync::atomic::AtomicI64,
}

impl AdmissionEnforcer {
    /// Note that the authoritative record was read at `now`.
    ///
    /// A definitive negative counts: the authority answered, which is what P measures.
    fn record_authoritative_read(&self, now: i64) {
        self.last_authoritative_read
            .fetch_max(now, std::sync::atomic::Ordering::Relaxed);
    }

    /// Has the authority been unreachable for longer than P (+ skew)?
    ///
    /// True also when it has never been reachable, and whenever degraded mode is not
    /// enabled at all — in both cases there is no window to be inside of.
    fn degraded_window_exhausted(&self, now: i64) -> bool {
        if !self.policy.allow_degraded_mode {
            return true;
        }
        let last = self
            .last_authoritative_read
            .load(std::sync::atomic::Ordering::Relaxed);
        if last == i64::MIN {
            return true;
        }
        now.saturating_sub(last)
            > self
                .policy
                .degraded_propagation_bound
                .saturating_add(self.policy.max_clock_skew)
    }
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
    fn audit(
        &self,
        event: mcp_re_core::audit::AuditEvent,
        actor_id: Option<String>,
        status: u16,
        now: i64,
    ) {
        if let Some(sink) = &self.audit {
            sink.record(&crate::audit_sink::AuditRecord {
                event,
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
    pub fn with_transport_binding(
        mut self,
        binding: Box<dyn TransportBindingPolicy + Send + Sync>,
    ) -> Self {
        self.transport_binding = Some(binding);
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

    /// The §7 currency gate. `None` when the call is admitted (or admission is not
    /// enforced); `Some(response)` is the signed rejection to return.
    ///
    /// Placed before replay admission and the inner round trip, because both are
    /// irreversible: burning a nonce and running a tool on behalf of a workload whose
    /// admission has been revoked is precisely what this exists to prevent.
    async fn admission_gate(
        &self,
        http_req: &HttpRequest,
        verified: &VerifiedHttpRequestEvidence,
        actor_id: &str,
        now: i64,
        execution: ExecutionDisposition,
    ) -> Option<ServedHttpResponse> {
        let enforcer = self.admission.as_ref()?;
        let block = verified.request_block.as_ref();
        let binding = block.and_then(|b| b.admission.as_ref());
        let assertion = block.and_then(|b| b.admission_assertion.as_deref());

        let (binding, assertion) = match (binding, assertion) {
            (Some(b), Some(a)) => (b, a),
            // The block validator already refuses one half without the other, so
            // reaching here means BOTH are absent: the call declares no admission.
            _ => {
                if enforcer.enforcement == AdmissionEnforcement::Required {
                    return Some(self.rejection(
                        http_req,
                        HttpProfileError::AdmissionStateUnavailable.wire_code(),
                        403,
                        now,
                        Some(&verified.evidence),
                        Some(actor_id.to_owned()),
                        execution,
                    ));
                }
                return None;
            }
        };

        // The authoritative lookup. An outage yields `None` — the ONLY input that
        // reaches the §5.2 degraded fork — while a healthy authority that has never
        // heard of this workload is a definitive negative, refused here rather than
        // being handed to a fork that would serve it on its own assertion.
        let authoritative = match enforcer.source.current(&binding.admission_id).await {
            Ok(Some(state)) => {
                enforcer.record_authoritative_read(now);
                Some(state)
            }
            Ok(None) => {
                enforcer.record_authoritative_read(now);
                return Some(self.rejection(
                    http_req,
                    HttpProfileError::AdmissionNotCurrent.wire_code(),
                    403,
                    now,
                    Some(&verified.evidence),
                    Some(actor_id.to_owned()),
                    execution,
                ));
            }
            // The source is unreachable. Whether the §5.2 degraded fork may be entered
            // at all is decided HERE, by how long the authority has been unreachable —
            // not downstream by how fresh the caller's assertion is, which the caller
            // controls.
            Err(_) => {
                if enforcer.degraded_window_exhausted(now) {
                    return Some(self.rejection(
                        http_req,
                        HttpProfileError::AdmissionStateUnavailable.wire_code(),
                        403,
                        now,
                        Some(&verified.evidence),
                        Some(actor_id.to_owned()),
                        execution,
                    ));
                }
                None
            }
        };

        let resolve = Arc::clone(&enforcer.resolve_authority);
        match check_admission(
            binding,
            assertion,
            // The VERIFIER-RESOLVED actor, never anything the request asserts. An
            // assertion issued to another workload names a different actor and is
            // refused here, so possession alone no longer satisfies the gate.
            actor_id,
            authoritative.as_ref(),
            mcp_re_http_profile::PROFILE_TAG,
            &[self.expected_audience.audience_id.as_str()],
            &enforcer.policy,
            now,
            move |kid: &str| resolve(kid),
        ) {
            // Admitted. Note what is NOT recorded: `VerifiedAdmission::degraded`
            // distinguishes a live-confirmed admission from one served on a stale
            // snapshot inside the P window, and the audit stream cannot currently
            // carry that difference — ADR-MCPS-035 §3 freezes the success-event
            // allowlist and says no third success event may be minted without an
            // ADR. So a degraded-mode serve is indistinguishable in audit from a
            // confirmed one. That is a real gap in the record, named here rather
            // than closed by quietly widening a pinned vocabulary.
            Ok(_) => None,
            Err(e) => Some(self.rejection(
                http_req,
                e.wire_code(),
                403,
                now,
                Some(&verified.evidence),
                Some(actor_id.to_owned()),
                execution,
            )),
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
            _ => (Some(&ex.verified.evidence), Some(ex.actor_id.to_owned())),
        };
        if refusal.posture == RefusalPosture::AfterAdmission {
            return self.response_rejection(
                ex.http_req,
                refusal.wire_code,
                refusal.status,
                ex.now,
                bound,
                actor,
                execution,
            );
        }
        self.rejection(
            ex.http_req,
            refusal.wire_code,
            refusal.status,
            ex.now,
            bound,
            actor,
            execution,
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
        a: &mcp_re_http_profile::ActiveDelegatedKey,
        now: i64,
        expires: i64,
        verified: &mcp_re_http_profile::VerifiedHttpRequestEvidence,
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
                        Some(&verified.evidence),
                        actor_id.clone(),
                        retention,
                        execution,
                    )
                    .await
                {
                    return rejection;
                }
                // The signed bodyless 202 IS the signed response for a notification,
                // and it is returned on this line — so the record describes bytes the
                // client actually receives.
                self.audit(
                    mcp_re_core::audit::AuditEvent::response_signed(),
                    Some(actor_id),
                    202,
                    now,
                );
                served(ack)
            }
            Err(e) => self.response_rejection(
                http_req,
                e.wire_code(),
                500,
                now,
                Some(&verified.evidence),
                Some(actor_id),
                execution,
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
    // machine, each with an explicit contract: the state it requires, the state it
    // establishes, what it may not do, and whether its refusal is free.
    //
    // The point is not fewer lines. It is that each transition can be tested — and
    // eventually PROVED — on its own, rather than only as a property of the whole
    // pipeline. A stage that returns `Err` returns the finished signed refusal, so
    // `handle` composes them with `?` and never re-decides what a failure means.
    //
    // Refusals take their retry contract from the machine, never from their own position:
    // every one of them passes `Self::disposition(progress)`.

    /// VERIFIED — RFC 9421 + RFC 9530 + the evidence block.
    ///
    /// ```text
    /// requires  exchange machine = Received
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
    ) -> Result<VerifiedHttpRequestEvidence, Refusal> {
        let no_material = |_b: &ArtifactBinding| None;
        // Scoped so the timer covers the verification and nothing after it.
        let verify_result = {
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Verify);
            verify_request_full_with_policy(
                http_req,
                &self.expected_audience,
                &no_material,
                self.resolve_actor.as_ref(),
                &self.verifier_policy,
                now,
            )
        };
        // The request never verified, so there is no trustworthy request hash to bind to
        // and no resolved actor to attribute the denial to.
        verify_result.map_err(|e| Refusal::preflight(e.wire_code(), 403))
    }

    /// TRANSPORT-BOUND — Mode-A: the verified request actor must be the mTLS peer.
    ///
    /// ```text
    /// requires  exchange machine = Verified
    /// ensures   Ok  => the signer and the transport peer are the same principal
    ///           Err => 403, bound to the request via `;req`
    /// forbids   any effect on the request's behalf
    /// refusal   free
    /// ```
    ///
    /// A deployment with no binding policy installed passes: the channel is then not
    /// claimed to be bound, rather than claimed to be bound by an absent check.
    fn transport_binding_stage(
        &self,
        ex: &Exchange<'_>,
        identity: Option<&crate::transport::TransportIdentity>,
    ) -> Result<(), Refusal> {
        let Some(binding) = &self.transport_binding else {
            return Ok(());
        };
        if binding.check(ex.actor_id, identity).is_ok() {
            return Ok(());
        }
        Err(Refusal::before_admission(
            "mcp-re.transport_binding_failed",
            403,
        ))
    }

    /// CONTINUATION-PREPARED — recover the retained open-leg bases for an ANSWER leg.
    ///
    /// ```text
    /// requires  exchange machine = AdmissionChecked
    /// ensures   the continuation machine is NotInvolved or Peeked — never Consumed
    /// forbids   consuming anything; this stage cannot fail
    /// refusal   n/a — a store outage flattens to "no bases", and the binding then
    ///           fails closed downstream rather than admitting an unbindable leg
    /// ```
    ///
    /// Keyed by the actor the VERIFIER resolved, never by anything the request asserts, so
    /// one peer cannot name another's continuation at all. `peek` has no side effect, which
    /// is what lets a request that is about to be refused leave a live approval intact.
    async fn prepare_continuation_stage(&self, ex: &Exchange<'_>) -> ContinuationPrep {
        let has_continuation = ex
            .verified
            .request_block
            .as_ref()
            .and_then(|b| b.continuation.as_ref())
            .is_some();
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
            (Some(store), Some(key)) => store.peek(key).await.ok().flatten(),
            _ => None,
        };
        ContinuationPrep {
            answer_state,
            answer_key,
            retained,
        }
    }

    /// REPLAY-ADMITTED — async §4 replay admission plus the continuation binding.
    ///
    /// ```text
    /// requires  exchange machine = ContinuationPrepared
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
    ) -> Result<(), Refusal> {
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
        .map(|_| ())
        .map_err(|e| Refusal::before_admission(e.wire_code(), 409))
    }

    /// ANSWERABLE — can this request be answered AT ALL?
    ///
    /// ```text
    /// requires  exchange machine = ReplayAdmitted
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
    ) -> Result<(Arc<mcp_re_http_profile::ActiveDelegatedKey>, i64), Refusal> {
        match self.signer.current(ex.now) {
            // The snapshot is taken ONCE and signs the reply below: `now` is fixed for the
            // whole request, so a key valid here is valid there.
            Some(a) => {
                let expires = (ex.now + self.sig_ttl_secs).min(a.exp);
                Ok((a, expires))
            }
            None => Err(Refusal::before_admission(
                McpReError::DelegatedSigningUnavailable.wire_code(),
                503,
            )),
        }
    }

    /// CONTINUATION-RETIRED — spend the approval, exactly once.
    ///
    /// ```text
    /// requires  exchange machine = Answerable
    /// ensures   Ok(true)  => THIS call removed the live entry; the approval is spent
    ///           Ok(false) => there was nothing to retire
    ///           Err       => 409, bound
    /// forbids   running the backend
    /// refusal   free of EXECUTION, but not free of consequence — see the caller
    /// ```
    ///
    /// One-shot is enforced here, by the store's atomic `consume`: of two concurrent answer
    /// legs that both bound successfully, exactly one proceeds. A store ERROR is also
    /// refused — the entry may or may not be gone, and admitting an answer that cannot be
    /// retired would make the continuation answerable twice.
    async fn retire_continuation_stage(
        &self,
        answer_key: Option<&String>,
    ) -> Result<bool, Refusal> {
        let (Some(store), Some(key)) = (&self.continuation_store, answer_key) else {
            return Ok(false);
        };
        match store.consume(key).await {
            Ok(true) => Ok(true),
            Ok(false) | Err(_) => Err(Refusal::before_admission(
                McpReError::ContinuationBindingFailed.wire_code(),
                409,
            )),
        }
    }

    /// FORWARDED — strip the proxy-owned `_meta` so the backend sees clean MCP.
    ///
    /// ```text
    /// requires  exchange machine = ContinuationRetired
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
    fn forward_body_stage(&self, ex: &Exchange<'_>) -> Result<Vec<u8>, Refusal> {
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
                Ok(body)
            }
            Err(e) => Err(Refusal::after_admission(e.wire_code(), 500)),
        }
    }

    /// RETENTION-RESERVED — take durable responsibility BEFORE the side effects run.
    ///
    /// ```text
    /// requires  exchange machine = Forwarded
    /// ensures   Ok  => the crossing of the execution threshold is itself durable
    ///           Err => 503, bound
    /// forbids   running the backend
    /// refusal   THE LAST FREE ONE — past the dispatch, no refusal can say nothing happened
    /// ```
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
    ) -> Result<RetentionDisposition, Refusal> {
        let Some(retention) = self.retention.as_ref() else {
            return Ok(RetentionDisposition::NotConfigured);
        };
        match retention.reserve(ex.http_req).await {
            Ok(reservation) => Ok(RetentionDisposition::Reserved(reservation)),
            Err(e) => {
                eprintln!(
                    "evidence retention could not accept the exchange, refusing before \
                     dispatch: {e}"
                );
                Err(Refusal::after_admission(
                    McpReError::EvidenceRetentionUnavailable.wire_code(),
                    503,
                ))
            }
        }
    }

    /// INNER-PLANE-ACCEPTED — can a dispatch begin at all?
    ///
    /// ```text
    /// requires  exchange machine = RetentionReserved
    /// ensures   Ok  => the inner plane has a permit and a live backend
    ///           Err => 503, bound
    /// forbids   transmitting anything
    /// refusal   THE LAST FREE ONE — past the dispatch, no refusal can say nothing happened
    /// ```
    ///
    /// Local saturation and a fully-ejected backend set are facts about THIS proxy, knowable
    /// without putting a byte on the wire. Discovering them from the far side of the
    /// threshold — which is what a seam returning only bytes forces — turned a
    /// definitely-not-executed outage into an exchange that must claim `possibly_executed`
    /// forever after, and served it as a signed HTTP 200 carrying an error body.
    fn inner_plane_stage(&self) -> Result<(), Refusal> {
        self.inner_async.admit().map_err(|_| {
            Refusal::after_admission(McpReError::InnerPlaneUnavailable.wire_code(), 503)
        })
    }

    /// RESPONSE-OBSERVED — what did the inner plane actually manage to do?
    ///
    /// ```text
    /// requires  exchange machine = Dispatched (the backend HAS acted)
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
    ) -> Result<Vec<u8>, Refusal> {
        match outcome {
            InnerOutcome::Replied(bytes) => {
                progress.observe_origin(ResponseOrigin::BackendReplied);
                Ok(bytes)
            }
            // A lost race against `admit`: the last permit went to another core between the
            // question and the dispatch. Reported as what it is, at the consequence the
            // exchange has already crossed — the floor does not move back for a more
            // precise late observation.
            InnerOutcome::NotDispatched(_) => Err(Refusal::after_admission(
                McpReError::InnerPlaneUnavailable.wire_code(),
                503,
            )),
            InnerOutcome::Indeterminate(_) => {
                progress.observe_origin(ResponseOrigin::DispatchIndeterminate);
                Err(Refusal::after_admission(
                    McpReError::InnerDispatchIndeterminate.wire_code(),
                    504,
                ))
            }
            InnerOutcome::InvalidUpstream(clause) => Err(Refusal::after_admission(
                HttpProfileError::UpstreamResponseInvalid(clause).wire_code(),
                502,
            )),
        }
    }

    /// RESPONSE-VALIDATED — the JSON-RPC control envelope must be legal before anything
    /// treats these bytes as a response.
    ///
    /// ```text
    /// requires  exchange machine = ResponseObserved
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
        ex: &Exchange<'_>,
        response: &HttpResponse,
    ) -> Result<serde_json::Value, Refusal> {
        let invalid = |clause| {
            Refusal::after_admission(
                HttpProfileError::UpstreamResponseInvalid(clause).wire_code(),
                502,
            )
        };
        let outstanding = outstanding_id(&ex.http_req.body).map_err(|_| invalid("request id"))?;
        let parsed = parse_response_body(&response.body).map_err(|e| match e {
            HttpProfileError::UpstreamResponseInvalid(clause) => invalid(clause),
            _ => invalid("response body"),
        })?;
        match validate_response_envelope(&parsed, &outstanding) {
            Ok(_) => Ok(parsed),
            Err(HttpProfileError::UpstreamResponseInvalid(clause)) => Err(invalid(clause)),
            Err(e) => Err(Refusal::after_admission(e.wire_code(), 502)),
        }
    }

    /// RESPONSE-CLASSIFIED — which MCP lifecycle transition is this reply?
    ///
    /// ```text
    /// requires  exchange machine = ResponseValidated
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
    fn classify_reply_stage(&self, parsed: &serde_json::Value) -> Result<ReplyClass, Refusal> {
        let result = parsed.get("result");
        match classify_result_type(result) {
            ResultTypeClass::Complete => Ok(ReplyClass::Terminal),
            ResultTypeClass::Unrecognized => Err(Refusal::after_admission(
                HttpProfileError::UnrecognizedResultType.wire_code(),
                502,
            )),
            ResultTypeClass::InputRequired => match input_required_state_of(result) {
                Ok(Some(state)) => Ok(ReplyClass::Open(state)),
                // Classified as non-terminal and then failed to yield its state: the two
                // arms cannot both be right, and the only safe reading is that the message
                // is invalid.
                _ => Err(Refusal::after_admission(
                    HttpProfileError::UpstreamResponseInvalid("input_required requestState")
                        .wire_code(),
                    502,
                )),
            },
        }
    }

    /// RESPONSE-SIGNED — the enforcement boundary puts its signature on the reply.
    ///
    /// ```text
    /// requires  exchange machine = ResponseClassified
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
    ) -> Result<Vec<u8>, Refusal> {
        // Scoped so the timer covers the signature and nothing after it.
        let sign_result = {
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Sign);
            sign_delegated_response_full(
                response,
                ex.http_req,
                &ex.verified.evidence,
                &a.server_signer,
                &a.credential,
                a.key.as_ref(),
                &a.delegated_kid,
                ex.now,
                expires,
            )
        };
        sign_result.map_err(|e| Refusal::after_admission(e.wire_code(), 500))
    }

    /// CONTINUATION-RECORDED — make an open leg answerable on any replica.
    ///
    /// ```text
    /// requires  exchange machine = ResponseSigned
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
    ) -> Result<(), Refusal> {
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
                McpReError::ReplayCacheUnavailable.wire_code(),
                503,
            ));
        };
        let bases = RetainedBases {
            previous_request_base: ex.verified.request_signature_base.clone(),
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
                return Ok(());
            }
        }
        Err(Refusal::after_admission(
            McpReError::ReplayCacheUnavailable.wire_code(),
            503,
        ))
    }

    /// Serve one request end to end on the async data plane.
    ///
    /// This function is the ASSEMBLY, not the work. It advances the request machine and
    /// composes the stages above; each stage carries its own contract, so what is visible
    /// here is the pipeline itself — which transition follows which, and where the
    /// execution threshold lies.
    ///
    /// Every `?` returns a finished signed refusal built by the stage that decided it.
    /// `handle` never re-decides what a failure means, which is why no exit here has to
    /// know how far the exchange had got: the machine already does.
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
            Ok(v) => v,
            // Signed inline rather than through `refuse`: there is no `Exchange` yet,
            // because nothing about the request is trusted.
            Err(refusal) => {
                return self.rejection(
                    &http_req,
                    refusal.wire_code,
                    refusal.status,
                    now,
                    None,
                    None,
                    Self::disposition(&progress),
                )
            }
        };
        progress.advance(ExchangeEvent::SignatureVerified);

        // The verifier-resolved actor, carried into every audit record from here on: a
        // denial after resolution knows who was denied, and dropping that is dropping the
        // attribution this surface exists to provide.
        let actor_id = verified.resolved_actor.actor_id();
        let ex = Exchange {
            http_req: &http_req,
            verified: &verified,
            actor_id: &actor_id,
            now,
        };

        if let Err(refusal) = self.transport_binding_stage(&ex, req.identity.as_ref()) {
            return self.refuse(&ex, refusal, &progress);
        }
        progress.advance(ExchangeEvent::TransportBindingChecked);

        if let Some(rejection) = self
            .admission_gate(
                &http_req,
                &verified,
                &actor_id,
                now,
                Self::disposition(&progress),
            )
            .await
        {
            return rejection;
        }
        progress.advance(ExchangeEvent::AdmissionCurrencyChecked);

        let prep = self.prepare_continuation_stage(&ex).await;
        if prep.retained.is_some() {
            // A `peek`, so nothing is spent yet — a refusal from here is still an ordinary
            // retry, which is the whole reason the read is not a `consume`.
            progress.observe_continuation(ContinuationState::Peeked);
        }
        progress.advance(ExchangeEvent::ContinuationPrepared);

        if let Err(refusal) = self.replay_admission_stage(&ex, prep.binding()).await {
            return self.refuse(&ex, refusal, &progress);
        }
        progress.advance(ExchangeEvent::ReplayAdmitted);

        let (a, expires) = match self.answerable_stage(&ex) {
            Ok(pair) => pair,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        progress.advance(ExchangeEvent::DelegatedKeySnapshotted);

        match self
            .retire_continuation_stage(prep.answer_key.as_ref())
            .await
        {
            // The human's approval is now spent. Every refusal from here to the dispatch
            // must say so: the action did not run, but an ordinary retry cannot make it run
            // either.
            Ok(true) => progress.observe_continuation(ContinuationState::Consumed),
            Ok(false) => {}
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
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
            mcp_re_core::audit::AuditEvent::request_accepted(),
            Some(actor_id.clone()),
            200,
            now,
        );

        let forwarded = match self.forward_body_stage(&ex) {
            Ok(body) => body,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        progress.advance(ExchangeEvent::ForwardBodyPrepared);

        let retention = match self.reserve_retention_stage(&ex).await {
            Ok(disposition) => disposition,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        progress.advance(ExchangeEvent::RetentionReserved);

        if let Err(refusal) = self.inner_plane_stage() {
            return self.refuse(&ex, refusal, &progress);
        }
        progress.advance(ExchangeEvent::InnerPlaneAccepted);

        // ===================== IRREVERSIBLE INNER DISPATCH =====================
        //
        // Every pre-dispatch prerequisite is now in hand, and `ReadyForDispatch` is what
        // says so: it cannot be built without them, and the dispatch consumes it. Past this
        // line no exit can claim nothing happened — which is why every one of them is a
        // `response_rejection` rather than a `rejection`.
        let ready = ReadyForDispatch::new(forwarded, a, expires, retention);
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
        // ABOVE the inner-outcome observation, deliberately. The 202 claims that the
        // enforcement boundary authenticated and accepted the message — never that any
        // action completed (#418) — so what became of the forwarded copy does not change
        // what it says. Classifying an outcome the exchange then discards would invent
        // refusal behaviour on a path whose claim is already narrow and already true.
        if matches!(
            outstanding_id(&http_req.body),
            Ok(mcp_re_http_profile::OutstandingId::Notification)
        ) {
            progress.advance(ExchangeEvent::NotificationAcknowledged);
            debug_assert!(progress.state().is_terminal());
            return self
                .answer_notification(
                    &http_req,
                    a.as_ref(),
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
            Ok(bytes) => bytes,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        progress.advance(ExchangeEvent::ResponseObserved);

        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: inner_bytes,
        };

        let parsed = match self.validate_envelope_stage(&ex, &response) {
            Ok(parsed) => parsed,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        progress.advance(ExchangeEvent::EnvelopeValidated);

        let class = match self.classify_reply_stage(&parsed) {
            Ok(class) => class,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        // The obligation is incurred HERE, before the reply is signed and long before it is
        // served. It latches: nothing downstream can decide this exchange opens no leg after
        // the classifier decided it does.
        progress.observe_open_leg(match class {
            ReplyClass::Terminal => OpenLeg::NotApplicable,
            ReplyClass::Open(_) => OpenLeg::Required,
        });
        progress.advance(ExchangeEvent::ResponseClassified);

        let response_base = match self.sign_reply_stage(&ex, &mut response, a.as_ref(), expires) {
            Ok(base) => base,
            Err(refusal) => return self.refuse(&ex, refusal, &progress),
        };
        progress.advance(ExchangeEvent::ResponseSigned);

        match &class {
            ReplyClass::Terminal => progress.advance(ExchangeEvent::ContinuationNotRequired),
            ReplyClass::Open(state) => {
                if let Err(refusal) = self.record_open_leg_stage(&ex, state, response_base).await {
                    return self.refuse(&ex, refusal, &progress);
                }
                progress.observe_open_leg(OpenLeg::Recorded);
                progress.advance(ExchangeEvent::OpenLegRecorded);
            }
        }

        if let Some(rejection) = self
            .retain_accepted(
                &http_req,
                &response,
                now,
                Some(&verified.evidence),
                actor_id.clone(),
                &retention,
                Self::disposition(&progress),
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
            mcp_re_core::audit::AuditEvent::response_signed(),
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
                    McpReError::EvidenceRetentionIndeterminate.wire_code(),
                    500,
                    now,
                    bound,
                    Some(actor_id),
                    execution,
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
        wire_code: &'static str,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: Option<String>,
        execution: ExecutionDisposition,
    ) -> ServedHttpResponse {
        self.audit(
            mcp_re_core::audit::AuditEvent::request_rejected_code(wire_code),
            actor_id,
            status,
            now,
        );
        self.signed_rejection(request, wire_code, status, now, bound, execution)
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
        wire_code: &'static str,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: Option<String>,
        execution: ExecutionDisposition,
    ) -> ServedHttpResponse {
        self.audit(
            mcp_re_core::audit::AuditEvent::response_rejected_code(wire_code),
            actor_id,
            status,
            now,
        );
        self.signed_rejection(request, wire_code, status, now, bound, execution)
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
    /// Carries no audit emission of its own: the two callers above choose the frozen
    /// event type, because which one is correct depends on whether the request had
    /// already been admitted.
    fn signed_rejection(
        &self,
        request: &HttpRequest,
        wire_code: &'static str,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        execution: ExecutionDisposition,
    ) -> ServedHttpResponse {
        let reason = RejectionReason::new(
            wire_code,
            format!("mcp-re http-profile proxy rejected: {wire_code}"),
        )
        .with_execution(execution);
        let resp = match self.signer.current(now) {
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
                built.unwrap_or_else(|_| unsigned_error(status, wire_code))
            }
            None => unsigned_error(status, wire_code),
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
    verified: &VerifiedHttpRequestEvidence,
    policy: VerifiedContextPolicy,
    now: i64,
) -> Result<Forwarded, HttpProfileError> {
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
fn unsigned_error(status: u16, wire_code: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE, "message": wire_code },
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
