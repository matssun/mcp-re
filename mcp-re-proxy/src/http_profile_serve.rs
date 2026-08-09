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
//! Per request:
//!   1. reconstruct the [`HttpRequest`] (method, `@target-uri`, headers, body);
//!   2. `verify_request_full` — RFC 9421 signature + RFC 9530 Content-Digest + the
//!      request evidence block (audience / artifact bindings), fail-closed;
//!   3. Mode-A transport binding — bind the verified request actor to the mTLS peer
//!      identity (when a binding policy is configured);
//!   4. recover the MRTR continuation bases for an answer leg — a non-destructive
//!      read, keyed by the RESOLVED ACTOR and the presented `requestState`;
//!   5. `dispatch_request_with_async_tier` — the authoritative async §4 replay
//!      admission + continuation binding, awaited (fail-closed on replay / store
//!      outage / binding mismatch);
//!   6. take the delegated key snapshot — can this request be answered at all?
//!   7. retire the continuation (one-shot), strip the proxy-owned top-level `_meta`,
//!      and forward the clean JSON-RPC to the stateless Streamable-HTTP inner backend
//!      via the async inner pool;
//!   8. `sign_delegated_response_full` — sign the reply with that snapshot, bound to
//!      THIS request (ADR-MCPRE-052).
//!
//! **Nothing irreversible happens on a request's behalf until it is both admitted and
//! answerable.** Steps 4 and 6 are ordered the way they are for that reason: a
//! destructive continuation read at step 4 let an about-to-be-rejected request destroy
//! a live approval leg, and discovering a missing delegated key only at step 8 meant
//! the backend had already run — and 503 is a status clients retry, so the action ran
//! twice.
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
use mcp_re_http_profile::result_class::ResultTypeClass;
use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::strip_proxy_owned_meta;
use mcp_re_http_profile::verify_request_full_with_policy;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
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
use crate::async_serve::ServedHttpRequest;
use crate::async_serve::ServedHttpResponse;
use crate::continuation_store::continuation_key;
use crate::continuation_store::AsyncContinuationStore;
use crate::continuation_store::RetainedBases;
use crate::delegated_server_signer::DelegatedServerSigner;
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

/// How many times the Step-8 open-leg record is attempted before the leg is failed.
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
            )),
        }
    }

    /// Serve one request end to end on the async data plane. Always returns a
    /// [`ServedHttpResponse`] — a signed reply on success, a signed rejection receipt
    /// on any fail-closed step. Only the replay admission and the inner round-trip
    /// are awaited; the RFC 9421 verify/sign are inline CPU (ADR-MCPRE-051 §2).
    pub async fn handle(&self, req: ServedHttpRequest, now: i64) -> ServedHttpResponse {
        let http_req = HttpRequest {
            method: req.method,
            target_uri: req.target_uri,
            headers: req.headers,
            body: req.body,
        };

        // Step 2 — verify (RFC 9421 + RFC 9530 + evidence block). DPoP artifact
        // bindings derive their credential from the covered Authorization header, so
        // no external material is supplied here; any binding lacking a credential
        // still fails closed.
        let no_material = |_b: &ArtifactBinding| None;
        // Scoped so the timer covers the verification and nothing after it.
        let verify_result = {
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Verify);
            verify_request_full_with_policy(
                &http_req,
                &self.expected_audience,
                &no_material,
                self.resolve_actor.as_ref(),
                &self.verifier_policy,
                now,
            )
        };
        let verified = match verify_result {
            Ok(v) => v,
            // Preflight failure: the request never verified, so there is no
            // trustworthy request hash — the rejection is signed unbound, and there is
            // no resolved actor to attribute it to.
            Err(e) => return self.rejection(&http_req, e.wire_code(), 403, now, None, None),
        };
        // The verifier-resolved actor, carried into every audit record from here on:
        // a denial that happens after resolution knows who was denied, and dropping
        // that is dropping the attribution the surface exists for.
        let actor_id = verified.resolved_actor.actor_id();

        // Step 3 — Mode-A transport binding: the verified request actor must match
        // the mTLS peer identity. Fail closed on mismatch.
        if let Some(binding) = &self.transport_binding {
            if binding.check(&actor_id, req.identity.as_ref()).is_err() {
                // Request-bound failure: the request verified, so bind the
                // rejection to it via `;req`.
                return self.rejection(
                    &http_req,
                    "mcp-re.transport_binding_failed",
                    403,
                    now,
                    Some(&verified.evidence),
                    Some(actor_id),
                );
            }
        }

        // Step 3b — §7 admission currency (ADR-MCPRE-053). Before replay admission
        // and the inner round trip, both of which are irreversible.
        if let Some(rejection) = self
            .admission_gate(&http_req, &verified, &actor_id, now)
            .await
        {
            return rejection;
        }

        // Step 4 — MRTR continuation prep (ADR-MCPS-047): if the verified request
        // carries a continuation, this is an ANSWER leg. Recover the retained open-leg
        // bases from the fleet-shared correlation store (keyed by the requestState the
        // client re-presents) so the pure dispatcher can bind the answer to the exact
        // prior exchange — across a replica switch. The owned `retained`/`answer_state`
        // outlive the borrowed `RetainedContinuation` handed to dispatch.
        let has_continuation = verified
            .request_block
            .as_ref()
            .and_then(|b| b.continuation.as_ref())
            .is_some();
        let answer_state = if has_continuation {
            extract_request_state(&http_req.body)
        } else {
            None
        };
        // Keyed by the actor the VERIFIER resolved, never by anything the request
        // asserts, so one peer cannot name another's continuation at all.
        let answer_key = answer_state.as_ref().map(|state| {
            continuation_key(
                &self.expected_audience.audience_id,
                &actor_id,
                state.as_bytes(),
            )
        });
        let retained = match (&self.continuation_store, &answer_key) {
            // `peek` has NO side effect: the entry is still there while the binding is
            // checked below, so a request that fails the binding cannot destroy a live
            // continuation on its way out. A store outage flattens to `None` — the
            // dispatcher then fails closed on the continuation binding rather than
            // admit an unbindable answer leg.
            (Some(store), Some(key)) => store.peek(key).await.ok().flatten(),
            _ => None,
        };
        let continuation_ctx = match (&retained, &answer_state) {
            (Some(bases), Some(state)) => Some(RetainedContinuation {
                previous_request_base: &bases.previous_request_base,
                input_required_response_base: &bases.input_required_response_base,
                request_state: state.as_bytes(),
            }),
            // A continuation was signed but no retained bases were recovered (no store,
            // no requestState, or a store miss / expired-or-already-answered entry):
            // pass None so the dispatcher fails closed `continuation_binding_failed`.
            _ => None,
        };

        // Step 5 — authoritative async §4 replay admission + continuation binding
        // (awaited). When a continuation is present it is verified against the retained
        // bases (digest equality under the client's signature); the nonce is burned
        // strictly last.
        if let Err(e) = dispatch_request_with_async_tier(
            &verified,
            &self.replay_async,
            continuation_ctx,
            &self.dispatch_cfg,
            now,
        )
        .await
        {
            return self.rejection(
                &http_req,
                e.wire_code(),
                409,
                now,
                Some(&verified.evidence),
                Some(actor_id),
            );
        }

        // Step 5a — can this request be ANSWERED at all? The delegated key is what makes
        // a reply signable, and no reply can be produced without one (ADR-MCPRE-052 §6:
        // fail-closed issuance past expiry). Asked here, before anything is done on the
        // request's behalf, because the two steps below are irreversible: retiring the
        // continuation and running the inner backend. Discovering the missing key only
        // at signing time meant the tool call had already executed and the client got a
        // 503 — a transient-looking status it will retry, so the action runs twice.
        //
        // The snapshot is taken ONCE and signs the reply below: `now` is fixed for the
        // whole request, so a key valid here is valid there.
        let a = match self.signer.current(now) {
            Some(a) => a,
            // The frozen signer-side availability token (never a client verification
            // verdict).
            None => {
                return self.rejection(
                    &http_req,
                    McpReError::DelegatedSigningUnavailable.wire_code(),
                    503,
                    now,
                    Some(&verified.evidence),
                    Some(actor_id),
                )
            }
        };
        // The advertised signature window never outlives the delegated credential that
        // authorizes it. `sig_ttl_secs` alone would let a response signed shortly
        // before the credential's `exp` claim a validity the verifier refuses seconds
        // later (`mcp-re.delegation_credential_expired`), so the two are reconciled
        // here — the response states the window it can actually be verified in.
        let expires = (now + self.sig_ttl_secs).min(a.exp);

        // Step 5b — the answer leg is admitted, so NOW retire its continuation. This is
        // where one-shot is enforced: `consume` reports whether this call removed the
        // live entry, so of two concurrent answer legs that both bound successfully,
        // exactly one proceeds and the other is refused as already-answered. A store
        // error is also refused — the entry may or may not be gone, and admitting an
        // answer we cannot retire would make the continuation answerable twice. The
        // request is refused before the inner backend runs, so nothing takes effect.
        if let (Some(store), Some(key)) = (&self.continuation_store, &answer_key) {
            match store.consume(key).await {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    return self.rejection(
                        &http_req,
                        McpReError::ContinuationBindingFailed.wire_code(),
                        409,
                        now,
                        Some(&verified.evidence),
                        Some(actor_id),
                    )
                }
            }
        }

        // ADR-MCPS-035: the request is now ADMITTED — it verified, cleared the transport
        // binding, won replay admission, and has a delegated key to answer with. Emitted
        // here rather than straight after signature verification so `accepted` and
        // `rejected` are MUTUALLY EXCLUSIVE per request: a signature-valid request that
        // then loses replay admission is a rejection, and a record claiming both would
        // make the surface useless for the attribution it exists to provide.
        //
        // Every exit BELOW this line records `mcp-re.response.rejected` instead, for
        // the same reason: the request was admitted, so a `request.rejected` record
        // would contradict this one — and the fault is on the response side anyway
        // (the backend's reply, its signature, or making it answerable).
        self.audit(
            mcp_re_core::audit::AuditEvent::request_accepted(),
            Some(actor_id.clone()),
            200,
            now,
        );

        // Step 6 — strip the proxy-owned top-level `_meta` (the request evidence
        // block) so the backend sees clean MCP, then forward through the async inner.
        let forwarded =
            match forwarded_body(&http_req.body, &verified, self.verified_context_policy, now) {
                Ok(Forwarded { body, seeded }) => {
                    if seeded {
                        // The caller had in fact seeded the reserved verified-context key
                        // — the §10 guard normalised it away, but a deliberate attempt to
                        // assert one's own authentication context to the inner server is
                        // exactly the event this surface exists to detect. The frozen
                        // audit vocabulary has no event for it (ADR-MCPS-035 §3 admits no
                        // third success event), so it is named on the proxy's diagnostic
                        // channel rather than left with no trace at all.
                        eprintln!(
                            "mcp-re-proxy: warning: request from actor {actor_id} seeded the \
                         reserved verified-context `_meta` key; stripped before forwarding \
                         (the inner server never saw it)"
                        );
                    }
                    body
                }
                // The trusted carrier is on but the context could not be written. The
                // inner server would otherwise receive an ordinary-looking request
                // carrying no verified context at all — fail closed rather than
                // degrade into an unauthenticated call.
                Err(e) => {
                    return self.response_rejection(
                        &http_req,
                        e.wire_code(),
                        500,
                        now,
                        Some(&verified.evidence),
                        Some(actor_id),
                    )
                }
            };
        // Step 6a — take durable retention responsibility BEFORE the side effects run.
        //
        // This is the only point at which refusing is still free. Past the dispatch
        // below, a retention failure can no longer be answered with "nothing happened",
        // and the difference is not cosmetic: the pre-dispatch refusal is retry-safe and
        // the post-dispatch one is not, while a retry carries a fresh nonce that the
        // replay tier cannot stop.
        //
        // It is NOT a probe, and does not claim the later write will succeed — nothing
        // can, because the backend and the store share no transaction. It makes the
        // crossing of the execution threshold durable, so what follows is a recorded
        // state rather than a guess.
        //
        // The write itself runs on the retention writer thread and this future AWAITS
        // its acknowledgement, so the core's runtime keeps serving while the fsync is in
        // progress. Awaiting is not optional: dispatching before the marker is durable
        // would make the reservation a hint rather than a record.
        //
        // The outcome is a `RetentionDisposition` rather than an `Option<Reservation>`:
        // "this deployment retains nothing" and "a reservation is missing" are different
        // facts, and collapsing them is what used to require a guard on the completion
        // path to tell them apart (ADR-MCPRE-058 §9.6).
        let retention = match self.retention.as_ref() {
            None => RetentionDisposition::NotConfigured,
            Some(retention) => match retention.reserve(&http_req).await {
                Ok(reservation) => RetentionDisposition::Reserved(reservation),
                Err(e) => {
                    eprintln!("evidence retention could not accept the exchange, refusing before dispatch: {e}");
                    return self.response_rejection(
                        &http_req,
                        McpReError::EvidenceRetentionUnavailable.wire_code(),
                        503,
                        now,
                        Some(&verified.evidence),
                        Some(actor_id),
                    );
                }
            },
        };

        // ===================== IRREVERSIBLE INNER DISPATCH =====================
        //
        // Every pre-dispatch prerequisite is now in hand, and `ReadyForDispatch` is what
        // says so: it cannot be built without them, and the dispatch below consumes it.
        // Past this line no exit can claim nothing happened — which is why every one of
        // them is a `response_rejection` rather than a `rejection`.
        let ready = ReadyForDispatch::new(forwarded, a, expires, retention);
        let inner_bytes = self.inner_async.dispatch(ready.forwarded()).await;
        let (inner_bytes, a, expires, retention) = ready.dispatched(inner_bytes).into_parts();

        // Step 7 — sign the backend reply, bound to THIS request, with the delegated key
        // + inline credential taken at step 5a (ADR-MCPRE-052).
        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: inner_bytes,
        };
        // Step 7a — a one-way NOTIFICATION (a JSON-RPC message with no `id`) gets a
        // signed bodyless 202, not a bodied reply (#424 / #418). The backend already
        // received it above (its side effects run); the 202 states only that the
        // enforcement boundary authenticated and accepted the message — NOT that any
        // action completed. The credential rides in the covered `mcp-re-delegation`
        // header, since a bodyless 202 has no body to carry it.
        if is_notification(&http_req.body) {
            return match sign_delegated_accepted_202(
                &http_req,
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
                            &http_req,
                            &ack,
                            now,
                            Some(&verified.evidence),
                            actor_id.clone(),
                            &retention,
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
                    &http_req,
                    e.wire_code(),
                    500,
                    now,
                    Some(&verified.evidence),
                    Some(actor_id),
                ),
            };
        }

        // Step 6b — the backend's reply must be classifiable before the enforcement
        // boundary puts its signature on it (MCPRE-495). MCP 2026-07-28 closes the
        // `resultType` set: unrecognized MUST be considered invalid. Signing one
        // anyway would produce a perfectly verifiable message whose continuation
        // semantics nobody can read — and a client that fails closed on it would be
        // told the PEP vouched for it. Checked whether or not this deployment runs
        // MRTR: the reply is unclassifiable either way.
        if matches!(
            classify_result_type(&response.body),
            Some(ResultTypeClass::Unrecognized)
        ) {
            return self.response_rejection(
                &http_req,
                HttpProfileError::UnrecognizedResultType.wire_code(),
                502,
                now,
                Some(&verified.evidence),
                Some(actor_id),
            );
        }

        // Scoped so the timer covers the signature and nothing after it.
        let sign_result = {
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Sign);
            sign_delegated_response_full(
                &mut response,
                &http_req,
                &verified.evidence,
                &a.server_signer,
                &a.credential,
                a.key.as_ref(),
                &a.delegated_kid,
                now,
                expires,
            )
        };
        let response_base = match sign_result {
            Ok(base) => base,
            Err(e) => {
                return self.response_rejection(
                    &http_req,
                    e.wire_code(),
                    500,
                    now,
                    Some(&verified.evidence),
                    Some(actor_id),
                )
            }
        };

        // Step 8 — MRTR open-leg record (ADR-MCPS-047): if the signed reply is an
        // `InputRequiredResult` carrying a requestState, record the retained bases so a
        // later answer leg on ANY replica can bind to this exchange. The previous-
        // request base is THIS request's verified signature base; the input-required-
        // response base is the reply's signature base just produced. If the shared tier
        // cannot record it, the reply cannot be honoured cross-replica — fail closed on
        // the shared-tier-outage token rather than return an unanswerable continuation.
        if let Some(store) = &self.continuation_store {
            let open_leg_state = match input_required_state(&response.body) {
                Ok(s) => s,
                Err(e) => {
                    return self.response_rejection(
                        &http_req,
                        e.wire_code(),
                        502,
                        now,
                        Some(&verified.evidence),
                        Some(actor_id),
                    )
                }
            };
            if let Some(state) = open_leg_state {
                let bases = RetainedBases {
                    previous_request_base: verified.request_signature_base.clone(),
                    input_required_response_base: response_base,
                };
                let key = continuation_key(
                    &self.expected_audience.audience_id,
                    &actor_id,
                    state.as_bytes(),
                );
                // Retried, briefly, before failing the leg. Reaching here means the
                // backend has ALREADY run: the shared tier answered the replay
                // admission at Step 5 microseconds ago, so a failure now is a
                // transient blip rather than the outage Step 5 already fails closed
                // on, and absorbing it is what keeps a retryable 503 — which
                // re-executes the tool call — off a path that has side effects.
                let mut recorded = false;
                for _ in 0..CONTINUATION_RECORD_ATTEMPTS {
                    if store
                        .store(&key, &bases, self.continuation_ttl_secs)
                        .await
                        .is_ok()
                    {
                        recorded = true;
                        break;
                    }
                }
                if !recorded {
                    return self.response_rejection(
                        &http_req,
                        McpReError::ReplayCacheUnavailable.wire_code(),
                        503,
                        now,
                        Some(&verified.evidence),
                        Some(actor_id),
                    );
                }
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
            )
            .await
        {
            return rejection;
        }
        // Emitted HERE, not at signing time: everything above can still discard this
        // response, and a `response.signed` record for bytes the client never received
        // is exactly the kind of contradiction that makes an audit stream unusable.
        self.audit(
            mcp_re_core::audit::AuditEvent::response_signed(),
            Some(actor_id),
            response.status,
            now,
        );
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
    async fn retain_accepted(
        &self,
        request: &HttpRequest,
        response: &HttpResponse,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: String,
        retention_owed: &RetentionDisposition,
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
    fn rejection(
        &self,
        request: &HttpRequest,
        wire_code: &'static str,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: Option<String>,
    ) -> ServedHttpResponse {
        self.audit(
            mcp_re_core::audit::AuditEvent::request_rejected_code(wire_code),
            actor_id,
            status,
            now,
        );
        self.signed_rejection(request, wire_code, status, now, bound)
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
    fn response_rejection(
        &self,
        request: &HttpRequest,
        wire_code: &'static str,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: Option<String>,
    ) -> ServedHttpResponse {
        self.audit(
            mcp_re_core::audit::AuditEvent::response_rejected_code(wire_code),
            actor_id,
            status,
            now,
        );
        self.signed_rejection(request, wire_code, status, now, bound)
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
    ) -> ServedHttpResponse {
        let reason = RejectionReason {
            wire_code,
            message: format!("mcp-re http-profile proxy rejected: {wire_code}"),
        };
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

/// Read `result.requestState` from a JSON-RPC RESPONSE body IFF the reply is an
/// A JSON-RPC NOTIFICATION: a message with a `method` and NO `id` (JSON-RPC 2.0
/// §4.1). A notification has no response, so an accepted one earns a signed
/// bodyless 202 rather than a bodied reply (#424 / #418).
fn is_notification(body: &[u8]) -> bool {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => v.get("method").is_some() && v.get("id").is_none(),
        Err(_) => false,
    }
}

/// The opaque MRTR state the OPEN leg minted (ADR-MCPS-047), through the profile's
/// single discriminator. `Ok(None)` for a terminal reply; an ERROR for a reply that
/// declares itself `input_required` and then carries no usable `requestState`.
///
/// The error case used to be `None`, which reads here as "terminal": the proxy
/// signed and returned a non-terminal leg while recording no continuation for it,
/// so no answer leg could ever be honoured on any replica and the client was handed
/// an unanswerable elicitation with a success status. Failing closed turns that into
/// a signed rejection naming the malformed body.
fn input_required_state(body: &[u8]) -> Result<Option<String>, HttpProfileError> {
    mcp_re_http_profile::result_class::input_required_state(body)
}

/// The `resultType` class of a backend reply, or `None` when the reply is not JSON
/// at all — which is not this check's business: the signing path treats an
/// unparseable backend body as an ordinary opaque payload, and the client's own
/// verification is what refuses it.
fn classify_result_type(body: &[u8]) -> Option<ResultTypeClass> {
    let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some(mcp_re_http_profile::result_class::classify_result_type(
        parsed.get("result"),
    ))
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
