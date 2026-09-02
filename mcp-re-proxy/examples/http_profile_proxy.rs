// SPDX-License-Identifier: Apache-2.0
//! `http_profile_proxy` — a networked MCP-RE **HTTP-profile** proxy front that
//! forwards to a real **Streamable-HTTP** MCP backend (FastMCP). This is the
//! ADR-MCPRE-050 go-forward carrier wired end-to-end over the wire, using the
//! proxy's own verify / replay / forward / sign code — NOT the object/legacy path
//! and NOT a stdio inner.
//!
//! Per POST it runs the real pipeline:
//!   1. reconstruct the `HttpRequest` (method, `@target-uri`, headers, body);
//!   2. `verify_request_full` — RFC 9421 signature + RFC 9530 Content-Digest +
//!      the request evidence block (audience/artifact bindings);
//!   3. `dispatch_request_with_tier_gate` — replay admission (fail-closed);
//!   4. strip the proxy-owned top-level `_meta` and forward the clean JSON-RPC to
//!      the Streamable-HTTP backend through the proxy's real `HttpInnerPool`;
//!   5. `sign_delegated_response_full` — sign the backend's reply with the DELEGATED
//!      key, bound to THIS request, carrying the root-signed credential that
//!      authorizes it (ADR-MCPRE-052 delegated-required) — or, for a one-way
//!      notification, `sign_delegated_accepted_202` (#424 / #418).
//!
//! Any fail-closed step emits a DELEGATED-signed rejection receipt instead — bound to
//! the request once it has verified, preflight (unbound) before that.
//!
//! This proof front is PLAIN HTTP: the HTTP-profile security is application-layer
//! (RFC 9421 request/response signatures), so a plain-HTTP local proof isolates the
//! profile crypto. mTLS transport binding is an additive layer folded in later.
//!
//! Launch (addresses come from config/ports.toml via the environment, never a
//! literal):
//!   HPP_BIND=127.0.0.1:8601 \
//!   HPP_INNER_URL=http://127.0.0.1:8620/mcp/ \
//!   HPP_TARGET=http://127.0.0.1:8601/mcp \
//!   cargo run -p mcp-re-proxy --example http_profile_proxy

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::ReplayCache;
use mcp_re_http_profile::build_delegated_rejection;
use mcp_re_http_profile::build_delegated_rejection_preflight;
use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RejectionReason;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use mcp_re_http_profile::result_class::input_required_state;
use mcp_re_http_profile::RetainedContinuation;

use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::continuation_store::continuation_key;
use mcp_re_proxy::continuation_store::AsyncContinuationStore;
use mcp_re_proxy::continuation_store::InMemoryContinuationStore;
use mcp_re_proxy::continuation_store::ResolvedActorId;
use mcp_re_proxy::continuation_store::RetainedBases;
use mcp_re_proxy::http_inner::HttpInnerPool;
use mcp_re_proxy::http_profile_dispatch::dispatch_request_with_tier_gate;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::http_profile_serve::extract_request_state;
#[cfg(feature = "redis_replay")]
use mcp_re_proxy::redis_store::RedisAtomicReplayStore;
use mcp_re_proxy::replay_tier::ReplayDurabilityTier;
#[cfg(feature = "redis_replay")]
use mcp_re_proxy::shared_replay::SharedReplayCache;

// Shared demo material; each example uses a different subset, so allow dead code.
#[allow(dead_code)]
#[path = "hpp_common/mod.rs"]
mod hpp_common;

/// Shared proxy state: the inner-plane client pool, the replay cache (in-memory
/// single-process OR a shared Redis tier), and the dispatch policy. All shared
/// across connections — replay must be detected across requests AND, with a shared
/// tier, across replicas.
struct ProxyState {
    inner: HttpInnerPool,
    replay: Box<dyn ReplayCache + Send + Sync>,
    dispatch_cfg: ProxyDispatchConfig,
    /// The ADR-MCPS-047 continuation correlation store. In-memory, because this front is
    /// one process: it carries a multi-round-trip call across its two legs, and makes no
    /// cross-replica claim. A fleet wires the shared Redis store instead — that is what
    /// the `serve_fleet` path does, and the difference is the store, not the protocol.
    continuations: InMemoryContinuationStore,
}

/// Lifetime of a recorded continuation in this proof front, in seconds.
///
/// An open leg is waiting on a human, so it outlives a request's freshness window; it is
/// bounded anyway because an elicitation nobody ever answers must not be answerable
/// forever.
const CONTINUATION_TTL_SECS: i64 = 300;

#[tokio::main]
async fn main() {
    let bind = std::env::var("HPP_BIND").expect("HPP_BIND (e.g. 127.0.0.1:8601)");
    let inner_url =
        std::env::var("HPP_INNER_URL").expect("HPP_INNER_URL (e.g. http://127.0.0.1:8620/mcp/)");
    let inner_uri = inner_url.parse().expect("HPP_INNER_URL is a valid URI");

    // Replay tier: a shared Redis tier under fleet-strict when HPP_REDIS_URL is set
    // (the multi-replica production posture — a nonce admitted on one replica is
    // rejected on any other sharing the store); otherwise a single-process
    // in-memory cache (fleet_strict off).
    let (replay, dispatch_cfg): (Box<dyn ReplayCache + Send + Sync>, ProxyDispatchConfig) =
        match std::env::var("HPP_REDIS_URL") {
            Ok(url) => {
                let tier_str = std::env::var("HPP_REPLAY_TIER")
                    .unwrap_or_else(|_| "redis-wait-quorum:2:2000".to_string());
                let tier = ReplayDurabilityTier::parse(&tier_str).expect("HPP_REPLAY_TIER");
                #[cfg(feature = "redis_replay")]
                {
                    let mut store = RedisAtomicReplayStore::connect(&url)
                        .unwrap_or_else(|e| panic!("connect redis {url}: {e:?}"));
                    if let ReplayDurabilityTier::QuorumAcknowledged { quorum, timeout_ms } = tier {
                        store = store.with_wait_quorum(quorum, timeout_ms);
                    }
                    eprintln!("{}", tier.startup_audit_line("redis"));
                    (
                        Box::new(SharedReplayCache::new(Box::new(store), 5))
                            as Box<dyn ReplayCache + Send + Sync>,
                        ProxyDispatchConfig {
                            fleet_strict: true,
                            tier: Some(tier),
                        },
                    )
                }
                #[cfg(not(feature = "redis_replay"))]
                {
                    let _ = (url, tier);
                    panic!(
                        "HPP_REDIS_URL is set but this example was built without the \
                         `redis_replay` feature; rebuild with \
                         `--features redis_replay` for the shared multi-replica tier"
                    );
                }
            }
            Err(_) => (
                Box::new(InMemoryReplayCache::new(0)),
                ProxyDispatchConfig {
                    fleet_strict: false,
                    tier: None,
                },
            ),
        };

    let state = Arc::new(ProxyState {
        inner: HttpInnerPool::new(vec![inner_uri], Duration::from_secs(10))
            .expect("build inner pool"),
        replay,
        dispatch_cfg,
        continuations: InMemoryContinuationStore::new(),
    });

    let listener = TcpListener::bind(&bind).await.expect("bind HPP_BIND");
    eprintln!(
        "http_profile_proxy: listening on http://{bind}  ->  inner {inner_url}  (target {}; fleet_strict={})",
        hpp_common::target(),
        state.dispatch_cfg.fleet_strict
    );

    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(tcp);
            let service = service_fn(move |req| handle(Arc::clone(&state), req));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

/// One request through the full HTTP-profile pipeline. Always returns a hyper
/// response — a signed reply on success, a signed rejection receipt on any
/// fail-closed step.
async fn handle(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => {
            return Ok(to_hyper(rejection(
                None,
                None,
                "mcp-re.serialization_failed",
                400,
            )))
        }
    };

    // The canonical @target-uri both sides sign over (deployment-configured).
    let http_req = HttpRequest {
        method,
        target_uri: hpp_common::target(),
        headers,
        body,
    };

    let now = hpp_common::now_unix();
    let resolver = hpp_common::resolver();
    let expected_audience = hpp_common::audience();
    // The proof request carries no artifact bindings, so no credential material is
    // needed; a binding with no obtainable credential still fails closed.
    let no_material = |_b: &ArtifactBinding| None;

    // Step 2 — verify (RFC 9421 + 9530 + evidence block).
    let verified = match Verifier::new(&VerifierPolicy::default(), &resolver).verify_request(
        &http_req,
        &expected_audience,
        &no_material,
        now,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("reject: verify_request_full -> {}", e.wire_code());
            // The request never verified: nothing to bind the receipt to.
            return Ok(to_hyper(rejection(
                Some(&http_req),
                None,
                e.wire_code(),
                403,
            )));
        }
    };

    // Step 3a — MRTR continuation prep (ADR-MCPS-047). A verified request carrying a
    // continuation is an ANSWER leg: recover the open leg's retained signature bases from
    // the correlation store, keyed by the opaque `requestState` the client re-presents,
    // so the dispatcher can bind this answer to the exact prior exchange. `peek` has no
    // side effect — a request that fails the binding must not destroy a live
    // continuation on its way out.
    //
    // The key is derived from the actor the VERIFIER resolved, never from anything the
    // request asserts, so one peer cannot name another's continuation at all.
    let answer_state = verified
        .request_block()
        .continuation
        .as_ref()
        .and_then(|_| extract_request_state(&http_req.body));
    let answer_key = answer_state.as_ref().map(|state| {
        continuation_key(
            &expected_audience.audience_id,
            &ResolvedActorId::of(verified.resolved_actor()),
            state.as_bytes(),
        )
    });
    let retained = match &answer_key {
        Some(key) => state.continuations.peek(key).await.ok().flatten(),
        None => None,
    };
    let continuation_ctx = match (&retained, &answer_state) {
        (Some(bases), Some(request_state)) => Some(RetainedContinuation {
            previous_request_base: &bases.previous_request_base,
            input_required_response_base: &bases.input_required_response_base,
            request_state: request_state.as_bytes(),
        }),
        // A continuation was signed but nothing was retained for it: pass None so the
        // dispatcher fails closed rather than admit an unbindable answer leg.
        _ => None,
    };

    // Step 3 — replay admission (fail-closed) through the configured tier: a shared
    // Redis tier detects a replay across ALL replicas; the fleet-strict gate refuses
    // a sub-minimum/undeclared tier before touching the store. A continuation, when
    // present, is verified here against the retained bases before the nonce is burned.
    if let Err(e) = dispatch_request_with_tier_gate(
        &verified,
        state.replay.as_ref(),
        continuation_ctx,
        &state.dispatch_cfg,
    ) {
        // Verified, then refused by replay admission: bind the receipt to its evidence.
        return Ok(to_hyper(rejection(
            Some(&http_req),
            Some(verified.evidence()),
            e.wire_code(),
            409,
        )));
    }

    // Step 3b — the answer leg is admitted, so retire its continuation NOW, before the
    // backend runs. This is where one-shot is enforced: `consume` reports whether this
    // call removed the live entry, so of two concurrent answer legs that both bound
    // successfully, exactly one proceeds. Refusing before the backend runs means the
    // loser's call never takes effect.
    if let Some(key) = &answer_key {
        if !matches!(state.continuations.consume(key).await, Ok(true)) {
            return Ok(to_hyper(rejection(
                Some(&http_req),
                Some(verified.evidence()),
                "mcp-re.continuation_binding_failed",
                409,
            )));
        }
    }

    // Step 4 — strip the proxy-owned top-level `_meta` (the request evidence
    // block) so the backend sees clean MCP, then forward through the real inner
    // pool. Preparing takes the plane's capacity and transmits nothing; dispatching
    // consumes it and never errors: a dead/hostile backend yields a synthesized
    // inner-unavailable response, which we STILL sign (fail-closed, never a silent
    // allow).
    let forwarded = strip_top_level_meta(&http_req.body);
    let prepared = match state.inner.prepare(&forwarded) {
        Ok(prepared) => prepared,
        Err(why) => panic!("the example's inner plane refused to prepare: {why:?}"),
    };
    // The example wires an in-process closure inner, which has no transport to fail and so
    // only ever reports `Replied`. The production path classifies all three post-commitment
    // outcomes; here anything else would be a bug in the seam, not a case this demo can
    // exercise.
    let inner_bytes = match prepared.dispatch().await {
        mcp_re_proxy::async_inner::DispatchedOutcome::Replied(bytes) => bytes,
        other => panic!("the example's in-process inner cannot report {other:?}"),
    };

    // Step 4a — a one-way NOTIFICATION (a JSON-RPC message with no `id`) earns a signed
    // bodyless 202, not a bodied reply (#424 / #418), exactly as the production serving
    // path does it. The backend already received it above; the 202 states only that the
    // enforcement boundary authenticated and accepted the message, NOT that any action
    // completed. Without this the notification fell through to the bodied signer, which
    // had no reply to sign and refused the exchange the SDKs are proved against.
    if is_notification(&http_req.body) {
        return Ok(
            match sign_delegated_accepted_202(
                &http_req,
                &hpp_common::delegation_credential(now),
                &hpp_common::delegated_key(),
                hpp_common::DELEGATED_KEY_ID,
                now,
                now + 300,
            ) {
                Ok(ack) => to_hyper(ack),
                Err(e) => to_hyper(rejection(
                    Some(&http_req),
                    Some(verified.evidence()),
                    e.wire_code(),
                    500,
                )),
            },
        );
    }

    // Step 5 — sign the backend reply, bound to THIS request.
    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: inner_bytes,
    };
    // The DELEGATED signer signs; the root only vouches for it via the credential the
    // response carries (ADR-MCPRE-052). The root key never touches a response, and the
    // verifier enrols only the root — it learns the delegated key from the credential.
    match sign_delegated_response_full(
        &mut response,
        &http_req,
        verified.evidence(),
        &hpp_common::delegated_server_identity(),
        &hpp_common::delegation_credential(now),
        &hpp_common::delegated_key(),
        hpp_common::DELEGATED_KEY_ID,
        now,
        now + 300,
    ) {
        Ok(response_base) => {
            // Step 6 — MRTR open-leg record (ADR-MCPS-047). When the signed reply is an
            // `InputRequiredResult`, retain the two signature bases a later answer leg
            // must bind to: THIS request's, and the reply's just produced. A reply that
            // cannot be classified is refused rather than signed away as terminal
            // (MCPRE-495); a continuation that cannot be recorded is refused rather than
            // returned unanswerable.
            let open_leg_state = match input_required_state(&response.body) {
                Ok(state) => state,
                Err(e) => {
                    return Ok(to_hyper(rejection(
                        Some(&http_req),
                        Some(verified.evidence()),
                        e.wire_code(),
                        502,
                    )))
                }
            };
            if let Some(request_state) = open_leg_state {
                let bases = RetainedBases {
                    previous_request_base: verified.request_signature_base().to_vec(),
                    input_required_response_base: response_base,
                };
                let key = continuation_key(
                    &expected_audience.audience_id,
                    &ResolvedActorId::of(verified.resolved_actor()),
                    request_state.as_bytes(),
                );
                if state
                    .continuations
                    .store(&key, &bases, CONTINUATION_TTL_SECS)
                    .await
                    .is_err()
                {
                    return Ok(to_hyper(rejection(
                        Some(&http_req),
                        Some(verified.evidence()),
                        "mcp-re.replay_cache_unavailable",
                        503,
                    )));
                }
            }
            Ok(to_hyper(response))
        }
        Err(e) => Ok(to_hyper(rejection(
            Some(&http_req),
            Some(verified.evidence()),
            e.wire_code(),
            500,
        ))),
    }
}

/// A DELEGATED-signed rejection receipt (ADR-MCPRE-052): a client that requires
/// delegation must be able to READ the refusal, so a receipt is signed the same way an
/// answer is — a direct-root receipt would fail the client's own verifier and the wire
/// code would be lost.
///
/// `evidence` is `Some` once the request has verified: the receipt is then BOUND to it,
/// which is strictly stronger. Before verification there is nothing to bind to, so the
/// preflight form is used.
fn rejection(
    request: Option<&HttpRequest>,
    evidence: Option<&RequestEvidence>,
    wire_code: &'static str,
    status: u16,
) -> HttpResponse {
    let now = hpp_common::now_unix();
    let reason = RejectionReason::new(
        wire_code,
        format!("mcp-re http-profile proxy rejected: {wire_code}"),
    );
    let credential = hpp_common::delegation_credential(now);
    match (request, evidence) {
        (Some(req), Some(ev)) => build_delegated_rejection(
            req,
            ev,
            &reason,
            status,
            &hpp_common::delegated_server_identity(),
            &credential,
            &hpp_common::delegated_key(),
            hpp_common::DELEGATED_KEY_ID,
            now,
            now + 300,
        ),
        _ => build_delegated_rejection_preflight(
            request,
            &reason,
            status,
            &hpp_common::delegated_server_identity(),
            &credential,
            &hpp_common::delegated_key(),
            hpp_common::DELEGATED_KEY_ID,
            now,
            now + 300,
        ),
    }
    .expect("rejection signs")
}

/// Remove the top-level `_meta` object (carrying the proxy-owned request evidence
/// block) so the forwarded body is clean MCP JSON-RPC. Non-object bodies pass
/// through unchanged (the inner would reject them anyway).
fn strip_top_level_meta(body: &[u8]) -> Vec<u8> {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("_meta");
            }
            serde_json::to_vec(&v).unwrap_or_else(|_| body.to_vec())
        }
        Err(_) => body.to_vec(),
    }
}

/// Translate the profile `HttpResponse` (status + headers + body) into a hyper
/// response, preserving every signed header (Content-Digest, Signature-Input,
/// Signature, Content-Type).
fn to_hyper(resp: HttpResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(resp.status);
    for (k, v) in &resp.headers {
        builder = builder.header(k, v);
    }
    builder
        .body(Full::new(Bytes::from(resp.body)))
        .expect("response builds")
}

/// A JSON-RPC NOTIFICATION: a message with a `method` and NO `id` (JSON-RPC 2.0 §4.1).
/// The same classification the production serving path performs.
fn is_notification(body: &[u8]) -> bool {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => v.get("method").is_some() && v.get("id").is_none(),
        Err(_) => false,
    }
}
