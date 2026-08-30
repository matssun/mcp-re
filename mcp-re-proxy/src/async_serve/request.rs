// SPDX-License-Identifier: Apache-2.0
//! One HTTP request over an established connection.
//!
//! The connection decided who the peer is; this decides whether THIS request is served, and
//! in what order the questions are asked. The order is the blocking loop's, deliberately:
//! per-core admission, then the header view, then the target-URI assertion, then the body,
//! then the channel-peer question that carries the per-request currency decision, then
//! routing-header hygiene, then the handler.
//!
//! Everything before the handler fails closed without the inner server being reached, and
//! the two shed statuses mean different things to the peer: `503` is this core saying *not
//! now* to a request that may be perfectly well formed, `4xx` is the request itself being
//! refused.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::Request;
use hyper::Response;

use crate::communication_assurance::MechanismVerifiedCredentialEvidence;
use crate::tls::assertion_header;
use crate::tls::routing_header_rejection;
use crate::tls::served_channel_peer;
use crate::tls::ServerOptions;

use super::core_admission::CoreAdmission;
use super::inbound::read_body;
use super::inbound::request_view;
use super::inbound::RequestView;
use super::overloaded_response;
use super::served_to_hyper;
use super::AsyncRequestHandler;
use super::InFlightGuard;
use super::ServedHttpRequest;
use super::ServedHttpResponse;

/// How often the scheduler-latency probe is sampled, in requests. The probe is itself a
/// spawned task, so sampling every request would measure a runtime perturbed by the
/// measurement; this is rare enough to be free and frequent enough to average out.
const SCHEDULER_PROBE_EVERY_N_REQUESTS: u64 = 500;

/// Serve one HTTP request: reconstruct the header view, read the body (capped),
/// run the SAME identity/rejection/handler pipeline as the blocking serve loop, and
/// frame the signed response bytes.
pub(super) async fn handle_request<H: AsyncRequestHandler>(
    req: Request<Incoming>,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    peer_credential: Arc<Option<MechanismVerifiedCredentialEvidence>>,
    admission: CoreAdmission,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // MCPRE-114: per-core admission control. Acquire an in-flight permit FIRST — if
    // the per-core ceiling is full, reject with 503 fail-closed BEFORE reading the
    // body or reaching the handler (the request never touches the inner server). The
    // owned permit is held for the rest of this request and released on return (RAII),
    // so the ceiling bounds requests actually in flight, never queuing them without
    // bound. `None` ⇒ no ceiling (unbounded in-flight).
    let _timed_total = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Total);
    // Sampled from the serving path so the probe queues behind exactly what a request
    // queues behind; see `probe_scheduler`.
    crate::stage_timers::probe_scheduler(SCHEDULER_PROBE_EVERY_N_REQUESTS);
    let _admission = {
        let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Admission);
        match &admission.in_flight {
            Some(semaphore) => match Arc::clone(semaphore).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return Ok(overloaded_response()),
            },
            None => None,
        }
    };

    // MCPRE-115: count this request as in flight for the duration of its processing
    // (body read + handler + response). Constructed AFTER admission so a shed 503 is
    // not counted; dropped on every return path below, so graceful drain sees the
    // count fall to zero exactly when the last request finishes.
    let _in_flight_guard = InFlightGuard::new(&admission.in_flight_requests);

    let RequestView {
        headers,
        header_pairs,
        method,
    } = match request_view(&req, &options) {
        Ok(view) => view,
        Err(refusal) => return Ok(*refusal),
    };
    let (body_bytes, _body_charge) = match read_body(req, &options, &admission.body_budget).await {
        Ok(read) => read,
        Err(refusal) => return Ok(refusal),
    };

    // ADR-MCPRE-064 (#623). ONE question: who authenticated, and what the controls said.
    let channel_peer = served_channel_peer(
        peer_credential.as_ref().as_ref(),
        &options,
        &body_bytes,
        crate::tls::wall_clock_unix(),
    );
    let assertion = assertion_header(&options, &headers);

    // SAME order as the blocking loop: the channel-peer question above (which carries the
    // per-request currency decision), then routing-header hygiene, then the handler. The
    // clock is read PER REQUEST: the credential is accepted once at handshake, so that is
    // the only point at which one past its `notAfter` is caught on an open connection.
    let served = match channel_peer
        .as_ref()
        .err()
        .cloned()
        .or_else(|| routing_header_rejection(&headers, &body_bytes))
    {
        // A pre-handler transport rejection carries a JSON error body, no RFC 9421
        // evidence; frame it as a 403 JSON reply.
        Some(error) => ServedHttpResponse::json(403, error),
        None => {
            let served_req = ServedHttpRequest {
                method,
                target_uri: options.target_uri.clone(),
                headers: header_pairs,
                body: body_bytes.to_vec(),
                peer: channel_peer.unwrap_or(None),
                assertion: assertion.map(str::to_string),
            };
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Handler);
            handler(served_req).await
        }
    };

    Ok(served_to_hyper(served))
}
