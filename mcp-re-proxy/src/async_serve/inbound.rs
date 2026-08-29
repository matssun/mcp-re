// SPDX-License-Identifier: Apache-2.0
//! Reading the inbound message: what it says about itself, then what it carries.
//!
//! Two steps in this order because the second consumes the first's subject. The RFC 9421
//! evidence carrier needs the `@method` and the whole header block — `Signature`,
//! `Signature-Input`, `Content-Digest` — and hyper hands the body over by value, so the
//! views are taken before `into_body`.
//!
//! Three refusals live here, and all three are before the inner server is reached. Two are
//! about the message (a header value with no safe rendering, a target the operator's
//! assertion does not reconstruct) and one is about this core (no budget for the body). The
//! last is a `503` and retry-safe; the others are the request's own refusal.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::Request;
use hyper::Response;

use crate::tls::ServerOptions;
use crate::transport::RequestHeaders;

use super::body_budget::collect_body;
use super::body_budget::BodyByteBudget;
use super::body_budget::BodyBytes;
use super::body_budget::BodyReadError;
use super::fail_closed_response;
use super::malformed_header_response;
use super::overloaded_response;
use super::target_uri_mismatch;

/// What the request says about itself before its body is read.
///
/// The three views are taken together because they come from the SAME message and the body
/// is consumed next: the RFC 9421 evidence carrier needs the `@method` and the full header
/// block (carrying `Signature`/`Signature-Input`/`Content-Digest`), and the header view
/// needs the case-insensitive duplicate-counting semantics the blocking path's
/// `RequestHeaders::parse` produces.
pub(super) struct RequestView {
    pub(super) headers: RequestHeaders,
    pub(super) header_pairs: Vec<(String, String)>,
    pub(super) method: String,
}

/// Read the request's own claims about itself, refusing the two that are refusable here.
///
/// A header value that is not valid UTF-8 has no lossy rendering this profile can safely
/// use, and a received target that contradicts the operator's asserted `@target-uri` is an
/// assertion that is provably not a reconstruction of this request. Both are refused before
/// any view of the message reaches anything else.
pub(super) fn request_view(
    req: &Request<Incoming>,
    options: &ServerOptions,
) -> Result<RequestView, Box<Response<Full<Bytes>>>> {
    // A header value that is not valid UTF-8 has no lossy rendering this profile can
    // safely use, so the request is refused here — before any view of it is built.
    // See [`malformed_header_response`].
    if req.headers().values().any(|value| value.to_str().is_err()) {
        return Err(Box::new(malformed_header_response()));
    }

    // A header view with the SAME case-insensitive lookup + duplicate-count
    // semantics the blocking path's `RequestHeaders::parse` produces (used by the
    // Tier-3 assertion extractor and the routing-header hygiene guard).
    let headers = RequestHeaders::from_pairs(
        req.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or(""))),
    );

    // Capture the RFC 9421 request view BEFORE the body is consumed: the `@method`
    // and the full header block (carrying `Signature`/`Signature-Input`/`Content-Digest`)
    // the handler needs to verify the HTTP evidence carrier (ADR-MCPRE-050).
    let method = req.method().as_str().to_owned();
    // C008/C045/C046: the covered `@target-uri` is the operator's configured value, not
    // the received line. That substitution IS the ruled reconstruction mechanism — a
    // proxy behind TLS termination cannot see the external target URI, so the operator
    // asserts it (`http-profile-open-questions.md`: "exact reconstruction of the
    // external @target-uri is mandatory; if it cannot be reconstructed, strict
    // verification fails"). What was missing is EXACT. Nothing checked the assertion
    // against reality, so a deployment fanning several ingress paths into one process
    // silently verified signatures over a target the request did not arrive at, and
    // the verifier's `expected_audience.target_uri != request.target_uri` check
    // compared the configured value with itself.
    //
    // Compare the received origin-form against the configured target's, and fail
    // closed on a mismatch. This does not bind the received line INTO the signature
    // (both ends must still agree on one canonical absolute URI); it refuses to serve
    // where the operator's assertion is provably not a reconstruction of this request.
    if let Some(mismatch) = target_uri_mismatch(&options.target_uri, req.uri()) {
        let _ = mismatch;
        return Err(Box::new(malformed_header_response()));
    }
    let header_pairs: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    Ok(RequestView {
        headers,
        header_pairs,
        method,
    })
}

/// Read the body under all three of its bounds, and say which one tripped.
///
/// `max_body_bytes`, the core's aggregate byte budget, and the aggregate read deadline
/// (slow-loris on a trickled body). Any of them tripping fails closed: the inner server is
/// never reached. The two refusals mean different things to the peer — `503` is this core
/// saying *not now* to a request that may be perfectly well formed, and it is retry-safe.
pub(super) async fn read_body(
    req: Request<Incoming>,
    options: &ServerOptions,
    budget: &Arc<BodyByteBudget>,
) -> Result<(Bytes, BodyBytes), Response<Full<Bytes>>> {
    let max_body = options.limits.max_body_bytes;
    let collect = collect_body(req.into_body(), max_body, budget);
    match options.limits.request_deadline {
        Some(deadline) => match tokio::time::timeout(deadline, collect).await {
            Ok(Ok(collected)) => Ok(collected),
            Ok(Err(BodyReadError::BudgetExhausted)) => Err(overloaded_response()),
            _ => Err(fail_closed_response()),
        },
        None => match collect.await {
            Ok(collected) => Ok(collected),
            Err(BodyReadError::BudgetExhausted) => Err(overloaded_response()),
            Err(_) => Err(fail_closed_response()),
        },
    }
}
