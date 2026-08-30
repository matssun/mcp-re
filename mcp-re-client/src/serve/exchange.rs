// SPDX-License-Identifier: Apache-2.0
//! One local exchange, from the accepted socket to the plain reply.
//!
//! The listener''s dispatch half: read, sign-forward-verify through [`ClientProxy`], and
//! render what came back as something an ordinary MCP client can act on. The local client
//! never sees an MCP-RE field — that transparency is the point.
//!
//! Two renderings are worth naming because they are where a wrong status would mislead:
//!
//! * an UNVERIFIABLE response is not a server verdict. The channel is compromised or
//!   misconfigured, so it is reported as a gateway failure, never as a result.
//! * a verified REJECTION rides in a 200 on purpose: it IS the server''s answer, and a
//!   JSON-RPC error is how a plain MCP client is told a call did not succeed. A 5xx would
//!   read as a channel failure and invite the retry the receipt''s own `retry_safety` may
//!   be refusing.

use std::net::TcpStream;
use std::time::Instant;

use mcp_re_client_proxy::CallParams;
use serde_json::Value;

use super::render::local_error;
use super::render::render_gateway_failure;
use super::render::render_verified;

use super::close::drain;
use super::close::drain_pending;
use super::deadlines::DeadlineWriter;
use super::request::read_request;
use super::response::write_response;
use super::LocalRequest;
use super::ServeContext;
use super::EXCHANGE_DEADLINE;
use super::WRITE_DEADLINE;

/// The write phase's own budget, armed from now.
///
/// Saturating rather than refusing: this is armed AFTER an exchange the remote server may
/// already have executed, and the reply still has to be delivered.
fn write_budget() -> Instant {
    Instant::now()
        .checked_add(WRITE_DEADLINE)
        .unwrap_or_else(Instant::now)
}

pub(super) fn handle_connection(mut stream: TcpStream, context: &ServeContext) {
    // Class R: a whole-phase budget, so an unrepresentable one is no budget at all and
    // the connection is closed rather than served without one.
    let Some(deadline) = Instant::now().checked_add(EXCHANGE_DEADLINE) else {
        return;
    };
    let _ = stream.set_nonblocking(false);
    let request = match read_request(&mut stream, deadline, context.allow_any_host) {
        Ok(request) => request,
        Err(status) => {
            let write_deadline = write_budget();
            let _ = write_response(
                &mut DeadlineWriter::new(&stream, write_deadline),
                status,
                None,
                b"{}",
            );
            // A refusal happens BEFORE the body is consumed, so bytes are still in
            // flight. Closing on top of them makes the kernel send RST rather than FIN,
            // and the caller then sees a reset instead of the refusal it was told —
            // turning every "405 method not allowed" into an unexplained broken pipe.
            drain(&mut stream);
            return;
        }
    };
    let (status, kind, body) = dispatch(context, &request);
    // A budget of its own, armed from here: the read phase may legitimately have used
    // its whole deadline, and a reply to an exchange the remote server has already
    // executed still has to be delivered.
    let write_deadline = write_budget();
    let _ = write_response(
        &mut DeadlineWriter::new(&stream, write_deadline),
        status,
        kind,
        &body,
    );
    // The same reasoning as the refusal path, and it costs more here: what a reset
    // would discard is a VERIFIED reply to a call the remote server has already
    // executed, and a client that retries a reset re-runs the side effect.
    //
    // This drain must not WAIT, though. The caller is by now reading our response, not
    // writing, so a blocking drain would add its full bound to every single exchange.
    // What turns close() into RST is bytes already sitting in the receive queue, and
    // those are exactly the ones a non-blocking drain takes.
    drain_pending(&mut stream);
}

/// Sign, forward, verify, and render the plain reply.
fn dispatch(
    context: &ServeContext,
    request: &LocalRequest,
) -> (u16, Option<&'static str>, Vec<u8>) {
    let Some(route_id) = route_for(&request.path, context.default_route.as_deref()) else {
        return (
            404,
            None,
            local_error(&Value::Null, "no route for this path").into(),
        );
    };
    let plain: Value = match serde_json::from_slice(&request.body) {
        Ok(plain) => plain,
        Err(_) => {
            return (
                400,
                None,
                local_error(&Value::Null, "malformed JSON-RPC").into(),
            )
        }
    };
    // The id belongs to the LOCAL caller's outstanding call; it is echoed on an error
    // path so a client can match a failure to the request that caused it.
    let id = plain.get("id").cloned().unwrap_or(Value::Null);

    let now = (context.clock)();
    // Class R, and the signed one: `expires` is an RFC 9421 parameter a verifier reads as
    // fact. A wrapped value lands in the past (rejected everywhere, silently) or far in
    // the future (valid long past the lifetime an operator configured). Neither is signed.
    let Some(expires) = now.checked_add(context.request_lifetime_secs) else {
        return (
            400,
            None,
            local_error(&id, "request lifetime does not fit the clock").into(),
        );
    };
    let params = CallParams {
        nonce: (context.nonce)(),
        created: now,
        expires,
        now_unix: now,
    };

    match context.proxy.handle(&route_id, &plain, &params) {
        Ok(response) => render_verified(&response, &id),
        // An UNVERIFIABLE response is not a server verdict — the channel is compromised
        // or misconfigured — so it is reported as a gateway failure, never as a result.
        Err(error) => render_gateway_failure(&error, &id),
    }
}

/// `/route/<id>` names a route; anything else falls to the configured default.
fn route_for(path: &str, default_route: Option<&str>) -> Option<String> {
    let path = path.split('?').next().unwrap_or(path);
    if let Some(id) = path.strip_prefix("/route/") {
        if !id.is_empty() && !id.contains('/') {
            return Some(id.to_owned());
        }
        return None;
    }
    default_route.map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_path_names_its_route() {
        assert_eq!(route_for("/route/r1", None).as_deref(), Some("r1"));
        assert_eq!(route_for("/route/r1?x=1", None).as_deref(), Some("r1"));
    }

    /// A nested path is not a route id. Accepting `/route/a/b` as `a/b` would let the
    /// path shape decide which route's bindings a request is signed under.
    #[test]
    fn a_nested_or_empty_path_names_no_route() {
        assert_eq!(route_for("/route/a/b", Some("d")), None);
        assert_eq!(route_for("/route/", Some("d")), None);
    }

    #[test]
    fn any_other_path_falls_to_the_default_route_only_when_one_is_configured() {
        assert_eq!(route_for("/mcp", Some("d")).as_deref(), Some("d"));
        assert_eq!(route_for("/mcp", None), None);
    }
}
