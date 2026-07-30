//! ADR-MCPRE-051 §3 (Phase 3) — the ASYNC inner-server seam.
//!
//! The async analogue of [`crate::proxy::InnerServer`]: an already-verified,
//! stripped, verified-context-injected request in; the inner server's response
//! bytes out — but AWAITED, so the per-core runtime worker is never blocked on
//! the inner round-trip. This is the seam the production inner plane
//! ([`crate::http_inner`], a per-core `hyper` client pool to stateless
//! Streamable-HTTP inner backends) plugs into; the async serving path
//! ([`crate::proxy::Proxy::handle_with_transport_async`]) awaits it instead of the
//! sync [`InnerServer`](crate::proxy::InnerServer), which stays for the stdio
//! dev/compat serving path.
//!
//! Contract, identical to the sync inner: `dispatch` ALWAYS yields response bytes.
//! A backend failure is NOT an error return — it is a synthesized JSON-RPC error
//! *response* the proxy still signs (a hostile or dead inner can never suppress the
//! signature; ADR-MCPS §response-signing). So the seam carries no `Result`: an
//! upstream outage becomes signed fail-closed bytes, never an unsigned pass-through
//! and never a silent allow.

use std::future::Future;
use std::pin::Pin;

/// The boxed, `Send` future an [`AsyncInnerServer`] returns: the inner server's
/// response bytes. Borrows the request for the duration of the call (the async
/// serving path holds the forwarded bytes across the await).
pub type InnerResponseFuture<'a> = Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>>;

/// An unmodified inner MCP server reached over an ASYNC transport (ADR-MCPRE-051
/// §3). Plain JSON-RPC request bytes in, plain JSON-RPC response bytes out, awaited
/// so the inner round-trip never blocks a per-core runtime worker.
///
/// Like the sync [`InnerServer`](crate::proxy::InnerServer), `dispatch` never
/// fails: an unreachable/slow/dead backend is surfaced as a synthesized JSON-RPC
/// error *response* (which the proxy signs), never as an error return — so the
/// fail-closed posture holds and the client always receives signed bytes.
pub trait AsyncInnerServer: Send + Sync {
    /// Dispatch one (already verified + stripped + context-injected) request to the
    /// inner server, awaiting its response bytes.
    fn dispatch<'a>(&'a self, request: &'a [u8]) -> InnerResponseFuture<'a>;
}

/// Any `Fn(&[u8]) -> Vec<u8>` is an async inner server: the (synchronous) closure
/// is evaluated eagerly and its result returned as a ready future. Ergonomic for
/// tests and embedding — an in-process echo/stub inner plugs into the async path
/// without a bespoke type. Real transports (the `hyper` pool) implement the trait
/// directly and genuinely await I/O.
impl<F> AsyncInnerServer for F
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync,
{
    fn dispatch<'a>(&'a self, request: &'a [u8]) -> InnerResponseFuture<'a> {
        let response = self(request);
        Box::pin(async move { response })
    }
}

/// A synthesized JSON-RPC error *response* (no `result`) returned when the inner
/// is unreachable — no inner wired, an inner-backend transport/timeout failure, a
/// non-2xx status, or (in the pool) all backends ejected / pool exhausted. It
/// carries no `result`, so `Proxy::build_signed_response` wraps it as a SIGNED
/// `inner_error` envelope: the client receives signed, fail-closed bytes, never an
/// unsigned pass-through and never a silent allow (ADR-MCPS response-signing +
/// ADR-MCPRE-051 §4 fail-closed posture).
///
/// The `id` is echoed from `request`, because the client correlates on it: JSON-RPC
/// 2.0 §5 requires an error response to carry the request's id, and reserves `null`
/// for the case where it could not be determined. Here it always can be — the
/// forwarded request is right there — and omitting it left the client holding signed,
/// fail-closed bytes it could not attribute to any call it made. `null` is emitted
/// only for a request whose id is genuinely absent or unreadable (a notification, or
/// a body that did not parse), which is the case the spec reserves it for.
pub(crate) fn inner_unavailable_response(request: &[u8]) -> Vec<u8> {
    // Re-serialised from the parsed value rather than spliced from the request bytes:
    // the id is attacker-influenced, and copying a raw fragment into a JSON document
    // is how injection happens. serde_json emits only well-formed JSON.
    let id = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32603, "message": "inner server unavailable" },
    });
    serde_json::to_vec(&body).unwrap_or_else(|_| {
        br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"inner server unavailable"}}"#
            .to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).expect("synthesized response is valid JSON")
    }

    #[test]
    fn the_synthesized_error_carries_the_requests_id() {
        // Without it the client cannot attribute the signed failure to the call it made.
        let out = parse(&inner_unavailable_response(
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#,
        ));
        assert_eq!(out["id"], serde_json::json!(7));
        assert_eq!(out["error"]["code"], serde_json::json!(-32603));
        assert!(
            out.get("result").is_none(),
            "an error response carries no result"
        );
    }

    #[test]
    fn a_string_id_survives_as_a_string() {
        let out = parse(&inner_unavailable_response(
            br#"{"jsonrpc":"2.0","id":"req-abc","method":"tools/call"}"#,
        ));
        assert_eq!(out["id"], serde_json::json!("req-abc"));
    }

    #[test]
    fn an_absent_or_unreadable_id_becomes_null() {
        // JSON-RPC 2.0 reserves null for exactly this: the id could not be determined.
        for request in [
            &br#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#[..],
            &b"not json at all"[..],
            &b""[..],
        ] {
            assert_eq!(
                parse(&inner_unavailable_response(request))["id"],
                serde_json::Value::Null
            );
        }
    }

    #[test]
    fn a_hostile_id_cannot_break_out_of_the_document() {
        // The id is attacker-influenced. Re-serialising rather than splicing is what
        // keeps it a value instead of syntax.
        let out = parse(&inner_unavailable_response(
            br#"{"jsonrpc":"2.0","id":"\",\"error\":{\"code\":0,\"message\":\"ok\"},\"result\":{\"ok\":true},\"x\":\"","method":"tools/call"}"#,
        ));
        assert!(out.get("result").is_none(), "no result may appear");
        assert_eq!(out["error"]["code"], serde_json::json!(-32603));
        assert!(out["id"].is_string());
    }
}
