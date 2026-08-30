// SPDX-License-Identifier: Apache-2.0
//! What a verified outcome looks like to an ordinary MCP client.
//!
//! The pipeline produces a CLASSIFICATION; a plain MCP client reads a status and a body.
//! The `Mcp-Re-Verified-Kind` header carries the classification for an embedder, but it is
//! outside the plain-MCP contract, so nothing in the status or body may depend on the
//! caller reading it. Three renderings carry the argument:
//!
//! * a NOTIFICATION has no reply, and answering it with a JSON body would invent a result
//!   the local client never asked for. The 202 says what the verified acknowledgement says
//!   and no more: the enforcement boundary accepted the message. It does NOT say the action
//!   completed.
//! * a verified `InputRequiredResult` is a PAUSE, not a reply. There is no continuation
//!   support here, so the answer leg the server is waiting for can never be signed and the
//!   variant''s `request_state` cannot be carried anywhere that would use it. Serving the
//!   pause as 200 with its result body — distinguished only by a header the plain-MCP
//!   contract does not cover — hands an embedder a finished tool result for an approval
//!   nobody gave. Both SDKs fail closed on an unanswerable elicitation; so does this, at
//!   501, because what is missing is this listener''s ability to continue the exchange.
//! * a verified REJECTION rides in a 200 on purpose: it IS the server''s answer, and a
//!   JSON-RPC error is how a plain MCP client is told a call did not succeed. A 5xx would
//!   read as a channel failure and invite the retry the receipt''s own `retry_safety` may be
//!   refusing.

use mcp_re_client_proxy::ResponseKind;
use serde_json::json;
use serde_json::Value;

/// Render a VERIFIED pipeline outcome as the local HTTP reply.
///
/// Separate from [`dispatch`] because this is where the classification the pipeline
/// produced becomes something an ordinary MCP client can act on, and an ordinary MCP
/// client reads a status and a body — not the `Mcp-Re-Verified-Kind` header, which is
/// outside the plain-MCP contract and exists for an embedder.
pub(super) fn render_verified(
    response: &mcp_re_client_proxy::ProxyResponse,
    id: &Value,
) -> (u16, Option<&'static str>, Vec<u8>) {
    let kind = match &response.kind {
        ResponseKind::Success => "success",
        ResponseKind::CallFailed { .. } => "call-failed",
        ResponseKind::InputRequired { .. } => "input-required",
        ResponseKind::AcceptedNotification => "accepted-notification",
        ResponseKind::VerifiedRejection { .. } => "verified-rejection",
    };
    match &response.kind {
        // A notification has no reply, and answering it with a JSON body would invent a
        // result the local client never asked for. The 202 says what the verified
        // acknowledgement says and no more: the enforcement boundary accepted the
        // message. It does NOT say the action completed.
        ResponseKind::AcceptedNotification => (202, Some(kind), Vec::new()),
        // A verified `InputRequiredResult` is a PAUSE, not a reply. `mcp-re-client-proxy`
        // has no continuation support, so the answer leg the server is waiting for can
        // never be signed here, and the variant's `request_state` cannot be carried
        // anywhere that would use it. Serving the pause as 200 with its result body —
        // distinguished only by a header the plain-MCP contract does not cover — hands
        // an embedder a finished tool result for an approval nobody gave.
        //
        // Both SDKs fail closed on an unanswerable elicitation. So does this: 501,
        // because what is missing is this listener's ability to continue the exchange,
        // not anything the caller or the remote server did wrong. The open leg stays
        // open at the server, where its own timeout retires it.
        ResponseKind::InputRequired { .. } => (
            501,
            Some(kind),
            local_error(
                id,
                "the server paused this call for input; this listener cannot sign an \
                 answer leg",
            )
            .into(),
        ),
        // A verified rejection rides in a 200 on purpose: it IS the server's answer, and
        // a JSON-RPC error is how a plain MCP client is told a call did not succeed. A
        // 5xx would read as a channel failure and invite the retry the receipt's own
        // `retry_safety` may be refusing. What the caller needs to make that decision is
        // in the body, where `plain_error_from_rejection` put it.
        _ => {
            let body = serde_json::to_vec(&response.plain_response)
                .unwrap_or_else(|_| local_error(id, "unserializable reply").into());
            (200, Some(kind), body)
        }
    }
}

pub(super) fn local_error(id: &Value, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE, "message": message },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verified pause must never be rendered as a finished call.
    ///
    /// Serving `InputRequired` as 200 with the result body — separated from a genuine
    /// success only by a header outside the plain-MCP contract — is how an elicitation
    /// reaches an application as a completed tool result, and the variant's
    /// `request_state` is dropped on the way, so no answer leg could be signed even if
    /// the embedder wanted to.
    #[test]
    fn a_verified_pause_is_not_rendered_as_a_finished_call() {
        let paused = mcp_re_client_proxy::ProxyResponse {
            plain_response: json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "resultType": mcp_re_http_profile::INPUT_REQUIRED_RESULT_TYPE,
                    "requestState": "st-1",
                },
            }),
            kind: ResponseKind::InputRequired {
                request_state: "st-1".to_owned(),
            },
        };
        let (status, kind, body) = render_verified(&paused, &json!(1));
        assert_ne!(
            status, 200,
            "a pause served as 200 reads as a completed call"
        );
        assert_eq!(status, 501);
        assert_eq!(kind, Some("input-required"));
        let parsed: Value = serde_json::from_slice(&body).expect("json body");
        assert!(
            parsed.get("result").is_none(),
            "the pause's own result must not reach the local client: {parsed}"
        );
        assert!(parsed["error"]["message"]
            .as_str()
            .expect("a message")
            .contains("answer leg"));

        // A genuine terminal success is unchanged: the guard refuses a pause, not a
        // reply.
        let done = mcp_re_client_proxy::ProxyResponse {
            plain_response: json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } }),
            kind: ResponseKind::Success,
        };
        let (status, kind, _) = render_verified(&done, &json!(1));
        assert_eq!((status, kind), (200, Some("success")));
    }
}
