// SPDX-License-Identifier: Apache-2.0
//! The producer's half of the transport contract: the three routing headers a request must
//! carry, derived from the body the signature protects.
//!
//! One authority: **a request the profile signs states its method, its target name and its
//! protocol version in the clear, and what it states is what its body says.** The headers are
//! derived here rather than supplied by every caller, so the producer cannot make the
//! agreement the verifier then insists on false by construction. A header the caller already
//! set is left exactly as given: the verifier, not the signer, refuses one that lies.

use serde_json::Value;

use crate::error::HttpProfileError;
use crate::ids::MCP_METHOD_HEADER;
use crate::ids::MCP_NAME_HEADER;
use crate::ids::MCP_PROTOCOL_VERSION_HEADER;
use crate::mcp_name_source::McpMethodTarget;
use crate::message::single_header;
use crate::message::HttpRequest;

/// The protocol version this profile speaks (MCP 2026-07-28).
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// Add the routing headers a JSON-RPC request body implies and the request does not already
/// carry. A body that is not a JSON-RPC request (no string `method`) implies none.
pub(crate) fn add_contract_headers(request: &mut HttpRequest) -> Result<(), HttpProfileError> {
    let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
        return Ok(());
    };
    let Some(method) = body.get("method").and_then(Value::as_str) else {
        return Ok(());
    };
    let name = match McpMethodTarget::of(method) {
        McpMethodTarget::Named(source) => body
            .get("params")
            .and_then(|p| source.extract(p))
            .map(str::to_owned),
        McpMethodTarget::NoTarget | McpMethodTarget::Unknown => None,
    };
    let derived = [
        ("Mcp-Method", MCP_METHOD_HEADER, Some(method.to_owned())),
        ("Mcp-Name", MCP_NAME_HEADER, name),
        (
            "MCP-Protocol-Version",
            MCP_PROTOCOL_VERSION_HEADER,
            Some(MCP_PROTOCOL_VERSION.to_owned()),
        ),
    ];
    for (wire, lookup, value) in derived {
        if let (Some(value), None) = (value, single_header(&request.headers, lookup)?) {
            request.headers.push((wire.to_owned(), value));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
        }
    }

    fn header(r: &HttpRequest, name: &'static str) -> Option<String> {
        single_header(&r.headers, name)
            .expect("one header")
            .map(str::to_owned)
    }

    /// The three headers come from the body: method, the target the method names, the version.
    #[test]
    fn the_headers_are_derived_from_the_protected_body() {
        let mut r =
            request(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#);
        add_contract_headers(&mut r).expect("derives");
        assert_eq!(header(&r, MCP_METHOD_HEADER), Some("tools/call".to_owned()));
        assert_eq!(header(&r, MCP_NAME_HEADER), Some("read".to_owned()));
        assert_eq!(
            header(&r, MCP_PROTOCOL_VERSION_HEADER),
            Some(MCP_PROTOCOL_VERSION.to_owned())
        );
    }

    /// A method that names no target gets no `Mcp-Name`, and a resource read names its uri.
    #[test]
    fn mcp_name_follows_the_method_that_names_a_target() {
        let mut list = request(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        add_contract_headers(&mut list).expect("derives");
        assert_eq!(header(&list, MCP_NAME_HEADER), None);
        let mut read = request(
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///a"}}"#,
        );
        add_contract_headers(&mut read).expect("derives");
        assert_eq!(header(&read, MCP_NAME_HEADER), Some("file:///a".to_owned()));
    }

    /// A header the caller set is left alone, so a lying one reaches the verifier's refusal.
    #[test]
    fn a_header_the_caller_set_is_not_overwritten() {
        let mut r =
            request(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#);
        r.headers.push(("Mcp-Method".into(), "tools/list".into()));
        add_contract_headers(&mut r).expect("derives");
        assert_eq!(header(&r, MCP_METHOD_HEADER), Some("tools/list".to_owned()));
    }

    /// A body that is not a JSON-RPC request implies nothing.
    #[test]
    fn a_body_that_is_not_a_request_implies_no_headers() {
        let mut r = request("not json");
        add_contract_headers(&mut r).expect("derives");
        assert_eq!(header(&r, MCP_METHOD_HEADER), None);
    }
}
