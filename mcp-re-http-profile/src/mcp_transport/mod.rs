// SPDX-License-Identifier: Apache-2.0
//! MCP transport + protocol-version policy (#415 rev 2 §4.1, issue #425).
//!
//! There is no session handshake in MCP-RE to "bump" — but 2026-07-28 makes the
//! protocol version and routing headers a PER-REQUEST transport contract, and
//! that contract is enforceable here. Covering a header that is present is
//! integrity of what was sent; this module is the rest of §4.1: which headers
//! MUST be sent, which protocol versions are acceptable, and that the headers
//! agree with the protected body.
//!
//! **Every check runs AFTER signature verification**, against covered headers and
//! the `content-digest`-covered body. That ordering is load-bearing, identical to
//! the reason the `Mcp-Method` divergence check waits: before the signature, both
//! the header and the body are attacker-chosen, so their agreement (or a version
//! string's value) proves nothing. After it, a required header that is present is
//! also covered (the closed-allowlist gate already enforced present ⇒ covered), a
//! version string is one the signer committed to, and a disagreement between a
//! covered header and the covered body is the SIGNER contradicting itself — which
//! the verifier refuses rather than resolving in either direction.
//!
//! **Presence, version policy, and agreement are LOCAL.** A message states which
//! version it used and which method it names; only this policy decides which
//! versions are acceptable and which headers are mandatory. `2026-07-28` being in
//! the IANA-style registry, or a client asserting it, is not the deployment's
//! consent to serve it. That is why the supported-version set lives here and not
//! on the wire.
//!
//! **The contract is mandatory.** A deployment cannot opt out of it and no waiver lets a
//! request omit a header it requires: presence, version and agreement are checked for every
//! request the verifier admits.

use serde_json::Value;

use crate::error::HttpProfileError;
use crate::ids::MCP_METHOD_HEADER;
use crate::ids::MCP_NAME_HEADER;
use crate::ids::MCP_PROTOCOL_VERSION_HEADER;
use crate::message::single_header;
use crate::message::HttpRequest;

/// The bodied contract: three covered headers, each checked against the protected body it
/// claims to describe.
mod agreement;
/// The producer's half: the three headers a signed request carries, derived from its body.
mod request_headers;
pub(crate) use request_headers::add_contract_headers;
pub use request_headers::MCP_PROTOCOL_VERSION;

/// The verifier-local MCP transport contract (§4.1).
///
/// [`McpTransportPolicy::mcp_2026_07_28`] is the only constructor; it takes the
/// deployment's accepted protocol-version set. All fields are private and read-only after
/// construction: no method derives a policy with a different set from an existing one.
///
/// ```compile_fail
/// use mcp_re_http_profile::McpTransportPolicy;
/// let _ = McpTransportPolicy::profile_default().with_supported_versions(&["1999-01-01"]);
/// ```
///
/// Enforcement is the verifier's, after the signature, and is not callable from outside:
///
/// ```compile_fail
/// use mcp_re_http_profile::{HttpRequest, McpTransportPolicy};
/// fn hostile(policy: &McpTransportPolicy, unverified: &HttpRequest) {
///     let _ = policy.enforce(unverified);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct McpTransportPolicy {
    supported_protocol_versions: Vec<String>,
    /// The `_meta` key carrying the protocol version in the body, checked under
    /// top-level `_meta` and under `params._meta`.
    protocol_version_body_key: String,
}

impl McpTransportPolicy {
    /// The strict 2026-07-28 per-request contract: `Mcp-Method` and
    /// `MCP-Protocol-Version` mandatory on every POST, `Mcp-Name` mandatory for every
    /// method the protocol table ([`McpMethodTarget`](crate::mcp_name_source::McpMethodTarget))
    /// says names a target, and agreeing with the params member it names it under.
    /// `supported_versions` is the deployment's accepted set —
    /// its consent, not the client's claim.
    pub fn mcp_2026_07_28(supported_versions: &[&str]) -> Self {
        McpTransportPolicy {
            supported_protocol_versions: supported_versions
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            protocol_version_body_key: "io.modelcontextprotocol/protocolVersion".to_owned(),
        }
    }

    /// The contract a [`VerifierPolicy`](crate::VerifierPolicy) carries until a deployment
    /// names its accepted versions: this profile's own protocol version.
    pub fn profile_default() -> Self {
        Self::mcp_2026_07_28(&[MCP_PROTOCOL_VERSION])
    }

    /// Enforce the part of the transport contract that applies to a VERIFIED request
    /// carrying NO body — a signed GET or DELETE on the streamable-HTTP leg.
    ///
    /// [`enforce`](Self::enforce) cannot serve this shape: it parses the body first,
    /// and every one of its agreement checks compares a covered header against a
    /// covered body member that does not exist here. What survives the loss of a body:
    ///
    /// - `MCP-Protocol-Version` never needed one. It is required on this shape exactly as
    ///   on a POST, and must name a version the deployment accepts.
    /// - `Mcp-Method` and `Mcp-Name` describe a body. Here there is none for them to agree
    ///   with, so a covered one would be an unconstrained routing claim: it is refused,
    ///   not passed through. Their absence is what a conforming GET or DELETE sends.
    ///
    /// Crate-private: the one caller, `bodyless::verify_bodyless_request`, runs it after
    /// the signature verified, so every header it reads is covered.
    pub(crate) fn enforce_bodyless(&self, request: &HttpRequest) -> Result<(), HttpProfileError> {
        for routing in [MCP_METHOD_HEADER, MCP_NAME_HEADER] {
            single_header(&request.headers, routing)?.map_or(Ok(()), |_| {
                Err(HttpProfileError::McpTransportDivergence(routing))
            })?;
        }
        let Some(h) = single_header(&request.headers, MCP_PROTOCOL_VERSION_HEADER)? else {
            return Err(HttpProfileError::McpTransportHeaderMissing(
                MCP_PROTOCOL_VERSION_HEADER,
            ));
        };
        if !self
            .supported_protocol_versions
            .iter()
            .any(|s| s == h.trim())
        {
            return Err(HttpProfileError::McpProtocolVersionUnsupported);
        }
        Ok(())
    }

    /// Every protocol version the body states, under top-level `_meta` and under
    /// `params._meta`. None stated → agreement is not checkable (the header presence and
    /// supported-set checks still apply); this mirrors the method-divergence rule,
    /// which also does nothing when there is no body value to disagree with.
    fn body_protocol_versions<'a>(
        &'a self,
        body: &'a Value,
        params: Option<&'a Value>,
    ) -> impl Iterator<Item = &'a str> + 'a {
        let from = move |v: &'a Value| -> Option<&'a str> {
            v.get("_meta")
                .and_then(|m| m.get(&self.protocol_version_body_key))
                .and_then(Value::as_str)
        };
        [Some(body), params].into_iter().flatten().filter_map(from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: Vec<(&str, &str)>, body: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn strict() -> McpTransportPolicy {
        McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"])
    }

    #[test]
    fn a_conforming_request_passes() {
        let r = req(
            vec![
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "read"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
        );
        strict()
            .enforce(&r)
            .expect("all headers present, supported, and agreeing");
    }

    #[test]
    fn a_missing_required_header_is_rejected() {
        // No Mcp-Method under the strict contract.
        let r = req(
            vec![("MCP-Protocol-Version", "2026-07-28")],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        );
        assert_eq!(
            strict().enforce(&r).unwrap_err(),
            HttpProfileError::McpTransportHeaderMissing("mcp-method"),
        );
    }

    #[test]
    fn a_missing_protocol_version_header_is_rejected() {
        // Mcp-Method present and agreeing, so the method arm passes and control
        // reaches the version-header requirement.
        let r = req(
            vec![("Mcp-Method", "initialize")],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        );
        assert_eq!(
            strict().enforce(&r).unwrap_err(),
            HttpProfileError::McpTransportHeaderMissing("mcp-protocol-version"),
        );
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let r = req(
            vec![
                ("Mcp-Method", "initialize"),
                ("MCP-Protocol-Version", "2025-06-18"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        );
        assert_eq!(
            strict().enforce(&r).unwrap_err(),
            HttpProfileError::McpProtocolVersionUnsupported,
        );
        assert_eq!(
            strict().enforce(&r).unwrap_err().wire_code(),
            "mcp-re.unsupported_version"
        );
    }

    #[test]
    fn header_body_version_divergence_is_rejected() {
        let r = req(
            vec![
                ("Mcp-Method", "initialize"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}"#,
        );
        assert_eq!(
            strict().enforce(&r).unwrap_err(),
            HttpProfileError::McpTransportDivergence("mcp-protocol-version"),
        );
    }

    #[test]
    fn mcp_name_required_and_must_agree() {
        // tools/call without Mcp-Name.
        let missing = req(
            vec![
                ("Mcp-Method", "tools/call"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
        );
        assert_eq!(
            strict().enforce(&missing).unwrap_err(),
            HttpProfileError::McpTransportHeaderMissing("mcp-name"),
        );

        // tools/call with a DISAGREEING Mcp-Name.
        let wrong = req(
            vec![
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "delete"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
        );
        assert_eq!(
            strict().enforce(&wrong).unwrap_err(),
            HttpProfileError::McpTransportDivergence("mcp-name"),
        );
    }

    #[test]
    fn resources_read_binds_mcp_name_to_params_uri() {
        let wrong = req(
            vec![
                ("Mcp-Method", "resources/read"),
                ("Mcp-Name", "file:///other"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///wanted"}}"#,
        );
        assert_eq!(
            strict().enforce(&wrong).unwrap_err(),
            HttpProfileError::McpTransportDivergence("mcp-name"),
        );
        let ok = req(
            vec![
                ("Mcp-Method", "resources/read"),
                ("Mcp-Name", "file:///wanted"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///wanted"}}"#,
        );
        strict().enforce(&ok).expect("agreeing uri");
    }

    #[test]
    fn resources_read_without_mcp_name_is_rejected() {
        let r = req(
            vec![
                ("Mcp-Method", "resources/read"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///wanted"}}"#,
        );
        assert_eq!(
            strict().enforce(&r).unwrap_err(),
            HttpProfileError::McpTransportHeaderMissing("mcp-name"),
        );
    }

    /// The bodyless contract requires the version header a POST requires, and refuses the
    /// routing headers a body would be needed to check.
    #[test]
    fn a_bodyless_request_states_a_supported_version_and_no_routing_header() {
        let bodyless = |headers: Vec<(&str, &str)>| strict().enforce_bodyless(&req(headers, ""));
        assert_eq!(
            bodyless(vec![("MCP-Protocol-Version", "2026-07-28")]),
            Ok(())
        );
        assert_eq!(
            bodyless(vec![]),
            Err(HttpProfileError::McpTransportHeaderMissing(
                "mcp-protocol-version"
            )),
        );
        assert_eq!(
            bodyless(vec![("MCP-Protocol-Version", "2025-06-18")]),
            Err(HttpProfileError::McpProtocolVersionUnsupported),
        );
        for (routing, refused) in [("Mcp-Method", "mcp-method"), ("Mcp-Name", "mcp-name")] {
            assert_eq!(
                bodyless(vec![
                    ("MCP-Protocol-Version", "2026-07-28"),
                    (routing, "tools/call")
                ]),
                Err(HttpProfileError::McpTransportDivergence(refused)),
                "{routing}"
            );
        }
    }

    #[test]
    fn a_params_meta_version_divergence_is_rejected() {
        // No top-level `_meta`: the body states its protocol version only under
        // `params._meta`, and it contradicts the covered header.
        let r = req(
            vec![
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "read"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ],
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}"#,
        );
        assert_eq!(
            strict().enforce(&r).unwrap_err(),
            HttpProfileError::McpTransportDivergence("mcp-protocol-version"),
        );
    }

    #[test]
    fn a_params_meta_version_contradicting_an_agreeing_top_level_meta_is_rejected() {
        let headers = || {
            vec![
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "read"),
                ("MCP-Protocol-Version", "2026-07-28"),
            ]
        };
        let split = req(
            headers(),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"params":{"name":"read","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}"#,
        );
        assert_eq!(
            strict().enforce(&split).unwrap_err(),
            HttpProfileError::McpTransportDivergence("mcp-protocol-version"),
        );
        let agreeing = req(
            headers(),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"params":{"name":"read","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
        );
        assert!(strict().enforce(&agreeing).is_ok());
    }
}
