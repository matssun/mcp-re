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
//! **`allow_legacy_header_omission` gates ABSENCE only, never agreement.** A
//! deployment that still serves pre-2026-07-28 clients sets it: a request that
//! omits these headers is then treated as a legacy client rather than rejected.
//! Whatever headers such a request DOES carry are still validated in full — the
//! flag waives "you must send it", never "it may lie".

use serde_json::Value;

use crate::error::HttpProfileError;
use crate::ids::MCP_METHOD_HEADER;
use crate::ids::MCP_NAME_HEADER;
use crate::ids::MCP_PROTOCOL_VERSION_HEADER;
use crate::message::single_header;
use crate::message::HttpRequest;

/// The body field an `Mcp-Name` header must agree with, per method.
///
/// `tools/call` names the tool in `params.name`; `resources/read` names the
/// resource in `params.uri`. The mapping is explicit because the two methods put
/// the same routing value under different keys, and a verifier comparing against
/// the wrong key would either miss a mismatch or invent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpNameSource {
    /// `params.name` — the `tools/call` shape.
    ParamsName,
    /// `params.uri` — the `resources/read` shape.
    ParamsUri,
}

impl McpNameSource {
    fn extract(self, params: &Value) -> Option<&str> {
        match self {
            McpNameSource::ParamsName => params.get("name").and_then(Value::as_str),
            McpNameSource::ParamsUri => params.get("uri").and_then(Value::as_str),
        }
    }
}

/// The verifier-local MCP transport contract (§4.1).
///
/// Construct with [`McpTransportPolicy::mcp_2026_07_28`] for the strict per-request
/// contract, or build one field-by-field for a mixed-version deployment. All fields
/// are private and read-only after construction.
#[derive(Debug, Clone)]
pub struct McpTransportPolicy {
    supported_protocol_versions: Vec<String>,
    require_protocol_version_header: bool,
    require_mcp_method: bool,
    /// `(method, where its Mcp-Name must agree)` — the methods for which `Mcp-Name`
    /// is mandatory and what it binds to.
    mcp_name_required: Vec<(String, McpNameSource)>,
    allow_legacy_header_omission: bool,
    /// The `_meta` key carrying the protocol version in the body, checked under
    /// top-level `_meta` and under `params._meta`.
    protocol_version_body_key: String,
}

impl McpTransportPolicy {
    /// The strict 2026-07-28 per-request contract: `Mcp-Method` and
    /// `MCP-Protocol-Version` mandatory on every POST, `Mcp-Name` mandatory for
    /// `tools/call` (→ `params.name`) and `resources/read` (→ `params.uri`), no
    /// legacy omission. `supported_versions` is the deployment's accepted set —
    /// its consent, not the client's claim.
    pub fn mcp_2026_07_28(supported_versions: &[&str]) -> Self {
        McpTransportPolicy {
            supported_protocol_versions: supported_versions.iter().map(|s| (*s).to_owned()).collect(),
            require_protocol_version_header: true,
            require_mcp_method: true,
            mcp_name_required: vec![
                ("tools/call".to_owned(), McpNameSource::ParamsName),
                ("resources/read".to_owned(), McpNameSource::ParamsUri),
            ],
            allow_legacy_header_omission: false,
            protocol_version_body_key: "io.modelcontextprotocol/protocolVersion".to_owned(),
        }
    }

    /// A mixed-version deployment: the same contract, but a request omitting the
    /// transport headers is served as a legacy client rather than rejected.
    /// Present headers are still validated in full.
    pub fn with_legacy_header_omission(mut self, allow: bool) -> Self {
        self.allow_legacy_header_omission = allow;
        self
    }

    /// Override the accepted protocol-version set.
    pub fn with_supported_versions(mut self, versions: &[&str]) -> Self {
        self.supported_protocol_versions = versions.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Enforce the transport contract against a VERIFIED request.
    ///
    /// Preconditions the caller guarantees: the signature verified, so any covered
    /// header this reads is signed, and the body matched its covered
    /// `content-digest`. Nothing here re-checks the signature — it reads protected
    /// values and applies the deployment's contract to them.
    pub fn enforce(&self, request: &HttpRequest) -> Result<(), HttpProfileError> {
        let body: Value = serde_json::from_slice(&request.body)
            .map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
        let body_method = body.get("method").and_then(Value::as_str);
        let params = body.get("params");

        // Whether this request carries ANY of the transport headers. A request
        // with none of them is a candidate for legacy treatment; one that carries
        // some but not all is not "legacy", it is malformed for its own version.
        let method_hdr = single_header(&request.headers, MCP_METHOD_HEADER)?;
        let version_hdr = single_header(&request.headers, MCP_PROTOCOL_VERSION_HEADER)?;
        let name_hdr = single_header(&request.headers, MCP_NAME_HEADER)?;
        let carries_any = method_hdr.is_some() || version_hdr.is_some() || name_hdr.is_some();
        let legacy = self.allow_legacy_header_omission && !carries_any;

        // --- Mcp-Method: presence, then agreement with the protected body -------
        match method_hdr {
            Some(h) => {
                if let Some(bm) = body_method {
                    if h.trim() != bm {
                        return Err(HttpProfileError::McpMethodDivergence);
                    }
                }
            }
            None => {
                if self.require_mcp_method && !legacy {
                    return Err(HttpProfileError::McpTransportHeaderMissing(MCP_METHOD_HEADER));
                }
            }
        }

        // --- MCP-Protocol-Version: presence, supported set, body agreement ------
        match version_hdr {
            Some(h) => {
                let v = h.trim();
                if !self.supported_protocol_versions.iter().any(|s| s == v) {
                    return Err(HttpProfileError::McpProtocolVersionUnsupported);
                }
                if let Some(body_version) = self.body_protocol_version(&body, params) {
                    if body_version != v {
                        // The covered header and the covered body name different
                        // protocol versions: the signer contradicting itself.
                        return Err(HttpProfileError::McpTransportDivergence(
                            MCP_PROTOCOL_VERSION_HEADER,
                        ));
                    }
                }
            }
            None => {
                if self.require_protocol_version_header && !legacy {
                    return Err(HttpProfileError::McpTransportHeaderMissing(
                        MCP_PROTOCOL_VERSION_HEADER,
                    ));
                }
            }
        }

        // --- Mcp-Name: required for selected methods, agreement with params -----
        if let Some(bm) = body_method {
            if let Some((_, source)) = self.mcp_name_required.iter().find(|(m, _)| m == bm) {
                match name_hdr {
                    Some(h) => {
                        // Agreement is checked whenever the header is present, even
                        // under legacy omission — the flag never licenses a lie.
                        let expected = params.and_then(|p| source.extract(p));
                        if let Some(expected) = expected {
                            if h.trim() != expected {
                                return Err(HttpProfileError::McpTransportDivergence(
                                    MCP_NAME_HEADER,
                                ));
                            }
                        }
                    }
                    None => {
                        if !legacy {
                            return Err(HttpProfileError::McpTransportHeaderMissing(
                                MCP_NAME_HEADER,
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Find the protocol version the body declares, under top-level `_meta` or
    /// `params._meta`. Absent → agreement is not checkable (the header presence and
    /// supported-set checks still apply); this mirrors the method-divergence rule,
    /// which also does nothing when there is no body value to disagree with.
    fn body_protocol_version<'a>(&self, body: &'a Value, params: Option<&'a Value>) -> Option<&'a str> {
        let from = |v: &'a Value| -> Option<&'a str> {
            v.get("_meta")
                .and_then(|m| m.get(&self.protocol_version_body_key))
                .and_then(Value::as_str)
        };
        from(body).or_else(|| params.and_then(from))
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
        strict().enforce(&r).expect("all headers present, supported, and agreeing");
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
    fn an_unsupported_version_is_rejected() {
        let r = req(
            vec![("Mcp-Method", "initialize"), ("MCP-Protocol-Version", "2025-06-18")],
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
            vec![("Mcp-Method", "initialize"), ("MCP-Protocol-Version", "2026-07-28")],
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
            vec![("Mcp-Method", "tools/call"), ("MCP-Protocol-Version", "2026-07-28")],
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
    fn legacy_omission_waives_absence_but_never_agreement() {
        let policy = strict().with_legacy_header_omission(true);

        // A request with NONE of the headers is served as legacy.
        let bare = req(
            vec![],
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
        );
        policy.enforce(&bare).expect("legacy client omitting all headers is accepted");

        // But a legacy-eligible deployment still rejects a PRESENT header that lies.
        let lying = req(
            vec![("Mcp-Method", "tools/list")],
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
        );
        assert_eq!(
            policy.enforce(&lying).unwrap_err(),
            HttpProfileError::McpMethodDivergence,
            "the flag waives 'must send', never 'may lie'"
        );
    }
}
