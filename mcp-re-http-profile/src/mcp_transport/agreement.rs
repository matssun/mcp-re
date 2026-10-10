// SPDX-License-Identifier: Apache-2.0
//! The bodied transport contract: three covered headers, each held against the protected
//! body it claims to describe.
//!
//! Every check here runs AFTER signature verification, which is load-bearing rather than
//! incidental: before the signature both the header and the body are attacker-chosen, so
//! their agreement proves nothing. After it, a disagreement between a covered header and the
//! covered body is the SIGNER contradicting itself — refused rather than resolved in either
//! direction.
//!
//! Two questions are asked of each header, and they are different questions: **must it be
//! here** and **does it tell the truth**. Both are answered for every request: the contract
//! is not optional for a deployment, and no waiver lets a request omit a header it requires.

use serde_json::Value;

use crate::error::HttpProfileError;
use crate::ids::MCP_METHOD_HEADER;
use crate::ids::MCP_NAME_HEADER;
use crate::ids::MCP_PROTOCOL_VERSION_HEADER;
use crate::mcp_name_source::McpMethodTarget;
use crate::message::single_header;
use crate::message::HttpRequest;

use super::McpTransportPolicy;

/// What the request said about itself in the three transport headers.
///
/// Read once, together, so each check sees the same three values.
struct TransportHeaders {
    method: Option<String>,
    version: Option<String>,
    name: Option<String>,
}

impl TransportHeaders {
    fn read(request: &HttpRequest) -> Result<Self, HttpProfileError> {
        let method = single_header(&request.headers, MCP_METHOD_HEADER)?.map(str::to_owned);
        let version =
            single_header(&request.headers, MCP_PROTOCOL_VERSION_HEADER)?.map(str::to_owned);
        let name = single_header(&request.headers, MCP_NAME_HEADER)?.map(str::to_owned);
        Ok(TransportHeaders {
            method,
            version,
            name,
        })
    }
}

impl McpTransportPolicy {
    /// `Mcp-Method`: present, and naming the method the protected body names.
    ///
    /// A body with no `method` member leaves nothing to disagree with, so agreement does
    /// nothing rather than failing — the header was not unconstrained in that case either,
    /// because a message with no method is not one this contract routes.
    ///
    /// A body method the protocol table does not list, but which a case-folding or trimming
    /// reader would take for one it does, is refused: the `Mcp-Name` requirement is keyed on
    /// the listed spelling, and a backend dispatching leniently would run the listed method
    /// without it. Which spelling is authoritative is ambiguous, so neither is chosen.
    fn check_method(
        &self,
        headers: &TransportHeaders,
        body_method: Option<&str>,
    ) -> Result<(), HttpProfileError> {
        let folds_onto_a_listed_method = body_method.is_some_and(|bm| {
            McpMethodTarget::of(bm) == McpMethodTarget::Unknown
                && McpMethodTarget::of(&bm.trim().to_ascii_lowercase()) != McpMethodTarget::Unknown
        });
        if folds_onto_a_listed_method {
            return Err(HttpProfileError::McpTransportDivergence(MCP_METHOD_HEADER));
        }
        let Some(h) = headers.method.as_deref() else {
            return Err(HttpProfileError::McpTransportHeaderMissing(
                MCP_METHOD_HEADER,
            ));
        };
        match body_method {
            Some(bm) if h.trim() != bm => Err(HttpProfileError::McpMethodDivergence),
            _ => Ok(()),
        }
    }

    /// `MCP-Protocol-Version`: present, in the deployment's accepted set, and
    /// agreeing with the body where the body says anything.
    ///
    /// Unlike `Mcp-Method`/`Mcp-Name`, an absent body value is the norm rather than a gap:
    /// the body declares a protocol version only in `_meta`, which most messages omit. The
    /// header is not unconstrained in that case — it was just checked against the supported
    /// set — so there is nothing to fail closed on.
    ///
    /// The supported set is the DEPLOYMENT's consent, not the client's claim. A version
    /// being in the registry, or a client asserting it, is not agreement to serve it.
    fn check_protocol_version(
        &self,
        headers: &TransportHeaders,
        body: &Value,
        params: Option<&Value>,
    ) -> Result<(), HttpProfileError> {
        let Some(h) = headers.version.as_deref() else {
            return Err(HttpProfileError::McpTransportHeaderMissing(
                MCP_PROTOCOL_VERSION_HEADER,
            ));
        };
        let v = h.trim();
        if !self.supported_protocol_versions.iter().any(|s| s == v) {
            return Err(HttpProfileError::McpProtocolVersionUnsupported);
        }
        // Any stated body version differing from the covered header is the signer
        // contradicting itself; requiring every location to equal the header also makes
        // them equal to each other.
        if self.body_protocol_versions(body, params).any(|b| b != v) {
            return Err(HttpProfileError::McpTransportDivergence(
                MCP_PROTOCOL_VERSION_HEADER,
            ));
        }
        Ok(())
    }

    /// `Mcp-Name`: required for every method the protocol table says names a target, and
    /// agreeing with the params member that carries it; refused on every other message.
    ///
    /// The requirement is read from [`McpMethodTarget`], the table the producer derives the
    /// header from, so the contract covers exactly the methods a signer names a target for.
    /// For those the params value the header mirrors must exist: without it there is nothing
    /// for the signed header to agree with, so an absent `params.name` / `params.uri` fails
    /// closed rather than licensing an arbitrary covered name. On a method that names no
    /// target, an unlisted one, or a body with no method, a covered `Mcp-Name` has nothing
    /// to agree with either, and is refused rather than passed through unconstrained.
    fn check_name(
        &self,
        headers: &TransportHeaders,
        body_method: Option<&str>,
        params: Option<&Value>,
    ) -> Result<(), HttpProfileError> {
        let target = body_method.map_or(McpMethodTarget::Unknown, McpMethodTarget::of);
        let McpMethodTarget::Named(source) = target else {
            return headers.name.as_ref().map_or(Ok(()), |_| {
                Err(HttpProfileError::McpTransportDivergence(MCP_NAME_HEADER))
            });
        };
        let Some(h) = headers.name.as_deref() else {
            return Err(HttpProfileError::McpTransportHeaderMissing(MCP_NAME_HEADER));
        };
        let Some(expected) = params.and_then(|p| source.extract(p)) else {
            return Err(HttpProfileError::McpTransportDivergence(MCP_NAME_HEADER));
        };
        if h.trim() != expected {
            return Err(HttpProfileError::McpTransportDivergence(MCP_NAME_HEADER));
        }
        Ok(())
    }

    /// Enforce the transport contract against a VERIFIED request.
    ///
    /// Preconditions the caller guarantees: the signature verified, so any covered header
    /// this reads is signed, and the body matched its covered `content-digest`. Nothing here
    /// re-checks the signature — it reads protected values and applies the deployment's
    /// contract to them. Crate-private for that reason: the one caller is the request floor
    /// (`verify::floor::request`), which runs it after the signature and digest checks.
    pub(crate) fn enforce(&self, request: &HttpRequest) -> Result<(), HttpProfileError> {
        let body: Value = serde_json::from_slice(&request.body)
            .map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
        let body_method = body.get("method").and_then(Value::as_str);
        let params = body.get("params");
        let headers = TransportHeaders::read(request)?;
        self.check_method(&headers, body_method)?;
        self.check_protocol_version(&headers, &body, params)?;
        self.check_name(&headers, body_method, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> McpTransportPolicy {
        McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"])
    }

    fn request(headers: &[(&str, &str)], body: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    const CALL: &str = r#"{"method":"tools/call","params":{"name":"deploy"}}"#;

    /// A body that is not JSON is refused as malformed evidence, before any header is
    /// compared: with no body method there is nothing a signed header could agree with,
    /// and agreeing headers must not carry a body the contract cannot read.
    #[test]
    fn a_body_that_is_not_json_is_refused_whatever_the_headers_say() {
        let headers = [
            (MCP_METHOD_HEADER, "tools/call"),
            (MCP_PROTOCOL_VERSION_HEADER, "2026-07-28"),
            (MCP_NAME_HEADER, "deploy"),
        ];
        for body in ["", "not json", r#"{"method":"tools/call""#] {
            assert!(
                matches!(
                    policy().enforce(&request(&headers, body)),
                    Err(HttpProfileError::MalformedEvidence("body json"))
                ),
                "{body:?} was not refused as malformed"
            );
        }
    }

    /// A method that REQUIRES `Mcp-Name` and a body with nothing for it to mirror fails
    /// closed. Otherwise an absent `params.name` would license an arbitrary covered name.
    #[test]
    fn a_required_name_with_no_params_member_to_mirror_fails_closed() {
        let headers = [
            (MCP_METHOD_HEADER, "tools/call"),
            (MCP_PROTOCOL_VERSION_HEADER, "2026-07-28"),
            (MCP_NAME_HEADER, "anything"),
        ];
        let no_target = r#"{"method":"tools/call","params":{}}"#;
        assert!(matches!(
            policy().enforce(&request(&headers, no_target)),
            Err(HttpProfileError::McpTransportDivergence(MCP_NAME_HEADER))
        ));
    }

    /// The supported set is the DEPLOYMENT's consent. A version the client asserts but this
    /// deployment does not accept is refused before any agreement is considered.
    #[test]
    fn an_unsupported_version_is_the_deployments_refusal_not_a_disagreement() {
        let headers = [
            (MCP_METHOD_HEADER, "tools/call"),
            (MCP_PROTOCOL_VERSION_HEADER, "2025-01-01"),
            (MCP_NAME_HEADER, "deploy"),
        ];
        assert!(matches!(
            policy().enforce(&request(&headers, CALL)),
            Err(HttpProfileError::McpProtocolVersionUnsupported)
        ));
    }

    /// Every method the protocol table says names a target is held to an agreeing
    /// `Mcp-Name` — not only the two the contract once listed.
    #[test]
    fn every_target_naming_method_requires_an_agreeing_name() {
        for (method, key, value) in [
            ("prompts/get", "name", "greet"),
            ("resources/subscribe", "uri", "file:///a"),
            ("resources/unsubscribe", "uri", "file:///a"),
        ] {
            let body = format!(r#"{{"method":"{method}","params":{{"{key}":"{value}"}}}}"#);
            let with = |name: Option<&str>| {
                let mut h = vec![
                    (MCP_METHOD_HEADER, method),
                    (MCP_PROTOCOL_VERSION_HEADER, "2026-07-28"),
                ];
                h.extend(name.map(|n| (MCP_NAME_HEADER, n)));
                policy().enforce(&request(&h, &body))
            };
            assert_eq!(
                with(None),
                Err(HttpProfileError::McpTransportHeaderMissing(MCP_NAME_HEADER)),
                "{method}"
            );
            assert_eq!(
                with(Some("other")),
                Err(HttpProfileError::McpTransportDivergence(MCP_NAME_HEADER)),
                "{method}"
            );
            assert_eq!(with(Some(value)), Ok(()), "{method}");
        }
    }

    /// A covered `Mcp-Name` on a message whose body names no target has nothing to agree
    /// with, and is refused rather than passed through unconstrained.
    #[test]
    fn a_covered_name_with_no_target_in_the_body_is_refused() {
        for body in [
            r#"{"method":"tools/list"}"#,
            r#"{"method":"x-vendor/deploy","params":{"name":"deploy"}}"#,
        ] {
            let method = if body.contains("tools/list") {
                "tools/list"
            } else {
                "x-vendor/deploy"
            };
            let headers = [
                (MCP_METHOD_HEADER, method),
                (MCP_PROTOCOL_VERSION_HEADER, "2026-07-28"),
            ];
            assert_eq!(policy().enforce(&request(&headers, body)), Ok(()), "{body}");
            let named = [headers[0], headers[1], (MCP_NAME_HEADER, "deploy")];
            assert_eq!(
                policy().enforce(&request(&named, body)),
                Err(HttpProfileError::McpTransportDivergence(MCP_NAME_HEADER)),
                "{body}"
            );
        }
    }

    /// A body method a lenient backend would read as a listed one, but which the table
    /// does not list, is refused, so it cannot carry `tools/call` past the name binding.
    #[test]
    fn a_case_or_padding_variant_of_a_listed_method_is_refused() {
        for variant in ["Tools/Call", "TOOLS/CALL", " tools/call", "Resources/Read"] {
            let body = format!(r#"{{"method":"{variant}","params":{{"name":"deploy"}}}}"#);
            let headers = [
                (MCP_METHOD_HEADER, variant),
                (MCP_PROTOCOL_VERSION_HEADER, "2026-07-28"),
            ];
            assert_eq!(
                policy().enforce(&request(&headers, &body)),
                Err(HttpProfileError::McpTransportDivergence(MCP_METHOD_HEADER)),
                "{variant:?}"
            );
        }
        let unlisted = [
            (MCP_METHOD_HEADER, "completion/complete"),
            (MCP_PROTOCOL_VERSION_HEADER, "2026-07-28"),
        ];
        assert_eq!(
            policy().enforce(&request(&unlisted, r#"{"method":"completion/complete"}"#)),
            Ok(())
        );
    }

    /// The whole contract, satisfied.
    #[test]
    fn a_conforming_request_passes_every_arm() {
        let headers = [
            (MCP_METHOD_HEADER, "tools/call"),
            (MCP_PROTOCOL_VERSION_HEADER, "2026-07-28"),
            (MCP_NAME_HEADER, "deploy"),
        ];
        assert!(policy().enforce(&request(&headers, CALL)).is_ok());
    }
}
