// SPDX-License-Identifier: Apache-2.0
//! RFC 9421 signature-base construction.
//!
//! The signature base is the exact byte string signed/verified: one line per
//! covered component (`"<identifier>": <value>`), then the
//! `"@signature-params"` line whose value is the serialized inner list of
//! covered identifiers followed by the signature parameters, in the exact
//! order they appear in `Signature-Input`. Lines are joined with `\n` and the
//! base is NOT newline-terminated (RFC 9421 §2.5).

use crate::error::HttpProfileError;
use crate::message::single_header;
use crate::message::HttpRequest;
use crate::message::HttpResponse;

/// A covered component identifier: a lowercase field name or derived
/// component (`@`-prefixed), optionally flagged `;req` (a request component
/// bound into a response signature, RFC 9421 §2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveredComponent {
    pub name: &'static str,
    pub req: bool,
}

impl CoveredComponent {
    pub fn new(name: &'static str) -> Self {
        CoveredComponent { name, req: false }
    }

    pub fn req(name: &'static str) -> Self {
        CoveredComponent { name, req: true }
    }

    /// The identifier as serialized both in the inner list and at the start of
    /// its signature-base line: `"name"` or `"name";req`.
    fn identifier(&self) -> String {
        if self.req {
            format!("\"{}\";req", self.name)
        } else {
            format!("\"{}\"", self.name)
        }
    }
}

/// Signature parameters, serialized in the exact order the fields are listed
/// here — the profile's normative order (created, expires, nonce, keyid, alg,
/// tag). `None` fields are omitted; the RFC 9421 KAT uses created+keyid only.
#[derive(Debug, Clone, Default)]
pub struct SignatureParams {
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
    pub keyid: Option<String>,
    pub alg: Option<String>,
    pub tag: Option<String>,
}

impl SignatureParams {
    /// Serialize the inner list `("a" "b" ...);created=...;keyid="..."` — the
    /// value of the `@signature-params` line and of the `Signature-Input`
    /// dictionary member.
    pub fn serialize_with(&self, components: &[CoveredComponent]) -> String {
        let list = components
            .iter()
            .map(CoveredComponent::identifier)
            .collect::<Vec<_>>()
            .join(" ");
        let mut out = format!("({list})");
        if let Some(created) = self.created {
            out.push_str(&format!(";created={created}"));
        }
        if let Some(expires) = self.expires {
            out.push_str(&format!(";expires={expires}"));
        }
        if let Some(nonce) = &self.nonce {
            out.push_str(&format!(";nonce=\"{nonce}\""));
        }
        if let Some(keyid) = &self.keyid {
            out.push_str(&format!(";keyid=\"{keyid}\""));
        }
        if let Some(alg) = &self.alg {
            out.push_str(&format!(";alg=\"{alg}\""));
        }
        if let Some(tag) = &self.tag {
            out.push_str(&format!(";tag=\"{tag}\""));
        }
        out
    }
}

/// The message a component value is resolved from: a request, or a response
/// whose `;req` components resolve against the originating request.
pub enum SourceMessage<'a> {
    Request(&'a HttpRequest),
    Response {
        response: &'a HttpResponse,
        request: &'a HttpRequest,
    },
}

/// Resolve one covered component's value, fail-closed: an absent field or an
/// unsupported derived component is a missing covered component, never a
/// blank line.
fn component_value(
    component: &CoveredComponent,
    source: &SourceMessage<'_>,
) -> Result<String, HttpProfileError> {
    // `;req` components resolve against the originating request.
    let (request, response): (Option<&HttpRequest>, Option<&HttpResponse>) = match source {
        SourceMessage::Request(r) => {
            if component.req {
                return Err(HttpProfileError::MissingCoveredComponent(component.name));
            }
            (Some(*r), None)
        }
        SourceMessage::Response { response, request } => {
            if component.req {
                (Some(*request), None)
            } else {
                (None, Some(*response))
            }
        }
    };

    if let Some(name) = component.name.strip_prefix('@') {
        return match (name, request, response) {
            ("method", Some(r), _) => Ok(r.method.to_ascii_uppercase()),
            ("target-uri", Some(r), _) => Ok(r.target_uri.clone()),
            ("authority", Some(r), _) => authority_of(&r.target_uri)
                .ok_or(HttpProfileError::MissingCoveredComponent(component.name)),
            ("path", Some(r), _) => {
                path_of(&r.target_uri).ok_or(HttpProfileError::MissingCoveredComponent(component.name))
            }
            ("status", _, Some(rsp)) => Ok(rsp.status.to_string()),
            _ => Err(HttpProfileError::MissingCoveredComponent(component.name)),
        };
    }

    // A field component: exact-once lookup on whichever message it targets.
    let headers = match (request, response) {
        (Some(r), None) => &r.headers,
        (None, Some(rsp)) => &rsp.headers,
        _ => return Err(HttpProfileError::MissingCoveredComponent(component.name)),
    };
    let mut found: Option<&str> = None;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(component.name) {
            if found.is_some() {
                // RFC 9421 would join duplicates; this profile fails closed on
                // duplicated covered fields (v0.11 grill B.1 exactly-once rule).
                return Err(HttpProfileError::MissingCoveredComponent(component.name));
            }
            found = Some(v.trim());
        }
    }
    found
        .map(str::to_owned)
        .ok_or(HttpProfileError::MissingCoveredComponent(component.name))
}

/// `host[:port]` from an absolute URI, lowercased (RFC 9421 `@authority`).
fn authority_of(target_uri: &str) -> Option<String> {
    let rest = target_uri.split_once("://")?.1;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_ascii_lowercase())
    }
}

/// The absolute path from an absolute URI (RFC 9421 `@path`), `/` if empty.
fn path_of(target_uri: &str) -> Option<String> {
    let rest = target_uri.split_once("://")?.1;
    let after_authority = match rest.find(['/', '?', '#']) {
        None => return Some("/".to_owned()),
        Some(i) => &rest[i..],
    };
    if after_authority.starts_with('/') {
        let end = after_authority.find(['?', '#']).unwrap_or(after_authority.len());
        Some(after_authority[..end].to_owned())
    } else {
        Some("/".to_owned())
    }
}

/// Build the exact signature-base bytes for `components` + `params` over
/// `source` (RFC 9421 §2.5).
pub fn signature_base(
    components: &[CoveredComponent],
    params: &SignatureParams,
    source: &SourceMessage<'_>,
) -> Result<Vec<u8>, HttpProfileError> {
    let mut lines = Vec::with_capacity(components.len() + 1);
    for c in components {
        let value = component_value(c, source)?;
        lines.push(format!("{}: {}", c.identifier(), value));
    }
    lines.push(format!(
        "\"@signature-params\": {}",
        params.serialize_with(components)
    ));
    Ok(lines.join("\n").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HttpRequest {
        HttpRequest {
            method: "post".into(),
            target_uri: "https://example.com/foo?p=1".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: b"{}".to_vec(),
        }
    }

    #[test]
    fn derived_components_resolve() {
        let r = request();
        let src = SourceMessage::Request(&r);
        let base = signature_base(
            &[
                CoveredComponent::new("@method"),
                CoveredComponent::new("@target-uri"),
                CoveredComponent::new("@authority"),
                CoveredComponent::new("@path"),
                CoveredComponent::new("content-type"),
            ],
            &SignatureParams::default(),
            &src,
        )
        .expect("resolves");
        let text = String::from_utf8(base).unwrap();
        assert!(text.contains("\"@method\": POST"));
        assert!(text.contains("\"@target-uri\": https://example.com/foo?p=1"));
        assert!(text.contains("\"@authority\": example.com"));
        assert!(text.contains("\"@path\": /foo"));
        assert!(text.ends_with(
            "\"@signature-params\": (\"@method\" \"@target-uri\" \"@authority\" \"@path\" \"content-type\")"
        ));
    }

    #[test]
    fn missing_covered_field_fails_closed() {
        let r = request();
        let src = SourceMessage::Request(&r);
        let err = signature_base(
            &[CoveredComponent::new("content-digest")],
            &SignatureParams::default(),
            &src,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::MissingCoveredComponent("content-digest"));
    }

    #[test]
    fn duplicated_covered_field_fails_closed() {
        let mut r = request();
        r.headers.push(("content-type".into(), "text/plain".into()));
        let src = SourceMessage::Request(&r);
        let err = signature_base(
            &[CoveredComponent::new("content-type")],
            &SignatureParams::default(),
            &src,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::MissingCoveredComponent("content-type"));
    }

    #[test]
    fn req_component_on_request_fails_closed() {
        let r = request();
        let src = SourceMessage::Request(&r);
        let err = signature_base(
            &[CoveredComponent::req("content-digest")],
            &SignatureParams::default(),
            &src,
        )
        .unwrap_err();
        assert!(matches!(err, HttpProfileError::MissingCoveredComponent(_)));
    }
}
