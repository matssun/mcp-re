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

/// Refuse a string signature parameter that RFC 8941 §3.3.3 cannot carry verbatim.
///
/// An `sf-string` is printable ASCII (0x20–0x7E) in which `"` and `\` may appear
/// only as the two-character escapes `\"` and `\\`. This profile refuses those two
/// characters outright rather than escaping them, for the same reason it refuses
/// `created=+1` and `created=0017` (see `verify::parse_i64`): the signature base is
/// rebuilt from PARSED values and re-serialized canonically, so any two wire
/// spellings that parse to one value collapse to one base. With escaping admitted,
/// an intermediary could rewrite the header between equivalent spellings and the
/// signature would still verify, leaving anyone who reads the raw bytes looking at
/// something other than what was signed. Refusing keeps the on-wire form pinned,
/// which is the property this profile actually needs.
///
/// Nothing legitimate is lost: `alg` and `tag` come from closed sets, `keyid` from
/// deployment configuration, and `nonce` is base64url. None of them can contain a
/// quote or a backslash without being malformed already.
pub(crate) fn validate_sf_string(value: &str, what: &'static str) -> Result<(), HttpProfileError> {
    let ok = value
        .bytes()
        .all(|b| (0x20..=0x7E).contains(&b) && b != b'"' && b != b'\\');
    if ok {
        Ok(())
    } else {
        Err(HttpProfileError::MalformedEvidence(what))
    }
}

/// The longest `nonce` this profile carries, in characters.
///
/// A generous ceiling, not a format: 128 bits of base64url is 22 characters, and the
/// replay key retains the nonce verbatim for the life of the signature window. Applied
/// on BOTH sides for the same reason as [`validate_sf_string`] — a value this profile
/// cannot carry must not be emitted, not merely rejected on the way back in. Enforced
/// only at parse, a signer could emit a nonce every conforming MCP-RE verifier refuses
/// as malformed evidence, and the far end is where the operator would find out.
pub(crate) const MAX_NONCE_CHARS: usize = 256;

/// Refuse a `nonce` longer than [`MAX_NONCE_CHARS`].
pub(crate) fn validate_nonce_length(nonce: &str) -> Result<(), HttpProfileError> {
    if nonce.len() > MAX_NONCE_CHARS {
        return Err(HttpProfileError::MalformedEvidence(
            "nonce signature parameter exceeds the length bound",
        ));
    }
    Ok(())
}

impl SignatureParams {
    /// Serialize the inner list `("a" "b" ...);created=...;keyid="..."` — the
    /// value of the `@signature-params` line and of the `Signature-Input`
    /// dictionary member.
    ///
    /// Fallible because a string parameter that RFC 8941 cannot carry verbatim must
    /// not be EMITTED, not merely rejected on the way back in: a signer that wrote
    /// one would produce a header no conforming parser reads the way this profile
    /// does. See [`validate_sf_string`].
    pub fn serialize_with(
        &self,
        components: &[CoveredComponent],
    ) -> Result<String, HttpProfileError> {
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
            validate_sf_string(nonce, "nonce signature parameter")?;
            validate_nonce_length(nonce)?;
            out.push_str(&format!(";nonce=\"{nonce}\""));
        }
        if let Some(keyid) = &self.keyid {
            validate_sf_string(keyid, "keyid signature parameter")?;
            out.push_str(&format!(";keyid=\"{keyid}\""));
        }
        if let Some(alg) = &self.alg {
            validate_sf_string(alg, "alg signature parameter")?;
            out.push_str(&format!(";alg=\"{alg}\""));
        }
        if let Some(tag) = &self.tag {
            validate_sf_string(tag, "tag signature parameter")?;
            out.push_str(&format!(";tag=\"{tag}\""));
        }
        Ok(out)
    }
}

/// The message a component value is resolved from: a request, a response whose
/// `;req` components resolve against the originating request, or a response with
/// NO request context (a rejection emitted before a request could be parsed —
/// `;req` components are then unresolvable and fail closed).
pub enum SourceMessage<'a> {
    Request(&'a HttpRequest),
    Response {
        response: &'a HttpResponse,
        request: &'a HttpRequest,
    },
    ResponseOnly(&'a HttpResponse),
}

/// Resolve one covered component's value and reject any value the base cannot
/// carry injectively.
///
/// CR/LF in ANY covered value — a field value or a derived component alike — would
/// make the base non-injective: components are joined one per line, so a value
/// containing a newline forges a second component line inside the base and two
/// different messages produce the same signature base. `@target-uri` is a REQUIRED
/// covered component on every request and, via `;req`, on every response, and a
/// deployment that reconstructs it behind TLS termination is exactly where those
/// bytes stop being operator-chosen. RFC 9110 forbids these bytes in a field value
/// and no URI, method token or status can contain them, so nothing legitimate is
/// refused.
fn component_value(
    component: &CoveredComponent,
    source: &SourceMessage<'_>,
) -> Result<String, HttpProfileError> {
    let value = resolve_component_value(component, source)?;
    if value.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err(HttpProfileError::MalformedEvidence(
            "covered component value contains CR or LF",
        ));
    }
    Ok(value)
}

/// Resolve one covered component's value, fail-closed: an absent field or an
/// unsupported derived component is a missing covered component, never a
/// blank line.
fn resolve_component_value(
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
        SourceMessage::ResponseOnly(response) => {
            if component.req {
                // No request context: a `;req` component cannot be resolved.
                return Err(HttpProfileError::MissingCoveredComponent(component.name));
            }
            (None, Some(*response))
        }
    };

    if let Some(name) = component.name.strip_prefix('@') {
        return match (name, request, response) {
            // RFC 9421 §2.2.1: the method name is case-sensitive and "no
            // transformation to the method's case is performed". Uppercasing it
            // here collapsed `post` and `POST` onto one signature base, so an
            // intermediary could rewrite the request line's method case and the
            // signature still verified — the audited bytes then differ from the
            // signed ones.
            ("method", Some(r), _) => Ok(r.method.clone()),
            ("target-uri", Some(r), _) => Ok(r.target_uri.clone()),
            ("authority", Some(r), _) => authority_of(&r.target_uri)
                .ok_or(HttpProfileError::MissingCoveredComponent(component.name)),
            ("path", Some(r), _) => path_of(&r.target_uri)
                .ok_or(HttpProfileError::MissingCoveredComponent(component.name)),
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
    let value = found.ok_or(HttpProfileError::MissingCoveredComponent(component.name))?;
    Ok(value.to_owned())
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
        let end = after_authority
            .find(['?', '#'])
            .unwrap_or(after_authority.len());
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
        params.serialize_with(components)?
    ));
    Ok(lines.join("\n").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
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
        assert_eq!(
            err,
            HttpProfileError::MissingCoveredComponent("content-digest")
        );
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
        assert_eq!(
            err,
            HttpProfileError::MissingCoveredComponent("content-type")
        );
    }

    /// RFC 9421 §2.2.1 performs no case transformation on `@method`. Two wire
    /// spellings must therefore produce two bases: normalising them onto one let an
    /// intermediary rewrite the request line without invalidating the signature.
    #[test]
    fn method_case_is_carried_verbatim_into_the_base() {
        let mut lower = request();
        lower.method = "post".into();
        let base_of = |r: &HttpRequest| {
            String::from_utf8(
                signature_base(
                    &[CoveredComponent::new("@method")],
                    &SignatureParams::default(),
                    &SourceMessage::Request(r),
                )
                .expect("resolves"),
            )
            .unwrap()
        };
        assert!(base_of(&lower).contains("\"@method\": post"));
        assert_ne!(
            base_of(&lower),
            base_of(&request()),
            "`post` and `POST` are two messages and must not share one base"
        );
    }

    /// The injectivity guard covers DERIVED components, not only field values: a
    /// newline inside `@target-uri` would forge a second `"name": value` line inside
    /// the base, so two distinct messages would produce one signature base.
    #[test]
    fn crlf_in_a_derived_component_fails_closed() {
        for (name, mutate) in [
            (
                "@target-uri",
                (|r: &mut HttpRequest| {
                    r.target_uri =
                        "https://example.com/mcp\n\"content-type\": application/json".into()
                }) as fn(&mut HttpRequest),
            ),
            ("@method", |r: &mut HttpRequest| {
                r.method = "POST\n\"x\": y".into()
            }),
        ] {
            let mut r = request();
            mutate(&mut r);
            let err = signature_base(
                &[CoveredComponent::new(name)],
                &SignatureParams::default(),
                &SourceMessage::Request(&r),
            )
            .unwrap_err();
            assert_eq!(
                err,
                HttpProfileError::MalformedEvidence("covered component value contains CR or LF"),
                "{name} must not carry a line break into the base"
            );
        }
    }

    /// The nonce length bound holds on the PRODUCING side, through every signer.
    ///
    /// Enforced only at parse, a caller or SDK configured with an oversized nonce
    /// produced requests that signed correctly and were then refused
    /// `mcp-re.malformed_envelope` by every conforming MCP-RE verifier — a
    /// self-inflicted outage discoverable only at the far end. Every other wire-form
    /// rule this profile has (the sf-string character class, integer spelling) is
    /// enforced on both sides; this is the same rule: a value this profile cannot
    /// carry must not be EMITTED, not merely rejected on the way back in.
    #[test]
    fn a_nonce_the_profile_cannot_carry_is_never_emitted() {
        let oversized = "n".repeat(MAX_NONCE_CHARS + 1);
        let at_bound = "n".repeat(MAX_NONCE_CHARS);
        let components = [CoveredComponent::new("@method")];

        let params_with = |nonce: &str| SignatureParams {
            nonce: Some(nonce.to_owned()),
            ..SignatureParams::default()
        };
        assert_eq!(
            params_with(&oversized)
                .serialize_with(&components)
                .unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "nonce signature parameter exceeds the length bound"
            ),
        );
        params_with(&at_bound)
            .serialize_with(&components)
            .expect("the bound itself is still emittable");

        // Both bodied and bodyless request signers route through that serializer, so
        // neither can emit a nonce its own verifier refuses.
        let mut bodied = request();
        assert_eq!(
            crate::sign::sign_request(
                &mut bodied,
                &mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32]),
                "k",
                1_700_000_000,
                1_700_000_300,
                &oversized,
            )
            .unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "nonce signature parameter exceeds the length bound"
            ),
        );

        let mut bodyless = HttpRequest {
            method: "DELETE".into(),
            target_uri: "https://example.com/mcp".into(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert_eq!(
            crate::bodyless::sign_bodyless_request(
                &mut bodyless,
                &mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32]),
                "k",
                1_700_000_000,
                1_700_000_300,
                &oversized,
            )
            .unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "nonce signature parameter exceeds the length bound"
            ),
        );
    }

    #[test]
    fn crlf_in_a_field_value_fails_closed() {
        let mut r = request();
        r.headers = vec![("Content-Type".into(), "application/json\r\nx: y".into())];
        let err = signature_base(
            &[CoveredComponent::new("content-type")],
            &SignatureParams::default(),
            &SourceMessage::Request(&r),
        )
        .unwrap_err();
        assert_eq!(
            err,
            HttpProfileError::MalformedEvidence("covered component value contains CR or LF")
        );
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
