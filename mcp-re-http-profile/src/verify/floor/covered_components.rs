// SPDX-License-Identifier: Apache-2.0
//! The signature-input inner list: which components a signature covers.
//!
//! One authority: **the closed set of identifiers this profile can ever cover, each named
//! at most once.** Two rules, both fail-closed and both about the same subject:
//!
//! - identifiers are `'static` here — anything outside the allowlist is foreign evidence,
//!   and admitting it would mean the verifier signing off on something it cannot rebuild;
//! - an identifier appears at most once for a given `;req`-ness. RFC 9421 §2.5 requires the
//!   error, but the reason it matters here is sharper: `signature_base` emits a line per
//!   occurrence, so duplicates would give one message many valid signature bases and
//!   therefore many evidence handles — the handle would stop being a function of the
//!   message.
//!
//! The list's exact SPACING is part of the same closed grammar and is checked here rather
//! than tolerated: the base is rebuilt from parsed values, so a spelling normalised away
//! verifies under the canonical signature (see [`super::sf_dictionary`] for the full
//! argument).

use crate::error::HttpProfileError;
use crate::sigbase::CoveredComponent;

/// Parse the inner list — the text between `(` and `)` — into its covered components.
pub(super) fn parse_covered_components(
    list: &str,
) -> Result<Vec<CoveredComponent>, HttpProfileError> {
    // The inner list is EXACTLY single-space separated, with no leading or trailing
    // space — the one form `sigbase` emits. `split_whitespace` accepted any run of
    // spaces and tabs and collapsed them, so `("@method"  "@target-uri")` and
    // `( "@method"\t"@target-uri" )` rebuilt to the same signature base and verified
    // under the same signature. An on-path intermediary could then rewrite the raw
    // `Signature-Input` header without invalidating anything, and every consumer that
    // logs, hashes, caches or diffs the RAW header — an audit sink, a retained-evidence
    // blob, a CDN cache key — saw bytes other than the ones that were signed. No
    // forgery, but the one-to-one correspondence the profile claims for itself did not
    // hold.
    if list.starts_with(' ') || list.ends_with(' ') || list.contains("  ") {
        return Err(HttpProfileError::MalformedEvidence("inner list spacing"));
    }
    if list.bytes().any(|b| b == b'\t') {
        return Err(HttpProfileError::MalformedEvidence("inner list spacing"));
    }
    let mut components: Vec<CoveredComponent> = Vec::new();
    for item in list.split(' ').filter(|i| !i.is_empty()) {
        let (name_part, req) = match item.strip_suffix(";req") {
            Some(p) => (p, true),
            None => (item, false),
        };
        let name = name_part
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or(HttpProfileError::MalformedEvidence("component identifier"))?;
        // Identifiers are 'static in this profile: admit only the closed set
        // the profile can ever cover; anything else is foreign evidence.
        let known: &'static str = match name {
            "@method" => "@method",
            "@target-uri" => "@target-uri",
            "@authority" => "@authority",
            "@path" => "@path",
            "@status" => "@status",
            "content-digest" => "content-digest",
            "content-type" => "content-type",
            "content-length" => "content-length",
            "authorization" => "authorization",
            "dpop" => "dpop",
            // MCP transport headers (§4.1). Coverable so a deployment whose
            // protocol version defines them can bind them; still fail-closed for
            // everything outside this set.
            "mcp-method" => "mcp-method",
            "mcp-name" => "mcp-name",
            "mcp-protocol-version" => "mcp-protocol-version",
            // The delegation-credential header on a delegated bodyless 202
            // (#424): coverable so the credential it carries is protected by the
            // response signature. Only the bodyless-202 path requires it.
            "mcp-re-delegation" => "mcp-re-delegation",
            // The request-evidence header on a bodyless 202 (C019b): coverable so the
            // per-instance coordinate it carries is protected by the response
            // signature. Only the bodyless-202 path requires it.
            "mcp-re-request-evidence" => "mcp-re-request-evidence",
            _ => {
                return Err(HttpProfileError::MalformedEvidence(
                    "unknown covered component",
                ))
            }
        };
        let component = if req {
            CoveredComponent::req(known)
        } else {
            CoveredComponent::new(known)
        };
        // RFC 9421 §2.5 requires an error when an identifier is added to the base
        // twice. Beyond conformance, admitting duplicates would mean one message has
        // many valid signature bases — `signature_base` emits a line per occurrence —
        // and therefore many distinct evidence handles for the same bytes, so the
        // handle would stop being a function of the message. `;req` makes an
        // identifier distinct: "content-digest" and "content-digest";req name
        // different values, so only an exact (name, req) repeat is a duplicate. This
        // is the same exactly-once discipline already applied to duplicated header
        // FIELDS in `sigbase`.
        if components
            .iter()
            .any(|c: &CoveredComponent| c.name == component.name && c.req == component.req)
        {
            return Err(HttpProfileError::MalformedEvidence(
                "duplicate covered component",
            ));
        }
        components.push(component);
    }
    Ok(components)
}
