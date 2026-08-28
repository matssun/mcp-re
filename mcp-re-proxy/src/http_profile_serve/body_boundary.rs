// SPDX-License-Identifier: Apache-2.0
//! The PEP's read/write boundary inside the client's JSON-RPC body (#415 rev 2 §10,
//! MCPRE-429, ADR-MCPS-047).
//!
//! One fact, stated here and nowhere else: **the enforcement boundary's interest in the
//! body is confined to named fields, and everything else passes through untouched.**
//! Three named fields exist —
//!
//! * `params.requestState`, which the proxy READS to key the correlation store and never
//!   interprets;
//! * the PEP-owned `_meta` request-evidence block, which the proxy STRIPS because it has
//!   just consumed it;
//! * the reserved verified-context `_meta` key, which the proxy WRITES and which a caller
//!   may therefore never author.
//!
//! Keeping them together is what makes the §10 guard checkable. The guard is not "strip
//! `_meta`" — deleting the whole block would destroy application data the PEP was asked to
//! pass through — it is "the PEP removes exactly what it owns, then writes exactly what it
//! is entitled to assert". Those two halves are one sentence about one boundary, and a
//! reader who has to visit two modules to read it can no longer tell whether the set of
//! PEP-owned keys removed matches the set the PEP writes.
//!
//! [`ForwardedBody`] is sealed: its representation is private, [`ForwardedBody::prepare`]
//! is its only producer, and the bytes are obtained only by
//! [`ForwardedBody::into_bytes_for_inner`] — which reports a caller's attempt on the
//! reserved key as it hands them over. Consuming clean bytes without the attempt being
//! named is therefore not a discipline the assembly keeps; it is unconstructible.

use mcp_re_http_profile::insert_verified_context;
use mcp_re_http_profile::strip_proxy_owned_meta;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::VerifiedContext;
use mcp_re_http_profile::VerifiedContextPolicy;
use mcp_re_http_profile::VerifiedMcpRequest;

/// Read `params.requestState` (a string) from a JSON-RPC request body — the opaque
/// MRTR state an answer leg re-presents (ADR-MCPS-047). `None` if the body is not
/// JSON, has no `params.requestState`, or it is not a string.
///
/// The value is read only to KEY the correlation store; it is never interpreted, and
/// what it binds to is settled by digest equality against the retained bases.
pub fn extract_request_state(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("params")?
        .get("requestState")?
        .as_str()
        .map(str::to_owned)
}

/// Remove exactly the `_meta` keys the PEP owns, reporting whether the caller had seeded
/// the reserved verified-context key.
///
/// Separated from [`ForwardedBody::prepare`] because this half is the §10 guard proper and
/// runs under EVERY policy, so it is the half that must be checkable on its own: that the
/// PEP removes what it owns and leaves what it does not is a property of the request body
/// alone, with no verified request and no policy in it.
fn strip_pep_owned(body: &[u8]) -> Result<(Vec<u8>, bool), HttpProfileError> {
    // The forwarded bytes are re-serialized below, which cannot carry a duplicate
    // member name or a number the f64 carrier alters. Refuse those on the ORIGINAL
    // bytes, using the same scan the response path applies, so the backend never sees
    // a body that differs from what the client signed.
    mcp_re_http_profile::reject_unrepresentable_json(body)?;
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(body) else {
        // A non-object body never verified as a full-profile request, so this is
        // unreachable on the served path; pass it through rather than invent bytes.
        return Ok((body.to_vec(), false));
    };
    let seeded = strip_proxy_owned_meta(&mut v);
    let stripped = serde_json::to_vec(&v)
        .map_err(|_| HttpProfileError::MalformedEvidence("body reserialize"))?;
    Ok((stripped, seeded))
}

/// The body the inner server receives, and the §10 guard's detection signal.
///
/// Private fields: holding one means the PEP-owned keys have been removed and, under
/// `Trusted`, the PEP's own context has been written. There is no way to assemble the
/// pair from outside this module and no way to read the bytes without the seeded-key
/// attempt being reported.
pub(super) struct ForwardedBody {
    /// The clean JSON-RPC bytes the inner server receives.
    body: Vec<u8>,
    /// Whether the caller had seeded the reserved verified-context key. The value was
    /// stripped either way; this is the only trace the attempt leaves, so the boundary
    /// names it rather than discarding it.
    seeded: bool,
}

impl ForwardedBody {
    /// Compose the body forwarded to the inner server.
    ///
    /// Two steps, in this order:
    ///
    /// 1. **Strip the PEP-owned `_meta` keys** — the request-evidence block the PEP
    ///    just consumed, and the reserved verified-context key. This is the §10 guard
    ///    and it runs on EVERY request regardless of policy: a caller that could seed
    ///    the reserved key would be asserting its own verified context to a server
    ///    that trusts the block implicitly, which is an authentication bypass rather
    ///    than a spoofing nuisance. A deployment with the carrier disabled must not be
    ///    one config flip away from forwarding attacker-authored context.
    ///
    ///    Only PEP-owned keys are removed. Application and MCP `_meta` entries are
    ///    none of the enforcement boundary's business — deleting the whole `_meta`
    ///    would not be caution, it would be destroying data the PEP was asked to pass
    ///    through.
    ///
    /// 2. **Write the PEP's own context**, only under an explicitly trusted channel.
    ///
    /// Returns `Err` if the trusted carrier is enabled and the context could not be
    /// written. That is deliberate: under `Trusted` the inner server is entitled to
    /// assume the PEP speaks, and silently forwarding a request WITHOUT the context it
    /// expects would degrade into an unauthenticated call that looks ordinary. Fail
    /// closed instead.
    pub(super) fn prepare(
        body: &[u8],
        verified: &VerifiedMcpRequest,
        policy: VerifiedContextPolicy,
        now: i64,
    ) -> Result<Self, HttpProfileError> {
        let (stripped, seeded) = strip_pep_owned(body)?;
        let body = match policy {
            VerifiedContextPolicy::Disabled => stripped,
            VerifiedContextPolicy::Trusted => {
                let ctx = VerifiedContext::from_verified(verified, now);
                insert_verified_context(&stripped, &ctx)?
            }
        };
        Ok(Self { body, seeded })
    }

    /// The bytes the inner server receives, naming a caller's reserved-key attempt as they
    /// are handed over.
    ///
    /// The report is not a separate step the assembly must remember: the bytes leave this
    /// type only through here, so an attempt on the reserved key cannot reach the backend
    /// path unnamed.
    ///
    /// A deliberate attempt to assert one's own authentication context to the inner server
    /// is exactly what this surface exists to detect. The frozen audit vocabulary has no
    /// event for it (ADR-MCPS-035 §3 admits no third success event), so it is named on the
    /// diagnostic channel rather than left with no trace at all.
    pub(super) fn into_bytes_for_inner(self, actor_id: &str) -> Vec<u8> {
        if self.seeded {
            eprintln!(
                "mcp-re-proxy: warning: request from actor {actor_id} seeded the reserved \
                 verified-context `_meta` key; stripped before forwarding (the inner \
                 server never saw it)"
            );
        }
        self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_state_is_read_only_as_a_string_under_params() {
        assert_eq!(
            extract_request_state(br#"{"params":{"requestState":"s-1"}}"#),
            Some("s-1".to_owned())
        );
        // Not JSON, no `params`, no `requestState`, and a non-string one all read as
        // absent: the value keys a store, so anything that is not the opaque string the
        // client presented is no key at all.
        assert_eq!(extract_request_state(b"not json"), None);
        assert_eq!(extract_request_state(br#"{"params":{}}"#), None);
        assert_eq!(extract_request_state(br#"{"requestState":"s-1"}"#), None);
        assert_eq!(extract_request_state(br#"{"params":{"requestState":7}}"#), None);
    }

    #[test]
    fn application_meta_survives_the_pep_owned_strip() {
        // The §10 guard is not "delete `_meta`". A boundary that removed the whole block
        // would be destroying data the PEP was asked to pass through, and the difference
        // is only observable on a body carrying an application entry.
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"app.trace":"t-1"}}}"#;
        let (stripped, seeded) = strip_pep_owned(body).expect("a well-formed body strips");
        assert!(!seeded, "no reserved key was present, so nothing was attempted");
        let v: serde_json::Value = serde_json::from_slice(&stripped).expect("json out");
        assert_eq!(
            v["params"]["_meta"]["app.trace"], "t-1",
            "an application `_meta` entry is none of the enforcement boundary's business"
        );
    }

    #[test]
    fn an_unrepresentable_body_is_refused_before_any_reserialization() {
        // Duplicate member names cannot survive the re-serialization, so they are refused
        // on the ORIGINAL bytes — otherwise the backend would see a body that differs from
        // the one the client signed.
        assert!(
            strip_pep_owned(br#"{"a":1,"a":2}"#).is_err(),
            "a body whose meaning changes under re-serialization never reaches the backend"
        );
    }
}
