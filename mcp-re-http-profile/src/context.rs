// SPDX-License-Identifier: Apache-2.0
//! The verified-context carrier (#415 rev 2 §10, issue #429).
//!
//! §10: the trusted verification boundary produces verified context; the carrier
//! between the enforcement boundary and the inner server must be explicitly
//! trusted; reserved verified-context fields in caller input must be rejected or
//! replaced.
//!
//! **The carrier is a reserved `_meta` block, and it is NOT evidence.** Everything
//! else in this crate is evidence: signed, digest-bound, verifiable by anyone
//! holding a key. This is the opposite — it is the PEP's *conclusion*, handed to
//! the inner server on the PEP's authority alone. The inner server cannot verify
//! it and must not try: there is no signature over it, because a signature would
//! imply the inner server could evaluate trust independently, which is exactly the
//! job the PEP exists to have already done.
//!
//! That makes the carrier's trust precondition load-bearing rather than incidental:
//!
//! **The channel PEP → inner server MUST be one only the PEP can write to** — a
//! loopback socket, a sidecar in the same pod, a UNIX socket. If anything else can
//! reach the inner server, it can assert any verified context it likes and the
//! inner server has no way to tell. There is no cryptographic fallback here, which
//! is why enabling the carrier is an explicit deployment act
//! ([`VerifiedContextPolicy::Trusted`]) and never a default.
//!
//! **The reserved-field guard.** Because the inner server trusts this block
//! implicitly, a caller that could seed it would be asserting its own verified
//! context — a total authentication bypass, not a spoofing nuisance. So the
//! reserved key is stripped from caller input at the boundary before the PEP writes
//! its own, unconditionally, whether or not the carrier is enabled: a deployment
//! that leaves it disabled must not be one reserved-key rename away from
//! forwarding attacker-authored context.

use serde::Deserialize;
use serde::Serialize;

use crate::block::AudienceTuple;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::ids::VERIFIED_CONTEXT_BLOCK_KEY;
use crate::verified_request::VerifiedMcpRequest;

/// Whether a deployment has an explicitly trusted channel to its inner server.
///
/// Default is [`VerifiedContextPolicy::Disabled`]: a PEP does not hand its
/// conclusions to a server it cannot prove it alone can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifiedContextPolicy {
    /// Do not carry verified context. The inner server sees clean MCP only.
    #[default]
    Disabled,
    /// The channel to the inner server is trusted: only this PEP can write to it
    /// (loopback / same-pod sidecar / UNIX socket). The operator asserts this;
    /// nothing here can check it.
    Trusted,
}

/// The PEP's verified conclusion about a request, carried to the inner server.
///
/// Every field is a TRUST-RESOLUTION OUTPUT, not a wire claim. `actor_id` is the
/// resolved actor the trust seam vouched for — deliberately not the presented
/// `keyid`, which is only a selector and would hand the inner server the one value
/// the caller chose. `key_id` is included for audit correlation and is explicitly
/// labelled as such so nobody authorizes on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedContext {
    /// The profile the request was verified under.
    pub profile: String,
    /// The resolved actor id — the identity to authorize on.
    pub actor_id: String,
    /// The presented keyid. AUDIT CORRELATION ONLY: a keyid is a selector the
    /// caller chose, never a trust-resolution output. Authorize on `actor_id`.
    pub key_id: String,
    /// The verified audience tuple.
    ///
    /// Always present on a context this crate BUILDS: [`VerifiedContext::from_verified`]
    /// takes a [`VerifiedMcpRequest`], so the full profile ran by construction. It stays
    /// optional because [`extract_verified_context`] also DESERIALIZES contexts, and what
    /// an inner server receives on the wire is a separate trust question from what this
    /// verifier concluded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<AudienceTuple>,
    /// The request evidence handle — the audit correlation key linking whatever
    /// the inner server does to the exact signed request that authorized it.
    pub request_evidence: RequestEvidence,
    /// The instant the PEP verified the request.
    pub verified_at: i64,
}

impl VerifiedContext {
    /// Build the context from the verifier's own output. Constructing it from
    /// anything else would defeat the point — this type exists to say "the PEP
    /// concluded this", so only the PEP's conclusion may build it.
    pub fn from_verified(verified: &VerifiedMcpRequest, verified_at: i64) -> Self {
        VerifiedContext {
            profile: verified.profile_id().to_owned(),
            actor_id: verified.resolved_actor().actor_id(),
            key_id: verified.key_id().to_owned(),
            audience: Some(verified.audience().clone()),
            request_evidence: verified.evidence().clone(),
            verified_at,
        }
    }
}

/// Strip ONLY the PEP-owned `_meta` keys from caller input (§10), leaving every
/// other entry intact.
///
/// Two keys are proxy-owned: the incoming request-evidence block (the PEP consumed
/// it; the inner server has no use for it) and the reserved verified-context key.
/// Everything else in `_meta` belongs to the application or to MCP itself and is
/// none of the enforcement boundary's business — a PEP that deletes the whole
/// `_meta` is not being careful, it is destroying data it was only asked to pass
/// through.
///
/// Called on EVERY request regardless of policy: a caller-seeded reserved field is
/// an attempted authentication bypass, and a deployment with the carrier disabled
/// must not be one config change away from forwarding it.
///
/// Returns `true` if the caller had in fact seeded the reserved verified-context
/// key — the caller gets no signal, but the PEP can audit the attempt.
pub fn strip_proxy_owned_meta(body: &mut serde_json::Value) -> bool {
    // BOTH `_meta` positions. MCP carries a `_meta` at the top level AND one inside
    // `params`, and an inner server reading the reserved key from either sees the same
    // thing — so stripping only the top-level one left `params._meta` as an unguarded
    // way to hand the inner server a caller-authored verified context. The guard is
    // there to make a caller-seeded context unreachable, not to make it move.
    let seeded_top = strip_reserved_keys(body.get_mut("_meta"));
    let seeded_params =
        strip_reserved_keys(body.get_mut("params").and_then(|p| p.get_mut("_meta")));
    // An empty `_meta` the PEP emptied is noise the caller never sent; drop it so
    // the inner server sees the body it would have seen without MCP-RE.
    drop_if_empty(body.as_object_mut(), "_meta");
    drop_if_empty(
        body.get_mut("params").and_then(|p| p.as_object_mut()),
        "_meta",
    );
    seeded_top || seeded_params
}

/// Remove the PEP-owned keys from one `_meta` object, reporting whether the reserved
/// verified-context key had been seeded.
fn strip_reserved_keys(meta: Option<&mut serde_json::Value>) -> bool {
    let Some(meta) = meta.and_then(|m| m.as_object_mut()) else {
        return false;
    };
    meta.remove(REQUEST_EVIDENCE_BLOCK_KEY);
    meta.remove(VERIFIED_CONTEXT_BLOCK_KEY).is_some()
}

/// Drop `key` from `object` when the value under it is a now-empty object.
fn drop_if_empty(object: Option<&mut serde_json::Map<String, serde_json::Value>>, key: &str) {
    let Some(object) = object else { return };
    let empty = object
        .get(key)
        .and_then(|v| v.as_object())
        .is_some_and(|m| m.is_empty());
    if empty {
        object.remove(key);
    }
}

/// Write the PEP's verified context into the forwarded body under the reserved key
/// (§10), replacing anything that was there.
///
/// The caller must have already stripped the caller-supplied `_meta` — this is
/// "replace", the second half of §10's "rejected or replaced", and it is only safe
/// on a body the PEP owns.
pub fn insert_verified_context(
    body: &[u8],
    context: &VerifiedContext,
) -> Result<Vec<u8>, HttpProfileError> {
    crate::body::insert_meta_block(body, VERIFIED_CONTEXT_BLOCK_KEY, context)
}

/// Read the verified context an inner server was handed.
///
/// ONLY call this on a body that arrived over the explicitly trusted channel. On
/// any other channel the block is an unauthenticated assertion — there is no
/// signature to check, by design.
pub fn extract_verified_context(body: &[u8]) -> Result<VerifiedContext, HttpProfileError> {
    crate::body::extract_meta_block(body, VERIFIED_CONTEXT_BLOCK_KEY, "verified context")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_proxy_keys_and_preserves_application_meta() {
        let mut body: serde_json::Value = serde_json::from_str(&format!(
            r#"{{"jsonrpc":"2.0","_meta":{{"{VERIFIED_CONTEXT_BLOCK_KEY}":{{"actor_id":"admin"}},"{REQUEST_EVIDENCE_BLOCK_KEY}":{{"profile":"x"}},"application.example/trace":"abc","io.modelcontextprotocol/x":1}}}}"#
        ))
        .unwrap();
        assert!(
            strip_proxy_owned_meta(&mut body),
            "the seeding attempt is reported"
        );
        assert!(body["_meta"].get(VERIFIED_CONTEXT_BLOCK_KEY).is_none());
        assert!(body["_meta"].get(REQUEST_EVIDENCE_BLOCK_KEY).is_none());
        // Not the PEP's data, not the PEP's business.
        assert_eq!(
            body["_meta"]["application.example/trace"],
            serde_json::json!("abc")
        );
        assert_eq!(
            body["_meta"]["io.modelcontextprotocol/x"],
            serde_json::json!(1)
        );
        assert!(
            !strip_proxy_owned_meta(&mut body),
            "idempotent; nothing left to report"
        );
    }

    #[test]
    fn a_meta_containing_only_proxy_keys_is_removed_entirely() {
        let mut body: serde_json::Value = serde_json::from_str(&format!(
            r#"{{"jsonrpc":"2.0","_meta":{{"{REQUEST_EVIDENCE_BLOCK_KEY}":{{"profile":"x"}}}}}}"#
        ))
        .unwrap();
        strip_proxy_owned_meta(&mut body);
        assert!(
            body.get("_meta").is_none(),
            "an emptied _meta is noise the caller never sent"
        );
    }

    #[test]
    fn strip_is_noop_without_meta() {
        let mut body: serde_json::Value = serde_json::from_str(r#"{"jsonrpc":"2.0"}"#).unwrap();
        assert!(!strip_proxy_owned_meta(&mut body));
    }
}
