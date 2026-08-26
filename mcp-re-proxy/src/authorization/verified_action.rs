// SPDX-License-Identifier: Apache-2.0
//! What the request asks to do — ADR-MCPRE-065 Law A-1.
//!
//! # The proposition
//!
//! Possession of [`VerifiedAuthorizationAction`] means:
//!
//! > These operation and target values were read from the exact body the RFC 9421 signature
//! > covered, for the request whose evidence proved that coverage.
//!
//! # Why the headers are not the coordinate
//!
//! `Mcp-Method` and `Mcp-Name` carry the same values and are far easier to read. They are
//! routing hints, and MCP-RE never trusts one for a security decision. The reason is not
//! fastidiousness — they *need not agree with the body*. The MCP transport contract that
//! makes `Mcp-Name` mandatory for `tools/call` / `resources/read` and requires it to match
//! `params.name` is `Unconstrained` by default, becoming `Enforced` only when a deployment
//! declares a protocol version.
//!
//! So a coordinate read from a header would make authorization semantics depend on whether
//! an unrelated transport-consistency policy happened to be switched on: the same signed
//! request would be authorized against one action with the contract enforced, and against a
//! header-chosen action without it. The contract exists to stop a header and a body
//! disagreeing in front of a human or a router. It is not what makes the coordinate
//! authoritative, and this authority does not consult it.
//!
//! # Why the pairing is proved rather than assumed
//!
//! The verified request and the body bytes arrive as two values. Handing both to a
//! constructor and trusting the caller to have passed the matching pair is exactly the L-5
//! shape ADR-MCPRE-063 names: two honest facts stating a false relation, with the caller
//! doing the pairing. The verified request retains the `Content-Digest` its signature
//! covered, so the pairing is *checkable* — and [`interpret_authorization_action`] checks
//! it. A body that is not the signed body cannot produce an inhabitant.
//!
//! # Scope
//!
//! Operation and target. Argument-level policy is a mechanism concern and belongs with the
//! first production evaluator, not with the boundary: a coordinate this authority cannot
//! describe without knowing a policy language is not a verified fact about the request.
//!
//! # This authority reports the body; it does not validate its shape
//!
//! A `tools/call` carrying no `params.name` is a malformed MCP request, and saying so is the
//! transport contract's job, not this one's. Refusing it here would mean an unauthorized
//! deployment started rejecting requests because of authorization — the same hidden coupling
//! Law A-1 rules out, running the other way. So the missing target is REPORTED, as its own
//! state, and a policy that cares denies it.

use mcp_re_core::McpReError;
use mcp_re_http_profile::mcp_name_source::mcp_name_source;
use mcp_re_http_profile::VerifiedMcpRequest;
use serde_json::Value;

/// What an operation names, as a closed set.
///
/// # Why this is not `Option<String>`
///
/// `None` would mean BOTH *this operation names no target* and *this operation names one
/// and the body did not carry it*. `tools/list` is the first; a `tools/call` with no
/// `params.name` is the second, and a policy granting "any tool of this operation" must not
/// match it. Collapsing them is the shape ADR-MCPRE-064 Slice 3 removed from credential
/// currency, and it would hide a malformed request inside a legitimate one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationTarget {
    /// This operation names no target. `tools/list`, `initialize`, and everything else
    /// whose authority is the method alone.
    NotApplicable,
    /// The signed body named this tool or resource.
    Named(String),
    /// This operation names a target and the signed body carries none.
    ///
    /// Not refused here — whether that is a legal MCP request is the transport contract's
    /// question. Reported so a policy can decline to match it.
    Absent,
}

impl AuthorizationTarget {
    /// The named target, or `None` for both of the other states.
    ///
    /// A convenience for a policy that treats *no target* and *target absent* alike. One
    /// that does not must match on the variants — which is why this is not the only way to
    /// read the value.
    pub fn named(&self) -> Option<&str> {
        match self {
            AuthorizationTarget::Named(t) => Some(t),
            AuthorizationTarget::NotApplicable | AuthorizationTarget::Absent => None,
        }
    }
}

/// The operation and target a verified request asks for.
///
/// Sealed: the representation and the constructor are private to this module, so the only
/// inhabitants are the ones [`interpret_authorization_action`] read out of a body it proved
/// was the signed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthorizationAction {
    operation: String,
    target: AuthorizationTarget,
}

impl VerifiedAuthorizationAction {
    /// The JSON-RPC `method` — the operation being requested.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// What this operation names.
    pub fn target(&self) -> &AuthorizationTarget {
        &self.target
    }
}

/// Why an action coordinate could not be read from a request.
///
/// Every arm is a statement about the REQUEST, not about the deployment: there is nothing
/// here that a differently-configured proxy would report differently, which is what Law A-1
/// requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationActionRefusal {
    /// The bytes offered as the request body are not the ones the signature covered.
    ///
    /// Not a client error in practice — the verifier already established the digest — but a
    /// serving path that reached this authority with some other body would be deciding
    /// policy over content nobody signed, and that must be unrepresentable rather than
    /// merely unlikely.
    BodyIsNotTheSignedBody,
    /// The signed body does not parse as JSON.
    BodyIsNotJson,
    /// The signed body carries no string `method`, so it names no operation.
    ///
    /// Unreachable on the serving path — a body with no `method` is not a legal JSON-RPC
    /// request and is refused before this authority runs. Kept because this operation is
    /// total over its inputs and must not depend on an ordering it cannot see.
    NoOperation,
}

/// The exhaustive projection onto the frozen Core taxonomy (ADR-MCPRE-066 Slice 2).
///
/// These are Core's own statements about the request, which is why ADR-MCPRE-065 rendered
/// them as Core tokens rather than minting authorization ones: a body that is not the signed
/// body IS a digest mismatch, and a body naming no operation IS a malformed envelope. This
/// authority is entitled to say so — and *only* to say so, in Core's existing words.
///
/// Exhaustive, with no wildcard: a new way for a coordinate to be unreadable is a compile
/// error here until it says which Core verdict it is. The variant that used to hide behind a
/// `_` was `BodyIsNotJson`, and a wildcard that already covers two unlike facts is exactly
/// how a third joins them unnoticed.
impl From<&AuthorizationActionRefusal> for McpReError {
    fn from(e: &AuthorizationActionRefusal) -> McpReError {
        match e {
            AuthorizationActionRefusal::BodyIsNotTheSignedBody => McpReError::DigestMismatch,
            AuthorizationActionRefusal::BodyIsNotJson | AuthorizationActionRefusal::NoOperation => {
                McpReError::MalformedEnvelope
            }
        }
    }
}

/// Read the action coordinate out of the request's signed body.
///
/// THE construction operation. It takes the verified request — never a caller's opinion of
/// what was signed — and the transmitted bytes, and refuses unless they are the same body.
pub fn interpret_authorization_action(
    verified: &VerifiedMcpRequest,
    body: &[u8],
) -> Result<VerifiedAuthorizationAction, AuthorizationActionRefusal> {
    // The pairing, PROVED — and by the owner of the digest, which is why this authority
    // holds no copy of the comparison. A body that satisfies the covered `Content-Digest`
    // is the body that was signed.
    if !verified.covers_body(body) {
        return Err(AuthorizationActionRefusal::BodyIsNotTheSignedBody);
    }
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return Err(AuthorizationActionRefusal::BodyIsNotJson);
    };
    let Some(operation) = body.get("method").and_then(Value::as_str) else {
        return Err(AuthorizationActionRefusal::NoOperation);
    };
    let target = match mcp_name_source(operation) {
        None => AuthorizationTarget::NotApplicable,
        Some(source) => match body.get("params").and_then(|p| source.extract(p)) {
            Some(named) => AuthorizationTarget::Named(named.to_owned()),
            None => AuthorizationTarget::Absent,
        },
    };
    Ok(VerifiedAuthorizationAction {
        operation: operation.to_owned(),
        target,
    })
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::interpret_authorization_action;
    use super::AuthorizationActionRefusal;
    use super::AuthorizationTarget;
    use crate::authorization::action_harness::verified_over;

    #[test]
    fn the_coordinate_is_read_from_the_signed_body() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;
        let verified = verified_over(body);
        let action = interpret_authorization_action(&verified, body).expect("reads");
        assert_eq!(action.operation(), "tools/call");
        assert_eq!(action.target().named(), Some("read"));
    }

    #[test]
    fn a_method_that_names_no_target_is_not_the_same_as_one_missing_its_target() {
        // The distinction a single `Option` destroys. A policy granting "any tool" must
        // match neither, and must be able to tell them apart when it wants to.
        let listing = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        assert_eq!(
            interpret_authorization_action(&verified_over(listing), listing)
                .expect("reads")
                .target(),
            &AuthorizationTarget::NotApplicable
        );
        let nameless = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
        assert_eq!(
            interpret_authorization_action(&verified_over(nameless), nameless)
                .expect("reads")
                .target(),
            &AuthorizationTarget::Absent
        );
    }

    #[test]
    fn a_malformed_request_is_reported_rather_than_refused_by_this_authority() {
        // Whether a `tools/call` must carry a tool name is the transport contract's
        // question. Refusing it here would make an unauthorized deployment start rejecting
        // requests because of authorization.
        let nameless = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
        assert!(interpret_authorization_action(&verified_over(nameless), nameless).is_ok());
    }

    #[test]
    fn a_body_that_is_not_the_signed_body_cannot_produce_a_coordinate() {
        // THE L-5 CONTROL. Two honest values — a real verified request and a real JSON body
        // — must not be pairable into a false relation by the caller that holds both.
        let signed = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;
        let other = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}"#;
        assert_eq!(
            interpret_authorization_action(&verified_over(signed), other),
            Err(AuthorizationActionRefusal::BodyIsNotTheSignedBody)
        );
    }

    #[test]
    fn resources_read_names_its_target_under_a_different_key() {
        let body =
            br#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"f://x"}}"#;
        let action = interpret_authorization_action(&verified_over(body), body).expect("reads");
        assert_eq!(action.target().named(), Some("f://x"));
    }

    #[test]
    fn a_signed_body_that_is_not_json_and_one_with_no_method_are_different_facts() {
        let junk = b"not json at all";
        assert_eq!(
            interpret_authorization_action(&verified_over(junk), junk),
            Err(AuthorizationActionRefusal::BodyIsNotJson)
        );
        let no_method = br#"{"jsonrpc":"2.0","id":1}"#;
        assert_eq!(
            interpret_authorization_action(&verified_over(no_method), no_method),
            Err(AuthorizationActionRefusal::NoOperation)
        );
    }
}
