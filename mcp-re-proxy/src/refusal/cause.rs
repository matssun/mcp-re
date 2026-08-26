// SPDX-License-Identifier: Apache-2.0
//! Which authority refused, and its own verdict in its own vocabulary.
//!
//! Separate from the refusal itself because they answer different questions. A refusal
//! says what a stage decided — the posture it must be signed under, the status the client
//! sees. This says WHO decided, and it is the half ADR-MCPRE-066 Slice 1 needs to survive
//! the stage boundary intact.

use mcp_re_core::McpReError;
use mcp_re_http_profile::HttpProfileError;

use crate::authorization::AuthorizationFacet;
use crate::authorization::AuthorizationRefusal;
use crate::authorization::AuthorizationRefusalFacet;
use crate::http_profile_dispatch::ProxyDispatchError;

/// Which authority refused, and its own verdict in its own vocabulary.
///
/// Closed: there are exactly two authorities on this path, and a third would be a design
/// decision rather than a variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RefusalCause {
    /// A Core verification verdict, in whichever of Core's own producers reached it.
    Core(CoreVerdict),
    /// The ADR-MCPRE-065 authorization boundary refused.
    ///
    /// Held whole rather than rendered, because the two arms inside it — no policy verdict was
    /// reached, versus a policy decided and denied — are the distinction ADR-MCPRE-066 Slice 1
    /// must be able to make. Rendering here would destroy it exactly as the string did.
    Authorization(AuthorizationRefusal),
}

/// Which Core producer reached the verdict.
///
/// Three arms rather than one `McpReError` because each producer's own error type says
/// strictly more than the token it renders to, and Slice 0's whole job is to stop discarding
/// that on the way to the audit boundary.
///
/// Each carries an exhaustive typed projection onto `McpReError`, and each derives its own
/// `wire_code` from that projection rather than keeping a second table beside it
/// (ADR-MCPRE-066 Slice 2). So this arm never invents a token and never chooses one — it
/// only remembers who spoke, and asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoreVerdict {
    /// The frozen taxonomy itself, named directly by the serving path.
    Taxonomy(McpReError),
    /// An RFC 9421 carrier failure.
    Carrier(HttpProfileError),
    /// A replay-tier or dispatch failure.
    Dispatch(ProxyDispatchError),
}

impl CoreVerdict {
    /// The Core verdict this producer reached, in the frozen taxonomy.
    ///
    /// Total, because every producer on this arm owns an exhaustive projection. This is what
    /// the audit boundary consumes: it takes an `McpReError`, so a producer that cannot
    /// name one cannot reach it.
    pub(crate) fn error(&self) -> McpReError {
        match self {
            CoreVerdict::Taxonomy(e) => e.clone(),
            CoreVerdict::Carrier(e) => McpReError::from(e),
            CoreVerdict::Dispatch(e) => McpReError::from(e),
        }
    }

    /// The frozen public token, derived from the verdict rather than chosen here.
    pub(crate) fn wire_code(&self) -> &'static str {
        self.error().wire_code()
    }
}

impl RefusalCause {
    /// The frozen public token this refusal is served as.
    ///
    /// The ONLY rendering point. Both arms already own a total mapping onto frozen vocabulary,
    /// so this adds no vocabulary and makes no choice: it asks each authority what it says.
    pub(crate) fn wire_code(&self) -> &'static str {
        match self {
            RefusalCause::Core(v) => v.wire_code(),
            RefusalCause::Authorization(r) => r.wire_code(),
        }
    }

    /// What the authorization authority may say about a request refused for this cause
    /// (ADR-MCPRE-066 Slice 1).
    ///
    /// Total, and it is the reason Slice 0 kept the cause typed. Every Core arm projects to
    /// `BeforePolicy` — a request whose signature did not verify, whose nonce replayed, or
    /// whose dispatch failed reached no policy, and the record's Core-owned `reason` already
    /// says what did go wrong. The authorization arm asks the authorization authority, which
    /// is the only one that can tell *no verdict was reached* from *a policy denied*.
    ///
    /// This composes; it does not decide. Neither authority's vocabulary is read here.
    /// The Core verdict this refusal is recorded under, or `None` where Core reached none.
    ///
    /// `None` has exactly one cause and it is not an omission: an authorization policy
    /// decided, and a policy denial is not a Core verdict. Core states nothing rather than
    /// borrowing a token, and the record's authorization coordinate says what did happen.
    ///
    /// The action arm DOES project: a body that is not the signed body really is a digest
    /// mismatch, and a body naming no operation really is a malformed envelope. Those are
    /// Core's own statements about the request, which is why ADR-MCPRE-065 rendered them as
    /// Core tokens in the first place.
    pub(crate) fn core_verdict(&self) -> Option<McpReError> {
        match self {
            RefusalCause::Core(v) => Some(v.error()),
            RefusalCause::Authorization(r) => r.core_verdict(),
        }
    }

    pub(crate) fn authorization_facet(&self) -> AuthorizationFacet {
        match self {
            RefusalCause::Core(_) => {
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy)
            }
            RefusalCause::Authorization(r) => r.audit_facet(),
        }
    }
}

impl From<McpReError> for RefusalCause {
    fn from(e: McpReError) -> Self {
        RefusalCause::Core(CoreVerdict::Taxonomy(e))
    }
}

impl From<HttpProfileError> for RefusalCause {
    fn from(e: HttpProfileError) -> Self {
        RefusalCause::Core(CoreVerdict::Carrier(e))
    }
}

impl From<ProxyDispatchError> for RefusalCause {
    fn from(e: ProxyDispatchError) -> Self {
        RefusalCause::Core(CoreVerdict::Dispatch(e))
    }
}

impl From<AuthorizationRefusal> for RefusalCause {
    fn from(r: AuthorizationRefusal) -> Self {
        RefusalCause::Authorization(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::AuthorizationActionRefusal;
    use mcp_re_policy::PolicyError;

    #[test]
    fn a_carrier_failure_arrives_as_a_core_verdict_that_remembers_its_producer() {
        let c = RefusalCause::from(HttpProfileError::ContentDigestMismatch);
        assert_eq!(
            c,
            RefusalCause::Core(CoreVerdict::Carrier(
                HttpProfileError::ContentDigestMismatch
            ))
        );
        // ...and serves the token it always did: Slice 0 is a wire no-op.
        assert_eq!(c.wire_code(), "mcp-re.digest_mismatch");
    }

    #[test]
    fn an_authorization_refusal_stays_authorization_provenance() {
        // THE property of this slice. A policy denial must not become a Core verdict on the
        // way to the audit boundary, or ADR-MCPRE-066 Slice 1 has nothing left to represent.
        let c = RefusalCause::from(AuthorizationRefusal::PolicyRefused(
            PolicyError::AuthorizationScopeDenied,
        ));
        assert!(matches!(c, RefusalCause::Authorization(_)));
        assert_eq!(c.wire_code(), "mcp-re.authorization_scope_denied");
    }

    #[test]
    fn the_two_authorization_arms_stay_distinguishable() {
        // What the pre-rendered string destroyed. Note the first arm SERVES a Core token —
        // which is precisely why a token could never have carried this distinction.
        let before = RefusalCause::from(AuthorizationRefusal::ActionNotVerifiable(
            AuthorizationActionRefusal::BodyIsNotTheSignedBody,
        ));
        let by = RefusalCause::from(AuthorizationRefusal::PolicyRefused(
            PolicyError::AuthorizationScopeDenied,
        ));
        assert_ne!(before, by);
        assert!(matches!(before, RefusalCause::Authorization(_)));
        assert_eq!(before.wire_code(), "mcp-re.digest_mismatch");
    }

    #[test]
    fn a_core_verdict_never_attributes_a_refusal_to_a_policy() {
        // A request that failed verification reached no policy. Saying anything else on the
        // record would send an operator to inspect a grant that was never consulted.
        use crate::authorization::AuthorizationFacet;
        use crate::authorization::AuthorizationRefusalFacet;
        for c in [
            RefusalCause::from(McpReError::ReplayDetected),
            RefusalCause::from(HttpProfileError::InvalidSignature),
            RefusalCause::from(ProxyDispatchError::NoDeclaredReplayTier),
        ] {
            assert_eq!(
                c.authorization_facet(),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy)
            );
        }
    }

    #[test]
    fn a_policy_denial_reaches_the_record_as_policy_provenance() {
        // The end-to-end property Slice 0 preserved and Slice 1 spends: the token the
        // policy authority produced arrives at the composition boundary still attributed
        // to the policy authority, in its own coordinate.
        use crate::authorization::AuthorizationFacet;
        use crate::authorization::AuthorizationRefusalFacet;
        let c = RefusalCause::from(AuthorizationRefusal::PolicyRefused(
            PolicyError::AuthorizationScopeDenied,
        ));
        assert_eq!(
            c.authorization_facet(),
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(
                PolicyError::AuthorizationScopeDenied
            ))
        );
    }

    #[test]
    fn a_policy_denial_has_no_core_verdict_to_be_recorded_under() {
        // Invariants 8 and 9, as one value. Core reached no verdict, so Core states none —
        // and because the audit boundary takes an `McpReError`, there is no route by which
        // the policy's token could be written into Core's `reason` instead. That was #637.
        let c = RefusalCause::from(AuthorizationRefusal::PolicyRefused(
            PolicyError::AuthorizationScopeDenied,
        ));
        assert_eq!(c.core_verdict(), None);
        // The client still receives the policy's own code: this is a wire no-op.
        assert_eq!(c.wire_code(), "mcp-re.authorization_scope_denied");
    }

    #[test]
    fn an_unreadable_action_coordinate_is_a_core_verdict_after_all() {
        // The other authorization arm DOES project. A body that is not the signed body is a
        // digest mismatch — Core's own statement about the request — which is why
        // ADR-MCPRE-065 rendered these as Core tokens rather than minting authorization
        // ones. Only the policy arm has nothing of Core's to say.
        let c = RefusalCause::from(AuthorizationRefusal::ActionNotVerifiable(
            AuthorizationActionRefusal::BodyIsNotTheSignedBody,
        ));
        assert_eq!(c.core_verdict(), Some(McpReError::DigestMismatch));
    }

    #[test]
    fn every_core_producer_names_a_verdict_and_the_token_follows_from_it() {
        // The derivation, end to end: the producer states which Core verdict it is, and the
        // wire token is that verdict's own rather than a second table's copy of it.
        for c in [
            RefusalCause::from(McpReError::ReplayDetected),
            RefusalCause::from(HttpProfileError::InvalidSignature),
            RefusalCause::from(ProxyDispatchError::NoDeclaredReplayTier),
        ] {
            let verdict = c.core_verdict().expect("a Core producer reached a verdict");
            assert_eq!(c.wire_code(), verdict.wire_code());
        }
    }

    #[test]
    fn a_dispatch_failure_is_a_core_verdict_and_keeps_its_own_token() {
        let c = RefusalCause::from(ProxyDispatchError::NoDeclaredReplayTier);
        assert!(matches!(c, RefusalCause::Core(CoreVerdict::Dispatch(_))));
        assert_eq!(c.wire_code(), "mcp-re.replay_cache_unavailable");
    }

    #[test]
    fn every_core_producer_renders_a_token_its_own_authority_owns() {
        // The Core arm never invents a token; it asks. Three producers, three delegations.
        for (v, expected) in [
            (
                CoreVerdict::Taxonomy(McpReError::ReplayDetected),
                "mcp-re.replay_detected",
            ),
            (
                CoreVerdict::Carrier(HttpProfileError::InvalidSignature),
                "mcp-re.invalid_signature",
            ),
            (
                CoreVerdict::Dispatch(ProxyDispatchError::NoDeclaredReplayTier),
                "mcp-re.replay_cache_unavailable",
            ),
        ] {
            assert_eq!(v.wire_code(), expected);
        }
    }
}
