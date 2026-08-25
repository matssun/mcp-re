// SPDX-License-Identifier: Apache-2.0
//! The mechanism seam — ADR-MCPRE-065 §5.
//!
//! ```text
//! verified semantic prerequisites
//!         v
//! mechanism adapter          <- token parsing, caveats, policy language live HERE
//!         v
//! authorization semantic fact
//!         v
//! serving decision
//! ```
//!
//! The same shape ADR-MCPRE-063 established for communication mechanisms. What crosses this
//! seam is verified facts in and a decision out; nothing above it learns how the decision
//! was reached, and nothing below it learns how the facts were verified.
//!
//! # No mechanism ships with this slice
//!
//! ADR-MCPS-013 selected Biscuit in the context of the native/JCS authorization carrier that
//! ADR-MCPRE-050 replaced, and ADR-MCPRE-065 R-1 rules that the selection does not carry
//! forward as a normative requirement for the RFC 9421 path. There is no Biscuit code in
//! this tree, no evaluator of any kind, and no dependency to preserve — so this slice
//! defines the seam and stops. Selecting the first production mechanism is the next bounded
//! piece of work, chosen UNDER this architecture rather than defining it.
//!
//! A deployment that attaches no evaluator is not authorizing anything, and
//! [`AuthorizationPosture`](super::posture::AuthorizationPosture) says exactly that rather
//! than reporting an allow.
//!
//! # The denial taxonomy is the frozen one
//!
//! Failures cross the seam as [`PolicyError`], the ADR-MCPS-013 taxonomy, so a mechanism
//! adapter cannot mint a wire token. That taxonomy already separates a DENIAL from an
//! evaluation that could not complete — `authorization_revocation_unavailable` is the
//! worked case — and an adapter that cannot decide must choose the token that says so.
//! Both fail closed; they are not the same operational fact and are not reported as one.

use mcp_re_policy::PolicyError;

use super::grant::GrantAttribution;
use super::request::AuthorizationRequest;

/// A policy mechanism that decides over verified request facts.
///
/// `Send + Sync` because the serving path is thread-per-core and one evaluator is shared by
/// every core. Evaluation borrows: an implementation that needs interior state owns its own
/// synchronization, exactly as the admission and trust seams do.
pub trait AuthorizationEvaluator: Send + Sync {
    /// Decide whether this request's actor may perform this request's action.
    ///
    /// `Ok` names the policy authority that granted it — a decision nobody can attribute is
    /// a decision nobody can revisit. `Err` is a refusal, carrying the frozen token that
    /// says why.
    fn evaluate(&self, request: &AuthorizationRequest) -> Result<GrantAttribution, PolicyError>;
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::AuthorizationEvaluator;
    use crate::authorization::action_harness::verified_over;
    use crate::authorization::grant::GrantAttribution;
    use crate::authorization::request::authorization_request;
    use crate::authorization::request::AuthorizationRequest;
    use mcp_re_policy::PolicyError;

    /// A conformance evaluator: grants exactly one tool to exactly one subject.
    ///
    /// It exists to exercise the SEAM, and it is `#[cfg(test)]` so it can never be reached
    /// from a serving path. A test needing an allow path is not a reason to promote an
    /// evaluator to production authority.
    struct OneToolForOneSubject;

    impl AuthorizationEvaluator for OneToolForOneSubject {
        fn evaluate(
            &self,
            request: &AuthorizationRequest,
        ) -> Result<GrantAttribution, PolicyError> {
            let subject_ok = request.actor().subject() == "did:example:agent-1";
            let target_ok = request.action().target().named() == Some("read");
            if subject_ok && target_ok {
                return Ok(GrantAttribution::new("conformance", "1"));
            }
            Err(PolicyError::AuthorizationScopeDenied)
        }
    }

    const READ: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;
    const DELETE: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}"#;

    #[test]
    fn the_seam_carries_verified_facts_in_and_an_attributed_grant_out() {
        let verified = verified_over(READ);
        let granted = OneToolForOneSubject
            .evaluate(&authorization_request(&verified, READ, None).expect("composes"))
            .expect("granted");
        assert_eq!(granted.authority(), "conformance");
        assert_eq!(granted.version(), "1");
    }

    #[test]
    fn a_denial_crosses_the_seam_as_the_frozen_token() {
        let verified = verified_over(DELETE);
        assert_eq!(
            OneToolForOneSubject
                .evaluate(&authorization_request(&verified, DELETE, None).expect("composes")),
            Err(PolicyError::AuthorizationScopeDenied)
        );
    }
}
