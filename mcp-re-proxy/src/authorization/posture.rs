// SPDX-License-Identifier: Apache-2.0
//! What this deployment can honestly say about a served request's permission.
//!
//! # Three states, because there are three facts
//!
//! ```text
//! NoPolicyConfigured   no authorization policy is deployed; nothing is claimed
//! Authorized           a policy evaluated these verified facts and permitted this action
//! (refused)            a policy denied, or evaluation could not be completed
//! ```
//!
//! The refusal is the `Err` half of the operation that produces this type, so the closed set
//! is three, not two — and the distinction that matters most is the first two. **`Off` is
//! not `Allow`.** A deployment with no policy has not authorized anything, and reporting it
//! as an allow manufactures a claim nobody made, in the one place where a later reader would
//! have no way to tell the difference.
//!
//! This is the discipline ADR-MCPRE-064 Slice 3 applied to credential currency, where
//! "nobody asked" and "asked and satisfied" were the two facts a `bool` destroyed. The same
//! collapse here would make an unconfigured proxy indistinguishable from a policy-protected
//! one in every record either produces.

use super::audit::AuthorizationAttribution;
use super::audit::AuthorizationFacet;
use super::grant::GrantAttribution;
use super::request::AuthorizationRequest;

/// A policy permitted this request.
///
/// Sealed: the representation and the constructor are private to this module, so the only
/// inhabitants are the ones [`super::decide::authorize`] built from a grant an evaluator
/// actually returned. Nothing can assert that a request was authorized.
#[derive(Debug, Clone)]
pub struct AuthorizedRequestFacts {
    request: AuthorizationRequest,
    granted: GrantAttribution,
}

impl AuthorizedRequestFacts {
    /// Only [`super::decide::authorize`] constructs one, and only from an evaluator's `Ok`.
    pub(super) fn new(request: AuthorizationRequest, granted: GrantAttribution) -> Self {
        AuthorizedRequestFacts { request, granted }
    }

    /// The verified facts the decision was taken over — who, what, and under which
    /// prerequisites.
    pub fn request(&self) -> &AuthorizationRequest {
        &self.request
    }

    /// The policy authority and version that permitted it.
    pub fn granted(&self) -> &GrantAttribution {
        &self.granted
    }

    /// What an audit record may say about this authorization (ADR-MCPRE-066 Slice 1).
    ///
    /// A NAMED projection, produced by the owner from its own private representation. The
    /// composition root never destructures these facts and never re-derives one: R-COMPOSE
    /// is satisfied by there being exactly one call, not by the caller being careful.
    pub fn audit_attribution(&self) -> AuthorizationAttribution {
        AuthorizationAttribution {
            authority: self.granted.authority().to_owned(),
            version: self.granted.version().to_owned(),
            action: self.request.action().clone(),
            attributable_to: self.request.evidence().clone(),
        }
    }
}

/// What this deployment claims about a request's permission.
#[derive(Debug, Clone)]
pub enum AuthorizationPosture {
    /// No authorization policy is deployed. This boundary claims NOTHING about permission —
    /// not that the request was permitted, and not that it was examined.
    NoPolicyConfigured,
    /// A policy evaluated the verified facts and permitted this action. Boxed so the
    /// no-policy posture — the common one, and the one every request carries on an
    /// unauthorized deployment — does not pay for the facts it does not hold.
    Authorized(Box<AuthorizedRequestFacts>),
}

impl AuthorizationPosture {
    /// The facts a policy permitted, or `None` where no policy is deployed.
    ///
    /// Named for what it returns rather than as an `is_authorized` predicate: a caller that
    /// only asks *yes or no* has already flattened the distinction this type exists to keep.
    pub fn authorized(&self) -> Option<&AuthorizedRequestFacts> {
        match self {
            AuthorizationPosture::NoPolicyConfigured => None,
            AuthorizationPosture::Authorized(facts) => Some(facts),
        }
    }

    /// What an audit record may say about this posture (ADR-MCPRE-066 Slice 1).
    ///
    /// The projection is total and keeps the postures apart, which is the point: nothing on
    /// the record path can turn *no policy is deployed* into *a policy permitted this*
    /// (ADR-MCPRE-066 §1.1). A refusal is not reachable from here — it is the `Err` half of
    /// the operation that produces this type, and projects itself.
    pub fn audit_facet(&self) -> AuthorizationFacet {
        match self {
            AuthorizationPosture::NoPolicyConfigured => AuthorizationFacet::NotConfigured,
            AuthorizationPosture::Authorized(facts) => {
                AuthorizationFacet::Authorized(facts.audit_attribution())
            }
        }
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::AuthorizationPosture;
    use crate::authorization::audit::AuthorizationFacet;

    #[test]
    fn an_unconfigured_deployment_does_not_report_an_authorization() {
        // `Off` is not `Allow`. The projection answers "which policy permitted this" with
        // nothing, because none did.
        assert!(AuthorizationPosture::NoPolicyConfigured
            .authorized()
            .is_none());
    }

    #[test]
    fn the_audit_projection_keeps_off_and_allow_apart() {
        // The same distinction one layer down. If this ever yields `Authorized`, every
        // record an unauthorized deployment writes claims a permission nobody granted.
        assert_eq!(
            AuthorizationPosture::NoPolicyConfigured.audit_facet(),
            AuthorizationFacet::NotConfigured
        );
    }
}
