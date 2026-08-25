// SPDX-License-Identifier: Apache-2.0
//! The gate between a decision and the backend — ADR-MCPRE-065 Slice 1.
//!
//! # Why this type exists
//!
//! "Dispatch only from an authorized request" is a sentence, and a sentence in a comment is
//! what the ADR-MCPRE-057 request machine was built to stop being the enforcement. Here the
//! enforcement is a type: the inner dispatch consumes a body it can obtain from exactly one
//! place — [`AuthorizationPosture::release`] — so a serving path that skipped the decision
//! has nothing to hand it.
//!
//! Deleting the authorization stage does not produce a subtly weaker proxy that still
//! compiles. It produces a compile error at the dispatch.
//!
//! # What it does NOT claim
//!
//! Not that a policy permitted the request. `NoPolicyConfigured` releases a body too,
//! because a deployment with no policy is entitled to serve — it simply claims nothing
//! while doing so. What possession proves is that the decision was TAKEN, which is the fact
//! the ordering is about; the CONTENT of the decision stays in the posture.

use super::posture::AuthorizationPosture;

/// A backend-bound body that an authorization decision released.
///
/// Sealed: the representation and the constructor are private to this module, and the only
/// producer is [`AuthorizationPosture::release`]. Nothing else in the crate can make one.
pub(crate) struct AuthorizedRequestBody {
    body: Vec<u8>,
}

impl AuthorizedRequestBody {
    /// The bytes to send, borrowed — the dispatch does not consume the body, because what
    /// survives it is the obligation, not the request.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.body
    }
}

impl AuthorizationPosture {
    /// Release `body` for dispatch under this decision.
    ///
    /// Consuming. One decision releases one body, so a path cannot take a single decision
    /// and dispatch twice under it, and cannot hold a posture and the body it released at
    /// the same time.
    pub(crate) fn release(self, body: Vec<u8>) -> AuthorizedRequestBody {
        AuthorizedRequestBody { body }
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::AuthorizationPosture;

    #[test]
    fn an_unconfigured_deployment_still_releases_a_body() {
        // The gate is about the DECISION having been taken, not about a policy having
        // permitted. A proxy with no policy serves, and claims nothing while doing so.
        let released = AuthorizationPosture::NoPolicyConfigured.release(b"body".to_vec());
        assert_eq!(released.bytes(), b"body");
    }
}
