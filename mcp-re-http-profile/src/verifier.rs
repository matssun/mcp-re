// SPDX-License-Identifier: Apache-2.0
//! The verification facade — one policy authority, and no `_with_policy` shadow API.
//!
//! Verifier-local policy is CONFIGURATION, not an assurance axis. It used to be both: every
//! operation existed twice, once at [`VerifierPolicy::default`] and once taking a policy,
//! so the public surface doubled to express a default argument. Assurance axes belong in
//! the product types ([`crate::verified_request`], [`crate::verified_response`]); this type
//! holds the configuration once and the operations name the proposition they establish.
//!
//! A method name may still say `bound` — the architectural requirement is that the
//! distinction SHALL NOT exist *only* there, and it does not: each operation returns a
//! different product.
//!
//! One authority means one copy. [`crate::verify::DelegationExpectations`] no longer
//! carries a `VerifierPolicy` of its own; the response-signature policy is this verifier's,
//! and what the delegation record still owns is the CREDENTIAL's own window and scope,
//! which is a different fact.

use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::error::HttpProfileError;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::VerifierPolicy;
use crate::verified_request::CryptographicFloorVerifiedRequest;
use crate::verified_request::VerifiedMcpRequest;
use crate::verified_response::CryptographicFloorVerifiedBoundResponse;
use crate::verified_response::CryptographicFloorVerifiedUnboundResponse;
use crate::verified_response::VerifiedDelegatedMcpResponse;
use crate::verified_response::VerifiedDelegatedUnboundResponse;
use crate::verified_response::VerifiedMcpResponse;
use crate::verify;
use crate::verify::DelegationExpectations;
use crate::ArtifactBinding;
use crate::AudienceTuple;

/// Verifier-local configuration plus the trust seam, applied to every operation below.
pub struct Verifier<'a, R> {
    policy: &'a VerifierPolicy,
    resolve_actor: &'a dyn Fn(&str, SignerSlot) -> R,
}

impl<'a, R: Into<ResolverOutcome>> Verifier<'a, R> {
    /// A caller that wants the profile defaults passes [`VerifierPolicy::default`]
    /// explicitly — one argument, rather than a second name for every operation.
    ///
    /// The policy is BORROWED. The serving path builds a verifier per request, and a
    /// policy that had to be cloned there would put an allocation on the hot path to
    /// express configuration that never changes.
    pub fn new(
        policy: &'a VerifierPolicy,
        resolve_actor: &'a dyn Fn(&str, SignerSlot) -> R,
    ) -> Self {
        Verifier {
            policy,
            resolve_actor,
        }
    }

    /// The configured policy, for a caller that must state what it verified under.
    pub fn policy(&self) -> &VerifierPolicy {
        self.policy
    }

    /// The trust seam, for the crate's own operations that resolve a slot directly.
    pub(crate) fn resolve_actor(&self) -> &'a dyn Fn(&str, SignerSlot) -> R {
        self.resolve_actor
    }

    /// Establish the request's cryptographic floor only.
    pub fn verify_request_floor(
        &self,
        request: &HttpRequest,
        now: i64,
    ) -> Result<CryptographicFloorVerifiedRequest, HttpProfileError> {
        verify::floor_request(request, self.resolve_actor, self.policy, now)
    }

    /// Establish the full MCP-RE profile for a request: the floor, plus audience equality
    /// and strict artifact binding.
    pub fn verify_request(
        &self,
        request: &HttpRequest,
        expected_audience: &AudienceTuple,
        artifact_material: &dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
        now: i64,
    ) -> Result<VerifiedMcpRequest, HttpProfileError> {
        verify::full_request(
            request,
            expected_audience,
            artifact_material,
            self.resolve_actor,
            self.policy,
            now,
        )
    }

    /// Establish a response's cryptographic floor, bound by `;req` to `request`.
    pub fn verify_bound_response_floor(
        &self,
        response: &HttpResponse,
        request: &HttpRequest,
        now: i64,
    ) -> Result<CryptographicFloorVerifiedBoundResponse, HttpProfileError> {
        verify::floor_bound_response(response, request, self.resolve_actor, self.policy, now)
    }

    /// Establish the full MCP-RE profile for a response bound to `request`.
    ///
    /// The expected request-evidence handle is DERIVED from `request`, not supplied beside
    /// it. It used to be a second operand, and a caller could hand in one exchange's
    /// request with another's handle: verification then established cryptographic binding
    /// to the first and semantic equality with the second, and nothing relating them. Both
    /// callers did relate them — a server passing the handle of the request it had just
    /// verified, a client the handle it retained from signing — but that is a convention
    /// held at call sites, and a third one would not have turned anything red.
    pub fn verify_bound_response(
        &self,
        response: &HttpResponse,
        request: &HttpRequest,
        now: i64,
    ) -> Result<VerifiedMcpResponse, HttpProfileError> {
        verify::full_bound_response(response, request, self.resolve_actor, self.policy, now)
    }

    /// Establish a response's cryptographic floor with NO request context. A `;req`
    /// component is malformed here — there is no request to resolve it against.
    pub fn verify_unbound_response_floor(
        &self,
        response: &HttpResponse,
        now: i64,
    ) -> Result<CryptographicFloorVerifiedUnboundResponse, HttpProfileError> {
        verify::floor_unbound_response(response, self.resolve_actor, self.policy, now)
    }

    /// Verify a delegated-key-signed response bound to `request` (ADR-MCPRE-052 §3).
    /// Delegation is REQUIRED: a response carrying no inline credential — including a
    /// directly root-signed one — is refused.
    ///
    /// As with [`Self::verify_bound_response`], the request-evidence handle is derived
    /// from `request` rather than accepted beside it.
    pub fn verify_delegated_bound_response(
        &self,
        response: &HttpResponse,
        request: &HttpRequest,
        expect: &DelegationExpectations<'_>,
        is_revoked: &dyn Fn(&str) -> bool,
        now: i64,
    ) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
        verify::delegated_bound_response(
            response,
            request,
            self.resolve_actor,
            self.policy,
            expect,
            is_revoked,
            now,
        )
    }

    /// Verify a delegated-key-signed response with NO request binding — the preflight and
    /// pre-parse rejection case. The block's `request_evidence` is diagnostic here and is
    /// not carried into the product.
    pub fn verify_delegated_unbound_response(
        &self,
        response: &HttpResponse,
        expect: &DelegationExpectations<'_>,
        is_revoked: &dyn Fn(&str) -> bool,
        now: i64,
    ) -> Result<VerifiedDelegatedUnboundResponse, HttpProfileError> {
        verify::delegated_unbound_response(
            response,
            self.resolve_actor,
            self.policy,
            expect,
            is_revoked,
            now,
        )
    }
}
