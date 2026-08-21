// SPDX-License-Identifier: Apache-2.0
//! The response verification products — the response half of ADR-MCPRE-061 §2 class 9.
//!
//! One `VerifiedHttpResponseEvidence` used to answer four materially different
//! verification paths, with `bound_request_evidence`, `body_request_evidence`,
//! `server_signer` and `delegation_issuer_kid` documented `None` "on the seam-only path".
//! Holding it told a consumer nothing about which proposition had been established.
//!
//! These are the legal products, and only the legal ones — there is deliberately no
//! Cartesian product of floor × bound × delegated:
//!
//! | product | what possession means |
//! |---|---|
//! | [`CryptographicFloorVerifiedBoundResponse`] | digest, signature and `;req` binding to a concrete request |
//! | [`CryptographicFloorVerifiedUnboundResponse`] | digest and signature, with **no** request context and `;req` forbidden |
//! | [`VerifiedMcpResponse`] | the bound floor, plus the response block bound to the expected request evidence |
//! | [`VerifiedDelegatedMcpResponse`] | a full bound response whose signer was authorized by a verified delegation chain |
//! | [`VerifiedDelegatedUnboundResponse`] | a delegated preflight/rejection response, explicitly without request binding |
//!
//! **Bound and unbound are different propositions, not an API convenience.** A bound
//! response verifies `;req` against a concrete request and compares the block's
//! `request_evidence` with the handle the caller expects. The unbound path has no
//! trustworthy request context: it forbids `;req` outright, and the block's
//! `request_evidence` is diagnostic rather than authoritative. Returning one type for both
//! would put the consumer back to inspecting a value to discover what happened.
//!
//! Fields are `pub` for the reason recorded in `docs/dev/sealed-owners.md`: a proved
//! postcondition outranks a seal, and Verus rejects private fields on a transparent
//! datatype. The assurance separation is carried by the types, which needs no seal.

use crate::block::ActorIdentity;
use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolvedActor;
use crate::RequestEvidence;

/// A response whose cryptographic floor holds **and which is bound to a concrete request**.
///
/// Possession means: the covered `Content-Digest` agreed, the RFC 9421 signature verified
/// under an allowed algorithm over a base that includes the `;req` components of that
/// request, and the presented keyid resolved through the trust seam in the `Response` slot.
///
/// It does **not** mean the response evidence block was read, and it does not mean the
/// block agrees with the request. That is [`VerifiedMcpResponse`].
#[derive(Debug, Clone)]
pub struct CryptographicFloorVerifiedBoundResponse {
    /// The resolved server/response signer — identity, key, and `Response` slot.
    pub resolved_server_actor: ResolvedActor,
    /// The response signature-base handle, under the response role label.
    pub response_signature_base_digest: RequestEvidence,
}

/// A response whose cryptographic floor holds **with no request context at all**.
///
/// The rejection-before-parse case: a signature covering only response components. A `;req`
/// component here is malformed, because there is no request to resolve it against.
///
/// This is a genuinely different proposition from
/// [`CryptographicFloorVerifiedBoundResponse`], not the same one with a field missing —
/// which is why it is a different type rather than an `Option`.
#[derive(Debug, Clone)]
pub struct CryptographicFloorVerifiedUnboundResponse {
    /// The resolved server/response signer — identity, key, and `Response` slot.
    pub resolved_server_actor: ResolvedActor,
    /// The response signature-base handle, under the response role label.
    pub response_signature_base_digest: RequestEvidence,
}

/// A response verified under the **full MCP-RE profile and bound to a request**.
///
/// Possession means everything [`CryptographicFloorVerifiedBoundResponse`] means, and in
/// addition that the response evidence block parsed and validated, that its `server_signer`
/// is the identity the signature was actually accepted under, and that its
/// `request_evidence` equals the handle the caller expected.
///
/// The expected handle is an INPUT, not a second assurance axis. A server passes
/// `verified_request.evidence()`; a client passes the handle it kept from signing. Where
/// it came from is the caller's business and does not change what this product proves.
///
/// A cryptographic floor is not a full profile, and no consumer can accept one for the
/// other by accident:
///
/// ```compile_fail
/// use mcp_re_http_profile::{CryptographicFloorVerifiedBoundResponse, VerifiedMcpResponse};
/// fn needs_full(_: &VerifiedMcpResponse) {}
/// fn from_floor(floor: &CryptographicFloorVerifiedBoundResponse) {
///     needs_full(floor);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedMcpResponse {
    /// The bound floor proposition this product also establishes.
    pub floor: CryptographicFloorVerifiedBoundResponse,
    /// The request evidence handle this response was required to bind to.
    pub bound_request_evidence: RequestEvidence,
    /// The handle the response block carried, compared equal to
    /// [`Self::bound_request_evidence`]. Both are retained because an audit record wants
    /// the received value, not only the verdict that it matched.
    pub body_request_evidence: RequestEvidence,
    /// The `server_signer` identity the block declared, verified against the keyid the
    /// signature was accepted under.
    pub server_signer: ActorIdentity,
}

/// A full bound response whose signer was authorized by a **verified delegation chain**
/// rather than by a trust-store entry (ADR-MCPRE-052 §3).
///
/// `delegation-required` is the only response-signing mode, so this is the product the
/// serving path actually produces. The issuer kid is present unconditionally: a product
/// that proves a delegation chain is not the same product with `Some`.
///
/// An unbound receipt cannot stand in for a request-bound answer. It is not a weaker
/// value of the same type — it is a different type, and the compiler says so:
///
/// ```compile_fail
/// use mcp_re_http_profile::{VerifiedDelegatedMcpResponse, VerifiedDelegatedUnboundResponse};
/// fn needs_bound(_: &VerifiedDelegatedMcpResponse) {}
/// fn from_unbound(receipt: &VerifiedDelegatedUnboundResponse) {
///     needs_bound(receipt);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedMcpResponse {
    /// The full bound MCP proposition. Its `resolved_server_actor` carries the DELEGATED
    /// key and the block's identity, vouched for the `Response` slot through the chain
    /// rather than by a direct trust-store lookup of the signing key.
    pub response: VerifiedMcpResponse,
    /// The ROOT issuer kid the credential chained to — the stable server-identity
    /// coordinate under ADR-MCPRE-052, since the delegated kid rotates every TTL.
    pub delegation_issuer_kid: String,
}

/// A delegated preflight or rejection response, verified **explicitly without request
/// binding** (MCPRE-122).
///
/// The credential chain and the response signature under `cnf.jwk` are verified exactly as
/// in the bound case, but the signature covers only response components and no
/// request-evidence comparison is made — no trustworthy request context exists. The
/// block's `request_evidence`, if any, is diagnostic and is **not** carried here, because
/// carrying it would invite a consumer to treat it as a binding.
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedUnboundResponse {
    /// The unbound floor proposition, with the credential-authorized signer.
    pub floor: CryptographicFloorVerifiedUnboundResponse,
    /// The `server_signer` identity the block declared, verified against the delegated kid.
    pub server_signer: ActorIdentity,
    /// The ROOT issuer kid the credential chained to.
    pub delegation_issuer_kid: String,
}

impl VerifiedMcpResponse {
    /// Assemble from the floor product and the block facts the full path established.
    ///
    /// `pub(crate)` because `verify` is the only legitimate producer inside this crate and
    /// no crate outside it should assemble a verdict; the fields above are `pub` for the
    /// prover's sake, so this is a convenience, not a seal.
    pub(crate) fn from_block(
        floor: CryptographicFloorVerifiedBoundResponse,
        bound_request_evidence: RequestEvidence,
        block: &HttpResponseEvidenceBlock,
    ) -> Self {
        VerifiedMcpResponse {
            floor,
            bound_request_evidence,
            body_request_evidence: RequestEvidence {
                digest_alg: block.request_evidence.digest_alg.clone(),
                digest_value: block.request_evidence.digest_value.clone(),
            },
            server_signer: block.server_signer.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::SignerSlot;
    use mcp_re_core::SigningKey;

    fn actor(keyid: &str) -> ResolvedActor {
        ResolvedActor {
            identity: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: keyid.into(),
            },
            verification_key: SigningKey::from_seed_bytes(&[9u8; 32]).public_key(),
            slot: SignerSlot::Response,
        }
    }

    fn bound_floor() -> CryptographicFloorVerifiedBoundResponse {
        CryptographicFloorVerifiedBoundResponse {
            resolved_server_actor: actor("resp-1"),
            response_signature_base_digest: RequestEvidence::from_response_signature_base(b"r"),
        }
    }

    #[test]
    fn a_bound_full_response_states_its_binding_without_an_option() {
        let expected = RequestEvidence::from_signature_base(b"req");
        let full = VerifiedMcpResponse {
            floor: bound_floor(),
            bound_request_evidence: expected.clone(),
            body_request_evidence: expected.clone(),
            server_signer: actor("resp-1").identity,
        };
        assert_eq!(full.bound_request_evidence, expected);
        assert_eq!(full.body_request_evidence, full.bound_request_evidence);
        assert_eq!(full.server_signer.keyid, "resp-1");
    }

    #[test]
    fn a_delegated_response_states_its_issuer_without_an_option() {
        let expected = RequestEvidence::from_signature_base(b"req");
        let delegated = VerifiedDelegatedMcpResponse {
            response: VerifiedMcpResponse {
                floor: bound_floor(),
                bound_request_evidence: expected.clone(),
                body_request_evidence: expected,
                server_signer: actor("resp-1").identity,
            },
            delegation_issuer_kid: "root-1".into(),
        };
        // The chain fact is not an `Option` that a consumer must interpret: the type is
        // reached only by a path that verified the chain.
        assert_eq!(delegated.delegation_issuer_kid, "root-1");
        assert_eq!(delegated.response.server_signer.keyid, "resp-1");
    }

    #[test]
    fn the_unbound_products_carry_no_request_binding_to_misread() {
        let unbound = VerifiedDelegatedUnboundResponse {
            floor: CryptographicFloorVerifiedUnboundResponse {
                resolved_server_actor: actor("resp-2"),
                response_signature_base_digest: RequestEvidence::from_response_signature_base(b"r"),
            },
            server_signer: actor("resp-2").identity,
            delegation_issuer_kid: "root-1".into(),
        };
        // There is no field here that a consumer could mistake for a request binding —
        // which is the point of the unbound product being its own type.
        assert_eq!(
            unbound.floor.resolved_server_actor.slot,
            SignerSlot::Response
        );
        assert_eq!(unbound.server_signer.keyid, "resp-2");
    }
}
