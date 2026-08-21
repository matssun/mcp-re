// SPDX-License-Identifier: Apache-2.0
//! Which delegated response product a verification produced.
//!
//! One main type per file: this value answers exactly one question — is the verified
//! delegated response bound to the request this client sent, or is it a receipt with no
//! request context at all?

use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::VerifiedDelegatedMcpResponse;
use mcp_re_http_profile::VerifiedDelegatedUnboundResponse;

/// The delegated evidence, in the shape that says whether it is bound to this request.
///
/// This replaces a `bound: bool` that sat beside the evidence: boundness was represented
/// twice, once by the flag and once by which verification path had produced the value, and
/// nothing related them. Here the type IS the answer.
#[derive(Debug, Clone)]
pub enum DelegatedResponseEvidence {
    /// Verified against the request this client sent, including its evidence handle.
    Bound(VerifiedDelegatedMcpResponse),
    /// Verified with no request context — a preflight or pre-parse rejection receipt.
    Unbound(VerifiedDelegatedUnboundResponse),
}

impl DelegatedResponseEvidence {
    /// Whether this evidence is bound to the request the client sent.
    ///
    /// A descriptive read for callers that report the shape onward. It is derived from the
    /// evidence rather than stored beside it, so the two cannot disagree.
    pub fn is_bound(&self) -> bool {
        matches!(self, DelegatedResponseEvidence::Bound(_))
    }

    /// The signer the response signature was accepted under — the DELEGATED key on both
    /// shapes.
    ///
    /// Not a `ResolvedActor`: nothing resolved this key through the trust seam. The seam
    /// answered for the ROOT issuer ([`Self::delegation_issuer_kid`]) and the credential
    /// chain authorized the key that actually signed.
    pub fn accepted_signer(&self) -> &mcp_re_http_profile::AcceptedResponseSigner {
        match self {
            DelegatedResponseEvidence::Bound(v) => &v.signature_facts.accepted_signer,
            DelegatedResponseEvidence::Unbound(v) => &v.signature_facts.accepted_signer,
        }
    }

    /// The response signature-base handle — the answer leg of an MRT exchange binds to it.
    pub fn response_signature_base_digest(&self) -> &mcp_re_http_profile::RequestEvidence {
        match self {
            DelegatedResponseEvidence::Bound(v) => {
                &v.signature_facts.response_signature_base_digest
            }
            DelegatedResponseEvidence::Unbound(v) => {
                &v.signature_facts.response_signature_base_digest
            }
        }
    }

    /// The server signer identity the block declared — available on both shapes.
    ///
    /// On both, the block's `server_signer` IS the accepted signer's identity: the
    /// delegated path checks the block's keyid against the credential's delegated kid
    /// before accepting the signature, so there is one identity here, not two.
    pub fn server_signer(&self) -> &ActorIdentity {
        &self.accepted_signer().identity
    }

    /// The ROOT issuer kid the credential chained to, available on both shapes.
    pub fn delegation_issuer_kid(&self) -> &str {
        match self {
            DelegatedResponseEvidence::Bound(v) => &v.delegation_issuer_kid,
            DelegatedResponseEvidence::Unbound(v) => &v.delegation_issuer_kid,
        }
    }
}
