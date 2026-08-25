// SPDX-License-Identifier: Apache-2.0
//! Test-only construction of a verified request whose signature covers a given body.
//!
//! Kept out of the production tree by `#[cfg(test)]` on the `mod` declaration: nothing here
//! may be reachable from a serving path, because everything here fabricates evidence.
//!
//! It exists because the authority under test refuses a body that is not the signed one,
//! and a control for that refusal needs a request whose digest genuinely matches — a
//! hand-written digest string would make every control pass for the wrong reason.

use mcp_re_http_profile::content_digest_sha256;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::CryptographicFloorVerifiedRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedMcpRequest;

/// The audience every harness request is verified for.
fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "aud".into(),
        target_uri: "https://example.test/mcp".into(),
        route: None,
    }
}

/// A verified request whose covered `Content-Digest` is the real digest of `body`.
pub(super) fn verified_over(body: &[u8]) -> VerifiedMcpRequest {
    verified_over_as(body, "did:example:agent-1", "key-a")
}

/// The same, with the resolved actor's subject and keyid chosen by the caller.
pub(super) fn verified_over_as(body: &[u8], subject: &str, keyid: &str) -> VerifiedMcpRequest {
    VerifiedMcpRequest {
        floor: CryptographicFloorVerifiedRequest {
            profile_id: "p".into(),
            signature_label: "mcpre".into(),
            resolved_actor: ResolvedActor {
                identity: ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.org".into(),
                    subject: subject.into(),
                    keyid: keyid.into(),
                },
                verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32]).public_key(),
                slot: SignerSlot::Request,
            },
            evidence: RequestEvidence::from_signature_base(b"base"),
            request_signature_base: b"base".to_vec(),
            content_digest: content_digest_sha256(body),
            created: 1,
            expires: 2,
            nonce: "n".into(),
            key_id: keyid.into(),
        },
        audience: audience(),
        audience_hash: audience().audience_hash(),
        request_block: HttpRequestEvidenceBlock {
            profile: "p".into(),
            audience: audience(),
            artifact_bindings: Vec::new(),
            continuation: None,
            admission: None,
            admission_assertion: None,
        },
    }
}
