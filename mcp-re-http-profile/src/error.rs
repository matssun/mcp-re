// SPDX-License-Identifier: Apache-2.0
//! Fail-closed error taxonomy for the HTTP profile.
//!
//! This file owns the TAXONOMY: what can go wrong in the HTTP profile, and what each
//! failure means. What each failure means *in Core's terms* is a second fact with a
//! second owner, and it lives in [`core_projection`] — an exhaustive
//! `From<&HttpProfileError> for McpReError` from which `wire_code` is derived.
//!
//! No parallel namespace (v0.11 grill E-11): every `wire_code()` is a token of the frozen
//! `mcp_re_core::McpReError` taxonomy. That is no longer a rule a test rechecks over two
//! agreeing string tables — the carrier states which Core verdict each failure IS, and the
//! token follows from it. The mapping was ratified by owner ruling 2026-07-07 (MCPRE-92),
//! which added five security-grouped codes to the frozen taxonomy for the signed-rejection
//! surface — `malformed_envelope`, `digest_mismatch`, `artifact_binding_failed`,
//! `request_binding_mismatch`, `continuation_binding_failed` — so the HTTP profile no
//! longer folds distinct failures onto coarser draft-01/02 tokens.

/// A fail-closed HTTP-profile verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProfileError {
    /// A required header or signature member is entirely absent — there is no
    /// evidence to parse. Maps to `mcp-re.missing_envelope`.
    MissingEvidence(&'static str),
    /// Evidence is present but structurally invalid against the profile's
    /// closed grammar (an unparseable `Signature-Input` member, a foreign
    /// covered component or parameter, a wrong-shaped digest member). Distinct
    /// from [`HttpProfileError::MissingEvidence`]; maps to
    /// `mcp-re.malformed_envelope` (MCPRE-92).
    MalformedEvidence(&'static str),
    /// A header that MUST appear exactly once appears more than once.
    DuplicateHeader(&'static str),
    /// `Content-Encoding` present on a signed MCP message (forbidden — the
    /// profile signs unencoded content bytes; v0.11 grill B.1).
    ContentEncodingPresent,
    /// The covered `Content-Type` on a covered exchange is not
    /// `application/json` — most consequentially, a `text/event-stream` response
    /// (#415 rev 2 §3.4: covered exchanges are JSON-mode only; per-event SSE
    /// evidence is deferred to a future companion profile). Same content-model
    /// family as [`HttpProfileError::ContentEncodingPresent`], so it maps to the
    /// same frozen `mcp-re.serialization_failed` token — the protected message is
    /// not in the value domain the profile can make statements about.
    NonJsonMediaType,
    /// The message content does not match the signed `Content-Digest`.
    ContentDigestMismatch,
    /// A covered component required by the profile is not covered.
    MissingCoveredComponent(&'static str),
    /// The signature parameters carry an unknown/foreign profile tag.
    UnknownProfileTag,
    /// The signature algorithm is not the profile's `ed25519`.
    UnsupportedAlgorithm,
    /// The Ed25519 signature does not verify over the reconstructed base.
    InvalidSignature,
    /// The `created`/`expires` window is stale, future-dated, or degenerate.
    StaleWindow,
    /// The `keyid` does not resolve to a trusted verification key.
    UnresolvedKeyId,
    /// The trust resolver could not ANSWER — a transient/operational failure such as
    /// an unreachable backing store (C079). Distinct from [`UnresolvedKeyId`], which
    /// is a definitive negative from a healthy resolver: a store outage and an unknown
    /// keyid are different facts, and collapsing them told an operator "untrusted key"
    /// during an outage. Never falls back to allow. Wire code
    /// `mcp-re.trust_resolver_unavailable`.
    TrustResolverUnavailable,
    /// Defense-in-depth (MCPRE-100): the trust seam returned a [`ResolvedActor`]
    /// whose vouched slot does not match the slot the verifier requested — a
    /// misbehaving resolver caught by the verifier's typed cross-check. Public
    /// wire code is `mcp-re.actor_binding_failed`, identical to an unresolved
    /// keyid; the distinct variant is internal/test-only diagnosis.
    ///
    /// [`ResolvedActor`]: crate::block::ResolvedActor
    ActorSlotMismatch,
    /// An `artifact_bindings[]` proof (DPoP `ath`, mTLS `x5t#S256`, RAR
    /// authorization-details digest) does not bind to the covered credential
    /// surface (MCPRE-95), or full-profile enforcement could not obtain the
    /// credential material for a present binding (MCPRE-101 strict rule). Maps to
    /// `mcp-re.artifact_binding_failed`.
    ArtifactBindingFailed,
    /// The full-profile request body block's `audience` does not match the
    /// verifier's expected audience tuple, or the tuple's target URI is
    /// inconsistent with the request `@target-uri` (MCPRE-101). Maps to
    /// `mcp-re.invalid_audience`.
    AudienceMismatch,
    /// Response evidence does not bind to the expected request (`;req`
    /// component mismatch or `request_evidence` mismatch) — a splice. Maps to
    /// `mcp-re.request_binding_mismatch` (MCPRE-92).
    ResponseBindingMismatch,
    /// The response signature does not verify.
    ResponseSignatureInvalid,
    /// An MRTR continuation handle does not match its mandated signature-base
    /// digest (MCPRE-97). Maps to `mcp-re.continuation_binding_failed`.
    ContinuationBindingFailed,
    /// A verified `result` declares a `resultType` this reader does not recognize
    /// (MCPRE-495). MCP 2026-07-28 closes the set: unrecognized MUST be considered
    /// invalid. Reading it as terminal instead would end an exchange whose
    /// continuation semantics are unknown, so it fails closed — the same posture
    /// [`McpReError::ContinuationTypeUnsupported`] takes for an unrecognized
    /// continuation `type`, and it maps to that same frozen token.
    ///
    /// [`McpReError::ContinuationTypeUnsupported`]: mcp_re_core::McpReError::ContinuationTypeUnsupported
    UnrecognizedResultType,
    /// The UPSTREAM (inner) server's reply is not a legal JSON-RPC 2.0 / MCP response
    /// to the request it answers (ADR-MCPRE-058 §10, ruling D5). The `&'static str`
    /// names the clause violated, for the operator debugging the backend.
    ///
    /// Deliberately NOT folded onto [`HttpProfileError::MalformedEvidence`]: that names
    /// the CALLER's evidence being structurally invalid, and an operator reading its
    /// token goes and looks at the client. This says the backend answered badly.
    UpstreamResponseInvalid(&'static str),
    /// The covered `Mcp-Method` transport header disagrees with the JSON-RPC
    /// `method` in the covered body (#415 rev 2 §4.1, MCPRE-425). Both are
    /// protected, so this is the signer stating two different methods — evidence
    /// that is present, self-contradictory, and therefore not interpretable.
    /// Maps to `mcp-re.malformed_envelope`.
    McpMethodDivergence,
    /// A transport header the deployment's MCP protocol version REQUIRES on every
    /// POST is absent (#415 rev 2 §4.1, MCPRE-425): the named `mcp-*` header is
    /// mandatory under the active [`McpTransportPolicy`] and the request omitted
    /// it. Maps to `mcp-re.missing_envelope`.
    ///
    /// [`McpTransportPolicy`]: crate::mcp_transport::McpTransportPolicy
    McpTransportHeaderMissing(&'static str),
    /// The `MCP-Protocol-Version` header names a version outside the deployment's
    /// accepted set (§4.1). Registration or a client's claim is not consent; the
    /// verifier's supported set is. Maps to `mcp-re.unsupported_version`.
    McpProtocolVersionUnsupported,
    /// A covered transport header (`MCP-Protocol-Version` or `Mcp-Name`) disagrees
    /// with the covered body it must match — the signer contradicting itself, as
    /// with [`HttpProfileError::McpMethodDivergence`]. Names the header. Maps to
    /// `mcp-re.malformed_envelope`.
    McpTransportDivergence(&'static str),

    // Admission assertion + §7 binding (Layer 1 → Layer 4, MCPRE-433).
    /// The admission assertion is malformed, has the wrong `typ`/`alg`, an
    /// inconsistent `kid`, a bad root signature, or a profile/audience mismatch.
    /// Maps to `mcp-re.actor_binding_failed` — the workload's admission identity
    /// did not authenticate.
    AdmissionAssertionInvalid,
    /// The admission assertion's `issuer_kid` is not a trusted admission authority.
    /// Maps to `mcp-re.actor_binding_failed`.
    AdmissionIssuerUntrusted,
    /// The admission assertion is outside its `[nbf, exp]` window or older than the
    /// declared freshness budget N. Maps to `mcp-re.expired_request`.
    AdmissionAssertionExpired,
    /// The call's admission binding does not describe the presented assertion
    /// (wrong id/generation, or it commits to a different admitted state). Maps to
    /// `mcp-re.request_binding_mismatch`.
    AdmissionBindingMismatch,
    /// The bound admission generation is not the authoritative current one, or the
    /// workload's status is not `Admitted` — a call from a superseded or
    /// revoked/suspended admission (§7 currency). Maps to
    /// `mcp-re.actor_binding_failed`.
    AdmissionNotCurrent,
    /// The authoritative admission state was unreachable and degraded mode was
    /// disabled or its bound exhausted — fail closed. Maps to
    /// `mcp-re.actor_binding_failed`.
    AdmissionStateUnavailable,

    // SCITT audit receipts (Layer 5, MCPRE-434).
    /// A receipt's Signed Statement or tree-head signature does not verify. Maps to
    /// `mcp-re.invalid_signature`.
    ReceiptInvalid,
    /// The receipt's inclusion proof does not re-derive the signed root. Maps to
    /// `mcp-re.request_binding_mismatch` — the statement is not bound into the log
    /// the receipt claims.
    ReceiptInclusionInvalid,
    /// The Signed Statement issuer or transparency service key is not trusted. Maps
    /// to `mcp-re.actor_binding_failed`.
    ReceiptIssuerUntrusted,
    /// The pinned transparency service issues position-bound receipts, and this one
    /// carries no position commitment. Refused rather than verified under the weaker
    /// contract: falling back on request would let an attacker strip the parameter.
    /// Maps to `mcp-re.request_binding_mismatch`.
    ReceiptPositionUnbound,
    /// The receipt's protected position commitment does not match the
    /// `(profile, log identity, vds, tree_size, leaf_index, root)` tuple it presents —
    /// the signature-covered position and the stated one disagree, which is a receipt
    /// restated at a position its issuer did not sign. Maps to
    /// `mcp-re.request_binding_mismatch`.
    ReceiptPositionMismatch,

    // Delegated signing-key attestation (ADR-MCPRE-052 §8, MCPRE-122). Each maps
    // to its precise frozen `mcp-re.delegation_*` token.
    /// A delegated-key response carried no valid delegation credential (in
    /// required mode, a directly root-signed response also lands here).
    DelegationCredentialMissing,
    /// The JWS is malformed, `alg` ≠ `EdDSA`, `kid` ≠ `issuer_kid`, `cnf` is
    /// self-inconsistent, or the root signature does not verify.
    DelegationCredentialInvalid,
    /// `now` is outside the credential's `[nbf, exp]` window (+ skew).
    DelegationCredentialExpired,
    /// The credential's `issuer_kid` is not a trusted root anchor.
    DelegationIssuerUntrusted,
    /// `mcp_re_profile` is not the active HTTP profile id.
    DelegationProfileMismatch,
    /// The verifier is not named in `aud`, or the audience-scope / server-signer
    /// binding does not match — a credential lifted outside its scope.
    DelegationAudienceMismatch,
    /// `mcp_re_key_use` does not permit this signature use.
    DelegationKeyUseInvalid,
    /// The credential's `trust_epoch` is not in the verifier's accepted set.
    DelegationTrustEpochStale,
    /// The RFC 9421 response `keyid` ≠ `delegated_kid`, or the response signature
    /// does not verify under `cnf.jwk`.
    DelegationKeyMismatch,
    /// `delegated_kid` or `issuer_kid` is revoked at the current trust epoch.
    DelegationRevoked,
}

mod core_projection;

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::HttpProfileError;

    /// What this file owns is the taxonomy, and the taxonomy's job is to keep failures
    /// that mean different things apart. MCPRE-92 separated omission from tampering
    /// precisely so a rejection could say which happened; they are distinct values here
    /// before anything projects them.
    #[test]
    fn omission_and_tampering_are_different_failures() {
        assert_ne!(
            HttpProfileError::MissingEvidence("signature"),
            HttpProfileError::MalformedEvidence("signature")
        );
    }

    /// A context-carrying variant is distinguished BY its context: two missing components
    /// are two different facts about the request, not one repeated.
    #[test]
    fn a_context_carrying_failure_names_what_was_missing() {
        assert_ne!(
            HttpProfileError::MissingCoveredComponent("@method"),
            HttpProfileError::MissingCoveredComponent("content-digest")
        );
    }

    /// A store outage is not a verdict about the caller's key. The taxonomy keeps them as
    /// separate variants; collapsing them once told an operator "untrusted key" during an
    /// outage.
    #[test]
    fn an_outage_is_not_an_untrusted_key() {
        assert_ne!(
            HttpProfileError::TrustResolverUnavailable,
            HttpProfileError::UnresolvedKeyId
        );
    }
}
