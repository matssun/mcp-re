// SPDX-License-Identifier: Apache-2.0
//! Body evidence blocks for the HTTP profile (ADR-MCPRE-050 §Resolved-owner
//! ruling 1, MCPRE-93).
//!
//! No new HTTP header fields are minted (v0.11 grill E-3): all MCP-specific
//! evidence rides in the JSON-RPC body under a `_meta` key and is protected
//! because `content-digest` is a covered component of the RFC 9421 signature.
//! These are **semantic evidence** blocks — not a custom crypto envelope — and
//! carry **no raw secrets**: authorization artifacts appear only as digests or
//! references (`digest_alg`/`digest_value`, `reference_*`), never token bytes.
//!
//! Two identifiers are pinned here for the replay key (MCPRE-94) and audit:
//!
//! - [`ActorIdentity::actor_id`] — the canonical identity of the signing actor
//!   AFTER trust resolution, including role and trusted key identity (not a raw
//!   keyid alone). Serialized `role:trust_domain:subject:keyid` with each
//!   component escaped so the join is injective.
//! - [`AudienceTuple::audience_hash`] — SHA-256 over the canonical audience
//!   tuple bytes, not merely `@target-uri`, so replay prevention never merges
//!   different MCP audiences that share one HTTP endpoint.

use mcp_re_core::b64url_encode;
use mcp_re_core::VerificationKey;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

pub mod artifact_binding;

pub use artifact_binding::ArtifactBinding;
pub use artifact_binding::ArtifactType;
pub use artifact_binding::BindingType;

use crate::error::HttpProfileError;
use crate::evidence::labeled_digest_value;
use crate::ids::EVIDENCE_DIGEST_ALG;
use crate::ids::EVIDENCE_LABEL_REQUEST;
use crate::ids::EVIDENCE_LABEL_REQUEST_STATE;
use crate::ids::EVIDENCE_LABEL_RESPONSE;
use crate::ids::MAX_ADMISSION_ASSERTION_LEN;
use crate::pdp_decision::MAX_AUTHORIZATION_DECISION_LEN;
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

/// The resolved signing-actor identity. Built by the verifier from what the
/// TrustResolver returned for the presented keyid — role and trusted key
/// identity, never the raw keyid alone (MCPRE-93/94 pin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorIdentity {
    /// Trust role the resolver assigned (e.g. `host`, `server`, `client`).
    pub role: String,
    /// Trust domain the subject belongs to.
    pub trust_domain: String,
    /// Resolved subject identity (e.g. a DID or service id — may itself contain
    /// `:`, which is why components are escaped before joining).
    pub subject: String,
    /// The RFC 9421 keyid the signature was verified under.
    pub keyid: String,
}

impl ActorIdentity {
    /// The canonical, injective `actor_id` string used as a replay-key
    /// component. Each field is escaped (`%`→`%25`, `:`→`%3A`) before the
    /// `role:trust_domain:subject:keyid` join, so distinct identities never
    /// collapse to the same key even when a subject contains colons.
    // ADR-MCPRE-059 ASM-0021: opaque to the continuation theorem, with no `ensures`. The
    // replay key's injectivity is its own property and its own future unit; nothing in the
    // unbypassability theorem depends on what this string is.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    pub fn actor_id(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            field_escape(&self.role),
            field_escape(&self.trust_domain),
            field_escape(&self.subject),
            field_escape(&self.keyid),
        )
    }
}

/// Escape a single actor-id component so `:` joins stay unambiguous. `%` first
/// (so the escape is reversible), then `:`.
fn field_escape(s: &str) -> String {
    // `%` first (so its own escape is not re-escaped), then EVERY separator any
    // consumer of this string uses. `:` joins the actor-id fields here; U+001F joins
    // the HTTP replay-key components downstream, and leaving it unescaped meant the
    // injectivity that key's construction ASSERTS was not enforced — an actor id
    // containing U+001F could produce the same joined key as a different
    // (actor, audience, nonce) triple.
    s.replace('%', "%25")
        .replace(':', "%3A")
        .replace('\u{1F}', "%1F")
}

/// The signing slot a keyid is resolved FOR. Passed INTO the trust seam so
/// role authorization is a decision of trust resolution, never inferred from a
/// role string after the fact (MCPRE-100): a key may be cryptographically valid
/// yet not trusted to sign in this slot, and that must fail
/// `actor_binding_failed` exactly like an unknown keyid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerSlot {
    /// The client/request-signer slot — [`crate::verify_request`].
    Request,
    /// The server/response-signer slot — [`crate::verify_response`],
    /// `verify_response_unbound`, and signed rejections.
    Response,
}

/// Trust-resolution output for a presented keyid: the resolved actor identity,
/// its verification key, and the slot the trust layer vouched this actor for.
/// The seam returns this ONLY when the key is trusted for the requested slot; a
/// wrong-slot key resolves to `None`, indistinguishable at the public error
/// layer from an unknown keyid (`mcp-re.actor_binding_failed`).
///
/// `keyid` is NOT `actor_id`: `actor_id` (see [`ActorIdentity::actor_id`]) is
/// the trust-resolution output that replay keys, response/body-block validation,
/// and audit consume — a keyid alone never introduces trust.
///
/// Not `PartialEq`/`Eq`: `VerificationKey` is opaque key material with no value
/// equality. Compare `identity` (or `actor_id()`) and `slot` instead.
#[derive(Debug, Clone)]
pub struct ResolvedActor {
    /// The resolved identity (role, trust domain, subject, keyid → `actor_id`).
    pub identity: ActorIdentity,
    /// The verification key trust resolution bound to this actor.
    pub verification_key: VerificationKey,
    /// The slot the trust layer authorized this actor for. The verifier asserts
    /// this equals the slot it requested — a typed defense-in-depth cross-check
    /// atop the seam's primary enforcement, never a role-string comparison.
    pub slot: SignerSlot,
}

/// What the trust seam answers with (C079).
///
/// The seam used to be `-> Option<ResolvedActor>`, which made a store OUTAGE and an
/// UNKNOWN KEYID the same observation. Both fail closed — that was never in doubt —
/// but they are different facts, and the verifier reported the outage as
/// `actor_binding_failed`, sending an operator to inspect the caller's credentials
/// during an incident in their own trust store. `mcp-re-core` has modelled the
/// distinction since the beginning (`TrustResolverError::Unavailable`); it simply could
/// not cross this seam, so `mcp-re.trust_resolver_unavailable` had no emission site.
///
/// `From<Option<ResolvedActor>>` is provided so a resolver with no notion of
/// unavailability — every in-process and test resolver — stays a one-line closure:
/// `None` means NOT TRUSTED, which is what it always meant.
#[derive(Debug, Clone)]
pub enum ResolverOutcome {
    /// The keyid resolves to this actor for the requested slot. Boxed so the
    /// negative outcomes do not each carry the resolved actor's footprint.
    Resolved(Box<ResolvedActor>),
    /// A definitive negative from a HEALTHY resolver: no such trusted binding.
    /// → `mcp-re.actor_binding_failed`.
    NotTrusted,
    /// The resolver could not answer (backing store unreachable, timeout). NOT a
    /// verdict about the key, and never a fallback to allow.
    /// → `mcp-re.trust_resolver_unavailable`.
    Unavailable,
}

impl ResolverOutcome {
    /// The resolved actor, collapsing both negative outcomes to `None`.
    ///
    /// Used where a downstream seam cannot yet express unavailability — currently the
    /// delegation credential's ROOT-key resolver, which is
    /// `Fn(&str) -> Option<VerificationKey>`. Collapsing there preserves today's
    /// fail-closed behaviour exactly; widening that seam too is follow-on work, and it
    /// is called out here rather than left as a silent narrowing.
    pub fn resolved(self) -> Option<ResolvedActor> {
        match self {
            ResolverOutcome::Resolved(actor) => Some(*actor),
            ResolverOutcome::NotTrusted | ResolverOutcome::Unavailable => None,
        }
    }
}

impl From<Option<ResolvedActor>> for ResolverOutcome {
    fn from(value: Option<ResolvedActor>) -> Self {
        match value {
            Some(actor) => ResolverOutcome::Resolved(Box::new(actor)),
            None => ResolverOutcome::NotTrusted,
        }
    }
}

impl ResolvedActor {
    /// The canonical `actor_id` of the resolved signer (delegates to
    /// [`ActorIdentity::actor_id`]).
    // ADR-MCPRE-059 ASM-0021: delegates to the identity form; opaque for the same reason.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    pub fn actor_id(&self) -> String {
        self.identity.actor_id()
    }
}

/// The MCP-RE audience tuple — richer than `@target-uri` (v0.11 grill E-3).
/// It names the intended verifier identity AND the concrete target URI (plus an
/// optional route discriminator) so audience binding is not aliased by a shared
/// HTTP endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceTuple {
    /// Intended verifier identity (mirrors the native envelope `audience`).
    pub audience_id: String,
    /// The absolute target URI the request is bound to (`@target-uri`).
    pub target_uri: String,
    /// Optional route/tenant discriminator for endpoints that multiplex
    /// several logical audiences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

impl AudienceTuple {
    /// Canonical byte serialization: the three ESCAPED slots joined by the unit
    /// separator `0x1F`, always three slots (empty route is an empty slot).
    ///
    /// Fixed arity alone does not make the encoding injective, because a separator
    /// INSIDE a field is indistinguishable from the join: these are
    /// serde-deserialized JSON strings, which carry any code point, so
    /// `("x", "y", Some("z\u{1f}"))` and `("x", "y\u{1f}z", Some(""))` produced one
    /// byte string and therefore one [`audience_hash`](Self::audience_hash). Each
    /// field is escaped through the same [`field_escape`] the `actor_id` join uses,
    /// which is reversible and leaves no `0x1F` in any slot, so distinct tuples
    /// cannot collapse.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let route = self.route.as_deref().unwrap_or("");
        let joined = format!(
            "{}\u{1f}{}\u{1f}{}",
            field_escape(&self.audience_id),
            field_escape(&self.target_uri),
            field_escape(route)
        );
        joined.into_bytes()
    }

    /// `base64url-no-pad(SHA-256(canonical audience tuple bytes))` — the
    /// `audience_hash` replay-key component.
    pub fn audience_hash(&self) -> String {
        b64url_encode(&Sha256::digest(self.canonical_bytes()))
    }
}

/// MRTR continuation carried in the request evidence block. Three standards-
/// derived handles (ADR-MCPRE-050 §Resolved-owner ruling 7): the derivation and
/// verification land in MCPRE-97; the schema is defined here so the block is
/// complete. `requestState` stays opaque but is now digest-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpContinuation {
    /// Continuation kind; `"mcp-mrt"` (kept MCP-specific).
    #[serde(rename = "type")]
    pub continuation_type: String,
    /// SHA-256 over the previous client request's RFC 9421 signature base.
    pub previous_request_evidence: RequestEvidenceDigest,
    /// SHA-256 over the verified `InputRequiredResult` response signature base.
    pub input_required_response_evidence: RequestEvidenceDigest,
    /// SHA-256 over the opaque `requestState` bytes — opaque-but-digest-bound.
    pub request_state_digest: RequestEvidenceDigest,
}

/// A split-form digest handle (`digest_alg`/`digest_value`) as used across the
/// HTTP profile's body evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEvidenceDigest {
    pub digest_alg: String,
    pub digest_value: String,
}

impl RequestEvidenceDigest {
    /// Derive the handle over the mandated input under its ROLE label
    /// (#416 rev 2 §7.1/§7.3): `base64url-no-pad(SHA-256(label || 0x00 || bytes))`.
    ///
    /// There is no unlabeled derivation: every handle states which role it is,
    /// so a caller cannot accidentally mint one that is valid in two fields.
    pub fn over_labeled(label: &str, bytes: &[u8]) -> Self {
        RequestEvidenceDigest {
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: labeled_digest_value(label, bytes),
        }
    }

    /// Constant-shape check that this handle commits to `bytes` IN ROLE `label`.
    /// A handle that commits to the same bytes in a different role does not match.
    // ADR-MCPRE-059 ASM-0023: the digest comparator, trusted at exactly the strength the
    // role-separation contract needs — a true answer means this handle's value IS the
    // labeled digest of these bytes under this label. The digest itself stays
    // uninterpreted, so no cryptographic property is assumed here.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    #[cfg_attr(feature = "verify", verus_spec(result =>
        ensures
            result ==> self.digest_value@ == crate::verus_std_specs::labeled_digest(label@, bytes@),
    ))]
    pub fn matches_labeled(&self, label: &str, bytes: &[u8]) -> bool {
        self.digest_alg == EVIDENCE_DIGEST_ALG
            && self.digest_value == labeled_digest_value(label, bytes)
    }
}

/// The `mcp-mrt` continuation type token (kept MCP-specific).
#[allow(clippy::redundant_static_lifetimes)]
#[cfg_attr(feature = "verify", verus_verify)]
pub const CONTINUATION_TYPE_MCP_MRT: &'static str = "mcp-mrt";

impl HttpContinuation {
    /// Build the three-handle continuation (MCPRE-97) from the mandated inputs:
    /// the previous client request's signature base, the verified
    /// `InputRequiredResult` response's signature base, and the opaque
    /// `requestState` bytes. All three are hashed — `requestState` stays opaque
    /// (never interpreted) but is now digest-bound.
    pub fn build(
        previous_request_base: &[u8],
        input_required_response_base: &[u8],
        request_state: &[u8],
    ) -> Self {
        HttpContinuation {
            continuation_type: CONTINUATION_TYPE_MCP_MRT.to_owned(),
            previous_request_evidence: RequestEvidenceDigest::over_labeled(
                EVIDENCE_LABEL_REQUEST,
                previous_request_base,
            ),
            input_required_response_evidence: RequestEvidenceDigest::over_labeled(
                EVIDENCE_LABEL_RESPONSE,
                input_required_response_base,
            ),
            request_state_digest: RequestEvidenceDigest::over_labeled(
                EVIDENCE_LABEL_REQUEST_STATE,
                request_state,
            ),
        }
    }

    /// Build the continuation from digest HANDLES the caller already holds — the
    /// previous client request's evidence digest (`RequestEvidence` over its
    /// signature base) and the verified `InputRequiredResult` response's evidence
    /// digest — plus the opaque `requestState` bytes (hashed here). This is the
    /// answer-leg client's path (ADR-MCPS-047): after verifying an
    /// `InputRequiredResult` it already has both evidence digests (its own sent-
    /// request handle and the response's `response_signature_base_digest`) and never
    /// needs to retain the raw signature bases. Wire-identical to a continuation
    /// built via [`HttpContinuation::build`] over the same bases.
    pub fn from_handles(
        previous_request_evidence: RequestEvidenceDigest,
        input_required_response_evidence: RequestEvidenceDigest,
        request_state: &[u8],
    ) -> Self {
        HttpContinuation {
            continuation_type: CONTINUATION_TYPE_MCP_MRT.to_owned(),
            previous_request_evidence,
            input_required_response_evidence,
            request_state_digest: RequestEvidenceDigest::over_labeled(
                EVIDENCE_LABEL_REQUEST_STATE,
                request_state,
            ),
        }
    }

    /// Verify the continuation against the exact bytes the client re-presents.
    /// A wrong type is malformed; any handle that does not commit to its input
    /// is a continuation-binding failure (a splice across the continuation
    /// boundary, or a tampered `requestState`).
    // ADR-MCPRE-059 WP3 — the continuation role-labeled BINDING DISCIPLINE contract, and
    // the discharge of what used to be ASM-0022. An accepted continuation's three handles
    // are the modeled digests of the three presented inputs, each under its OWN required
    // role label.
    //
    // What that is not: separation. Ruling out a wrong-role handle that happens to collide
    // needs `digest(label_a, x) != digest(label_b, y)` for distinct labels — a domain-
    // separation property of the construction, held at `boundary.crypto_primitives` and
    // deliberately absent from the model here.
    #[cfg_attr(feature = "verify", verus_spec(out =>
        ensures
            out matches Ok(()) ==> {
                &&& self.previous_request_evidence.digest_value@
                        == crate::verus_std_specs::labeled_digest(
                            crate::ids::EVIDENCE_LABEL_REQUEST@, previous_request_base@)
                &&& self.input_required_response_evidence.digest_value@
                        == crate::verus_std_specs::labeled_digest(
                            crate::ids::EVIDENCE_LABEL_RESPONSE@, input_required_response_base@)
                &&& self.request_state_digest.digest_value@
                        == crate::verus_std_specs::labeled_digest(
                            crate::ids::EVIDENCE_LABEL_REQUEST_STATE@, request_state@)
            },
    ))]
    pub fn verify(
        &self,
        previous_request_base: &[u8],
        input_required_response_base: &[u8],
        request_state: &[u8],
    ) -> Result<(), HttpProfileError> {
        if self.continuation_type != CONTINUATION_TYPE_MCP_MRT {
            return Err(HttpProfileError::MalformedEvidence("continuation type"));
        }
        // Each handle is checked IN ITS ROLE: a previous-request handle presented
        // as the response handle (or vice versa) fails here even if the bytes
        // behind it are otherwise legitimate evidence.
        if !self
            .previous_request_evidence
            .matches_labeled(EVIDENCE_LABEL_REQUEST, previous_request_base)
            || !self
                .input_required_response_evidence
                .matches_labeled(EVIDENCE_LABEL_RESPONSE, input_required_response_base)
            || !self
                .request_state_digest
                .matches_labeled(EVIDENCE_LABEL_REQUEST_STATE, request_state)
        {
            return Err(HttpProfileError::ContinuationBindingFailed);
        }
        Ok(())
    }
}

/// The request-side body evidence block (`se.syncom/mcp-re.http.request`).
/// `profile`, `audience`, and a non-empty `artifact_bindings` are required;
/// `continuation` is present only on a continuation request (like the native
/// envelope), so it is optional in presence but part of the schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestEvidenceBlock {
    /// The signed profile id; cross-checked against the RFC 9421 `tag`.
    pub profile: String,
    /// The audience tuple (richer than `@target-uri`).
    pub audience: AudienceTuple,
    /// Required, non-empty. Generalizes the draft-02 `authorization_binding`.
    pub artifact_bindings: Vec<ArtifactBinding>,
    /// MRTR continuation (present only on continuation requests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<HttpContinuation>,
    /// The §7 admission binding: which admission the call acts under (MCPRE-433).
    /// Present only where a deployment enforces admission; optional so pre-433
    /// vectors and admission-free deployments are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<crate::admission::AdmissionBinding>,
    /// The inline admission assertion (compact JOSE/JWS) the binding commits to
    /// (MCPRE-493).
    ///
    /// A sibling of `admission`, protected by the covered `content-digest` exactly
    /// as it is — the same shape the response block uses for `server_delegation`,
    /// and for the same reason: an evidence artifact the verifier must have in hand
    /// travels with the message rather than being fetched. It rides in the BODY, not
    /// a header, because E-3 admits a new MCP-RE header field only where the message
    /// shape leaves no alternative (a bodyless 202), and a request has a body.
    ///
    /// Without it the binding is uncheckable: the binding commits to a digest of the
    /// admitted-state the authority attested, so a verifier holding only the binding
    /// can compare that digest against nothing. `validate` therefore requires the two
    /// to appear together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_assertion: Option<String>,
    /// The inline authorization decision (compact JOSE/JWS) an external authority issued
    /// for this call — ADR-MCPRE-065 Slice 2.
    ///
    /// A sibling of the `pdp-decision` / `opaque-digest` entry in
    /// [`artifact_bindings`](Self::artifact_bindings), exactly as `admission_assertion` is a
    /// sibling of `admission`, and protected the same way: by the covered `content-digest`.
    /// It rides in the BODY because E-3 admits a new MCP-RE header field only where the
    /// message shape leaves no alternative, and a request has a body.
    ///
    /// Carried rather than referenced. A deployment that had to resolve a decision reference
    /// would be unable to serve whenever its authority was unreachable, and the proposition
    /// this evidence supports would then silently include *the PDP is online*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_decision: Option<String>,
}

impl HttpRequestEvidenceBlock {
    /// Structural validation, fail-closed: profile tag matches, at least one
    /// artifact binding, every binding structurally valid.
    pub fn validate(&self, expected_profile: &str) -> Result<(), HttpProfileError> {
        if self.profile != expected_profile {
            return Err(HttpProfileError::UnknownProfileTag);
        }
        if self.artifact_bindings.is_empty() {
            return Err(HttpProfileError::MalformedEvidence(
                "empty artifact_bindings",
            ));
        }
        for b in &self.artifact_bindings {
            b.validate()?;
        }
        // Admission is both halves or neither. A binding alone commits to a digest
        // of state no one here can see, so it cannot be checked; an assertion alone
        // is an authority's statement bound to no call. Either shape would verify
        // structurally and enforce nothing, which is worse than being absent —
        // absent is at least legible as "this deployment does not do admission".
        match (&self.admission, &self.admission_assertion) {
            (None, None) => {}
            (Some(_), Some(jws)) => {
                if jws.len() > MAX_ADMISSION_ASSERTION_LEN {
                    // Bounded before parsing: an assertion is a compact JWS over a
                    // small claim set, and an unbounded value is a parse/memory
                    // surface reachable pre-trust.
                    return Err(HttpProfileError::MalformedEvidence(
                        "admission assertion size",
                    ));
                }
            }
            _ => {
                return Err(HttpProfileError::MalformedEvidence(
                    "admission binding and assertion must appear together",
                ))
            }
        }
        self.validate_authorization_decision()?;
        Ok(())
    }

    /// The structural rules for an inline authorization decision (ADR-MCPRE-065 Slice 2).
    ///
    /// Three of them, and each closes a way the pairing could be ambiguous:
    ///
    /// 1. **Both halves or neither.** A binding alone commits to the digest of a document
    ///    nobody supplied, so nothing can check it; a decision alone is an authority's
    ///    statement bound to no call. Either shape verifies structurally and enforces
    ///    nothing — worse than absent, which is at least legible as *this deployment does
    ///    not do authorization*.
    /// 2. **Exactly one applicable binding.** Two `pdp-decision` / `opaque-digest` entries
    ///    would leave the verifier choosing which one the document is supposed to match,
    ///    and a caller supplying both a matching and a non-matching one would pass whichever
    ///    check happened to be written first.
    /// 3. **A reference binding never satisfies it.** `pdp-decision` / `reference-digest` is
    ///    the LINKAGE form: it names an external decision MCP-RE does not authenticate or
    ///    interpret. Letting it stand in for the evidence form would let a call claim an
    ///    enforcement decision it never carried.
    ///
    /// Size is bounded before any of it: the value is read from an unauthenticated peer and
    /// an unbounded one is a parse and memory surface reachable pre-trust.
    fn validate_authorization_decision(&self) -> Result<(), HttpProfileError> {
        let applicable = self
            .artifact_bindings
            .iter()
            .filter(|b| {
                b.artifact_type == ArtifactType::PdpDecision
                    && b.binding_type == BindingType::OpaqueDigest
            })
            .count();
        match (&self.authorization_decision, applicable) {
            (None, _) => Ok(()),
            (Some(jws), _) if jws.len() > MAX_AUTHORIZATION_DECISION_LEN => Err(
                HttpProfileError::MalformedEvidence("authorization decision size"),
            ),
            (Some(_), 1) => Ok(()),
            (Some(_), 0) => Err(HttpProfileError::MalformedEvidence(
                "authorization decision without a pdp-decision opaque-digest binding",
            )),
            (Some(_), _) => Err(HttpProfileError::MalformedEvidence(
                "more than one pdp-decision opaque-digest binding",
            )),
        }
    }
}

/// The response-side body evidence block (`se.syncom/mcp-re.http.response`,
/// MCPRE-101). Carries the resolved server signer identity and the request
/// evidence handle this response is bound to. Like the request block it rides in
/// the JSON-RPC body `_meta` and is protected by the covered `content-digest`.
///
/// `request_evidence` is explicit MCP semantic defense-in-depth ON TOP of the
/// cryptographic `;req` binding: `verify_response_full` compares it against the
/// recomputed request signature-base digest from the verified request context,
/// and a mismatch is `request_binding_mismatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseEvidenceBlock {
    /// The signed profile id; cross-checked against `PROFILE_TAG`.
    pub profile: String,
    /// The server's resolved signer identity (role, trust domain, subject,
    /// keyid). Cross-checked against the keyid the response signature verified
    /// under.
    pub server_signer: ActorIdentity,
    /// The inline delegation credential (compact JOSE/JWS), when the response is
    /// signed by a delegated key (ADR-MCPRE-052 §2). A sibling of `server_signer`,
    /// protected by the covered `content-digest` exactly as `server_signer` is.
    /// Absent on directly root-signed responses (backward-compatible: pre-052
    /// vectors omit it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_delegation: Option<String>,
    /// The request evidence handle (`SHA-256` over the request signature base)
    /// this response asserts it is answering.
    pub request_evidence: RequestEvidenceDigest,
}

impl HttpResponseEvidenceBlock {
    /// Structural validation, fail-closed: the profile tag matches.
    pub fn validate(&self, expected_profile: &str) -> Result<(), HttpProfileError> {
        if self.profile != expected_profile {
            return Err(HttpProfileError::UnknownProfileTag);
        }
        Ok(())
    }
}

/// A base64url-no-pad token: URL-safe alphabet, no `=` padding, non-empty.
pub(crate) fn is_b64url_no_pad(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::PROFILE_TAG;

    fn dpop_binding() -> ArtifactBinding {
        ArtifactBinding {
            artifact_type: ArtifactType::OauthDpop,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: "sha256".into(),
            digest_value: "abcdEF012_-".into(),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        }
    }

    fn block() -> HttpRequestEvidenceBlock {
        HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.into(),
            audience: AudienceTuple {
                audience_id: "did:example:server".into(),
                target_uri: "https://mcp.example.com/mcp".into(),
                route: None,
            },
            artifact_bindings: vec![dpop_binding()],
            continuation: None,
            admission: None,
            admission_assertion: None,
            authorization_decision: None,
        }
    }

    #[test]
    fn block_round_trips() {
        let b = block();
        let json = serde_json::to_string(&b).unwrap();
        let back: HttpRequestEvidenceBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
        b.validate(PROFILE_TAG).expect("valid");
    }

    #[test]
    fn unknown_field_fails_closed() {
        let json = r#"{"profile":"mcp-re-http-v1","audience":{"audience_id":"a","target_uri":"u"},"artifact_bindings":[],"surprise":1}"#;
        let err = serde_json::from_str::<HttpRequestEvidenceBlock>(json);
        assert!(
            err.is_err(),
            "deny_unknown_fields must reject stray members"
        );
    }

    #[test]
    fn empty_artifact_bindings_fails_closed() {
        let mut b = block();
        b.artifact_bindings.clear();
        assert_eq!(
            b.validate(PROFILE_TAG).unwrap_err(),
            HttpProfileError::MalformedEvidence("empty artifact_bindings")
        );
    }

    #[test]
    fn foreign_profile_fails_closed() {
        let mut b = block();
        b.profile = "someone-elses-profile".into();
        assert_eq!(
            b.validate(PROFILE_TAG).unwrap_err(),
            HttpProfileError::UnknownProfileTag
        );
    }

    // ----- actor_id determinism + injectivity -----

    #[test]
    fn actor_id_is_deterministic_and_pinned() {
        let a = ActorIdentity {
            role: "host".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:host".into(),
            keyid: "client-key-1".into(),
        };
        // Golden: subject colons are escaped so the join stays unambiguous.
        assert_eq!(
            a.actor_id(),
            "host:example.com:did%3Aexample%3Ahost:client-key-1"
        );
        assert_eq!(a.actor_id(), a.actor_id());
    }

    #[test]
    fn actor_id_is_injective_across_colon_boundaries() {
        // Without escaping, ("a:b","c") and ("a","b:c") would collide.
        let x = ActorIdentity {
            role: "r".into(),
            trust_domain: "d".into(),
            subject: "a:b".into(),
            keyid: "c".into(),
        };
        let y = ActorIdentity {
            role: "r".into(),
            trust_domain: "d".into(),
            subject: "a".into(),
            keyid: "b:c".into(),
        };
        assert_ne!(x.actor_id(), y.actor_id());
    }

    // ----- audience_hash determinism + discrimination -----

    #[test]
    fn audience_hash_is_deterministic_and_b64url() {
        let a = AudienceTuple {
            audience_id: "did:example:server".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            route: None,
        };
        assert_eq!(a.audience_hash(), a.audience_hash());
        assert!(!a.audience_hash().contains('='), "base64url no-pad");
        assert!(!a.audience_hash().contains(':'), "bare digest, no prefix");
    }

    #[test]
    fn different_audiences_on_one_endpoint_hash_differently() {
        let base = "https://mcp.example.com/mcp";
        let a = AudienceTuple {
            audience_id: "did:example:server-a".into(),
            target_uri: base.into(),
            route: None,
        };
        let b = AudienceTuple {
            audience_id: "did:example:server-b".into(),
            target_uri: base.into(),
            route: None,
        };
        // Same HTTP endpoint, different verifier identity -> different hash.
        assert_ne!(a.audience_hash(), b.audience_hash());
        // Route discriminator also separates.
        let c = AudienceTuple {
            route: Some("tenant-1".into()),
            ..a.clone()
        };
        assert_ne!(a.audience_hash(), c.audience_hash());
    }

    #[test]
    fn separator_cannot_be_forged_across_fields() {
        // audience_id "x" + target "y" must differ from audience_id "x\u{1f}y".
        let a = AudienceTuple {
            audience_id: "x".into(),
            target_uri: "y".into(),
            route: None,
        };
        let b = AudienceTuple {
            audience_id: "x\u{1f}y".into(),
            target_uri: "".into(),
            route: None,
        };
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    /// Fixed arity does not rescue the join on its own: a separator carried INSIDE a
    /// field is indistinguishable from the join that follows it. These pairs are
    /// distinct audiences that shared one `audience_hash` — one replay-key audience
    /// slot and one delegated-credential scope value for two different MCP audiences.
    #[test]
    fn a_separator_inside_a_field_does_not_collapse_two_audiences() {
        let collisions = [
            (
                AudienceTuple {
                    audience_id: "x".into(),
                    target_uri: "y".into(),
                    route: Some("z\u{1f}".into()),
                },
                AudienceTuple {
                    audience_id: "x".into(),
                    target_uri: "y\u{1f}z".into(),
                    route: Some(String::new()),
                },
            ),
            (
                AudienceTuple {
                    audience_id: "a\u{1f}b".into(),
                    target_uri: "c".into(),
                    route: Some("d".into()),
                },
                AudienceTuple {
                    audience_id: "a".into(),
                    target_uri: "b\u{1f}c".into(),
                    route: Some("d".into()),
                },
            ),
        ];
        for (a, b) in collisions {
            assert_ne!(a, b, "the pair must really be two different tuples");
            assert_ne!(
                a.canonical_bytes(),
                b.canonical_bytes(),
                "{a:?} and {b:?} must not share one canonical encoding"
            );
            assert_ne!(a.audience_hash(), b.audience_hash());
        }
    }

    /// The escape must be reversible, or it would trade one collision for another:
    /// a field containing the escape marker must not collide with the escaped form
    /// of a different field.
    #[test]
    fn the_escape_marker_itself_does_not_create_a_collision() {
        let a = AudienceTuple {
            audience_id: "%1F".into(),
            target_uri: "t".into(),
            route: None,
        };
        let b = AudienceTuple {
            audience_id: "\u{1f}".into(),
            target_uri: "t".into(),
            route: None,
        };
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert_ne!(a.audience_hash(), b.audience_hash());
    }

    // ----- no raw secrets -----

    #[test]
    fn artifact_binding_carries_only_digest_and_reference_never_token_bytes() {
        // A DPoP artifact is expressed as a digest, not the token. The serialized
        // form has no field able to hold raw token/secret bytes.
        let json = serde_json::to_string(&dpop_binding()).unwrap();
        assert!(json.contains("digest_value"));
        for forbidden in ["token", "jwt", "secret", "private", "access_token"] {
            assert!(
                !json.contains(forbidden),
                "no raw-secret field: {forbidden}"
            );
        }
    }

    #[test]
    fn opaque_binding_with_reference_fields_fails_closed() {
        let mut b = dpop_binding();
        b.reference_value = Some("grant-123".into());
        assert!(b.validate().is_err());
    }

    #[test]
    fn reference_binding_missing_fields_fails_closed() {
        let b = ArtifactBinding {
            artifact_type: ArtifactType::OauthRar,
            binding_type: BindingType::ReferenceDigest,
            digest_alg: "sha256".into(),
            digest_value: "abcd".into(),
            authorization_system_id: Some("authz".into()),
            reference_scheme_id: None,
            reference_value: None,
        };
        assert!(b.validate().is_err());
    }

    // ----- MRTR continuation (three handles) -----

    const PREV_BASE: &[u8] = b"previous-request-signature-base";
    const IRR_BASE: &[u8] = b"input-required-response-signature-base";
    const REQ_STATE: &[u8] = b"opaque-request-state-blob";

    #[test]
    fn continuation_round_trips_and_verifies() {
        let c = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
        let json = serde_json::to_string(&c).unwrap();
        let back: HttpContinuation = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        c.verify(PREV_BASE, IRR_BASE, REQ_STATE)
            .expect("binds its inputs");
        // The type token is the MCP-specific mcp-mrt.
        assert_eq!(c.continuation_type, "mcp-mrt");
    }

    #[test]
    fn tampered_request_state_breaks_the_digest() {
        // requestState stays opaque (never interpreted) but IS digest-bound.
        let c = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
        let err = c
            .verify(PREV_BASE, IRR_BASE, b"opaque-request-state-TAMPERED")
            .unwrap_err();
        assert_eq!(err, HttpProfileError::ContinuationBindingFailed);
        assert_eq!(err.wire_code(), "mcp-re.continuation_binding_failed");
    }

    #[test]
    fn splice_across_continuation_boundary_fails() {
        // A continuation presented against a DIFFERENT previous request (a
        // splice) must not verify.
        let c = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
        assert_eq!(
            c.verify(b"some-other-request-base", IRR_BASE, REQ_STATE)
                .unwrap_err(),
            HttpProfileError::ContinuationBindingFailed
        );
        // Likewise a different input-required response.
        assert_eq!(
            c.verify(PREV_BASE, b"other-irr-base", REQ_STATE)
                .unwrap_err(),
            HttpProfileError::ContinuationBindingFailed
        );
    }

    #[test]
    fn wrong_continuation_type_is_malformed() {
        let mut c = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
        c.continuation_type = "some-other-continuation".into();
        assert_eq!(
            c.verify(PREV_BASE, IRR_BASE, REQ_STATE).unwrap_err(),
            HttpProfileError::MalformedEvidence("continuation type")
        );
    }
}
