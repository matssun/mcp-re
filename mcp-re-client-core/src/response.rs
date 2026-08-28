// SPDX-License-Identifier: Apache-2.0
//! RFC 9421 signed-response verification on the client side (ADR-MCPRE-050,
//! MCPRE-101). The return leg of [`crate::request`].
//!
//! Given the received [`HttpResponse`] and the request context the client kept
//! from signing (`SignedRequest`: the sent [`HttpRequest`] and its
//! [`RequestEvidence`] handle), it confirms the response is genuine RFC 9421 +
//! RFC 9530 evidence bound to THIS request:
//! [`mcp_re_http_profile::verify_response_bound_full`] performs the
//! `Content-Digest` check, the RFC 9421 signature verification over the `;req`-bound
//! signature base (a spliced response fails), server-signer trust resolution through
//! the injected actor resolver, and the response-block `request_evidence` binding.
//!
//! The response evidence is an RFC 9421 signature over the `;req`-bound base plus the
//! RFC 9530 Content-Digest, not a JSON-RPC `_meta` block. Trust resolution stays
//! behind the actor-resolver seam, so the proxy/SDK
//! injects the live-trust / OCSP-backed resolver and this pure module never reaches
//! the network.

use crate::delegated_evidence::DelegatedResponseEvidence;
use crate::delegated_trust::DelegatedResponseTrust;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedMcpResponse;
use mcp_re_http_profile::Verifier;
use serde_json::Value;

use crate::execution_contract::rejection_receipt;
use crate::execution_contract::ExecutionContract;

/// The MCP-RE round-trip classification of a verified response body
/// (ADR-MCPS-047). Read ONLY from the signed, verified body — never from
/// untrusted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultClass {
    /// An ordinary terminal result.
    Terminal,
    /// An `InputRequiredResult` — a non-terminal leg awaiting client continuation.
    InputRequired,
    /// A `resultType` this client does not recognize. MCP 2026-07-28 requires it
    /// be considered invalid, so it is never resolved to [`Terminal`]: a caller
    /// that acts on the exchange must refuse it.
    ///
    /// [`Terminal`]: ResultClass::Terminal
    Unrecognized,
}

/// What the client expects of the bound response for one outstanding request: the
/// exact request it sent (for the `;req` binding), the [`RequestEvidence`] handle
/// the response must bind, and an optional pinned server signer.
#[derive(Debug, Clone)]
pub struct ResponseExpectation {
    /// The exact [`HttpRequest`] the client signed and sent.
    pub request: HttpRequest,
    /// The [`RequestEvidence`] handle the response's `request_evidence` must equal.
    pub request_evidence: RequestEvidence,
    /// The server signer policy expects for this route/audience, if pinned. When
    /// `Some`, the verified server signer keyid MUST equal it (unexpected → fail
    /// closed) even if some other signer would independently resolve.
    pub expected_server_signer_keyid: Option<String>,
}

impl ResponseExpectation {
    /// Build an expectation from the sent request and its evidence handle, with no
    /// pinned signer (resolver scope governs).
    pub fn new(request: HttpRequest, request_evidence: RequestEvidence) -> Self {
        ResponseExpectation {
            request,
            request_evidence,
            expected_server_signer_keyid: None,
        }
    }

    /// Pin the expected server signer keyid. A verified-but-unexpected signer then
    /// fails closed.
    pub fn with_expected_server_signer(mut self, keyid: impl Into<String>) -> Self {
        self.expected_server_signer_keyid = Some(keyid.into());
        self
    }
}

/// Verify a signed RFC 9421 response and confirm it binds the expected request.
///
/// `resolve_actor` is the client's trust seam (injected by the proxy/SDK; live
/// trust + OCSP live behind it, so this pure module performs no I/O). On success
/// returns the [`VerifiedMcpResponse`]; on any failure the precise frozen
/// [`HttpProfileError`], fail-closed.
pub fn verify_signed_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    verifier: &Verifier<'_, R>,
    expectation: &ResponseExpectation,
    now: i64,
) -> Result<VerifiedMcpResponse, HttpProfileError> {
    let verified = verifier.verify_bound_response(
        response,
        &expectation.request,
        &expectation.request_evidence,
        now,
    )?;

    enforce_expected_server_signer(expectation, &verified)?;

    Ok(verified)
}

/// The unexpected-signer guard (client policy): a signer that verifies but is not the
/// one policy bound to this route/audience fails closed.
///
/// Direct-root mode only. `resolved_server_actor.identity.keyid` is the keyid the
/// response signature was accepted under, which on that path is the stable server
/// signer the pin names.
fn enforce_expected_server_signer(
    expectation: &ResponseExpectation,
    verified: &VerifiedMcpResponse,
) -> Result<(), HttpProfileError> {
    if let Some(expected) = &expectation.expected_server_signer_keyid {
        if &verified.floor.resolved_server_actor.identity.keyid != expected {
            return Err(HttpProfileError::ResponseBindingMismatch);
        }
    }
    Ok(())
}

/// Enforce `expected_server_signer_keyid` on the DELEGATED path (C004b, resolved
/// 2026-07-27).
///
/// The pin binds to the credential's ROOT ISSUER kid, not to the keyid the response
/// signature verified under. That keyid is the DELEGATED kid — an RFC 7638 thumbprint
/// that rotates every TTL by design — so pinning it would fail on the first rotation
/// and means nothing about server identity. The issuer kid is the anchor the credential
/// proves a chain to, and is what an operator means by "this server".
///
/// The interim behaviour this replaces refused any set pin outright, so an operator who
/// configured one learned it was unenforced rather than believing a control that never
/// ran. That was the correct holding position; it is not a control.
///
/// The "missing issuer is a contradiction" branch this used to carry is gone: the
/// delegated products hold the issuer kid unconditionally, so an issuer-less delegated
/// verdict is not a state that can be constructed. What remains is the comparison.
fn check_expected_server_signer(
    expectation: &ResponseExpectation,
    issuer_kid: &str,
) -> Result<(), HttpProfileError> {
    let Some(pinned) = expectation.expected_server_signer_keyid.as_deref() else {
        return Ok(());
    };
    if issuer_kid == pinned {
        Ok(())
    } else {
        Err(HttpProfileError::ResponseBindingMismatch)
    }
}

/// A verified response plus its multi-round-trip classification (ADR-MCPS-047),
/// read from the signed, verified body.
#[derive(Debug, Clone)]
pub struct ClassifiedResponse {
    /// The verification verdict.
    pub verified: VerifiedMcpResponse,
    /// Terminal vs `InputRequiredResult`.
    pub class: ResultClass,
}

/// Verify a signed RFC 9421 response AND classify its result body for the
/// multi-round-trip flow. Classification runs ONLY after verification succeeds, so
/// the class is never trusted from unverified bytes.
///
/// [`ResultClass::Unrecognized`] is returned rather than raised: this function's
/// job is to report what the verified body says, and a caller inspecting a record
/// may legitimately want to see it. A caller acting on a LIVE exchange must refuse
/// it — [`continuation_state`] is the seam that does, and it is what the SDK
/// bindings call.
pub fn verify_and_classify_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    verifier: &Verifier<'_, R>,
    expectation: &ResponseExpectation,
    now: i64,
) -> Result<ClassifiedResponse, HttpProfileError> {
    let verified = verify_signed_response(response, verifier, expectation, now)?;
    let body: Value = serde_json::from_slice(&response.body)
        .map_err(|_| HttpProfileError::MalformedEvidence("response body"))?;
    let class = classify_result(body.get("result"));
    Ok(ClassifiedResponse { verified, class })
}

/// Classify a (verified) `result` body through the profile's single discriminator
/// ([`mcp_re_http_profile::result_class`], ADR-MCPS-047). An absent `resultType` is
/// terminal, as MCP 2026-07-28 requires of clients; an unrecognized one is
/// [`ResultClass::Unrecognized`], never terminal.
///
/// This is the typed client-side face of that one classifier, not a second copy of
/// it: the discriminator string lives in the lower crate every reader shares, so
/// the SEP-2322 drift guard that pins this function covers the proxy, chain
/// reconstruction and both SDK bindings too.
pub fn classify_result(result: Option<&Value>) -> ResultClass {
    use mcp_re_http_profile::result_class::ResultTypeClass;
    match mcp_re_http_profile::result_class::classify_result_type(result) {
        ResultTypeClass::InputRequired => ResultClass::InputRequired,
        ResultTypeClass::Complete => ResultClass::Terminal,
        ResultTypeClass::Unrecognized => ResultClass::Unrecognized,
    }
}

/// The continuation state a VERIFIED response carries, for callers that must act
/// on a live exchange rather than reconstruct a record: `Some(state)` for an
/// `InputRequiredResult`, `None` for a terminal reply, and an ERROR for a reply
/// that announces itself non-terminal without a usable `requestState`.
///
/// This is what the SDK bindings call. Each of them used to open-code the JSON walk
/// and collapse the malformed case to `None`, which their transports read as
/// terminal: the open leg's correlation entry was consumed, the input-required
/// callback never fired, no answer leg was ever signed, and an elicitation was
/// handed to the application as a completed tool result. See
/// [`mcp_re_http_profile::result_class::input_required_state`] for the three-way
/// contract.
pub fn continuation_state(body: &[u8]) -> Result<Option<String>, HttpProfileError> {
    mcp_re_http_profile::result_class::input_required_state(body)
}

// ---- ADR-MCPRE-052 delegated-required client verification (MCPRE-122) --------

/// The deployment policy the client applies when verifying a DELEGATED-key-signed
/// response (ADR-MCPRE-052 §3) — the owned, client-side mirror of
/// [`mcp_re_http_profile::DelegationExpectations`]. The trusted ROOT issuer is
/// injected through the actor resolver (the credential's `issuer_kid` resolved for
/// the `Response` slot); this carries the audience-scope, epoch, and skew policy the
/// credential must satisfy.
#[derive(Debug, Clone)]
pub struct DelegationPolicy {
    /// This client's accepted verifier audience identifier(s); the credential's
    /// `aud` must name one.
    pub verifier_audiences: Vec<String>,
    /// The audience-scope hash the delegated key must be scoped to (the request's
    /// audience hash the deployment coordinates).
    pub expected_audience_hash: String,
    /// The accepted trust-epoch set (default `{ current }`, optionally
    /// `{ current, previous }` in a bounded rollout window).
    pub accepted_epochs: Vec<String>,
    /// Clock-skew tolerance, seconds, as CONFIGURED. The value actually applied is
    /// [`DelegationPolicy::bounded_clock_skew`] — the field is `pub`, so nothing can
    /// guarantee it was ever validated, and both windows read the bounded value rather
    /// than this one.
    ///
    /// It governs BOTH the credential's `nbf`/`exp` window and the RFC 9421
    /// response-signature freshness gate, and the two must be the same number: a
    /// deployment that widened the skew for a real clock spread and got it on one
    /// window only is running two different notions of "close enough" on one message.
    pub max_clock_skew: i64,
}

impl DelegationPolicy {
    /// The clock-skew tolerance this policy actually applies: the configured value
    /// clamped to the profile's `0..=MAX_CLOCK_SKEW_BOUND` range.
    ///
    /// The bound is the profile's, not this crate's ([`VerifierPolicy::new`] refuses
    /// anything outside it), and it has to be applied HERE because the delegation
    /// credential's freshness check consumes the number raw: `DelegationExpectations`
    /// carries it straight through to `DelegationVerifyParams.max_clock_skew`, which
    /// widens `nbf`/`exp` with no cap of its own. Passing the configured value there
    /// while the signature gate silently clamped it meant a policy of 604800 accepted a
    /// delegated credential a week past its `exp` — the TTL is the primary bound on a
    /// compromised delegated key, so that window has to stay bounded (DEL-4).
    ///
    /// Clamping rather than rejecting keeps a misconfiguration from turning every
    /// response unverifiable, and unlike the previous fallback it leaves the two windows
    /// equal: one number, bounded, on both gates.
    ///
    /// [`VerifierPolicy::new`]: mcp_re_http_profile::VerifierPolicy::new
    fn bounded_clock_skew(&self) -> i64 {
        self.max_clock_skew
            .clamp(0, mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND)
    }

    /// The RFC 9421 signature-acceptance policy this delegation policy implies.
    ///
    /// Built from [`bounded_clock_skew`](Self::bounded_clock_skew), so the construction
    /// can no longer fail on the skew argument; the fallback remains only because
    /// `new` is fallible in its algorithm argument too.
    fn verifier_policy(&self) -> mcp_re_http_profile::VerifierPolicy {
        mcp_re_http_profile::VerifierPolicy::new(&["ed25519"], self.bounded_clock_skew())
            .unwrap_or_default()
    }

    /// Build a delegation policy.
    pub fn new(
        verifier_audiences: Vec<String>,
        expected_audience_hash: impl Into<String>,
        accepted_epochs: Vec<String>,
        max_clock_skew: i64,
    ) -> Self {
        DelegationPolicy {
            verifier_audiences,
            expected_audience_hash: expected_audience_hash.into(),
            accepted_epochs,
            max_clock_skew,
        }
    }
}

/// The verified-response outcome the client hands its caller (ADR-MCPRE-052): a
/// success, or a delegated REJECTION receipt (request-bound or preflight-unbound)
/// carrying the server's frozen wire code and its execution/retry contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedOutcome {
    /// A delegated-signed, request-bound SUCCESS response.
    Success,
    /// A delegated-signed REJECTION receipt. `bound` distinguishes a request-bound
    /// receipt (the server verified the request before a later fail-closed step)
    /// from a preflight-unbound one (the request never earned a trustworthy hash).
    /// `wire_code` is the server's frozen `mcp-re.*` reason from the verified body.
    /// `execution` is the ADR-MCPRE-058 §10 execution/retry contract the same body
    /// carries — the difference between a refusal that ran nothing and one whose
    /// side effect a retry would perform twice.
    Rejection {
        wire_code: Option<String>,
        execution: ExecutionContract,
    },
}

/// A verified delegated response: the verification evidence plus the outcome.
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedResponse {
    /// The verified response evidence, bound or unbound.
    pub verified: DelegatedResponseEvidence,
    /// Success vs delegated rejection receipt.
    pub outcome: DelegatedOutcome,
}

/// Verify a DELEGATED-required response on the client (ADR-MCPRE-052 §3, MCPRE-122).
///
/// Delegation is REQUIRED and there is NO downgrade: a response with no inline
/// credential — INCLUDING a directly root-signed one — fails closed
/// (`delegation_credential_missing`); an unsigned response fails closed (no signature
/// to verify); there is no object/`_meta` evidence path.
///
/// A SUCCESS (2xx) MUST be request-bound — verified with
/// [`mcp_re_http_profile::verify_delegated_response_bound_full`] against the request
/// the client signed (a stripped-`;req` "success" cannot produce a valid delegated
/// signature). A non-2xx REJECTION receipt is verified request-bound first (a request
/// the server verified before a later fail-closed step) and, failing that, as a
/// preflight-unbound receipt — NEVER accepting an unbound receipt as a bound success.
/// On total failure the (more specific) bound error is surfaced, fail-closed.
///
/// `trust` is the client's [`DelegatedResponseTrust`] authority: ONE value answering both
/// which root issuer resolves and which identifiers are revoked. It is consulted for
/// revocation with each identifier the credential carries — its `delegated_kid`, its
/// `issuer_kid`, and its `jti`. A [`TrustedIssuerSet`] is one; so is a
/// [`CompositeResponseTrust`] over a directory and a separate denylist. A trust authority
/// whose revocation half is empty is the explicit TTL-only posture — the deployment
/// relies on short delegated-key TTLs alone.
pub fn verify_delegated_response(
    response: &HttpResponse,
    trust: &dyn DelegatedResponseTrust,
    expectation: &ResponseExpectation,
    policy: &DelegationPolicy,
    now: i64,
) -> Result<VerifiedDelegatedResponse, HttpProfileError> {
    let audiences: Vec<&str> = policy
        .verifier_audiences
        .iter()
        .map(String::as_str)
        .collect();
    let epochs: Vec<&str> = policy.accepted_epochs.iter().map(String::as_str).collect();
    let verifier_policy = policy.verifier_policy();
    let expect = DelegationExpectations {
        verifier_audiences: &audiences,
        expected_audience_hash: policy.expected_audience_hash.as_str(),
        accepted_epochs: &epochs,
        max_clock_skew: policy.bounded_clock_skew(),
    };
    // Adapt the one trust authority to the http-profile verifier's two closure forms.
    // Both halves come from the SAME value, so a resolver that answers cannot be paired
    // with a revocation source that does not.
    let is_revoked = |identifier: &str| trust.is_revoked(identifier);
    let is_revoked = &is_revoked;
    let resolve_actor = |kid: &str, slot: SignerSlot| trust.resolve_issuer(kid, slot, now);
    let resolve_actor = &resolve_actor;

    // A SUCCESS must be request-bound. The server only ever signs success responses
    // with the `;req` binding, and a stripped-`;req` "success" changes the signature
    // base so no valid delegated signature can cover it — so this is a hard floor.
    let verifier = Verifier::new(&verifier_policy, resolve_actor);
    if (200..300).contains(&response.status) {
        let verified = verifier.verify_delegated_bound_response(
            response,
            &expectation.request,
            &expectation.request_evidence,
            &expect,
            is_revoked,
            now,
        )?;
        check_expected_server_signer(expectation, &verified.delegation_issuer_kid)?;
        return Ok(VerifiedDelegatedResponse {
            verified: DelegatedResponseEvidence::Bound(verified),
            outcome: DelegatedOutcome::Success,
        });
    }

    // A REJECTION receipt: verify request-bound first, then preflight-unbound. Both
    // require the inline credential + a valid delegated signature, so an unsigned or
    // direct-root rejection fails closed here (no downgrade, no unsigned acceptance).
    match verifier.verify_delegated_bound_response(
        response,
        &expectation.request,
        &expectation.request_evidence,
        &expect,
        is_revoked,
        now,
    ) {
        Ok(verified) => {
            check_expected_server_signer(expectation, &verified.delegation_issuer_kid)?;
            let (wire_code, execution) = rejection_receipt(&response.body);
            Ok(VerifiedDelegatedResponse {
                verified: DelegatedResponseEvidence::Bound(verified),
                outcome: DelegatedOutcome::Rejection {
                    wire_code,
                    execution,
                },
            })
        }
        Err(bound_err) => {
            match verifier.verify_delegated_unbound_response(response, &expect, is_revoked, now) {
                Ok(verified) => {
                    check_expected_server_signer(expectation, &verified.delegation_issuer_kid)?;
                    // The unbound signature binds nothing about the request, so a receipt
                    // that verifies here is not yet an answer to THIS request. Confirm the
                    // server produced it for the bytes this client sent before reporting a
                    // refusal at all.
                    check_unbound_receipt_is_about_this_request(response, &expectation.request)?;
                    let (wire_code, execution) = rejection_receipt(&response.body);
                    Ok(VerifiedDelegatedResponse {
                        verified: DelegatedResponseEvidence::Unbound(verified),
                        outcome: DelegatedOutcome::Rejection {
                            wire_code,
                            execution,
                        },
                    })
                }
                // Neither path verified — fail closed. Surface the bound error (the more
                // specific of the two for a receipt claiming to be about this request).
                Err(_unbound_err) => Err(bound_err),
            }
        }
    }
}

/// The `digest_alg` a preflight receipt uses for the digest of the bytes it received.
/// It is the ONLY alg that names "these are the request bytes that reached me".
const RECEIVED_DIGEST_ALG: &str = "sha-256-received";

/// Confirm that a preflight-UNBOUND rejection receipt is at least about the request
/// this client sent.
///
/// The unbound signature covers only response components — no `@method`, no
/// `@target-uri`, no request digest — so on its own ANY preflight receipt the server
/// ever emitted verifies as the answer to ANY in-flight request. An attacker who can
/// substitute response bytes mints one on demand (send one unverifiable request, keep
/// the signed refusal) and injects it as the answer to a victim's call, which may
/// already have executed at the backend. That is the did-not-run/possibly-ran collapse
/// the exchange machine exists to prevent, delivered with a valid signature.
///
/// The one request-derived value such a receipt does carry is the digest of the bytes
/// the server received, in the response evidence block's `request_evidence` under the
/// `sha-256-received` alg. The block rides in the body, so the covered
/// `Content-Digest` and the verified response signature protect it: the server signed
/// this digest, and a substituted receipt cannot carry a value the signer did not
/// produce. Requiring it to equal the digest of the body THIS client sent narrows
/// "any receipt for any request" to "a receipt the server produced for these exact
/// request bytes".
///
/// It is a BYTE binding, not an instance binding: two transmissions of identical bytes
/// share it, and the request nonce lives in a header the unbound signature does not
/// cover. That residue is exactly why the outcome still reports `bound: false` — the
/// caller is told this receipt is not tied to this transmission, and must not treat it
/// as one. A receipt carrying no received-digest at all (`digest_alg: "none"`) is
/// about no request and cannot be an answer to this one.
fn check_unbound_receipt_is_about_this_request(
    response: &HttpResponse,
    request: &HttpRequest,
) -> Result<(), HttpProfileError> {
    let body: Value = serde_json::from_slice(&response.body)
        .map_err(|_| HttpProfileError::MalformedEvidence("rejection receipt body"))?;
    let evidence = body
        .get("_meta")
        .and_then(|meta| meta.get(mcp_re_http_profile::RESPONSE_EVIDENCE_BLOCK_KEY))
        .and_then(|block| block.get("request_evidence"))
        .ok_or(HttpProfileError::MalformedEvidence(
            "rejection receipt carries no request_evidence",
        ))?;
    let alg = evidence.get("digest_alg").and_then(Value::as_str);
    let value = evidence.get("digest_value").and_then(Value::as_str);
    let (Some(alg), Some(value)) = (alg, value) else {
        return Err(HttpProfileError::MalformedEvidence(
            "rejection receipt request_evidence is not a digest",
        ));
    };
    if alg != RECEIVED_DIGEST_ALG {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }
    if value != mcp_re_http_profile::content_digest_sha256(&request.body) {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }
    Ok(())
}

/// Verify the delegated-signed bodyless **202** a server returns for a one-way
/// message (#424), on the client. Returns the resolved server actor.
///
/// The serving path emits these in production for any JSON-RPC message with no `id`,
/// and until this existed nothing on the client side of the tree could check one — a
/// client had a signed acknowledgement it could only take on faith, which is the
/// posture MCP-RE exists to remove.
///
/// **What a verified 202 means: the enforcement boundary authenticated and accepted
/// the message.** It does NOT mean the action completed, or even started — a
/// `notifications/cancelled` that verifies here has been accepted for delivery, not
/// carried out. Treating it as completion is the misreading this doc exists to
/// prevent.
///
/// **Its binding is INSTANCE-level** (see
/// `docs/spec/http-profile-conformance-notes.md` §3.4): the acknowledgement covers
/// `mcp-re-request-evidence`, the digest of the request's own signature base, which
/// includes the request nonce. A 202 for transmission A therefore does NOT verify for a
/// distinct transmission A′, even when A and A′ carry identical method, target and body
/// bytes — so a client may read a verified 202 as proof that THIS transmission reached
/// the boundary, not merely that identical content did at some unspecified time.
///
/// Same trust input as [`verify_delegated_response`]: one [`DelegatedResponseTrust`]
/// authority supplies both the ROOT ISSUER anchor for the `Response` slot and the
/// revocation decision, and the credential must satisfy `policy` (audience scope,
/// accepted epochs, skew).
pub fn verify_delegated_accepted_202(
    response: &HttpResponse,
    request: &HttpRequest,
    trust: &dyn DelegatedResponseTrust,
    policy: &DelegationPolicy,
    now: i64,
) -> Result<ResolvedActor, HttpProfileError> {
    verify_delegated_accepted_202_pinned(response, request, trust, policy, None, now)
}

/// [`verify_delegated_accepted_202`] with the route's PINNED server signer enforced.
///
/// `expected_issuer_kid` is the same coordinate the bodied path pins
/// (`check_expected_server_signer`): the credential's ROOT ISSUER kid, not the
/// delegated kid that rotates every TTL. A verifying acknowledgement from some OTHER
/// server whose credential chains to any trusted anchor and is scoped to this
/// audience fails closed with `ResponseBindingMismatch`, exactly as it does on the
/// bodied path — without this the pin was enforced on replies and silently absent on
/// one-way notifications, so an operator's configured control read as enabled and did
/// not run on half the traffic.
///
/// The kid is taken from the VERIFIED product, never re-read from the wire: the credential
/// header is a COVERED component of the 202's signature (an uncovered one is refused), the
/// root signature covers the JWS header, and the credential verifier requires
/// `header.kid == claims.issuer_kid` — so
/// [`AcknowledgedDelegation::issuer_kid`](mcp_re_http_profile::AcknowledgedDelegation::issuer_kid)
/// is the anchor the response provably chained to, and there is no second reader of the
/// raw bytes to disagree with the first.
pub fn verify_delegated_accepted_202_pinned(
    response: &HttpResponse,
    request: &HttpRequest,
    trust: &dyn DelegatedResponseTrust,
    policy: &DelegationPolicy,
    expected_issuer_kid: Option<&str>,
    now: i64,
) -> Result<ResolvedActor, HttpProfileError> {
    let audiences: Vec<&str> = policy
        .verifier_audiences
        .iter()
        .map(String::as_str)
        .collect();
    let epochs: Vec<&str> = policy.accepted_epochs.iter().map(String::as_str).collect();
    let verifier_policy = policy.verifier_policy();
    let expect = DelegationExpectations {
        verifier_audiences: &audiences,
        expected_audience_hash: policy.expected_audience_hash.as_str(),
        accepted_epochs: &epochs,
        max_clock_skew: policy.bounded_clock_skew(),
    };
    let is_revoked = |identifier: &str| trust.is_revoked(identifier);
    let resolve_actor = |kid: &str, slot: SignerSlot| trust.resolve_issuer(kid, slot, now);
    let acknowledged = mcp_re_http_profile::verify_delegated_accepted_202(
        response,
        request,
        &Verifier::new(&verifier_policy, &resolve_actor),
        &expect,
        &is_revoked,
        now,
    )?;
    // The pin is compared against the VERIFIED product's anchor. This used to re-parse the
    // response's own credential header — untrusted bytes read to answer a question the
    // verifier had just answered — so the pin depended on the second reader agreeing with
    // the first about which of two credential headers to believe.
    if let Some(pinned) = expected_issuer_kid {
        if acknowledged.issuer_kid() != pinned {
            return Err(HttpProfileError::ResponseBindingMismatch);
        }
    }
    Ok(acknowledged.into_actor())
}

#[cfg(test)]
mod delegated_tests {
    use super::*;
    use crate::build_signed_request;
    use crate::delegated_trust::RevocationSource;
    use crate::delegated_trust::StaticRevocationList;
    use crate::delegated_trust::TrustedIssuerSet;
    use crate::execution_contract::ExecutionStatus;
    use crate::execution_contract::RetrySafety;
    use crate::RequestSigningInputs;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::build_delegated_rejection;
    use mcp_re_http_profile::build_delegated_rejection_preflight;
    use mcp_re_http_profile::sign_response_full;
    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::AudienceTuple;
    use mcp_re_http_profile::CustodyConfig;
    use mcp_re_http_profile::DelegatedSigningCustody;
    use mcp_re_http_profile::DelegationClaims;
    use mcp_re_http_profile::DelegationHeader;
    use mcp_re_http_profile::RejectionReason;
    use mcp_re_http_profile::PROFILE_TAG;
    use serde_json::json;
    use serde_json::Map;

    const ROOT_SEED: [u8; 32] = [33u8; 32];
    const CLIENT_SEED: [u8; 32] = [11u8; 32];
    const CLIENT_KEY_ID: &str = "client-key-1";
    const ROOT_KID: &str = "root-kid";
    const AUD: &str = "verifier-1";
    const AUD_SCOPE: &str = "aud-scope-1";
    const EPOCH: &str = "epoch-1";
    const TARGET: &str = "https://mcp.example.com/mcp?route=a";
    const NOW: i64 = 1_700_000_100;
    const CREATED: i64 = 1_700_000_000;
    const EXPIRES: i64 = 1_700_000_300;

    fn root_key() -> SigningKey {
        SigningKey::from_seed_bytes(&ROOT_SEED)
    }
    fn client_key() -> SigningKey {
        SigningKey::from_seed_bytes(&CLIENT_SEED)
    }
    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        }
    }
    /// A real, structurally valid artifact binding. `artifact_bindings` is required
    /// and non-empty — `build_signed_request` refuses to sign an empty set, since the
    /// verifier would reject it as `malformed_evidence` — so these tests supply one
    /// rather than relying on a request no server could accept.
    fn bindings() -> Vec<crate::ArtifactBinding> {
        vec![crate::ArtifactBinding::opaque_digest(
            crate::ArtifactType::OauthDpop,
            b"access-token-under-test",
        )]
    }
    /// One [`DelegatedResponseTrust`] over the test root plus a chosen revocation set.
    ///
    /// The tests used to pass a resolver and a revocation list as two arguments. They
    /// cannot any more, and that is the point of MCPRE-172: the pairing a caller could
    /// get wrong is no longer expressible, in a test or in production.
    struct TestTrust {
        revoked: StaticRevocationList,
    }

    impl RevocationSource for TestTrust {
        fn is_revoked(&self, identifier: &str) -> bool {
            self.revoked.is_revoked(identifier)
        }
    }

    impl DelegatedResponseTrust for TestTrust {
        fn resolve_issuer(&self, issuer_kid: &str, slot: SignerSlot, _now: i64) -> ResolverOutcome {
            resolver()(issuer_kid, slot).into()
        }
    }

    /// The test root, with `revoked` as the delegated-identifier revocation half.
    fn trust_with(revoked: StaticRevocationList) -> TestTrust {
        TestTrust { revoked }
    }

    /// The client's trust seam: the ROOT issuer key (by its issuer kid) for the
    /// Response slot. The delegated key is authorized by the credential alone.
    fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
        move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
            (ROOT_KID, SignerSlot::Response) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "server".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:server".into(),
                    keyid: ROOT_KID.into(),
                },
                verification_key: root_key().public_key(),
                slot,
            }),
            _ => None,
        }
    }
    fn policy() -> DelegationPolicy {
        DelegationPolicy::new(
            vec![AUD.to_string()],
            AUD_SCOPE,
            vec![EPOCH.to_string()],
            60,
        )
    }
    fn custody_cfg() -> CustodyConfig {
        CustodyConfig {
            issuer_kid: ROOT_KID.into(),
            iss: "did:example:server".into(),
            profile: PROFILE_TAG.into(),
            aud: AUD.into(),
            audience_hash: AUD_SCOPE.into(),
            trust_epoch: EPOCH.into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            ttl: 300,
            overlap: 60,
        }
    }
    fn custody() -> DelegatedSigningCustody<
        impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
        impl FnMut() -> SigningKey,
    > {
        let root = root_key();
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(mcp_re_http_profile::issue_delegation_credential(
                &root, h, c,
            ))
        };
        let mut n = 100u8;
        let factory = move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        };
        DelegatedSigningCustody::new(custody_cfg(), issue, factory)
    }
    fn signed() -> crate::SignedRequest {
        let inputs = RequestSigningInputs::new(
            CLIENT_KEY_ID.to_string(),
            audience(),
            bindings(),
            "nonce-1-padded-to-the-128-bit-floor",
            CREATED,
            EXPIRES,
        );
        let params: Map<String, Value> = json!({ "name": "read" }).as_object().cloned().unwrap();
        build_signed_request(
            &json!(1),
            "tools/call",
            params,
            TARGET,
            &inputs,
            &client_key(),
        )
        .expect("client signs request")
    }
    fn expectation(signed: &crate::SignedRequest) -> ResponseExpectation {
        ResponseExpectation::new(signed.request().clone(), signed.evidence().clone())
    }
    fn success_body() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
    }

    #[test]
    fn delegated_success_is_verified_and_classified() {
        let signed = signed();
        let mut custody = custody();
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(NOW, &mut resp, signed.request(), signed.evidence())
            .expect("server delegated-signs the success response");
        let out = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect("client verifies delegated success");
        assert_eq!(out.outcome, DelegatedOutcome::Success);
        // The delegated key is profile-issued, so its keyid is the RFC 7638 JWK
        // thumbprint of the key that actually signed (#415 rev 2 §1.5) — derived
        // from the key material, not from an issuer-private counter.
        let snap = custody.active_snapshot().expect("a key is active");
        assert_eq!(
            out.verified.server_signer().keyid,
            mcp_re_http_profile::jwk_thumbprint_ed25519(&snap.key.public_key().to_b64url()),
        );
    }

    /// C004b: the signer pin is ENFORCED on the delegated path, against the credential's
    /// ROOT ISSUER kid. It was previously enforced only in `verify_signed_response`
    /// (pre-052 direct-root), so every production caller got no enforcement while the
    /// control read as enabled; the interim behaviour refused any set pin outright, which
    /// was an honest holding position but not a control.
    #[test]
    fn delegated_success_enforces_the_pin_against_the_root_issuer() {
        let signed = signed();
        let mut custody = custody();
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(NOW, &mut resp, signed.request(), signed.evidence())
            .expect("server delegated-signs the success response");

        // No pin: verifies exactly as before (no behaviour change for the normal path).
        let ok = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect("an unpinned delegated success still verifies");
        assert_eq!(ok.outcome, DelegatedOutcome::Success);

        // The verified evidence reports the anchor the credential chained to.
        assert_eq!(ok.verified.delegation_issuer_kid(), ROOT_KID);

        // A pin on the ROOT ISSUER verifies — the coordinate that is stable across
        // delegated-key rotation.
        let pinned = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed).with_expected_server_signer(ROOT_KID),
            &policy(),
            NOW,
        )
        .expect("a pin naming the root issuer verifies");
        assert_eq!(pinned.outcome, DelegatedOutcome::Success);

        // Any other root fails closed.
        let err = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed).with_expected_server_signer("some-other-root-kid"),
            &policy(),
            NOW,
        )
        .expect_err("a pin naming a different root must fail closed");
        assert_eq!(err, HttpProfileError::ResponseBindingMismatch);

        // And NOT against the accepted signer keyid: that is the ephemeral delegated
        // kid, so pinning it would break on the first rotation.
        let delegated_kid = ok.verified.server_signer().keyid.clone();
        assert_ne!(delegated_kid, ROOT_KID);
        let err = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed).with_expected_server_signer(&delegated_kid),
            &policy(),
            NOW,
        )
        .expect_err("the pin binds to the issuer, not to the rotating delegated kid");
        assert_eq!(err, HttpProfileError::ResponseBindingMismatch);
    }

    /// The same enforcement applies to rejection receipts — a receipt is evidence too,
    /// so a pin must reach it.
    #[test]
    fn delegated_rejection_enforces_the_pin_against_the_root_issuer() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new("mcp-re.replay_detected", "replayed");
        let resp = build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            409,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds bound delegated rejection");
        verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed).with_expected_server_signer(ROOT_KID),
            &policy(),
            NOW,
        )
        .expect("a receipt whose credential chains to the pinned root verifies");
        let err = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed).with_expected_server_signer("some-other-root-kid"),
            &policy(),
            NOW,
        )
        .expect_err("a pin naming a different root must fail closed on a receipt too");
        assert_eq!(err, HttpProfileError::ResponseBindingMismatch);
    }

    #[test]
    fn delegated_bound_rejection_is_verified_and_classified() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new("mcp-re.replay_detected", "replayed");
        let resp = build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            409,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds bound delegated rejection");
        let out = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect("client verifies bound rejection");
        assert_eq!(
            out.outcome,
            DelegatedOutcome::Rejection {
                wire_code: Some("mcp-re.replay_detected".into()),
                execution: ExecutionContract::default(),
            }
        );
    }

    #[test]
    fn delegated_preflight_rejection_is_verified_unbound() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new("mcp-re.request_signature_invalid", "bad request");
        let resp = build_delegated_rejection_preflight(
            Some(signed.request()),
            &reason,
            403,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds preflight delegated rejection");
        let out = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect("client verifies preflight rejection unbound");
        assert_eq!(
            out.outcome,
            DelegatedOutcome::Rejection {
                wire_code: Some("mcp-re.request_signature_invalid".into()),
                execution: ExecutionContract::default(),
            }
        );
    }

    /// A preflight-unbound receipt the server minted for SOMEBODY ELSE'S request must
    /// not verify as the answer to this one.
    ///
    /// The unbound signature covers only response components, so before the
    /// received-digest check every preflight receipt the server ever emitted was a
    /// valid, freshness-current, audience-scoped refusal of any in-flight request — and
    /// one is trivially minted on demand by sending a single unverifiable request. The
    /// victim's call may already have executed at the backend.
    #[test]
    fn a_preflight_receipt_for_another_request_is_not_an_answer_to_this_one() {
        let mine = signed();
        // A different request: different params, so different body bytes.
        let inputs = RequestSigningInputs::new(
            CLIENT_KEY_ID.to_string(),
            audience(),
            bindings(),
            "nonce-2-padded-to-the-128-bit-floor",
            CREATED,
            EXPIRES,
        );
        let params: Map<String, Value> = json!({ "name": "attacker-chosen" })
            .as_object()
            .cloned()
            .unwrap();
        let theirs = build_signed_request(
            &json!(99),
            "tools/call",
            params,
            TARGET,
            &inputs,
            &client_key(),
        )
        .expect("the attacker signs its own request");
        assert_ne!(mine.request().body, theirs.request().body);

        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new("mcp-re.request_signature_invalid", "bad request");
        // The receipt the server genuinely emitted for the ATTACKER's request.
        let spliced = build_delegated_rejection_preflight(
            Some(theirs.request()),
            &reason,
            403,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds a preflight rejection for the attacker's request");

        // Presented as the answer to MY request, it must fail closed rather than
        // arriving as an authoritative denial of a call that may already have run.
        let err = verify_delegated_response(
            &spliced,
            &trust_with(StaticRevocationList::new()),
            &expectation(&mine),
            &policy(),
            NOW,
        )
        .expect_err("a receipt about another request must not answer this one");
        assert_eq!(err, HttpProfileError::ResponseBindingMismatch);

        // And the receipt the server produced for MY bytes still verifies, so the guard
        // refuses splicing rather than the preflight path itself.
        let mine_receipt = build_delegated_rejection_preflight(
            Some(mine.request()),
            &reason,
            403,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds a preflight rejection for this request");
        let out = verify_delegated_response(
            &mine_receipt,
            &trust_with(StaticRevocationList::new()),
            &expectation(&mine),
            &policy(),
            NOW,
        )
        .expect("the receipt for this request's bytes still verifies");
        assert!(matches!(out.outcome, DelegatedOutcome::Rejection { .. }));
    }

    /// A receipt with NO received-digest is about no request at all, so it cannot be
    /// the answer to this one — the generic-receipt form of the same splice.
    #[test]
    fn a_preflight_receipt_about_no_request_answers_nothing() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new("mcp-re.request_signature_invalid", "bad request");
        let generic = build_delegated_rejection_preflight(
            None,
            &reason,
            403,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds a receipt with no request context");
        let err = verify_delegated_response(
            &generic,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect_err("a receipt about no request must not answer this one");
        assert_eq!(err, HttpProfileError::ResponseBindingMismatch);
    }

    /// SL-10: the execution/retry contract the server derives from its exchange machine
    /// reaches the client as typed state, not only as a wire code.
    ///
    /// Without it a post-dispatch refusal is indistinguishable from an ordinary outage,
    /// and the caller's retry re-executes a tool call that already ran.
    #[test]
    fn a_post_dispatch_rejection_carries_its_execution_and_retry_contract() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new("mcp-re.upstream_unavailable", "backend already ran")
            .with_execution(mcp_re_http_profile::ExecutionDisposition::PossiblyExecuted);
        let resp = build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            503,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds a post-dispatch rejection");
        let out = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect("client verifies the receipt");
        let DelegatedOutcome::Rejection { execution, .. } = &out.outcome else {
            panic!("a 503 receipt is a rejection, got {:?}", out.outcome);
        };
        assert!(execution.is_stated());
        assert_eq!(execution.execution(), ExecutionStatus::PossiblyExecuted);
        assert_eq!(execution.retry(), RetrySafety::UnsafeWithoutReconciliation);
        assert!(execution.retry_is_refused());

        // The destroyed-approval case is a DIFFERENT remedy and must not read as the
        // reconciliation one: nothing ran, but the retry needs a new elicitation.
        let reason = RejectionReason::new("mcp-re.evidence_retention_unavailable", "no store")
            .with_execution(
                mcp_re_http_profile::ExecutionDisposition::ApprovalSpentNothingExecuted,
            );
        let resp = build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            503,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds an approval-spent rejection");
        let out = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect("client verifies the receipt");
        let DelegatedOutcome::Rejection { execution, .. } = &out.outcome else {
            panic!("a 503 receipt is a rejection");
        };
        assert_eq!(execution.execution(), ExecutionStatus::NotExecuted);
        assert_eq!(execution.retry(), RetrySafety::UnsafeWithoutNewElicitation);
        assert!(execution.continuation_consumed());
        assert!(execution.retry_is_refused());
    }

    /// An UNSTATED contract is not a statement that nothing ran. Collapsing the two is
    /// how "unknown whether it ran" becomes "safe to retry" at the one call site that
    /// decides.
    #[test]
    fn an_unstated_contract_is_not_a_did_not_run_verdict() {
        let empty = ExecutionContract::default();
        assert!(!empty.is_stated());
        assert_eq!(empty.execution(), ExecutionStatus::Unstated);
        assert_ne!(empty.execution(), ExecutionStatus::NotExecuted);
        assert_eq!(empty.retry(), RetrySafety::Unstated);
        assert!(!empty.continuation_consumed());
        assert!(!empty.retention_failed());

        // A token this client does not know is a statement it did not understand —
        // never absence, and never permission.
        let unknown = ExecutionContract {
            execution_status: Some("something_new".into()),
            retry_safety: Some("also_new".into()),
            ..ExecutionContract::default()
        };
        assert!(unknown.is_stated());
        assert!(matches!(
            unknown.execution(),
            ExecutionStatus::Unrecognized(_)
        ));
        assert!(matches!(unknown.retry(), RetrySafety::Unrecognized(_)));
        assert!(unknown.retry_is_refused());
    }

    /// `evidence_retention_indeterminate` says one thing more than the generic
    /// post-dispatch case: the audit store has no record of a call that may have run.
    #[test]
    fn a_retention_failure_is_readable_as_such() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new(
            mcp_re_core::McpReError::EvidenceRetentionIndeterminate.wire_code(),
            "the evidence write failed after dispatch",
        );
        let resp = build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            500,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds a retention-indeterminate rejection");
        let out = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect("client verifies the receipt");
        let DelegatedOutcome::Rejection { execution, .. } = &out.outcome else {
            panic!("a 500 receipt is a rejection");
        };
        assert_eq!(execution.execution(), ExecutionStatus::PossiblyExecuted);
        assert!(execution.retention_failed());
        assert!(execution.retry_is_refused());
    }

    #[test]
    fn direct_root_success_is_rejected_no_credential() {
        // A pre-052 directly-root-signed 200 has no inline credential — the delegated
        // verifier fails closed (no direct-root fallback).
        let signed = signed();
        let server_identity = ActorIdentity {
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:server".into(),
            keyid: ROOT_KID.into(),
        };
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        sign_response_full(
            &mut resp,
            signed.request(),
            signed.evidence(),
            &server_identity,
            &root_key(),
            ROOT_KID,
            NOW,
            NOW + 300,
        )
        .expect("server directly root-signs");
        let err = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationCredentialMissing);
    }

    #[test]
    fn unsigned_response_is_rejected() {
        // The server's last-resort unsigned error (no RFC 9421 signature) must never
        // be accepted in delegated-required mode.
        let signed = signed();
        let resp = HttpResponse {
            status: 503,
            headers: vec![("content-type".into(), "application/json".into())],
            body: json!({
                "jsonrpc": "2.0",
                "error": { "code": -32001, "message": "mcp-re.delegated_signing_unavailable" },
                "id": Value::Null,
            })
            .to_string()
            .into_bytes(),
        };
        assert!(verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW
        )
        .is_err());
    }

    #[test]
    fn unbound_signature_is_not_accepted_as_success() {
        // An unbound (response-only) signature presented with a 2xx status must be
        // rejected: a success MUST carry the `;req` request binding.
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new("mcp-re.request_signature_invalid", "x");
        // Build an UNBOUND signature but stamp a success status onto it.
        let mut resp = build_delegated_rejection_preflight(
            Some(signed.request()),
            &reason,
            200,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("build unbound response");
        resp.status = 200;
        assert!(verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &policy(),
            NOW
        )
        .is_err());
    }

    // ---- revocation seam (ADR-MCPRE-052 §3 step 7, MCPRE-122) ----------------

    /// A signed 200 whose delegated key is on the client's denylist fails closed with
    /// `DelegationRevoked` — even though the signature and credential are otherwise
    /// valid and fresh.
    #[test]
    fn revoked_delegated_kid_rejects_success() {
        let signed = signed();
        let mut custody = custody();
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(NOW, &mut resp, signed.request(), signed.evidence())
            .expect("server delegated-signs the success response");
        let kid = custody.active_snapshot().unwrap().delegated_kid;
        let revoked = StaticRevocationList::new().revoke(kid);
        let err = verify_delegated_response(
            &resp,
            &trust_with(revoked),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationRevoked);
    }

    /// Revoking the ROOT issuer kid rejects every credential it anchors.
    #[test]
    fn revoked_issuer_kid_rejects_success() {
        let signed = signed();
        let mut custody = custody();
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(NOW, &mut resp, signed.request(), signed.evidence())
            .expect("sign");
        let revoked = StaticRevocationList::new().revoke(ROOT_KID);
        let err = verify_delegated_response(
            &resp,
            &trust_with(revoked),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationRevoked);
    }

    /// Revoking the credential's `jti` (not a kid) also fails closed — the client
    /// entry point forwards the jti to the revocation seam, not only the delegated
    /// and issuer kids. The jti is minted inside custody; we read it back from the
    /// key-lifecycle audit to revoke the exact value on the wire.
    #[test]
    fn revoked_by_jti_rejects_success() {
        let signed = signed();
        let mut custody = custody();
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(NOW, &mut resp, signed.request(), signed.evidence())
            .expect("server delegated-signs the success response");
        let jti = custody
            .audit()
            .last()
            .expect("an issued key-lifecycle event carrying the credential jti")
            .jti
            .clone();
        assert!(!jti.is_empty(), "the credential carries a jti to revoke by");
        let revoked = StaticRevocationList::new().revoke(jti);
        let err = verify_delegated_response(
            &resp,
            &trust_with(revoked),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationRevoked);
    }

    /// A non-empty denylist that does NOT name this credential still verifies — the
    /// seam is real (it says no), not a blanket deny.
    #[test]
    fn non_revoked_credential_verifies_with_nonempty_list() {
        let signed = signed();
        let mut custody = custody();
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(NOW, &mut resp, signed.request(), signed.evidence())
            .expect("sign");
        let revoked = StaticRevocationList::from_identifiers([
            "some-other/delegated/9".to_string(),
            "unrelated-root".to_string(),
        ]);
        assert!(!revoked.is_empty());
        let out = verify_delegated_response(
            &resp,
            &trust_with(revoked),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .expect("verifies — this credential is not on the denylist");
        assert_eq!(out.outcome, DelegatedOutcome::Success);
    }

    /// A rejection RECEIPT signed with a revoked delegated key is itself rejected —
    /// revocation fails closed on the return leg too (a revoked key cannot even deliver
    /// a trustworthy denial).
    #[test]
    fn revoked_delegated_key_rejection_receipt_is_rejected() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason::new("mcp-re.replay_detected", "replayed");
        let resp = build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            409,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds bound delegated rejection");
        let revoked = StaticRevocationList::new().revoke(snap.delegated_kid.clone());
        let err = verify_delegated_response(
            &resp,
            &trust_with(revoked),
            &expectation(&signed),
            &policy(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationRevoked);
    }

    // ---- the configured skew is BOUNDED on both windows ----------------------

    /// The credential's `nbf`/`exp` window is widened by the configured skew and had no
    /// cap of its own: `DelegationExpectations.max_clock_skew` reached
    /// `DelegationVerifyParams` raw. An operator who set a week got a week on the
    /// credential window — the TTL that bounds a compromised delegated key's exposure —
    /// while the signature gate they could observe was silently clamped, so testing the
    /// setting showed nothing wrong.
    ///
    /// The response signature here is fresh at the verification instant; only the
    /// CREDENTIAL is stale, so the failure this asserts is the credential window's.
    #[test]
    fn an_out_of_range_skew_cannot_widen_the_credential_window() {
        // A request whose own window brackets the (much later) verification instant.
        let inputs = RequestSigningInputs::new(
            CLIENT_KEY_ID.to_string(),
            audience(),
            bindings(),
            "nonce-skew-padded-to-the-128-bit-floor",
            CREATED,
            NOW + 100_000,
        );
        let params: Map<String, Value> = json!({ "name": "read" }).as_object().cloned().unwrap();
        let signed = build_signed_request(
            &json!(1),
            "tools/call",
            params,
            TARGET,
            &inputs,
            &client_key(),
        )
        .expect("client signs request");

        // A credential issued long ago: ttl is 300s, so it expired 3300s before `late`.
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let late = NOW + 3600;
        assert!(
            snap.exp < late - 300,
            "the credential is stale by > the bound"
        );

        // The receipt is signed AT `late`, so its RFC 9421 freshness window is current.
        let reason = RejectionReason::new("mcp-re.replay_detected", "replayed");
        let resp = build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            409,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            late,
            late + 300,
        )
        .expect("server signs a fresh receipt off a stale credential");

        let a_week = DelegationPolicy::new(
            vec![AUD.to_string()],
            AUD_SCOPE,
            vec![EPOCH.to_string()],
            604_800,
        );
        // The BEHAVIOUR first: what the credential window does, not what the accessor
        // returns. Unclamped, 604800s of tolerance swallows the 3300s the credential is
        // past `exp` and this verification succeeds.
        let err = verify_delegated_response(
            &resp,
            &trust_with(StaticRevocationList::new()),
            &expectation(&signed),
            &a_week,
            late,
        )
        .expect_err("a week of skew must not honour a credential 3300s past exp");
        assert_eq!(err, HttpProfileError::DelegationCredentialExpired);

        assert_eq!(
            a_week.bounded_clock_skew(),
            mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
            "the configured value is clamped, not passed through",
        );
        // And the same clamped number reaches the signature gate, so the two windows
        // are one policy rather than 30s on one and a week on the other.
        assert_eq!(
            a_week.verifier_policy().max_clock_skew(),
            mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
        );
        // A negative configured value clamps to zero rather than narrowing asymmetrically.
        assert_eq!(
            DelegationPolicy::new(vec![], "", vec![], -5).bounded_clock_skew(),
            0
        );
    }

    // ---- the trust picture's own expiry -------------------------------------

    /// The manifest `expires_at` gate lived only at load time, so a client that does not
    /// refresh verified forever against a document the org stopped standing behind. Once
    /// the set carries the deadline, every root in it stops resolving at `now > expires_at`
    /// — the check is part of the verification rather than of a background loop.
    #[test]
    fn an_expired_trust_picture_stops_resolving_its_roots() {
        let signed = signed();
        let mut custody = custody();
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(NOW, &mut resp, signed.request(), signed.evidence())
            .expect("server delegated-signs the success response");

        let root = ResolvedActor {
            identity: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: ROOT_KID.into(),
            },
            verification_key: root_key().public_key(),
            slot: SignerSlot::Response,
        };
        let live = TrustedIssuerSet::new().with_current(root.clone());
        // A hand-assembled set has no document behind it and no deadline to enforce.
        assert!(live.manifest_expires_at().is_none());
        verify_delegated_response(&resp, &live, &expectation(&signed), &policy(), NOW)
            .expect("a set with no expiry verifies");

        let published = TrustedIssuerSet::new()
            .with_current(root)
            .with_manifest_expiry(NOW + 60);
        assert!(published.resolve_root(ROOT_KID, NOW).is_some());
        verify_delegated_response(&resp, &published, &expectation(&signed), &policy(), NOW)
            .expect("inside the document's window it verifies exactly as before");

        // One second past the document's own deadline nothing in it resolves.
        assert!(published.is_expired(NOW + 61));
        assert!(published.resolve_root(ROOT_KID, NOW + 61).is_none());
        let err = verify_delegated_response(
            &resp,
            &published,
            &expectation(&signed),
            &policy(),
            NOW + 61,
        )
        .expect_err("an expired trust picture must not verify a response");
        assert_eq!(err, HttpProfileError::DelegationIssuerUntrusted);
    }

    // ---- the route's pin on the one-way notification leg ---------------------

    /// The signed bodyless 202 that acknowledges a notification. The bodied path pins
    /// the credential's ROOT ISSUER; this leg took no expectation at all, so on a route
    /// with a pinned server any holder of a delegated key under ANY trusted root could
    /// acknowledge that route's `notifications/cancelled` and the client reported it as
    /// accepted.
    #[test]
    fn a_pinned_route_refuses_a_202_from_another_root() {
        let inputs = RequestSigningInputs::new(
            CLIENT_KEY_ID.to_string(),
            audience(),
            bindings(),
            "nonce-202-padded-to-the-128-bit-floor",
            CREATED,
            EXPIRES,
        );
        let params: Map<String, Value> = json!({ "reason": "user cancelled" })
            .as_object()
            .cloned()
            .unwrap();
        let notification = crate::build_signed_notification(
            "notifications/cancelled",
            params,
            TARGET,
            &inputs,
            &client_key(),
        )
        .expect("client signs the notification");

        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let ack = mcp_re_http_profile::sign_delegated_accepted_202(
            notification.request(),
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("the boundary signs the acknowledgement");

        // Unpinned: verifies, as it always did.
        verify_delegated_accepted_202_pinned(
            &ack,
            notification.request(),
            &trust_with(StaticRevocationList::new()),
            &policy(),
            None,
            NOW,
        )
        .expect("an unpinned route still accepts a well-formed acknowledgement");

        // Pinned to the root this credential chains to: verifies.
        verify_delegated_accepted_202_pinned(
            &ack,
            notification.request(),
            &trust_with(StaticRevocationList::new()),
            &policy(),
            Some(ROOT_KID),
            NOW,
        )
        .expect("the acknowledgement chains to the pinned root");

        // Pinned to a different root: fails closed, exactly as on the bodied path.
        let err = verify_delegated_accepted_202_pinned(
            &ack,
            notification.request(),
            &trust_with(StaticRevocationList::new()),
            &policy(),
            Some("some-other-root-kid"),
            NOW,
        )
        .expect_err("a 202 from an unpinned root must not acknowledge this route");
        assert_eq!(err, HttpProfileError::ResponseBindingMismatch);

        // And the pin is NOT the rotating delegated kid — pinning that would break on
        // the first rotation and says nothing about which server answered.
        let err = verify_delegated_accepted_202_pinned(
            &ack,
            notification.request(),
            &trust_with(StaticRevocationList::new()),
            &policy(),
            Some(&snap.delegated_kid),
            NOW,
        )
        .expect_err("the pin binds to the issuer, not to the delegated kid");
        assert_eq!(err, HttpProfileError::ResponseBindingMismatch);
    }

    /// After rotation, a response signed by the NEW delegated key verifies even while
    /// the OLD key is revoked — revocation of a retired key does not break serving.
    #[test]
    fn rotation_to_new_delegated_key_succeeds_when_old_revoked() {
        // A request whose freshness window brackets the post-rotation serve instant.
        let inputs = RequestSigningInputs::new(
            CLIENT_KEY_ID.to_string(),
            audience(),
            bindings(),
            "nonce-rot-padded-to-the-128-bit-floor",
            CREATED,
            NOW + 600,
        );
        let params: Map<String, Value> = json!({ "name": "read" }).as_object().cloned().unwrap();
        let signed = build_signed_request(
            &json!(1),
            "tools/call",
            params,
            TARGET,
            &inputs,
            &client_key(),
        )
        .expect("client signs request");

        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue key/1");
        let kid1 = custody.active_snapshot().unwrap().delegated_kid;

        // Advance past exp - overlap (300 - 60 = 240) so sign_response rotates to key/2.
        let rot = NOW + 250;
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(rot, &mut resp, signed.request(), signed.evidence())
            .expect("server signs with the rotated key");
        let kid2 = custody.active_snapshot().unwrap().delegated_kid;
        assert_ne!(kid2, kid1, "rotation must mint a new delegated kid");

        // Old key revoked; the new (active) key is not.
        let revoked = StaticRevocationList::new().revoke(kid1);
        let out = verify_delegated_response(
            &resp,
            &trust_with(revoked),
            &expectation(&signed),
            &policy(),
            rot,
        )
        .expect("response on the rotated key verifies while the old key is revoked");
        assert_eq!(out.outcome, DelegatedOutcome::Success);
    }
}
