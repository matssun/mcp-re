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

use mcp_re_http_profile::verify_delegated_response_bound_full;
use mcp_re_http_profile::verify_delegated_response_unbound;
use mcp_re_http_profile::verify_response_bound_full;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpResponseEvidence;
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;

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
/// returns the [`VerifiedHttpResponseEvidence`]; on any failure the precise frozen
/// [`HttpProfileError`], fail-closed.
pub fn verify_signed_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    expectation: &ResponseExpectation,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    let verified = verify_response_bound_full(
        response,
        &expectation.request,
        &expectation.request_evidence,
        resolve_actor,
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
    verified: &VerifiedHttpResponseEvidence,
) -> Result<(), HttpProfileError> {
    if let Some(expected) = &expectation.expected_server_signer_keyid {
        if &verified.resolved_server_actor.identity.keyid != expected {
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
/// Fails closed if the verified evidence carries no issuer at all: reaching here means
/// the delegated path ran, so a missing issuer is a contradiction, and silently
/// accepting an unpinnable response would restore the very gap this closes.
fn check_expected_server_signer(
    expectation: &ResponseExpectation,
    verified: &VerifiedHttpResponseEvidence,
) -> Result<(), HttpProfileError> {
    let Some(pinned) = expectation.expected_server_signer_keyid.as_deref() else {
        return Ok(());
    };
    match verified.delegation_issuer_kid.as_deref() {
        Some(issuer) if issuer == pinned => Ok(()),
        _ => Err(HttpProfileError::ResponseBindingMismatch),
    }
}

/// A verified response plus its multi-round-trip classification (ADR-MCPS-047),
/// read from the signed, verified body.
#[derive(Debug, Clone)]
pub struct ClassifiedResponse {
    /// The verification verdict.
    pub verified: VerifiedHttpResponseEvidence,
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
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    expectation: &ResponseExpectation,
    now: i64,
) -> Result<ClassifiedResponse, HttpProfileError> {
    let verified = verify_signed_response(response, resolve_actor, expectation, now)?;
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

/// The client-side delegated-credential revocation seam (ADR-MCPRE-052 §3 step 7).
///
/// Consulted during delegated verification with EACH identifier the credential
/// presents — its `delegated_kid`, its `issuer_kid` (root anchor), and its `jti`
/// (per-credential id) — and reports whether ANY of them is revoked at the current
/// trust epoch. Revocation is checked in ADDITION to freshness: short delegated-key
/// TTLs bound the exposure window, and this seam narrows it to the moment of report.
///
/// This is deliberately a narrow, pure interface. The in-memory
/// [`StaticRevocationList`] covers the GKE proof and small deployments; a networked
/// source (a signed revocation feed, an OCSP-style responder with its own freshness
/// proof) implements the same trait later WITHOUT touching the verifier. Implementations
/// MUST be non-blocking — this is consulted on the response-verification path.
pub trait RevocationSource: Send + Sync {
    /// Report whether `identifier` (a `delegated_kid`, `issuer_kid`, or credential
    /// `jti`) is revoked at the current epoch. A conservative source MAY return `true`
    /// for an identifier it cannot resolve; an empty denylist reports `false` for all
    /// (TTL-only reliance — see [`StaticRevocationList::new`]).
    fn is_revoked(&self, identifier: &str) -> bool;
}

/// An in-memory static denylist of revoked identifiers — any mix of `delegated_kid`s,
/// root `issuer_kid`s, and credential `jti`s (ADR-MCPRE-052 §3 step 7). This is the
/// concrete seam a networked revocation feed replaces later; it is enough for the GKE
/// proof (exercise both allow and deny) and for deployments that publish a small,
/// operator-curated denylist.
///
/// An EMPTY list means "no identifier is revoked" — the explicit TTL-only posture. It
/// is a deliberate operator choice (constructed via [`StaticRevocationList::new`]), not
/// a silent default: a `DelegatedRequired` route cannot be built without SOME source.
#[derive(Debug, Clone, Default)]
pub struct StaticRevocationList {
    revoked: HashSet<String>,
}

impl StaticRevocationList {
    /// An empty denylist — nothing is revoked (explicit TTL-only reliance). The
    /// operator chooses this deliberately; it is never the implicit default of a
    /// delegated-required route.
    pub fn new() -> Self {
        StaticRevocationList {
            revoked: HashSet::new(),
        }
    }

    /// Build a denylist from an initial set of revoked identifiers (kids and/or jtis).
    pub fn from_identifiers<I, S>(identifiers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        StaticRevocationList {
            revoked: identifiers.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one revoked identifier (a `delegated_kid`, `issuer_kid`, or `jti`), builder
    /// style.
    pub fn revoke(mut self, identifier: impl Into<String>) -> Self {
        self.revoked.insert(identifier.into());
        self
    }

    /// Whether the denylist is empty (the TTL-only posture).
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

impl RevocationSource for StaticRevocationList {
    fn is_revoked(&self, identifier: &str) -> bool {
        self.revoked.contains(identifier)
    }
}

/// The client-side TRUST-ANCHOR lifecycle (ADR-MCPRE-052 root rotation + revocation)
/// — which ROOT issuers the verifier trusts to anchor a delegation credential, and
/// for how long. This is the MASTER-key analogue of [`StaticRevocationList`] (which
/// governs individual short-lived DELEGATED keys): this governs the ISSUER itself.
///
/// Trust-anchor rotation is NOT delegated-key rotation. A delegated key rotates every
/// few minutes under ONE root (the hot path); a root rotation swaps the anchor the
/// whole fleet chains to — a rare, high-stakes ceremony that needs a controlled
/// OVERLAP so credentials issued under the outgoing root keep verifying until a
/// cutover deadline, then stop. That overlap deadline is the mechanism a single
/// `issuer_kid -> key` map cannot express.
///
/// Four states per `issuer_kid`, evaluated at `now`:
///   * CURRENT — a live root; its credentials verify (subject to the usual scope /
///     freshness / epoch gates).
///   * RETIRED — a superseded root inside its overlap window; its credentials verify
///     ONLY while `now <= valid_until`, then resolve to untrusted
///     (`delegation_issuer_untrusted`). This is trust-anchor rotation.
///   * REVOKED — a compromised / withdrawn root; the ONE decisive action that
///     invalidates ALL its descendant delegated credentials at once
///     (`delegation_revoked`), even before their own `exp` and WITHOUT chasing each
///     delegated key. (Consulted via the [`RevocationSource`] impl below.)
///   * UNKNOWN — any other issuer; rejected `delegation_issuer_untrusted`.
///
/// The verifier core (`verify_delegation_credential`) is unchanged: this set feeds
/// its two existing seams — the `resolve_root` actor resolver (current + in-window
/// retired) and the `is_revoked` revocation source (revoked issuers). Because the
/// resolver is rebuilt per verification with the caller's injected `now`
/// ([`TrustedIssuerSet::response_resolver`]), the overlap window is enforced without
/// the pure verifier ever reading a clock.
#[derive(Debug, Clone, Default)]
pub struct TrustedIssuerSet {
    /// Live roots: `issuer_kid` -> the resolved ROOT actor (identity + pubkey).
    current: HashMap<String, ResolvedActor>,
    /// Superseded-but-overlapping roots: `issuer_kid` -> (actor, `valid_until` unix).
    retired: HashMap<String, (ResolvedActor, i64)>,
    /// Withdrawn / compromised roots (by `issuer_kid`).
    revoked: HashSet<String>,
}

impl TrustedIssuerSet {
    /// An empty set — trusts no root (every issuer is UNKNOWN → rejected). Roots are
    /// added deliberately; a delegated-required verifier cannot silently trust one.
    pub fn new() -> Self {
        TrustedIssuerSet::default()
    }

    /// Add a CURRENT (live) root, keyed by the actor's `keyid` (= the credential
    /// `issuer_kid`). The actor MUST be for the `Response` slot (it anchors the
    /// server/response signer).
    pub fn with_current(mut self, root: ResolvedActor) -> Self {
        self.current.insert(root.identity.keyid.clone(), root);
        self
    }

    /// Add a RETIRED root that remains trusted only through `valid_until` (unix
    /// seconds) — the overlap deadline. After it, credentials under this root resolve
    /// to untrusted.
    pub fn with_retired(mut self, root: ResolvedActor, valid_until: i64) -> Self {
        self.retired
            .insert(root.identity.keyid.clone(), (root, valid_until));
        self
    }

    /// Mark an `issuer_kid` REVOKED — one decisive action invalidating every
    /// descendant delegated credential immediately (`delegation_revoked`).
    pub fn revoke(mut self, issuer_kid: impl Into<String>) -> Self {
        self.revoked.insert(issuer_kid.into());
        self
    }

    /// Resolve an `issuer_kid` to its trusted ROOT actor AT `now`: a current root, or
    /// a retired root still inside its overlap window (`now <= valid_until`). A
    /// retired root past its window, or an unknown issuer, resolves to `None`
    /// (→ `delegation_issuer_untrusted`).
    ///
    /// A revoked-but-still-current/retired root DOES resolve here on purpose: the
    /// credential's signature is then checked and the [`RevocationSource`] impl
    /// rejects it as `delegation_revoked` (the honest reason), rather than masking a
    /// revocation as an untrusted-issuer error.
    pub fn resolve_root(&self, issuer_kid: &str, now: i64) -> Option<ResolvedActor> {
        // RETIREMENT WINS. A kid listed as both current and retiring is a contradiction
        // in the manifest, and reading `current` first resolved it in the permissive
        // direction: the root stayed trusted unconditionally and its `valid_until`
        // cutover was never evaluated — so a retirement an org published could be
        // undone by leaving the same kid in the current list. Checking the deadline
        // first makes the contradiction fail safe: past `valid_until` nothing resolves.
        if let Some((actor, valid_until)) = self.retired.get(issuer_kid) {
            return (now <= *valid_until).then(|| actor.clone());
        }
        self.current.get(issuer_kid).cloned()
    }

    /// A `resolve_actor` closure for [`verify_delegated_response`] that anchors the
    /// RESPONSE slot in this set at `now`. The Request slot is never resolved on the
    /// response-verification path, so it returns `None`. Rebuild it per verification
    /// with the current `now` so the overlap window is honoured.
    ///
    /// This resolver REFUSES a revoked issuer (`None` → `delegation_issuer_untrusted`)
    /// even though [`resolve_root`](Self::resolve_root) resolves one. A resolver handed
    /// to the verifier alone cannot know whether the caller ALSO wired this set in as
    /// the `revocation` argument, and if they did not, resolving a revoked root would
    /// verify its descendant credentials — revocation silently not applying because a
    /// value had to be passed twice to take effect. Refusing here makes the raw seam
    /// safe standing on its own.
    ///
    /// Prefer [`verify_delegated_response_anchored`], which takes the set ONCE, wires
    /// both seams itself, and can therefore afford to resolve a revoked root so the
    /// rejection carries the honest `delegation_revoked` reason instead of
    /// `delegation_issuer_untrusted`.
    pub fn response_resolver(
        &self,
        now: i64,
    ) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + '_ {
        move |kid: &str, slot: SignerSlot| match slot {
            SignerSlot::Response if !self.is_revoked(kid) => self.resolve_root(kid, now),
            _ => None,
        }
    }

    /// The resolver used by [`verify_delegated_response_anchored`], which pairs it with
    /// this same set as the revocation source. It DOES resolve a revoked root, so the
    /// credential's signature is checked and the revocation seam produces
    /// `delegation_revoked` — the honest reason — rather than masking a revocation as
    /// an untrusted issuer. Private: it is only safe because the caller is this
    /// module, which wires both seams together by construction.
    fn anchored_resolver(
        &self,
        now: i64,
    ) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + '_ {
        move |kid: &str, slot: SignerSlot| match slot {
            SignerSlot::Response => self.resolve_root(kid, now),
            _ => None,
        }
    }
}

impl RevocationSource for TrustedIssuerSet {
    fn is_revoked(&self, identifier: &str) -> bool {
        self.revoked.contains(identifier)
    }
}

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
    /// Clock-skew tolerance, seconds. Governs BOTH the credential window and the RFC
    /// 9421 response-signature freshness gate.
    ///
    /// It used to reach only the credential: both entry points built their
    /// `DelegationExpectations` with `VerifierPolicy::default()`, pinning the
    /// signature gate at the built-in 30s whatever the operator configured. A
    /// deployment that widened the skew for a real clock spread got it on one of the
    /// two windows and silently not the other.
    pub max_clock_skew: i64,
}

impl DelegationPolicy {
    /// The RFC 9421 signature-acceptance policy this delegation policy implies.
    ///
    /// One configured skew drives both windows. A skew outside the profile's bound
    /// falls back to the default rather than failing the verification: the value was
    /// already accepted into this struct, and refusing here would turn a
    /// misconfiguration into an unverifiable response.
    fn verifier_policy(&self) -> mcp_re_http_profile::VerifierPolicy {
        mcp_re_http_profile::VerifierPolicy::new(&["ed25519"], self.max_clock_skew)
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
/// carrying the server's frozen wire code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedOutcome {
    /// A delegated-signed, request-bound SUCCESS response.
    Success,
    /// A delegated-signed REJECTION receipt. `bound` distinguishes a request-bound
    /// receipt (the server verified the request before a later fail-closed step)
    /// from a preflight-unbound one (the request never earned a trustworthy hash).
    /// `wire_code` is the server's frozen `mcp-re.*` reason from the verified body.
    Rejection {
        bound: bool,
        wire_code: Option<String>,
    },
}

/// A verified delegated response: the verification evidence plus the outcome.
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedResponse {
    /// The verified response evidence (server signer, bound request evidence, …).
    pub verified: VerifiedHttpResponseEvidence,
    /// Success vs delegated rejection receipt (bound / preflight).
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
/// `resolve_actor` is the client's trust seam; `revocation` is the client-side
/// [`RevocationSource`] consulted with the credential's `delegated_kid`, `issuer_kid`,
/// and `jti` (an empty [`StaticRevocationList`] is the explicit TTL-only posture — the
/// deployment relies on short delegated-key TTLs alone).
pub fn verify_delegated_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    expectation: &ResponseExpectation,
    policy: &DelegationPolicy,
    revocation: &dyn RevocationSource,
    now: i64,
) -> Result<VerifiedDelegatedResponse, HttpProfileError> {
    let audiences: Vec<&str> = policy
        .verifier_audiences
        .iter()
        .map(String::as_str)
        .collect();
    let epochs: Vec<&str> = policy.accepted_epochs.iter().map(String::as_str).collect();
    let expect = DelegationExpectations {
        policy: policy.verifier_policy(),
        verifier_audiences: &audiences,
        expected_audience_hash: policy.expected_audience_hash.as_str(),
        accepted_epochs: &epochs,
        max_clock_skew: policy.max_clock_skew,
    };
    // Adapt the revocation seam to the http-profile verifier's closure form. The
    // verifier consults it with each identifier the credential carries.
    let is_revoked = |identifier: &str| revocation.is_revoked(identifier);
    let is_revoked = &is_revoked;

    // A SUCCESS must be request-bound. The server only ever signs success responses
    // with the `;req` binding, and a stripped-`;req` "success" changes the signature
    // base so no valid delegated signature can cover it — so this is a hard floor.
    if (200..300).contains(&response.status) {
        let verified = verify_delegated_response_bound_full(
            response,
            &expectation.request,
            &expectation.request_evidence,
            resolve_actor,
            &expect,
            is_revoked,
            now,
        )?;
        check_expected_server_signer(expectation, &verified)?;
        return Ok(VerifiedDelegatedResponse {
            verified,
            outcome: DelegatedOutcome::Success,
        });
    }

    // A REJECTION receipt: verify request-bound first, then preflight-unbound. Both
    // require the inline credential + a valid delegated signature, so an unsigned or
    // direct-root rejection fails closed here (no downgrade, no unsigned acceptance).
    match verify_delegated_response_bound_full(
        response,
        &expectation.request,
        &expectation.request_evidence,
        resolve_actor,
        &expect,
        is_revoked,
        now,
    ) {
        Ok(verified) => {
            check_expected_server_signer(expectation, &verified)?;
            Ok(VerifiedDelegatedResponse {
                verified,
                outcome: DelegatedOutcome::Rejection {
                    bound: true,
                    wire_code: rejection_wire_code(&response.body),
                },
            })
        }
        Err(bound_err) => match verify_delegated_response_unbound(
            response,
            resolve_actor,
            &expect,
            is_revoked,
            now,
        ) {
            Ok(verified) => {
                check_expected_server_signer(expectation, &verified)?;
                Ok(VerifiedDelegatedResponse {
                    verified,
                    outcome: DelegatedOutcome::Rejection {
                        bound: false,
                        wire_code: rejection_wire_code(&response.body),
                    },
                })
            }
            // Neither path verified — fail closed. Surface the bound error (the more
            // specific of the two for a receipt claiming to be about this request).
            Err(_unbound_err) => Err(bound_err),
        },
    }
}

/// Verify a DELEGATED-required response anchored in a [`TrustedIssuerSet`] — the same
/// verification as [`verify_delegated_response`], with the trust-anchor set supplied
/// ONCE.
///
/// The set feeds two seams the verifier treats as independent: the root RESOLVER
/// (current + in-window retired) and the REVOCATION source (revoked issuers). Passing
/// it through [`verify_delegated_response`] means passing the same value in two
/// argument positions, and getting that wrong fails in the permissive direction — a
/// caller who builds the resolver from the set but passes an empty revocation list
/// verifies credentials under a root they have marked REVOKED, with nothing to
/// indicate the revocation is inert. Revocation of a trust anchor is the one decisive
/// action that invalidates every descendant delegated credential at once, so it must
/// not depend on remembering to say it twice.
///
/// Use this whenever the trust anchors come from a [`TrustedIssuerSet`] (including one
/// loaded from a signed trust-anchor manifest). Reach for
/// [`verify_delegated_response`] only when the resolver and the revocation source are
/// genuinely different objects — e.g. a resolver backed by a live directory plus a
/// separately-fed denylist.
pub fn verify_delegated_response_anchored(
    response: &HttpResponse,
    expectation: &ResponseExpectation,
    policy: &DelegationPolicy,
    issuers: &TrustedIssuerSet,
    now: i64,
) -> Result<VerifiedDelegatedResponse, HttpProfileError> {
    let resolver = issuers.anchored_resolver(now);
    verify_delegated_response(response, &resolver, expectation, policy, issuers, now)
}

/// The server's frozen wire code from a (verified) rejection-receipt body
/// (`error.data.mcp_re_error.wire_code`), if present. Read ONLY after verification.
fn rejection_wire_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body).ok().and_then(|v| {
        v.pointer("/error/data/mcp_re_error/wire_code")
            .and_then(|w| w.as_str())
            .map(str::to_owned)
    })
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
/// Same trust inputs as [`verify_delegated_response`]: the ROOT ISSUER anchor comes
/// through `resolve_actor` for the `Response` slot, and the credential must satisfy
/// `policy` (audience scope, accepted epochs, skew) and clear `revocation`.
pub fn verify_delegated_accepted_202<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &DelegationPolicy,
    revocation: &dyn RevocationSource,
    now: i64,
) -> Result<ResolvedActor, HttpProfileError> {
    let audiences: Vec<&str> = policy
        .verifier_audiences
        .iter()
        .map(String::as_str)
        .collect();
    let epochs: Vec<&str> = policy.accepted_epochs.iter().map(String::as_str).collect();
    let expect = DelegationExpectations {
        policy: policy.verifier_policy(),
        verifier_audiences: &audiences,
        expected_audience_hash: policy.expected_audience_hash.as_str(),
        accepted_epochs: &epochs,
        max_clock_skew: policy.max_clock_skew,
    };
    let is_revoked = |identifier: &str| revocation.is_revoked(identifier);
    mcp_re_http_profile::verify_delegated_accepted_202(
        response,
        request,
        resolve_actor,
        &expect,
        &is_revoked,
        now,
    )
}

#[cfg(test)]
mod delegated_tests {
    use super::*;
    use crate::build_signed_request;
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
        )
        .expect("client verifies delegated success");
        assert_eq!(out.outcome, DelegatedOutcome::Success);
        // The delegated key is profile-issued, so its keyid is the RFC 7638 JWK
        // thumbprint of the key that actually signed (#415 rev 2 §1.5) — derived
        // from the key material, not from an issuer-private counter.
        let snap = custody.active_snapshot().expect("a key is active");
        assert_eq!(
            out.verified.server_signer.as_ref().unwrap().keyid,
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
        )
        .expect("an unpinned delegated success still verifies");
        assert_eq!(ok.outcome, DelegatedOutcome::Success);

        // The verified evidence reports the anchor the credential chained to.
        assert_eq!(ok.verified.delegation_issuer_kid.as_deref(), Some(ROOT_KID));

        // A pin on the ROOT ISSUER verifies — the coordinate that is stable across
        // delegated-key rotation.
        let pinned = verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed).with_expected_server_signer(ROOT_KID),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
        )
        .expect("a pin naming the root issuer verifies");
        assert_eq!(pinned.outcome, DelegatedOutcome::Success);

        // Any other root fails closed.
        let err = verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed).with_expected_server_signer("some-other-root-kid"),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
        )
        .expect_err("a pin naming a different root must fail closed");
        assert_eq!(err, HttpProfileError::ResponseBindingMismatch);

        // And NOT against the accepted signer keyid: that is the ephemeral delegated
        // kid, so pinning it would break on the first rotation.
        let delegated_kid = ok.verified.server_signer.as_ref().unwrap().keyid.clone();
        assert_ne!(delegated_kid, ROOT_KID);
        let err = verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed).with_expected_server_signer(&delegated_kid),
            &policy(),
            &StaticRevocationList::new(),
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
        let reason = RejectionReason {
            wire_code: "mcp-re.replay_detected",
            message: "replayed".into(),
        };
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
            &resolver(),
            &expectation(&signed).with_expected_server_signer(ROOT_KID),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
        )
        .expect("a receipt whose credential chains to the pinned root verifies");
        let err = verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed).with_expected_server_signer("some-other-root-kid"),
            &policy(),
            &StaticRevocationList::new(),
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
        let reason = RejectionReason {
            wire_code: "mcp-re.replay_detected",
            message: "replayed".into(),
        };
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
        )
        .expect("client verifies bound rejection");
        assert_eq!(
            out.outcome,
            DelegatedOutcome::Rejection {
                bound: true,
                wire_code: Some("mcp-re.replay_detected".into())
            }
        );
    }

    #[test]
    fn delegated_preflight_rejection_is_verified_unbound() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason {
            wire_code: "mcp-re.request_signature_invalid",
            message: "bad request".into(),
        };
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
        )
        .expect("client verifies preflight rejection unbound");
        assert_eq!(
            out.outcome,
            DelegatedOutcome::Rejection {
                bound: false,
                wire_code: Some("mcp-re.request_signature_invalid".into())
            }
        );
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &StaticRevocationList::new(),
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
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
        let reason = RejectionReason {
            wire_code: "mcp-re.request_signature_invalid",
            message: "x".into(),
        };
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &StaticRevocationList::new(),
            NOW,
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &revoked,
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &revoked,
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &revoked,
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &revoked,
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
        let reason = RejectionReason {
            wire_code: "mcp-re.replay_detected",
            message: "replayed".into(),
        };
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &revoked,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationRevoked);
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
            &resolver(),
            &expectation(&signed),
            &policy(),
            &revoked,
            rot,
        )
        .expect("response on the rotated key verifies while the old key is revoked");
        assert_eq!(out.outcome, DelegatedOutcome::Success);
    }
}
