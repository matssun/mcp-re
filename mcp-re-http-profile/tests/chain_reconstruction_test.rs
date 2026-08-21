// SPDX-License-Identifier: Apache-2.0
//! Retained-chain reconstruction (#416 rev 2 §9, issue #431).
//!
//! The property under test is the one §9.3 exists for: a missing middle hop must
//! yield an INCOMPLETE call record, never a complete-looking terminal result.
//! Every message in these chains verifies on its own — that is what makes the
//! failure worth a test. Per-hop validity is not chain integrity.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::block::AudienceTuple;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::reconstruct_chain;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::ChainAudit;
use mcp_re_http_profile::ChainLabel;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::IncompleteReason;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::RetainedHop;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
/// The ROOT issuer: the credential signer, off the request path. Delegated-required
/// is the only response-signing mode, so a reconstruction that could not verify a
/// delegated response could not verify any evidence the proxy actually emits.
const ROOT_SEED: [u8; 32] = [22u8; 32];
const DELEGATED_SEED: [u8; 32] = [44u8; 32];
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const NOW: i64 = 1_700_000_100;
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "server-key-1";
const DELEGATED_KID: &str = "server-key-1/delegated/1";
const TARGET: &str = "https://mcp.example.com/mcp";
const VERIFIER_AUD: &str = "did:example:server";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED_SEED)
}

/// The delegation credential every hop response carries inline. Minted over the
/// hop's own window so a chain whose turns sit at different times still verifies at
/// each hop's own instant.
fn credential(created: i64, expires: i64) -> String {
    let d = delegated_key();
    let header = DelegationHeader {
        typ: mcp_re_http_profile::DELEGATION_TYP.into(),
        alg: mcp_re_http_profile::DELEGATION_ALG.into(),
        kid: ROOT_KID.into(),
    };
    let claims = DelegationClaims {
        iss: "did:example:server".into(),
        iat: created,
        nbf: created,
        exp: expires,
        jti: format!("evt-{created}"),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_audience_hash: AUD_SCOPE.into(),
        mcp_re_server_signer: server_signer().actor_id(),
        mcp_re_key_use: mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: DELEGATED_KID.into(),
        issuer_kid: ROOT_KID.into(),
        trust_epoch: EPOCH.into(),
        cnf: Cnf {
            jwk: DelegatedJwk {
                kty: mcp_re_http_profile::JWK_KTY_OKP.into(),
                crv: mcp_re_http_profile::JWK_CRV_ED25519.into(),
                kid: DELEGATED_KID.into(),
                x: d.public_key().to_b64url(),
            },
        },
    };
    issue_delegation_credential(&root_key(), &header, &claims)
}

/// The delegated-verification inputs. Nothing is revoked in these chains; the
/// revocation seam is exercised by the delegation suite.
fn expectations() -> DelegationExpectations<'static> {
    DelegationExpectations {
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: &[EPOCH],
        max_clock_skew: 60,
    }
}

fn nothing_revoked(_: &str) -> bool {
    false
}

/// [`expectations`] for the cases that vary the RFC 9421 acceptance window.
///
/// The window itself is no longer here: the response-signature policy belongs to the
/// verifier, and these cases pass it to `reconstruct_chain` directly.
#[allow(dead_code)]
fn expectations_with(_policy: &VerifierPolicy) -> DelegationExpectations<'static> {
    DelegationExpectations { ..expectations() }
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key()),
            // The ROOT issuer, not the ephemeral delegated key: under
            // delegated-required the trust seam pins the root the credential chains
            // to, and the delegated key is authorized BY the credential rather than
            // enrolled.
            (ROOT_KID, SignerSlot::Response) => ("server", root_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key.public_key(),
            slot,
        })
    }
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "mcp.example.com".into(),
        target_uri: TARGET.into(),
        route: Some("tools/call".into()),
    }
}

/// The full-profile audit inputs. The blocks under test carry an `OauthDpop` binding
/// over `b"tok"` and no `Authorization` header, so the material function is what makes
/// that binding checkable — a binding whose credential cannot be obtained fails closed.
fn artifact_material(_: &ArtifactBinding) -> Option<Vec<u8>> {
    Some(b"tok".to_vec())
}

static ARTIFACT_MATERIAL: fn(&ArtifactBinding) -> Option<Vec<u8>> = artifact_material;

fn audit() -> ChainAudit<'static> {
    static AUD: std::sync::OnceLock<AudienceTuple> = std::sync::OnceLock::new();
    ChainAudit {
        expected_audience: AUD.get_or_init(audience),
        artifact_material: &ARTIFACT_MATERIAL,
    }
}

fn server_signer() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: DELEGATED_KID.into(),
    }
}

fn block(continuation: Option<HttpContinuation>) -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation,
        admission: None,
        admission_assertion: None,
    }
}

/// Sign one hop: a request (optionally continuing a previous one) and the
/// response that answers it. Returns the hop plus the two role-labeled handles
/// the next hop's continuation will have to name.
fn hop(
    nonce: &str,
    continuation: Option<HttpContinuation>,
    body: &str,
) -> (RetainedHop, RequestEvidence, RequestEvidence) {
    hop_at(CREATED, EXPIRES, nonce, continuation, body)
}

/// A hop signed over a window no verifier will accept, so the handle derivation
/// [`hop_at`] performs is skipped — it would fail on the very window under test.
/// Returns only the retained messages, which is all a malformed-window case needs.
fn hop_with_bad_window(created: i64, expires: i64, nonce: &str) -> RetainedHop {
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
    };
    let req_evidence = sign_request_full(
        &mut request,
        &block(None),
        &client_key(),
        CLIENT_KEY_ID,
        created,
        expires,
        nonce,
    )
    .expect("signing does not police the window; verification does");

    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: DONE.as_bytes().to_vec(),
    };
    sign_delegated_response_full(
        &mut response,
        &request,
        &req_evidence,
        &server_signer(),
        &credential(created, expires),
        &delegated_key(),
        DELEGATED_KID,
        created,
        expires,
    )
    .expect("response signs");

    RetainedHop { request, response }
}

/// [`hop`] with the signing window given explicitly, for chains whose turns are
/// minted at different times — which is every real chain.
fn hop_at(
    created: i64,
    expires: i64,
    nonce: &str,
    continuation: Option<HttpContinuation>,
    body: &str,
) -> (RetainedHop, RequestEvidence, RequestEvidence) {
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
    };
    let req_evidence = sign_request_full(
        &mut request,
        &block(continuation),
        &client_key(),
        CLIENT_KEY_ID,
        created,
        expires,
        nonce,
    )
    .expect("request signs");

    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    };
    sign_delegated_response_full(
        &mut response,
        &request,
        &req_evidence,
        &server_signer(),
        &credential(created, expires),
        &delegated_key(),
        DELEGATED_KID,
        created,
        expires,
    )
    .expect("response signs");

    // The response handle the next continuation must name is the response-role
    // digest of this response's signature base — recomputed by verifying, exactly
    // as the reconstruction will. Verified at the hop's own `created`, which is
    // inside its own window whatever that window is.
    let verified_rsp = mcp_re_http_profile::Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &response,
            &request,
            &req_evidence,
            &expectations(),
            &nothing_revoked,
            created,
        )
        .expect("response verifies");
    let rsp_evidence = verified_rsp
        .response
        .floor
        .response_signature_base_digest
        .clone();

    (
        RetainedHop { request, response },
        req_evidence,
        rsp_evidence,
    )
}

const AWAITING: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}"#;
const DONE: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

/// Build a 3-hop chain R0→S0→R1→S1→R2→S2, each hop continuing the last, ending
/// terminally. This is the multi-hop positive (#416 §13.4 "multi-hop" claim).
fn three_hop_chain() -> Vec<RetainedHop> {
    let (h0, r0, s0) = hop("n-0", None, AWAITING);
    let (h1, r1, s1) = hop(
        "n-1",
        Some(HttpContinuation::from_handles(
            to_digest(&r0),
            to_digest(&s0),
            b"state-0",
        )),
        AWAITING,
    );
    let (h2, _r2, _s2) = hop(
        "n-2",
        Some(HttpContinuation::from_handles(
            to_digest(&r1),
            to_digest(&s1),
            b"state-1",
        )),
        DONE,
    );
    vec![h0, h1, h2]
}

fn to_digest(e: &RequestEvidence) -> mcp_re_http_profile::RequestEvidenceDigest {
    mcp_re_http_profile::RequestEvidenceDigest {
        digest_alg: e.digest_alg.clone(),
        digest_value: e.digest_value.clone(),
    }
}

fn reconstruct(hops: &[RetainedHop]) -> ChainLabel {
    reconstruct_chain(
        hops,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        &audit(),
        &nothing_revoked,
        NOW,
    )
    .label
}

// --- positives ---------------------------------------------------------------

#[test]
fn multi_hop_chain_reconstructs_complete() {
    let hops = three_hop_chain();
    let label = reconstruct(&hops);
    assert_eq!(
        label,
        ChainLabel::Complete,
        "every hop verifies and re-links"
    );
}

#[test]
fn single_terminal_hop_reconstructs_complete() {
    let (h0, _, _) = hop("n-solo", None, DONE);
    assert_eq!(reconstruct(&[h0]), ChainLabel::Complete);
}

#[test]
fn complete_chain_reports_every_hops_evidence() {
    let hops = three_hop_chain();
    let out = reconstruct_chain(
        &hops,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        &audit(),
        &nothing_revoked,
        NOW,
    );
    assert!(out.label.is_complete());
    assert_eq!(
        out.hop_evidence.len(),
        3,
        "the record accounts for all 3 hops"
    );
    // Request-role and response-role handles are domain-separated (§7.3), so no
    // hop's two handles collide even though both digest a signature base.
    for h in &out.hop_evidence {
        assert_ne!(
            h.request_evidence.digest_value,
            h.response_evidence.digest_value
        );
    }
}

// --- the missing middle hop (§9.1/§9.3) --------------------------------------

/// THE test this module exists for. Drop R1→S1 from a 3-hop chain and hand the
/// auditor R0→S0 and R2→S2. Both remaining hops verify perfectly; S2 is a
/// genuine, correctly-signed terminal result. It must still be labeled
/// INCOMPLETE, naming hop 1 — because R2's continuation links to a turn that is
/// not in the record.
#[test]
fn missing_middle_hop_is_incomplete_not_a_complete_terminal() {
    let all = three_hop_chain();
    let truncated = vec![all[0].clone(), all[2].clone()];

    // Precondition: this is not a test about broken messages. Each surviving hop
    // verifies on its own — the record is a set of individually valid evidence.
    for h in &truncated {
        let v = mcp_re_http_profile::Verifier::new(&VerifierPolicy::default(), &resolver())
            .verify_request_floor(&h.request, NOW)
            .expect("the retained request verifies on its own");
        mcp_re_http_profile::Verifier::new(&VerifierPolicy::default(), &resolver())
            .verify_delegated_bound_response(
                &h.response,
                &h.request,
                v.evidence(),
                &expectations(),
                &nothing_revoked,
                NOW,
            )
            .expect("the retained response verifies and is bound to its request");
    }

    let label = reconstruct(&truncated);
    assert_eq!(
        label,
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::ContinuationDoesNotLink,
        },
        "a terminal answer whose predecessor is absent does not complete the call"
    );
    assert!(!label.is_complete());
}

/// The same record, read naively: every hop is valid, so a checker that only
/// verified signatures would call this complete. Pinning the contrast makes the
/// regression obvious if reconstruction ever softens to a per-hop loop.
#[test]
fn per_hop_validity_does_not_imply_a_complete_chain() {
    let all = three_hop_chain();
    let truncated = vec![all[0].clone(), all[2].clone()];
    let out = reconstruct_chain(
        &truncated,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        &audit(),
        &nothing_revoked,
        NOW,
    );
    assert!(!out.label.is_complete());
    // The verified prefix is still reported: hop 0 IS accounted for. An auditor
    // learns which part of the record stands, not merely that it failed.
    assert_eq!(out.hop_evidence.len(), 1);
}

// --- other incomplete shapes -------------------------------------------------

/// A truncated chain: the record stops on a turn still awaiting input. Every hop
/// verifies; the call simply has no ending.
#[test]
fn chain_ending_non_terminally_is_incomplete() {
    let all = three_hop_chain();
    let prefix = vec![all[0].clone(), all[1].clone()];
    assert_eq!(
        reconstruct(&prefix),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::TerminalExpected,
        },
    );
}

/// THE front-truncation test. Given a real 3-hop call, submit only hops 1 and 2.
/// Every submitted hop verifies, hop 2 re-links to hop 1, and hop 2 is terminal —
/// so every check but one says "complete". The one that must catch it is hop 0's
/// own continuation: it names a predecessor the record cannot produce, so the
/// record starts after the call did.
///
/// Without the hop-0 check this reconstructs as `Complete`, and a SCITT Signed
/// Statement over it reports `is_complete_record() == true` while the opening
/// turns — the original request, its audience and its artifact bindings — are
/// missing. That is the truncated-record laundering §9.3 forbids, from the one
/// direction the shape checks do not cover.
#[test]
fn front_truncated_chain_is_incomplete_not_a_complete_record() {
    let all = three_hop_chain();
    let front_truncated = vec![all[1].clone(), all[2].clone()];

    // Precondition: this is not a test about broken messages. Both submitted hops
    // verify on their own, exactly as they did inside the whole call.
    for h in &front_truncated {
        let v = mcp_re_http_profile::Verifier::new(&VerifierPolicy::default(), &resolver())
            .verify_request_floor(&h.request, NOW)
            .expect("the retained request verifies on its own");
        mcp_re_http_profile::Verifier::new(&VerifierPolicy::default(), &resolver())
            .verify_delegated_bound_response(
                &h.response,
                &h.request,
                v.evidence(),
                &expectations(),
                &nothing_revoked,
                NOW,
            )
            .expect("the retained response verifies and is bound to its request");
    }

    let out = reconstruct_chain(
        &front_truncated,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        &audit(),
        &nothing_revoked,
        NOW,
    );
    assert_eq!(
        out.label,
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::ContinuationDoesNotLink,
        },
        "a hop that names a predecessor absent from the record does not open a call"
    );
    assert!(!out.label.is_complete());
    // Nothing is reported as accounted for: the break is at the first hop.
    assert!(out.hop_evidence.is_empty());
}

/// The complementary positive: a genuine opening hop carries NO continuation and
/// still reconstructs. Without this the hop-0 rule could be tightened into
/// rejecting every chain and the negative above would still pass.
#[test]
fn an_opening_hop_without_a_continuation_still_opens_a_complete_record() {
    assert_eq!(reconstruct(&three_hop_chain()), ChainLabel::Complete);
}

/// A hop after the first with no continuation at all: nothing links it backwards.
#[test]
fn later_hop_without_a_continuation_is_incomplete() {
    let (h0, _, _) = hop("n-a", None, AWAITING);
    let (h1, _, _) = hop("n-b", None, DONE);
    assert_eq!(
        reconstruct(&[h0, h1]),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::MissingContinuation,
        },
    );
}

/// A continuation naming a DIFFERENT chain's evidence. The handles are
/// well-formed and the messages verify; they simply do not describe this record.
#[test]
fn continuation_from_another_chain_is_incomplete() {
    let (h0, _r0, _s0) = hop("n-x", None, AWAITING);
    let (_other, other_r, other_s) = hop("n-other", None, AWAITING);
    let (h1, _, _) = hop(
        "n-y",
        Some(HttpContinuation::from_handles(
            to_digest(&other_r),
            to_digest(&other_s),
            b"state-x",
        )),
        DONE,
    );
    assert_eq!(
        reconstruct(&[h0, h1]),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::ContinuationDoesNotLink,
        },
    );
}

/// A chain that claims to continue past a turn that already answered terminally.
#[test]
fn terminal_before_the_end_is_incomplete() {
    let (h0, r0, s0) = hop("n-t0", None, DONE);
    let (h1, _, _) = hop(
        "n-t1",
        Some(HttpContinuation::from_handles(
            to_digest(&r0),
            to_digest(&s0),
            b"state",
        )),
        DONE,
    );
    assert_eq!(
        reconstruct(&[h0, h1]),
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::NonTerminalExpected,
        },
    );
}

/// Role substitution (§7.3): a continuation that names the previous REQUEST's
/// handle in the response slot. Domain separation means the lifted handle is a
/// different value in that role, so re-linking rejects it.
#[test]
fn handles_swapped_between_roles_do_not_relink() {
    let (h0, r0, s0) = hop("n-s0", None, AWAITING);
    let (h1, _, _) = hop(
        "n-s1",
        Some(HttpContinuation::from_handles(
            to_digest(&s0), // response handle presented as the previous-request one
            to_digest(&r0), // and vice versa
            b"state",
        )),
        DONE,
    );
    assert_eq!(
        reconstruct(&[h0, h1]),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::ContinuationDoesNotLink,
        },
    );
}

/// An unverifiable hop names itself, so an auditor knows which turn to distrust.
#[test]
fn tampered_hop_is_named_by_index() {
    let mut hops = three_hop_chain();
    hops[1].response.body = DONE.as_bytes().to_vec(); // breaks its content-digest
    let out = reconstruct(&hops);
    match out {
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::ResponseUnverifiable(_),
        } => {}
        other => panic!("expected hop 1 named unverifiable, got {other:?}"),
    }
}

#[test]
fn empty_chain_is_incomplete() {
    assert_eq!(
        reconstruct(&[]),
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::EmptyChain,
        },
    );
}

/// THE regression for the detached-classification hole. A chain whose last hop is
/// a signed `InputRequiredResult` is TRUNCATED: the call has no ending. Previously
/// a caller could pass `HopOutcome::Terminal` alongside it and the chain would
/// reconstruct as COMPLETE — the classification was authoritative over the
/// protected bytes that contradicted it.
///
/// The classification is now read from the response body that just verified, so
/// there is no parameter left to lie with. The truncated chain is incomplete
/// because its own protected content says the turn was still awaiting input.
#[test]
fn a_truncated_chain_cannot_be_relabelled_complete() {
    let all = three_hop_chain();
    let prefix = vec![all[0].clone(), all[1].clone()];

    // Both hops verify, and hop 1's response is a genuine, correctly-signed
    // InputRequiredResult — the record simply stops mid-call.
    assert_eq!(
        reconstruct(&prefix),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::TerminalExpected,
        },
        "protected content says the last turn awaited input; nothing can override it"
    );
}

/// The mirror: terminality is read from the bytes, so a genuinely terminal ending
/// is recognised without anyone asserting it.
#[test]
fn terminality_is_derived_from_protected_content() {
    let hops = three_hop_chain();
    assert_eq!(reconstruct(&hops), ChainLabel::Complete);

    // Flip ONLY the last response's protected classification (re-signed), and the
    // same three hops become a truncated chain — the label tracks the bytes.
    let (h0, r0, s0) = hop("n-d0", None, AWAITING);
    let (h1, _, _) = hop(
        "n-d1",
        Some(HttpContinuation::from_handles(
            to_digest(&r0),
            to_digest(&s0),
            b"state-d",
        )),
        AWAITING, // the final turn still awaits input
    );
    assert_eq!(
        reconstruct(&[h0, h1]),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::TerminalExpected,
        },
    );
}

/// MCPRE-495: a hop whose `resultType` this reader does not recognize makes the
/// record incomplete AT THAT HOP, rather than being read as terminal.
///
/// This is the direction that matters. Reconstruction is the one reader for which
/// "unknown ⇒ terminal" looks safe — a false truncation is only a false alarm —
/// but it is not safe at the END of a chain: if the last hop carries an extension's
/// non-terminal result, unknown-as-terminal reports a chain that stops mid-call as
/// COMPLETE. An auditor is owed "hop 1 declares a result type I cannot classify",
/// not a confident verdict derived from a value nobody read.
#[test]
fn an_unrecognized_result_type_makes_the_record_incomplete_at_that_hop() {
    const UNRECOGNIZED: &str =
        r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"com.example/deferred"}}"#;

    let (h0, r0, s0) = hop("n-u0", None, AWAITING);
    let (h1, _, _) = hop(
        "n-u1",
        Some(HttpContinuation::from_handles(
            to_digest(&r0),
            to_digest(&s0),
            b"state-u",
        )),
        UNRECOGNIZED,
    );

    assert_eq!(
        reconstruct(&[h0, h1]),
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::UnrecognizedResultType,
        },
        "every message verifies and re-links; whether the call ENDED is what is unknown"
    );
}

/// The same value at a NON-final hop is refused too. Here unknown-as-terminal would
/// have produced `NonTerminalExpected` — an accurate-sounding label for the wrong
/// reason, blaming the chain's shape for what is really an unreadable result type.
#[test]
fn an_unrecognized_result_type_mid_chain_is_named_for_what_it_is() {
    const UNRECOGNIZED: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"partial"}}"#;

    let (h0, r0, s0) = hop("n-m0", None, UNRECOGNIZED);
    let (h1, _, _) = hop(
        "n-m1",
        Some(HttpContinuation::from_handles(
            to_digest(&r0),
            to_digest(&s0),
            b"state-m",
        )),
        DONE,
    );

    assert_eq!(
        reconstruct(&[h0, h1]),
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::UnrecognizedResultType,
        },
    );
}

// --- the record is verified as a record, not as live traffic (C033) ----------

/// A chain whose turns span more than one freshness window, audited long after
/// the call ended. This is what a retained record actually looks like: a human
/// answered an elicitation after lunch, and the archive is read next year.
///
/// Every fixture above signs all three hops inside ONE window bracketing `NOW`,
/// which is why none of them caught this. Reconstruction used to hand the live
/// clock to every hop's freshness check, so the moment the record aged past a
/// single window — an hour by default, and less than the gap between hop 0 and
/// hop 1 here — `Complete` became unreachable for evidence that was entirely
/// intact. The label decayed with age instead of describing the evidence, and a
/// SCITT receipt over it would have committed to `Incomplete` for a whole call.
fn aged_chain() -> Vec<RetainedHop> {
    // Two hours between turns, so no two hops share a window and none of them
    // contains the audit instant.
    const TURN: i64 = 7_200;
    let (h0, r0, s0) = hop_at(CREATED, CREATED + 300, "a-0", None, AWAITING);
    let (h1, r1, s1) = hop_at(
        CREATED + TURN,
        CREATED + TURN + 300,
        "a-1",
        Some(HttpContinuation::from_handles(
            to_digest(&r0),
            to_digest(&s0),
            b"state-0",
        )),
        AWAITING,
    );
    let (h2, _r2, _s2) = hop_at(
        CREATED + 2 * TURN,
        CREATED + 2 * TURN + 300,
        "a-2",
        Some(HttpContinuation::from_handles(
            to_digest(&r1),
            to_digest(&s1),
            b"state-1",
        )),
        DONE,
    );
    vec![h0, h1, h2]
}

/// The audit instant: a year after the last hop closed. Every window in the
/// chain is long shut.
const AUDIT_LATER: i64 = CREATED + 31_536_000;

#[test]
fn an_aged_multi_hop_record_still_reconstructs_complete() {
    let hops = aged_chain();
    let out = reconstruct_chain(
        &hops,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        &audit(),
        &nothing_revoked,
        AUDIT_LATER,
    );
    assert_eq!(
        out.label,
        ChainLabel::Complete,
        "an intact record does not stop being intact because it got old"
    );
    assert_eq!(out.hop_evidence.len(), 3);
}

/// The precondition that makes the test above meaningful: these hops genuinely
/// are outside each other's windows and outside the audit instant's. If a future
/// refactor narrowed the gaps, the test would still pass while proving nothing.
#[test]
fn the_aged_chains_hops_really_are_out_of_window_at_audit_time() {
    for (i, h) in aged_chain().iter().enumerate() {
        let err = mcp_re_http_profile::Verifier::new(&VerifierPolicy::default(), &resolver())
            .verify_request_floor(&h.request, AUDIT_LATER)
            .expect_err("hop {i}'s window is closed at the audit instant");
        assert!(
            matches!(err, mcp_re_http_profile::HttpProfileError::StaleWindow),
            "hop {i} should be stale against the live clock, got {err:?}"
        );
    }
}

/// Aging must not be the only thing that changed. A record is still refused if a
/// hop is dated AFTER the audit instant — `now` did not stop mattering, it became
/// a ceiling rather than a window.
#[test]
fn a_hop_created_after_the_audit_instant_is_refused() {
    let hops = aged_chain();
    // Audit as of a moment between hop 0 and hop 1: hop 1 has not happened yet.
    let audit_at = CREATED + 3_600;
    assert_eq!(
        reconstruct_chain(
            &hops,
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            &expectations(),
            &audit(),
            &nothing_revoked,
            audit_at
        )
        .label,
        ChainLabel::Incomplete {
            hop: 1,
            reason: IncompleteReason::HopAfterAuditInstant,
        },
        "a record cannot contain evidence from after the audit"
    );
}

/// The ceiling allows the same skew the live path does, so an archivist whose
/// clock trails the signer's does not reject its own honest records.
#[test]
fn the_audit_ceiling_tolerates_the_configured_skew() {
    let policy = VerifierPolicy::default();
    let (h0, _, _) = hop_at(CREATED, CREATED + 300, "skew", None, DONE);

    let within = CREATED - policy.max_clock_skew();
    assert_eq!(
        reconstruct_chain(
            std::slice::from_ref(&h0),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            &expectations_with(&policy),
            &audit(),
            &nothing_revoked,
            within
        )
        .label,
        ChainLabel::Complete,
        "a hop one skew ahead of the auditor's clock is honest disagreement"
    );

    let beyond = CREATED - policy.max_clock_skew() - 1;
    assert_eq!(
        reconstruct_chain(
            &[h0],
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            &expectations_with(&policy),
            &audit(),
            &nothing_revoked,
            beyond
        )
        .label,
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::HopAfterAuditInstant,
        },
        "one second past the tolerance is no longer disagreement"
    );
}

/// Verifying each hop at its own `created` must not have relaxed the checks that
/// are properties of the MESSAGE rather than of the clock. An over-wide window is
/// still refused, at any age — otherwise "verify it at its own created" would be
/// a way to smuggle a decade-long signature into a retained record.
#[test]
fn an_over_wide_window_is_still_refused_in_an_aged_record() {
    let policy = VerifierPolicy::default();
    let h0 = hop_with_bad_window(
        CREATED,
        CREATED + policy.max_signature_validity() + 1,
        "wide",
    );
    match reconstruct_chain(
        &[h0],
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations_with(&policy),
        &audit(),
        &nothing_revoked,
        AUDIT_LATER,
    )
    .label
    {
        ChainLabel::Incomplete {
            hop: 0,
            reason:
                IncompleteReason::RequestUnverifiable(
                    mcp_re_http_profile::HttpProfileError::StaleWindow,
                ),
        } => {}
        other => panic!("expected the width bound to still fire, got {other:?}"),
    }
}

/// And the degenerate window: `expires <= created` leaves no instant at all, so
/// there is nothing for "its own created" to fall inside. It must not become
/// self-satisfying.
#[test]
fn a_degenerate_window_is_still_refused_in_an_aged_record() {
    let h0 = hop_with_bad_window(CREATED, CREATED, "degenerate");
    match reconstruct_chain(
        &[h0],
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        &audit(),
        &nothing_revoked,
        AUDIT_LATER,
    )
    .label
    {
        ChainLabel::Incomplete {
            hop: 0,
            reason:
                IncompleteReason::RequestUnverifiable(
                    mcp_re_http_profile::HttpProfileError::StaleWindow,
                ),
        } => {}
        other => panic!("expected the degenerate-window check to still fire, got {other:?}"),
    }
}

// --- the request EVIDENCE BLOCK, not merely the signature over it -------------

/// Sign one hop with a caller-chosen evidence block, so a test can put a block in
/// the retained bytes that the enforcement boundary would have refused.
fn hop_with_block(nonce: &str, blk: &HttpRequestEvidenceBlock, body: &str) -> RetainedHop {
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
    };
    let req_evidence = sign_request_full(
        &mut request,
        blk,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        nonce,
    )
    .expect("request signs");
    RetainedHop {
        response: signed_answer(&request, &req_evidence, body),
        request,
    }
}

/// The delegated response answering `request`, signed over the same window.
fn signed_answer(
    request: &HttpRequest,
    req_evidence: &RequestEvidence,
    body: &str,
) -> HttpResponse {
    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    };
    sign_delegated_response_full(
        &mut response,
        request,
        req_evidence,
        &server_signer(),
        &credential(CREATED, EXPIRES),
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("response signs");
    response
}

/// A hop whose block names a DIFFERENT service than the URI the request went to.
///
/// The signature says nothing about this: the block rides in the body, which is
/// covered by `content-digest`, so a request naming another audience is a perfectly
/// well-signed request. Reconstruction ran the MINIMAL proof path, which never opens
/// the block, so such a hop reconstructed as verified and the record was labelled
/// `Complete` — and a SCITT Signed Statement over it asserts a whole call record
/// containing a request the enforcement boundary would have refused with
/// `audience_mismatch`.
#[test]
fn a_hop_whose_block_names_another_target_is_not_a_verified_hop() {
    let mut elsewhere = block(None);
    elsewhere.audience = AudienceTuple {
        audience_id: "other.example.com".into(),
        target_uri: "https://other.example.com/mcp".into(),
        route: Some("tools/call".into()),
    };
    let hop = hop_with_block("n-elsewhere", &elsewhere, DONE);

    // Precondition: the hop is not broken. It verifies on the minimal path — the
    // one reconstruction used to run — so nothing about the signature catches this.
    mcp_re_http_profile::Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&hop.request, NOW)
        .expect("the request is correctly signed; only its block is wrong");

    assert_eq!(
        reconstruct(&[hop]),
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::RequestUnverifiable(
                mcp_re_http_profile::HttpProfileError::AudienceMismatch
            ),
        },
    );
}

/// A hop carrying no evidence block at all. `sign_request` produces exactly this:
/// a valid RFC 9421 request with no `_meta` block, which the minimal path accepts
/// and the full profile does not.
#[test]
fn a_hop_with_no_evidence_block_is_not_a_verified_hop() {
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
    };
    let req_evidence = mcp_re_http_profile::sign_request(
        &mut request,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        "n-blockless",
    )
    .expect("request signs");
    let response = signed_answer(&request, &req_evidence, DONE);

    mcp_re_http_profile::Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request_floor(&request, NOW)
        .expect("the minimal path accepts a blockless request");

    let label = reconstruct(&[RetainedHop { request, response }]);
    match label {
        ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::RequestUnverifiable(_),
        } => {}
        other => panic!("a blockless hop must not be a verified hop, got {other:?}"),
    }
}

/// The positive control: an honest block still reconstructs, so the checks above
/// could not have been satisfied by refusing everything.
#[test]
fn an_honest_block_still_reconstructs_complete() {
    assert_eq!(
        reconstruct(&[hop_with_block("n-honest", &block(None), DONE)]),
        ChainLabel::Complete
    );
}

// --- C082: the full-profile checks reconstruction used to skip -------------------

/// Audience-tuple EQUALITY, not merely "the block names the URI it was sent to".
///
/// The weaker check passed a hop whose audience named a different audience id or route
/// on the same endpoint, so a record could be attested `Complete` while containing
/// requests the enforcement boundary would have refused for the wrong audience.
#[test]
fn a_hop_whose_audience_is_not_the_verifiers_own_breaks_the_chain() {
    let mut elsewhere = block(None);
    elsewhere.audience = AudienceTuple {
        audience_id: "other.example.com".into(),
        target_uri: TARGET.into(),
        route: Some("tools/call".into()),
    };
    // The URI still matches, so the old target-URI-only check would have passed it.
    assert_eq!(elsewhere.audience.target_uri, audience().target_uri);
    match reconstruct(&[hop_with_block("n-aud", &elsewhere, DONE)]) {
        ChainLabel::Incomplete {
            hop: 0,
            reason:
                IncompleteReason::RequestUnverifiable(
                    mcp_re_http_profile::HttpProfileError::AudienceMismatch,
                ),
        } => {}
        other => panic!("a foreign audience must break the chain, got {other:?}"),
    }
}

/// A binding whose credential surface cannot be obtained fails CLOSED. Reconstruction
/// previously never looked at `artifact_bindings[]` at all, so a hop carrying a binding
/// nobody could check was indistinguishable from one carrying none.
#[test]
fn a_binding_with_no_obtainable_credential_breaks_the_chain() {
    fn nothing_available(_: &ArtifactBinding) -> Option<Vec<u8>> {
        None
    }
    static NOTHING: fn(&ArtifactBinding) -> Option<Vec<u8>> = nothing_available;
    let aud = audience();
    let starved = ChainAudit {
        expected_audience: &aud,
        artifact_material: &NOTHING,
    };
    let hops = [hop_with_block("n-artifact", &block(None), DONE)];
    let out = reconstruct_chain(
        &hops,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        &starved,
        &nothing_revoked,
        NOW,
    );
    match out.label {
        ChainLabel::Incomplete {
            hop: 0,
            reason:
                IncompleteReason::RequestUnverifiable(
                    mcp_re_http_profile::HttpProfileError::ArtifactBindingFailed,
                ),
        } => {}
        other => panic!("an uncheckable binding must break the chain, got {other:?}"),
    }
}

// --- C114: a record that verified nothing still has an identity ------------------

/// Two DIFFERENT submissions that both break at hop 0 must not produce the same record.
///
/// Every field derived from the verified prefix is empty for both — that is the defect:
/// the statements were byte-identical, so a record about one call could be presented as
/// a record about any other call that failed the same way. The submitted-bytes
/// commitment is what tells them apart.
#[test]
fn two_records_that_verified_nothing_are_still_distinguishable() {
    let mut first = block(None);
    first.audience = AudienceTuple {
        audience_id: "first.example.com".into(),
        target_uri: TARGET.into(),
        route: Some("tools/call".into()),
    };
    let mut second = block(None);
    second.audience = AudienceTuple {
        audience_id: "second.example.com".into(),
        target_uri: TARGET.into(),
        route: Some("tools/call".into()),
    };
    let a = [hop_with_block("n-id-a", &first, DONE)];
    let b = [hop_with_block("n-id-b", &second, DONE)];
    let run = |hops: &[RetainedHop]| {
        reconstruct_chain(
            hops,
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            &expectations(),
            &audit(),
            &nothing_revoked,
            NOW,
        )
    };
    let (ra, rb) = (run(&a), run(&b));

    // Both verified nothing: the identity fields the old record had are identical.
    assert!(ra.hop_evidence.is_empty() && rb.hop_evidence.is_empty());
    assert_eq!(ra.label, rb.label, "they even fail the same way");

    assert_ne!(
        ra.submitted_commitment, rb.submitted_commitment,
        "two different submissions must not share one identity",
    );
    assert!(!ra.submitted_commitment.is_empty());
}

/// The identity is of the SUBMISSION, so it is stable across runs of the same bytes —
/// otherwise it could not be compared by anyone but the process that computed it.
#[test]
fn the_submitted_identity_is_a_function_of_the_bytes_alone() {
    let hops = [hop_with_block("n-stable", &block(None), DONE)];
    let run = || {
        reconstruct_chain(
            &hops,
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            &expectations(),
            &audit(),
            &nothing_revoked,
            NOW,
        )
        .submitted_commitment
    };
    assert_eq!(run(), run());
    // And an empty chain, which verifies nothing and has no hops at all, still gets one.
    let empty = reconstruct_chain(
        &[],
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(),
        &audit(),
        &nothing_revoked,
        NOW,
    );
    assert!(!empty.submitted_commitment.is_empty());
    assert_ne!(empty.submitted_commitment, run());
}
