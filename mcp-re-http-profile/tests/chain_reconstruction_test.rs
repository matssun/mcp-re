// SPDX-License-Identifier: Apache-2.0
//! Retained-chain reconstruction (#416 rev 2 §9, issue #431).
//!
//! The property under test is the one §9.3 exists for: a missing middle hop must
//! yield an INCOMPLETE call record, never a complete-looking terminal result.
//! Every message in these chains verifies on its own — that is what makes the
//! failure worth a test. Per-hop validity is not chain integrity.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::block::AudienceTuple;
use mcp_re_http_profile::reconstruct_chain;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::ChainLabel;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::IncompleteReason;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::RetainedHop;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const NOW: i64 = 1_700_000_100;
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_KEY_ID: &str = "server-key-1";
const TARGET: &str = "https://mcp.example.com/mcp";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key()),
            (SERVER_KEY_ID, SignerSlot::Response) => ("server", server_key()),
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

fn server_signer() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: SERVER_KEY_ID.into(),
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
        CREATED,
        EXPIRES,
        nonce,
    )
    .expect("request signs");

    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    };
    sign_response_full(
        &mut response,
        &request,
        &req_evidence,
        &server_signer(),
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("response signs");

    // The response handle the next continuation must name is the response-role
    // digest of this response's signature base — recomputed by verifying, exactly
    // as the reconstruction will.
    let verified_rsp = mcp_re_http_profile::verify_response_bound_full(
        &response,
        &request,
        &req_evidence,
        &resolver(),
        NOW,
    )
    .expect("response verifies");
    let rsp_evidence = verified_rsp.response_signature_base_digest.clone();

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
    reconstruct_chain(hops, &resolver(), &VerifierPolicy::default(), NOW).label
}

// --- positives ---------------------------------------------------------------

#[test]
fn multi_hop_chain_reconstructs_complete() {
    let hops = three_hop_chain();
    let label = reconstruct(&hops);
    assert_eq!(label, ChainLabel::Complete, "every hop verifies and re-links");
}

#[test]
fn single_terminal_hop_reconstructs_complete() {
    let (h0, _, _) = hop("n-solo", None, DONE);
    assert_eq!(reconstruct(&[h0]), ChainLabel::Complete);
}

#[test]
fn complete_chain_reports_every_hops_evidence() {
    let hops = three_hop_chain();
    let out = reconstruct_chain(&hops, &resolver(), &VerifierPolicy::default(), NOW);
    assert!(out.label.is_complete());
    assert_eq!(out.hop_evidence.len(), 3, "the record accounts for all 3 hops");
    // Request-role and response-role handles are domain-separated (§7.3), so no
    // hop's two handles collide even though both digest a signature base.
    for h in &out.hop_evidence {
        assert_ne!(h.request_evidence.digest_value, h.response_evidence.digest_value);
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
        let v = mcp_re_http_profile::verify_request(&h.request, &resolver(), NOW)
            .expect("the retained request verifies on its own");
        mcp_re_http_profile::verify_response_bound_full(
            &h.response,
            &h.request,
            &v.evidence,
            &resolver(),
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
    let out = reconstruct_chain(&truncated, &resolver(), &VerifierPolicy::default(), NOW);
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
