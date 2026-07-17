// SPDX-License-Identifier: Apache-2.0
//! Retained-chain reconstruction (#416 rev 2 §9).
//!
//! Per-turn binding proves that ONE answer belongs to ONE question. It does not
//! prove that a chain of turns is whole. §9.1: a complete call record requires
//! re-linking and verifying EVERY hop; §9.3: a terminal response completes only
//! its own request unless the whole chain verifies.
//!
//! The failure this module exists to prevent is a quiet one. Given hops R0→S0 and
//! R2→S2 with R1→S1 missing, every retained message still verifies on its own,
//! and S2 still looks like a perfectly good terminal answer. An auditor reading
//! "all signatures valid" would call that a complete record of the call. It is
//! not — a whole turn is unaccounted for, and the request that S2 answers was
//! never linked to the request the record claims started the call. So the output
//! here is never a bare boolean: a chain is [`ChainLabel::Complete`], or it is
//! [`ChainLabel::Incomplete`] and NAMES the hop that broke it.
//!
//! What this module verifies, per hop:
//!   1. the request verifies (content-digest, evidence, trust, signature);
//!   2. the response verifies AND is `;req`-bound to that same request;
//!   3. for every hop after the first, the request's continuation re-links to the
//!      PREVIOUS hop: its `previous_request_evidence` is that hop's request
//!      handle and its `input_required_response_evidence` is that hop's response
//!      handle — both role-labeled, so a handle cannot be lifted between fields;
//!   4. the shape of the chain: every hop before the last is non-terminal
//!      (`InputRequiredResult`), the last is terminal, and only the first hop may
//!      carry no continuation.
//!
//! What it does NOT do: fetch evidence, decide retention, or judge whether the
//! set it was handed is all the evidence that exists. A caller that retains three
//! hops out of four and asks about those three gets an answer about those three.
//! Detecting that a hop is missing from the MIDDLE is what re-linking gives you;
//! detecting that the chain was truncated at the END is what the terminal-shape
//! check gives you. Neither can tell you the retention itself was honest — that
//! is Layer 5's job, and the reason [`ChainReconstruction`] is shaped to be
//! committed to (a SCITT receipt over a complete OR explicitly-incomplete record).

use crate::block::HttpContinuation;
use crate::block::HttpRequestEvidenceBlock;
use crate::block::ResolvedActor;
use crate::block::SignerSlot;
use crate::body::extract_meta_block;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::VerifierPolicy;
use crate::verify::verify_request_with_policy;
use crate::verify::verify_response_bound_full_with_policy;

/// The retained evidence for ONE hop (§9.2): the complete request and response
/// messages as they went over the wire.
///
/// The §9.2 list — message content, `Content-Digest`, `Signature-Input`,
/// `Signature`, key/delegation evidence, handles, bindings — is carried entirely
/// by these two messages plus the resolver: the digest and signature headers ride
/// on the messages, the evidence blocks ride in the bodies (protected because
/// `content-digest` is covered), the handles are DERIVED here rather than
/// retained, and key evidence is resolved through the trust seam. Retaining
/// derived handles would let a retention bug or a dishonest archivist state a
/// handle that does not match the bytes beside it; recomputing them means the
/// bytes are the only thing anyone has to keep honest.
#[derive(Debug, Clone)]
pub struct RetainedHop {
    pub request: HttpRequest,
    pub response: HttpResponse,
}

/// Why a chain is not a complete record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompleteReason {
    /// The hop's request did not verify on its own.
    RequestUnverifiable(HttpProfileError),
    /// The hop's response did not verify, or is not bound to its request.
    ResponseUnverifiable(HttpProfileError),
    /// The hop's request carries no continuation, but it is not the first hop —
    /// so nothing links it to what came before. This is the missing-middle case:
    /// the messages are individually valid and the chain is still broken.
    MissingContinuation,
    /// The hop's continuation does not re-link to the previous hop's evidence.
    /// A hop whose predecessor is absent from the record lands here: its
    /// continuation names evidence that is not the hop we were given.
    ContinuationDoesNotLink,
    /// A hop before the last answered terminally: the chain claims to continue
    /// past a turn that was already finished.
    NonTerminalExpected,
    /// The last hop is still awaiting input: the record stops mid-call. A
    /// truncated chain is incomplete even though every hop in it verified.
    TerminalExpected,
    /// The reconstruction was handed no hops at all.
    EmptyChain,
}

/// The verdict on a retained chain. Never a bare boolean (§9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainLabel {
    /// Every hop verified and re-linked, and the chain ends terminally.
    Complete,
    /// The chain is not a complete record. `hop` is the zero-based index of the
    /// first hop that broke it — an auditor is told WHICH turn is unaccounted
    /// for, not merely that something is wrong.
    Incomplete { hop: usize, reason: IncompleteReason },
}

impl ChainLabel {
    pub fn is_complete(&self) -> bool {
        matches!(self, ChainLabel::Complete)
    }
}

/// The reconstruction output. Shaped so a Layer 5 receipt can commit to it: the
/// label is part of the record, so an incomplete chain is representable and
/// distinguishable rather than being an absence of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReconstruction {
    pub label: ChainLabel,
    /// The per-hop (request handle, response handle) pairs, in order, for every
    /// hop that verified before the chain was labeled. On a `Complete` chain this
    /// is every hop; on an `Incomplete` one it is the verified prefix — the part
    /// of the record that IS accounted for.
    pub hop_evidence: Vec<HopEvidence>,
}

/// The two role-labeled handles a verified hop contributes to the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopEvidence {
    pub request_evidence: RequestEvidence,
    pub response_evidence: RequestEvidence,
}

/// Whether a hop's response was terminal or awaited client input.
///
/// DERIVED from the response's protected body, never supplied alongside it. An
/// earlier revision took this from a caller array parallel to `hops`, which was a
/// real hole: a caller could label a signed `InputRequiredResult` as `Terminal`
/// and a truncated chain would reconstruct as COMPLETE — the exact
/// "classification outside protected content" failure §13.2 lists. The
/// discriminator does live inside protected bytes; the bug was that
/// reconstruction was not reading them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopOutcome {
    /// An `InputRequiredResult`: this turn expects a continuation to follow.
    InputRequired,
    /// A terminal result: the call ends here.
    Terminal,
}

/// Classify a VERIFIED response body (`resultType == "input_required"`,
/// SEP-2322 / ADR-MCPS-047).
///
/// Only ever called on bytes whose signature and `content-digest` already
/// verified, so the classification is a reading of protected content rather than
/// a claim about it. Anything that is not the input-required discriminator is
/// terminal — the conservative direction, since mislabeling a terminal answer as
/// non-terminal would make a COMPLETE chain look truncated (a false alarm),
/// whereas the reverse would let a truncated chain pass as complete.
fn classify_verified_response(body: &[u8]) -> HopOutcome {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let is_input_required = parsed
        .as_ref()
        .and_then(|v| v.get("result"))
        .and_then(|r| r.get("resultType"))
        .and_then(|t| t.as_str())
        == Some("input_required");
    if is_input_required {
        HopOutcome::InputRequired
    } else {
        HopOutcome::Terminal
    }
}

/// Re-link and verify a retained chain R0→S0→R1→…→Sn (§9).
///
/// `hops` is the retained evidence in call order. `resolve_actor` is the same
/// trust seam the live path uses — a keyid never introduces trust here either, and
/// reconstruction is not a reason to relax it.
///
/// Terminal/non-terminal status is DERIVED from each response's protected body
/// after that response verifies. It is deliberately not a parameter: a caller-
/// supplied classification would be authoritative over the chain-shape rule, and a
/// truncated chain could be labeled complete by asserting its last
/// `InputRequiredResult` was terminal.
///
/// Returns the label plus the verified prefix. Verification stops at the first
/// broken hop: past that point the record is already not complete, and continuing
/// would invite reporting later hops as "fine" when nothing links them to a
/// beginning.
pub fn reconstruct_chain(
    hops: &[RetainedHop],
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    policy: &VerifierPolicy,
    now: i64,
) -> ChainReconstruction {
    let mut hop_evidence: Vec<HopEvidence> = Vec::with_capacity(hops.len());

    if hops.is_empty() {
        return ChainReconstruction {
            label: ChainLabel::Incomplete {
                hop: 0,
                reason: IncompleteReason::EmptyChain,
            },
            hop_evidence,
        };
    }

    for (i, hop) in hops.iter().enumerate() {
        // 1. The hop's request must verify on its own.
        let verified_req =
            match verify_request_with_policy(&hop.request, resolve_actor, policy, now) {
                Ok(v) => v,
                Err(e) => {
                    return incomplete(hop_evidence, i, IncompleteReason::RequestUnverifiable(e))
                }
            };

        // 2. The hop's response must verify AND be bound to that request.
        let verified_rsp = match verify_response_bound_full_with_policy(
            &hop.response,
            &hop.request,
            &verified_req.evidence,
            resolve_actor,
            policy,
            now,
        ) {
            Ok(v) => v,
            Err(e) => {
                return incomplete(hop_evidence, i, IncompleteReason::ResponseUnverifiable(e))
            }
        };

        // 3. Re-link to the previous hop. The first hop has nothing to link to;
        //    every later hop MUST carry a continuation naming its predecessor's
        //    two handles. This is where a missing middle hop is caught: hop i's
        //    continuation names hop i-1, so if i-1 is absent from the record the
        //    hop we DO have in that slot does not match.
        match (i, request_continuation(&hop.request)) {
            (0, _) => {}
            (_, None) => return incomplete(hop_evidence, i, IncompleteReason::MissingContinuation),
            (_, Some(c)) => {
                let prev: &HopEvidence = &hop_evidence[i - 1];
                let links = c.previous_request_evidence.digest_value
                    == prev.request_evidence.digest_value
                    && c.previous_request_evidence.digest_alg == prev.request_evidence.digest_alg
                    && c.input_required_response_evidence.digest_value
                        == prev.response_evidence.digest_value
                    && c.input_required_response_evidence.digest_alg
                        == prev.response_evidence.digest_alg;
                if !links {
                    return incomplete(
                        hop_evidence,
                        i,
                        IncompleteReason::ContinuationDoesNotLink,
                    );
                }
            }
        }

        // 4. Chain shape: every hop but the last awaits input; the last is
        //    terminal. The classification is read from the response body that
        //    just verified in step 2 — protected content, not an assertion
        //    travelling beside it.
        let outcome = classify_verified_response(&hop.response.body);
        let is_last = i + 1 == hops.len();
        match (is_last, outcome) {
            (false, HopOutcome::Terminal) => {
                return incomplete(hop_evidence, i, IncompleteReason::NonTerminalExpected)
            }
            (true, HopOutcome::InputRequired) => {
                return incomplete(hop_evidence, i, IncompleteReason::TerminalExpected)
            }
            _ => {}
        }

        hop_evidence.push(HopEvidence {
            request_evidence: verified_req.evidence.clone(),
            response_evidence: verified_rsp.response_signature_base_digest.clone(),
        });
    }

    ChainReconstruction {
        label: ChainLabel::Complete,
        hop_evidence,
    }
}

fn incomplete(
    hop_evidence: Vec<HopEvidence>,
    hop: usize,
    reason: IncompleteReason,
) -> ChainReconstruction {
    ChainReconstruction {
        label: ChainLabel::Incomplete { hop, reason },
        hop_evidence,
    }
}

/// The continuation from a request's evidence block, if it carries one.
///
/// Reading it here is safe only because the caller has already verified the
/// request's signature: `content-digest` is a covered component, so the block is
/// protected by the signature over the bytes this parses.
fn request_continuation(request: &HttpRequest) -> Option<HttpContinuation> {
    extract_meta_block::<HttpRequestEvidenceBlock>(
        &request.body,
        REQUEST_EVIDENCE_BLOCK_KEY,
        "request evidence block",
    )
    .ok()?
    .continuation
}
