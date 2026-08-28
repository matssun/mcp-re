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
//!   1. the request verifies (content-digest, signature evidence, trust,
//!      signature), and its evidence BLOCK is present, structurally valid, and
//!      names the URI the request was sent to;
//!   2. the response verifies AND is `;req`-bound to that same request;
//!   3. for every hop after the first, the request's continuation re-links to the
//!      PREVIOUS hop: its `previous_request_evidence` is that hop's request
//!      handle and its `input_required_response_evidence` is that hop's response
//!      handle — both role-labeled, so a handle cannot be lifted between fields;
//!   4. the shape of the chain: every hop before the last is non-terminal
//!      (`InputRequiredResult`), the last is terminal, and the first hop carries no
//!      continuation — one that does names a predecessor the record cannot produce.
//!
//! What it does NOT do: fetch evidence, decide retention, or judge whether the
//! set it was handed is all the evidence that exists. A caller that retains three
//! hops out of four and asks about those three gets an answer about those three.
//! Detecting that a hop is missing from the MIDDLE is what re-linking gives you;
//! detecting that the chain was truncated at the END is what the terminal-shape
//! check gives you, and at the START, that hop 0's own continuation has nothing to
//! link to. Neither can tell you the retention itself was honest — that
//! is Layer 5's job, and the reason [`ChainReconstruction`] is shaped to be
//! committed to (a SCITT receipt over a complete OR explicitly-incomplete record).
//!
//! The two full-profile REQUEST checks that need inputs the retained bytes cannot
//! supply — equality of each hop's audience tuple against the VERIFIER's own, and
//! `artifact_bindings[]`, whose credential surface (an mTLS certificate, a RAR detail)
//! the request does not carry — are taken from [`ChainAudit`] and enforced through the
//! same function the live path uses. A `Complete` label therefore asserts what an
//! admission asserts, which is the point: the label is embedded in a SCITT Signed
//! Statement, so "served" and "accounted for" must be one verdict.

use mcp_re_core::b64url_encode;
use sha2::Digest;
use sha2::Sha256;

use crate::block::ArtifactBinding;
use crate::block::AudienceTuple;
use crate::block::HttpRequestEvidenceBlock;
use crate::block::ResolverOutcome;
use crate::body::extract_meta_block;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::ids::REQUEST_LABEL;
use crate::ids::RESPONSE_LABEL;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::VerifierPolicy;
use crate::verifier::Verifier;
use crate::verify::floor::signature_input::parse_signature_input_for;
use crate::verify::DelegationExpectations;

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
    /// The hop's response declares a `resultType` this reader does not recognize,
    /// so whether that turn ended is unknown. The record is labeled incomplete AT
    /// THAT HOP rather than assuming an answer: a chain whose shape rests on an
    /// unread value is not a chain anyone verified.
    UnrecognizedResultType,
    /// The reconstruction was handed no hops at all.
    EmptyChain,
    /// A message in this hop declares a `created` later than the audit instant.
    /// A record cannot contain evidence from the future, so the chain is refused
    /// rather than verified at an instant its own archivist could not have
    /// observed.
    HopAfterAuditInstant,
}

/// The verdict on a retained chain. Never a bare boolean (§9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainLabel {
    /// Every hop verified and re-linked, and the chain ends terminally.
    Complete,
    /// The chain is not a complete record. `hop` is the zero-based index of the
    /// first hop that broke it — an auditor is told WHICH turn is unaccounted
    /// for, not merely that something is wrong.
    Incomplete {
        hop: usize,
        reason: IncompleteReason,
    },
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
    /// A digest over the SUBMITTED hop bytes, whether or not any of them verified.
    ///
    /// [`hop_evidence`](Self::hop_evidence) is the verified prefix, so a chain that
    /// broke at hop 0 contributes nothing to it and every such record collapsed to the
    /// same three identity fields: two empty handles and a fold over zero bytes. A
    /// Signed Statement about one could not be told from a statement about any other
    /// call that failed the same way, which makes "this record is about that call" an
    /// unanswerable question exactly where an auditor most needs it answered.
    ///
    /// This is the answer, and it is deliberately taken from what was SUBMITTED rather
    /// than from what verified: unverified bytes are still specific bytes. It is an
    /// identity, never an endorsement — nothing here asserts the submission was
    /// well-formed, authentic, or served.
    pub submitted_commitment: String,
}

/// The full-profile inputs a retained record cannot supply for itself.
///
/// Audience-tuple equality needs the VERIFIER's own tuple, and `artifact_bindings[]`
/// needs a credential surface (mTLS certificate, RAR detail) the retained request does
/// not carry. Without them reconstruction ran the minimal proof path and a `Complete`
/// label asserted less than the enforcement boundary does — so a Signed Statement could
/// commit to a whole call record containing requests the live path would have refused.
///
/// Bundled rather than added as two more positional parameters so that a caller has to
/// name what it is supplying, and so that adding a third full-profile input later is not
/// another signature break at every call site.
pub struct ChainAudit<'a> {
    /// The verifier's own audience tuple. Every hop's block must equal it.
    pub expected_audience: &'a AudienceTuple,
    /// Credential bytes for bindings that cannot be derived from covered headers. A
    /// binding with no obtainable credential fails closed.
    pub artifact_material: &'a dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
}

/// Digest the submitted hops, length-delimited so no two distinct submissions can share
/// a preimage.
///
/// Every variable-length field is preceded by its length as 8 octets big-endian.
/// Concatenating raw bytes would let a request ending in one byte and a response
/// beginning with another produce the same stream as a different split, which is exactly
/// the ambiguity an identity must not have.
fn submitted_commitment(hops: &[RetainedHop]) -> String {
    let mut h = Sha256::new();
    h.update(SUBMITTED_COMMITMENT_DOMAIN.len().to_be_bytes());
    h.update(SUBMITTED_COMMITMENT_DOMAIN);
    h.update((hops.len() as u64).to_be_bytes());
    for hop in hops {
        // The request line and the response status are part of what was submitted, so
        // two submissions differing only in method or status must not share an identity.
        h.update(u64::from(hop.response.status).to_be_bytes());
        for part in [
            hop.request.method.as_bytes(),
            hop.request.target_uri.as_bytes(),
            hop.request.body.as_slice(),
            hop.response.body.as_slice(),
        ] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        // The signatures are what make one submission of the same JSON distinct from
        // another, so they are part of the identity too.
        for headers in [&hop.request.headers, &hop.response.headers] {
            let mut signature_headers: Vec<(&str, &str)> = headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("signature"))
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            signature_headers.sort_unstable();
            h.update((signature_headers.len() as u64).to_be_bytes());
            for (name, value) in signature_headers {
                h.update((name.len() as u64).to_be_bytes());
                h.update(name.as_bytes());
                h.update((value.len() as u64).to_be_bytes());
                h.update(value.as_bytes());
            }
        }
    }
    b64url_encode(&h.finalize())
}

/// Domain separator for [`submitted_commitment`], so its digests can never be confused
/// with any other SHA-256 this profile takes over evidence.
const SUBMITTED_COMMITMENT_DOMAIN: &[u8] = b"mcp-re-evidence/v2:submitted-chain";

/// The two role-labeled handles a verified hop contributes to the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopEvidence {
    pub request_evidence: RequestEvidence,
    pub response_evidence: RequestEvidence,
}

/// Whether a hop's response was terminal, awaited client input, or could not be
/// classified at all.
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
    /// A `resultType` this reader does not recognize, so whether the turn ended
    /// is unknown.
    Unrecognized,
}

/// Classify a VERIFIED response body through the single discriminator
/// ([`crate::result_class`], SEP-2322 / ADR-MCPS-047).
///
/// Only ever called on bytes whose signature and `content-digest` already
/// verified, so the classification is a reading of protected content rather than
/// a claim about it.
///
/// An unrecognized `resultType` is reported as such rather than folded into
/// terminal. Reconstruction is the one reader for which "unknown ⇒ terminal" is
/// nearly defensible — mislabeling a terminal answer as non-terminal is only a
/// false alarm, while the reverse lets a truncated chain pass as complete — but
/// "nearly" is doing the work. If the last hop of a truncated chain carried an
/// extension's non-terminal `resultType`, unknown-as-terminal would label that
/// chain COMPLETE, which is precisely the laundering §9.3 forbids. An auditor is
/// better served by "hop 2 declares a result type I cannot classify" than by a
/// confident answer derived from a value nobody read.
///
/// A body that will not parse is terminal: an unparseable body cannot have
/// verified in step 2, so this is never reached with one.
fn classify_verified_response(body: &[u8]) -> HopOutcome {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    match crate::result_class::classify_result_type(parsed.as_ref().and_then(|v| v.get("result"))) {
        crate::result_class::ResultTypeClass::InputRequired => HopOutcome::InputRequired,
        crate::result_class::ResultTypeClass::Complete => HopOutcome::Terminal,
        crate::result_class::ResultTypeClass::Unrecognized => HopOutcome::Unrecognized,
    }
}

/// Re-link and verify a retained chain R0→S0→R1→…→Sn (§9).
///
/// `hops` is the retained evidence in call order. `resolve_actor` is the same
/// trust seam the live path uses — a keyid never introduces trust here either, and
/// reconstruction is not a reason to relax it.
///
/// `now` is the AUDIT instant, not the freshness clock: each message is verified
/// at its own covered `created`, and `now` bounds those from above so a record
/// cannot contain evidence from the future. [`hop_instant`] carries the reasoning.
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
/// `expect` and `is_revoked` are the ADR-MCPRE-052 delegated-verification inputs.
///
/// They are not optional and there is no direct-root fallback, because there is no
/// direct-root evidence to reconstruct: delegated-required is the only response-signing
/// mode the serving path has. Verifying hop responses through the pre-052 path — as an
/// earlier revision did — meant reconstruction could not verify the evidence MCP-RE
/// actually emits (every hop failed on an unresolvable delegated kid), and an auditor
/// who worked around that by vouching for delegated kids at the trust seam would have
/// skipped the credential's expiry, revocation, audience scope, key use, trust epoch
/// and root binding for the audit verdict. That verdict is not local: the label is
/// embedded in the SCITT Signed Statement, so a receipt could commit to a COMPLETE call
/// record established without any delegation chain ever being checked.
pub fn reconstruct_chain<R: Into<ResolverOutcome>>(
    hops: &[RetainedHop],
    verifier: &Verifier<'_, R>,
    expect: &DelegationExpectations<'_>,
    audit: &ChainAudit<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> ChainReconstruction {
    let mut hop_evidence: Vec<HopEvidence> = Vec::with_capacity(hops.len());
    // Taken over what was handed in, before any of it is judged, so the record has an
    // identity on every path out of this function including the ones that verify nothing.
    let submitted = submitted_commitment(hops);

    if hops.is_empty() {
        return ChainReconstruction {
            label: ChainLabel::Incomplete {
                hop: 0,
                reason: IncompleteReason::EmptyChain,
            },
            hop_evidence,
            submitted_commitment: submitted,
        };
    }

    for (i, hop) in hops.iter().enumerate() {
        // 0. Each message is verified at its own covered `created`, bounded above
        //    by the audit instant. See [`hop_instant`] for why a retained record
        //    cannot be held to the live clock.
        let request_at = match hop_instant(
            &hop.request.headers,
            REQUEST_LABEL,
            "request signature-input",
            verifier.policy(),
            now,
        ) {
            Ok(t) => t,
            Err(HopInstantError::Unreadable(e)) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::RequestUnverifiable(e),
                    submitted,
                )
            }
            Err(HopInstantError::AfterAuditInstant) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::HopAfterAuditInstant,
                    submitted,
                )
            }
        };
        let response_at = match hop_instant(
            &hop.response.headers,
            RESPONSE_LABEL,
            "response signature-input",
            verifier.policy(),
            now,
        ) {
            Ok(t) => t,
            Err(HopInstantError::Unreadable(e)) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::ResponseUnverifiable(e),
                    submitted,
                )
            }
            Err(HopInstantError::AfterAuditInstant) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::HopAfterAuditInstant,
                    submitted,
                )
            }
        };

        // 1. The hop's request must verify on its own.
        let verified_req = match verifier.verify_request_floor(&hop.request, request_at) {
            Ok(v) => v,
            Err(e) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::RequestUnverifiable(e),
                    submitted,
                )
            }
        };

        // 1b. The request evidence block itself, not merely the signature over it.
        //
        //     Step 1 runs the MINIMAL proof path, which stops at the RFC 9421
        //     signature and the MCP transport contract: it never looks inside the
        //     block. A hop with no block at all, or one whose block fails its own
        //     structural rules, or one whose audience names a target other than the
        //     URI the request was actually sent to, verified all the same — so a
        //     record could be labelled `Complete`, and a Signed Statement issued over
        //     it, while containing requests the enforcement boundary would have
        //     refused. "Served" and "accounted for" have to be the same verdict.
        //
        //     The audience tuple and `artifact_bindings[]` are enforced through the
        //     SAME function the live path uses, against the caller-supplied
        //     [`ChainAudit`]. One implementation, so an auditor's `Complete` cannot
        //     mean less than an admission.
        let block: HttpRequestEvidenceBlock = match extract_meta_block(
            &hop.request.body,
            REQUEST_EVIDENCE_BLOCK_KEY,
            "request evidence block",
        ) {
            Ok(b) => b,
            Err(e) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::RequestUnverifiable(e),
                    submitted,
                )
            }
        };
        if let Err(e) = block.validate(&verified_req.profile_id) {
            return incomplete(
                hop_evidence,
                i,
                IncompleteReason::RequestUnverifiable(e),
                submitted,
            );
        }
        if let Err(e) = crate::verify::enforce_full_profile_bindings(
            &hop.request,
            &block,
            audit.expected_audience,
            audit.artifact_material,
        ) {
            return incomplete(
                hop_evidence,
                i,
                IncompleteReason::RequestUnverifiable(e),
                submitted,
            );
        }

        // 2. The hop's response must verify AND be bound to that request.
        let verified_rsp = match verifier.verify_delegated_bound_response(
            &hop.response,
            &hop.request,
            &verified_req.evidence,
            expect,
            is_revoked,
            response_at,
        ) {
            Ok(v) => v,
            Err(e) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::ResponseUnverifiable(e),
                    submitted,
                )
            }
        };

        // 3. Re-link to the previous hop. Every hop after the first MUST carry a
        //    continuation naming its predecessor's two handles. This is where a
        //    missing middle hop is caught: hop i's continuation names hop i-1, so if
        //    i-1 is absent from the record the hop we DO have in that slot does not
        //    match.
        //
        //    Hop 0 OPENS the record, and that is a claim about the record, not a
        //    licence to skip the check. A hop 0 that carries a continuation names a
        //    predecessor the record cannot produce: the call started before the
        //    evidence does. Accepting it labelled a front-truncated record
        //    `Complete` — submit hops 1 and 2 of a real R0→S0→R1→S1→R2→S2 call and
        //    every remaining hop verifies, hop 2 re-links to hop 1, hop 2 is
        //    terminal — so a Signed Statement could commit to a whole call record
        //    with the opening turns, their audience and their artifact bindings
        //    missing. It lands on the same reason as the missing middle, which is
        //    what it is: a continuation naming evidence that is not in the record.
        match (i, block.continuation.as_ref()) {
            (0, None) => {}
            (0, Some(_)) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::ContinuationDoesNotLink,
                    submitted,
                )
            }
            (_, None) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::MissingContinuation,
                    submitted,
                )
            }
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
                        submitted,
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
            (_, HopOutcome::Unrecognized) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::UnrecognizedResultType,
                    submitted,
                )
            }
            (false, HopOutcome::Terminal) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::NonTerminalExpected,
                    submitted,
                )
            }
            (true, HopOutcome::InputRequired) => {
                return incomplete(
                    hop_evidence,
                    i,
                    IncompleteReason::TerminalExpected,
                    submitted,
                )
            }
            _ => {}
        }

        hop_evidence.push(HopEvidence {
            request_evidence: verified_req.evidence.clone(),
            response_evidence: verified_rsp
                .signature_facts
                .response_signature_base_digest
                .clone(),
        });
    }

    ChainReconstruction {
        label: ChainLabel::Complete,
        hop_evidence,
        submitted_commitment: submitted,
    }
}

/// Why an instant could not be taken from a retained message.
enum HopInstantError {
    /// The message carries no readable `signature-input`, or no `created` in it.
    /// Verification would fail on the same ground, so this is reported as the
    /// message being unverifiable rather than as a distinct kind of break.
    Unreadable(HttpProfileError),
    /// The message declares a `created` after the audit instant.
    AfterAuditInstant,
}

/// The instant at which ONE retained message is verified.
///
/// A retained chain is a RECORD, not live traffic. Verifying every hop against the
/// caller's live clock made [`ChainLabel::Complete`] unreachable for any genuine
/// multi-turn call older than a single freshness window: hop 0's window closes
/// while the call is still in progress, so the label decayed with age instead of
/// describing the evidence. Each message is therefore verified at its OWN covered
/// `created`, which satisfies its own freshness test by construction — a window
/// with `expires <= created` is refused skew-free, so `created` always lies inside
/// the window that message declares.
///
/// This does not relax the window rules. Both are properties of the message rather
/// than of the clock, and both still run per hop: the degenerate-window check and
/// the bound on how WIDE a signer may declare its window. And `created` is covered
/// by the signature that is about to be checked, so a hop cannot move its own
/// verification instant without invalidating itself — reading it here, before that
/// signature verifies, decides only which instant to test, never whether to trust.
///
/// `now` keeps a job, and a sharper one: it is the AUDIT instant. A message
/// `created` after it is refused, because a record cannot contain evidence from
/// the future. The same skew tolerance the live path allows applies, so an
/// archivist whose clock trails the signer's by less than the tolerance does not
/// see its own honest records rejected.
fn hop_instant(
    headers: &[(String, String)],
    label: &str,
    what: &'static str,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<i64, HopInstantError> {
    let parsed =
        parse_signature_input_for(headers, label, what).map_err(HopInstantError::Unreadable)?;
    let created = parsed
        .params
        .created
        .ok_or(HopInstantError::Unreadable(HttpProfileError::StaleWindow))?;
    if created.saturating_sub(policy.max_clock_skew()) > now {
        return Err(HopInstantError::AfterAuditInstant);
    }
    Ok(created)
}

fn incomplete(
    hop_evidence: Vec<HopEvidence>,
    hop: usize,
    reason: IncompleteReason,
    submitted_commitment: String,
) -> ChainReconstruction {
    ChainReconstruction {
        label: ChainLabel::Incomplete { hop, reason },
        hop_evidence,
        submitted_commitment,
    }
}

#[cfg(test)]
mod tests {
    // This module is the file's test region: `scripts/module_size_gate.py` opens it at the
    // `#[cfg(test)]` above and stops counting production lines here. The note lives INSIDE
    // the region rather than above it, because a comment above the marker is a production
    // line, and this file is registered in `config/module-size-debt.toml` — where the
    // ratchet only turns one way.
    use super::*;

    fn hop(status: u16, body: &str) -> RetainedHop {
        RetainedHop {
            request: HttpRequest {
                method: "POST".to_string(),
                target_uri: "https://mcp.example.com/mcp".to_string(),
                headers: vec![("signature".to_string(), "sig=:AAAA:".to_string())],
                body: br#"{"jsonrpc":"2.0","id":1}"#.to_vec(),
            },
            response: HttpResponse {
                status,
                headers: vec![("signature".to_string(), "sig=:BBBB:".to_string())],
                body: body.as_bytes().to_vec(),
            },
        }
    }

    /// Two submissions that differ only in the response STATUS are different submissions.
    ///
    /// The commitment is what a Layer 5 receipt binds to, so a refusal and a success over
    /// identical bodies must not share an identity.
    #[test]
    fn the_response_status_is_part_of_the_submitted_identity() {
        assert_ne!(
            submitted_commitment(&[hop(200, "{}")]),
            submitted_commitment(&[hop(400, "{}")])
        );
    }

    /// Two submissions of the SAME JSON under different signatures are different
    /// submissions. Without this the commitment would identify the content rather than
    /// the act of submitting it.
    #[test]
    fn the_signature_is_part_of_the_submitted_identity() {
        let mut other = hop(200, "{}");
        other.response.headers = vec![("signature".to_string(), "sig=:CCCC:".to_string())];
        assert_ne!(
            submitted_commitment(&[hop(200, "{}")]),
            submitted_commitment(&[other])
        );
    }

    /// The length prefixes are load-bearing: moving a byte across a field boundary must
    /// change the digest. Without them `("ab", "")` and `("a", "b")` would hash the same
    /// concatenation and two distinct submissions would share one identity.
    #[test]
    fn field_boundaries_cannot_be_shifted_without_changing_the_commitment() {
        let mut left = hop(200, "{}");
        left.request.method = "POSTX".to_string();
        left.request.target_uri = "https://mcp.example.com/mcp".to_string();

        let mut right = hop(200, "{}");
        right.request.method = "POST".to_string();
        right.request.target_uri = "Xhttps://mcp.example.com/mcp".to_string();

        assert_ne!(
            submitted_commitment(&[left]),
            submitted_commitment(&[right])
        );
    }

    /// Signature headers are sorted before hashing, so header ORDER is not part of the
    /// identity — the same submission observed through two transports commits equally.
    #[test]
    fn signature_header_order_does_not_change_the_commitment() {
        let mut a = hop(200, "{}");
        a.request.headers = vec![
            ("signature".to_string(), "sig1=:AA:".to_string()),
            ("signature".to_string(), "sig2=:BB:".to_string()),
        ];
        let mut b = hop(200, "{}");
        b.request.headers = vec![
            ("signature".to_string(), "sig2=:BB:".to_string()),
            ("signature".to_string(), "sig1=:AA:".to_string()),
        ];
        assert_eq!(submitted_commitment(&[a]), submitted_commitment(&[b]));
    }

    /// Only `signature` headers contribute. A hop-by-hop header a proxy added is not part
    /// of what was submitted, so it must not change the identity.
    #[test]
    fn non_signature_headers_are_outside_the_submitted_identity() {
        let mut with_extra = hop(200, "{}");
        with_extra
            .request
            .headers
            .push(("x-forwarded-for".to_string(), "10.0.0.1".to_string()));
        assert_eq!(
            submitted_commitment(&[hop(200, "{}")]),
            submitted_commitment(&[with_extra])
        );
    }

    /// The hop COUNT is committed, so a chain is not confusable with a prefix of a longer
    /// one carrying the same hops.
    #[test]
    fn the_hop_count_is_part_of_the_submitted_identity() {
        assert_ne!(
            submitted_commitment(&[hop(200, "{}")]),
            submitted_commitment(&[hop(200, "{}"), hop(200, "{}")])
        );
    }

    /// An unrecognized `resultType` is NEVER folded into terminal. Doing so would label a
    /// truncated chain COMPLETE when its last hop carried an extension's non-terminal
    /// type — the laundering §9.3 forbids.
    #[test]
    fn an_unrecognized_result_type_is_not_terminal() {
        let outcome = classify_verified_response(
            br#"{"result":{"resultType":"something/nobody/registered"}}"#,
        );
        assert_eq!(outcome, HopOutcome::Unrecognized);
        assert_ne!(outcome, HopOutcome::Terminal);
    }

    /// An `InputRequiredResult` announces that the turn expects a continuation.
    ///
    /// Built from the profile's own constant rather than a literal, so this test cannot
    /// pass while disagreeing with the single discriminator every other reader shares.
    #[test]
    fn an_input_required_result_expects_a_continuation() {
        let body = format!(
            r#"{{"result":{{"resultType":"{}"}}}}"#,
            crate::result_class::INPUT_REQUIRED_RESULT_TYPE
        );
        assert_eq!(
            classify_verified_response(body.as_bytes()),
            HopOutcome::InputRequired
        );
    }

    /// An explicit terminal `resultType` ends the call, from the same constant.
    #[test]
    fn an_explicit_complete_result_type_is_terminal() {
        let body = format!(
            r#"{{"result":{{"resultType":"{}"}}}}"#,
            crate::result_class::COMPLETE_RESULT_TYPE
        );
        assert_eq!(
            classify_verified_response(body.as_bytes()),
            HopOutcome::Terminal
        );
    }

    /// An absent `resultType` is terminal, as MCP 2026-07-28 requires of readers.
    #[test]
    fn an_absent_result_type_is_terminal() {
        assert_eq!(
            classify_verified_response(br#"{"result":{"content":[]}}"#),
            HopOutcome::Terminal
        );
    }

    /// `is_complete` is true of exactly one label. An incomplete chain never reports as a
    /// complete record, whatever broke it or where.
    #[test]
    fn only_the_complete_label_reports_complete() {
        assert!(ChainLabel::Complete.is_complete());
        for reason in [
            IncompleteReason::MissingContinuation,
            IncompleteReason::ContinuationDoesNotLink,
            IncompleteReason::NonTerminalExpected,
            IncompleteReason::TerminalExpected,
            IncompleteReason::UnrecognizedResultType,
            IncompleteReason::EmptyChain,
            IncompleteReason::HopAfterAuditInstant,
        ] {
            assert!(
                !ChainLabel::Incomplete { hop: 0, reason }.is_complete(),
                "an incomplete chain reported as a complete record"
            );
        }
    }
}
