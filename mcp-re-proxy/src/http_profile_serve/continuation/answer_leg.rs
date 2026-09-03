// SPDX-License-Identifier: Apache-2.0
//! The ANSWER leg: read a live approval, then spend it exactly once (ADR-MCPS-047).
//!
//! Two operations and two products, and every distinction here exists to stop the assembly
//! from collapsing an outcome into a neighbouring one:
//!
//! * the read is a `peek`. It has no side effect, which is what lets a request that is
//!   about to be refused leave a live approval intact — the refusals before the retirement
//!   are free, and they stay free only because nothing above spent anything.
//! * a deployment that holds no correlation capability refuses a leg that needs one,
//!   rather than letting the missing capability surface downstream as the caller's
//!   unbindable continuation.
//! * the spend is the store's atomic `consume`. Of two concurrent answer legs that both
//!   bound successfully, exactly one proceeds.
//! * the spend has FOUR outcomes rather than two, because the store's `Err` is not its
//!   `Ok(false)`.

use mcp_re_core::McpReError;
use mcp_re_http_profile::RetainedContinuation;

use crate::continuation_store::continuation_key;
use crate::continuation_store::ContinuationStoreError;
use crate::continuation_store::RetainedBases;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::http_profile_serve::Exchange;
use crate::refusal::Refusal;

use super::ContinuationPlane;

impl ContinuationPlane {
    /// CONTINUATION-PREPARED — recover the retained open-leg bases for an ANSWER leg.
    ///
    /// ```text
    /// ensures   Ok  => the continuation machine is NotInvolved or Peeked — never Consumed
    ///           Err => 503, bound: the shared tier did not answer
    /// forbids   consuming anything
    /// refusal   free — `peek` has no side effect, so nothing is spent
    /// ```
    ///
    /// Keyed by the actor the VERIFIER resolved, never by anything the request asserts, so
    /// one peer cannot name another's continuation at all.
    ///
    /// Three absences, and only ONE of them is about the caller.
    ///
    /// * this deployment holds no correlation capability. A DEPLOYMENT fact, and the leg
    ///   that needs correlation is refused as one — see [`capability_absent`].
    /// * the store did not answer. Also a deployment fact, refused as one.
    /// * the store answered and there was no live entry — never opened, expired, already
    ///   answered — or the request carries no usable continuation state. Those leave no
    ///   bases, and the binding then fails closed `continuation_binding_failed`, which is
    ///   a statement about the CALLER.
    ///
    /// Flattening the first two into the third reports a forged continuation every time
    /// the shared tier blips or a deployment runs without the capability, and hides a
    /// genuine splice attempt inside both.
    pub(in crate::http_profile_serve) async fn prepare(
        &self,
        ex: &Exchange<'_>,
        audience_id: &str,
    ) -> Result<Established<ContinuationPrep>, Refusal> {
        let has_continuation = ex.verified.request_block().continuation.is_some();
        let answer_state = if has_continuation {
            crate::http_profile_serve::extract_request_state(&ex.http_req.body)
        } else {
            None
        };
        let answer_key = answer_state
            .as_ref()
            .map(|state| continuation_key(audience_id, ex.actor_id, state.as_bytes()));
        let retained = match (&self.store, &answer_key) {
            (Some(store), Some(key)) => peeked_or_refusal(store.peek(key).await)?,
            // A key exists, so this leg NEEDS correlation, and this deployment holds no
            // capability to correlate with. Refused here rather than left to produce no
            // bases: the binding downstream would report the caller's continuation as
            // unbindable, which is a claim about the caller this deployment cannot make.
            (None, Some(_)) => return Err(capability_absent()),
            _ => None,
        };
        Ok(Established::new(
            ContinuationPrep {
                answer_state,
                answer_key,
                retained,
            },
            ExchangeEvent::ContinuationPrepared,
        ))
    }
}

/// What a `peek` established, or the refusal an unanswered store earns.
///
/// The one place the two absences are told apart, so that neither call site nor reader has
/// to reconstruct the distinction from an `Option` that lost it. `Ok(None)` is a MISS —
/// never opened, expired, already answered — and the binding then fails closed on the
/// caller's behalf. `Err` is an OUTAGE, which is a statement about this deployment rather
/// than about the caller: flattening the two would report a forged continuation every time
/// the shared tier blips, and would hide a genuine splice attempt inside an outage.
///
/// Neither outcome proceeds unbound, which is the property this exists to make checkable.
fn peeked_or_refusal(
    peeked: Result<Option<RetainedBases>, ContinuationStoreError>,
) -> Result<Option<RetainedBases>, Refusal> {
    peeked.map_err(|_| Refusal::before_admission(McpReError::ReplayCacheUnavailable, 503))
}

/// The refusal for a leg that needs correlation in a deployment that holds no correlation
/// capability.
///
/// The SAME classification an outage earns, and deliberately so: from the caller's side
/// "the tier this deployment would have consulted is not there" and "it did not answer" are
/// one fact — the deployment cannot decide this continuation — and they carry the same
/// retry meaning. What matters is that neither is reported as the caller's forged
/// continuation. A distinct wire code would split a caller-visible distinction out of two
/// deployment states the caller can do nothing differently about, and the frozen taxonomy
/// already expresses the one that matters.
///
/// Free, like every refusal above the retirement: nothing was peeked and nothing spent.
fn capability_absent() -> Refusal {
    Refusal::before_admission(McpReError::ReplayCacheUnavailable, 503)
}

/// What CONTINUATION-PREPARED recovered.
///
/// The owned `retained` and `answer_state` outlive the borrowed [`RetainedContinuation`]
/// handed to replay admission, which is why the borrow is produced on demand by
/// [`ContinuationPrep::binding`] rather than stored.
///
/// Private fields: the assembly reads named projections, so it cannot form its own opinion
/// about what an absent base means.
pub(in crate::http_profile_serve) struct ContinuationPrep {
    answer_state: Option<String>,
    answer_key: Option<String>,
    retained: Option<RetainedBases>,
}

impl ContinuationPrep {
    /// The binding to check the answer leg against, when there is one to check.
    ///
    /// `None` covers the CALLER-SIDE absences — no `requestState`, a store miss, an
    /// expired or already-answered entry — because the dispatcher must fail closed on
    /// `continuation_binding_failed` in all of them. A continuation that was signed but
    /// cannot be bound is never admitted.
    ///
    /// The deployment-side absences do not reach here at all: an outage and a missing
    /// capability are refused in [`ContinuationPlane::prepare`], so this `None` no longer
    /// stands for two kinds of fact at once.
    pub(in crate::http_profile_serve) fn binding(&self) -> Option<RetainedContinuation<'_>> {
        match (&self.retained, &self.answer_state) {
            (Some(bases), Some(state)) => Some(RetainedContinuation {
                previous_request_base: &bases.previous_request_base,
                input_required_response_base: &bases.input_required_response_base,
                request_state: state.as_bytes(),
            }),
            _ => None,
        }
    }

    /// Whether a live approval was READ for this exchange — the fact the continuation
    /// machine records as `Peeked`.
    ///
    /// Named rather than left as `retained.is_some()` at the call site: the assembly would
    /// then be deciding what an absent base means, which is the one reading this owner
    /// keeps for itself.
    pub(in crate::http_profile_serve) fn was_peeked(&self) -> bool {
        self.retained.is_some()
    }

    /// The key this exchange's approval is retired under, when it answers one.
    pub(in crate::http_profile_serve) fn answer_key(&self) -> Option<&String> {
        self.answer_key.as_ref()
    }
}

#[cfg(test)]
pub(in crate::http_profile_serve) mod tests {
    use super::*;
    use crate::continuation_store::AsyncContinuationStore;
    use std::sync::Arc;



    /// D1b′ / SLICE B: a deployment holding NO correlation capability refuses an answer
    /// leg that needs one, as a fact about the deployment.
    ///
    /// The dangerous alternative is the one that was here: no store means no retained
    /// bases, the binding downstream is absent, and the caller is told
    /// `continuation_binding_failed` — a statement that its continuation was forged. It
    /// fails closed either way; what it did not do is fail closed HONESTLY. Every
    /// legitimate answer leg reaching a deployment without the capability was reported as
    /// an attack.
    #[tokio::test]
    async fn an_absent_capability_is_the_deployments_fact_and_not_the_callers() {
        let verified = verified_as("did:example:host-a", "key-1");
        let actor_id = verified.resolved_actor().actor_id();
        let http_req = http_request(br#"{"params":{"requestState":"s-1"}}"#);
        let ex = Exchange {
            http_req: &http_req,
            verified: &verified,
            actor_id: &actor_id,
            now: 1,
            key: None,
        };

        let Err(refusal) = ContinuationPlane::disabled().prepare(&ex, "aud").await else {
            panic!("a leg needing correlation in a deployment with none must be refused");
        };
        assert_eq!(refusal.status, 503, "a deployment-side unavailability");
        assert_eq!(
            refusal.cause,
            crate::refusal::RefusalCause::from(McpReError::ReplayCacheUnavailable),
            "the same classification an outage earns, and never a binding failure"
        );
    }

    /// The negative half, which is what keeps the control above from being satisfied by a
    /// plane that refuses everything.
    ///
    /// A store-less deployment serving a request that needs NO correlation is ordinary and
    /// must proceed. The refusal is scoped to legs that actually need the capability.
    #[tokio::test]
    async fn a_store_less_deployment_still_serves_a_leg_that_needs_no_correlation() {
        let mut verified = verified_as("did:example:host-a", "key-1");
        verified.request_block.continuation = None;
        let actor_id = verified.resolved_actor().actor_id();
        let http_req = http_request(br#"{"params":{"requestState":"s-1"}}"#);
        let ex = Exchange {
            http_req: &http_req,
            verified: &verified,
            actor_id: &actor_id,
            now: 1,
            key: None,
        };

        let established = ContinuationPlane::disabled()
            .prepare(&ex, "aud")
            .await
            .expect("a leg carrying no continuation is not this owner's to refuse");
        let prep = crate::exchange_state::ExchangeProgress::new().establish(established);
        assert_eq!(prep.answer_key(), None);
        assert!(prep.binding().is_none());
        assert!(!prep.was_peeked(), "nothing was read, so nothing is at stake");
    }

    fn digest(of: &str) -> mcp_re_http_profile::RequestEvidenceDigest {
        mcp_re_http_profile::RequestEvidenceDigest {
            digest_alg: "sha-256".into(),
            digest_value: mcp_re_core::b64url_encode(of.as_bytes()),
        }
    }

    /// A verified request whose resolved actor is `subject`/`keyid`, carrying a
    /// continuation so the answer leg computes a key at all.
    ///
    /// The value stands in for a verification product because what is under test is the
    /// hop AFTER verification. That the product the serving path holds is the one THIS
    /// exchange's verification returned is THM-0051's, and is not re-derived here.
    pub(in crate::http_profile_serve) fn verified_as(
        subject: &str,
        keyid: &str,
    ) -> mcp_re_http_profile::VerifiedMcpRequest {
        let audience = mcp_re_http_profile::AudienceTuple {
            audience_id: "aud".into(),
            target_uri: "https://example.test/mcp".into(),
            route: None,
        };
        mcp_re_http_profile::VerifiedMcpRequest {
            floor: mcp_re_http_profile::CryptographicFloorVerifiedRequest {
                profile_id: "p".into(),
                signature_label: "mcpre".into(),
                resolved_actor: mcp_re_http_profile::ResolvedActor {
                    identity: mcp_re_http_profile::ActorIdentity {
                        role: "client".into(),
                        trust_domain: "example.com".into(),
                        subject: subject.into(),
                        keyid: keyid.into(),
                    },
                    verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32])
                        .public_key(),
                    slot: mcp_re_http_profile::SignerSlot::Request,
                },
                evidence: mcp_re_http_profile::RequestEvidence::from_signature_base(b"base"),
                request_signature_base: b"base".to_vec(),
                content_digest: mcp_re_http_profile::content_digest_sha256(b"{}"),
                created: 1,
                expires: 2,
                nonce: "n".into(),
                key_id: keyid.into(),
            },
            audience: audience.clone(),
            audience_hash: audience.audience_hash(),
            request_block: mcp_re_http_profile::HttpRequestEvidenceBlock {
                profile: "p".into(),
                audience,
                artifact_bindings: Vec::new(),
                continuation: Some(mcp_re_http_profile::HttpContinuation {
                    continuation_type: "mcp-mrt".into(),
                    previous_request_evidence: digest("prev"),
                    input_required_response_evidence: digest("irr"),
                    request_state_digest: digest("s-1"),
                }),
                admission: None,
                admission_assertion: None,
                authorization_decision: None,
            },
        }
    }

    /// A body that names a second identity in the members a leg reading the request would
    /// read. Nothing admits it; it is here so the controls can show it names nothing.
    pub(in crate::http_profile_serve) const BODY_ASSERTING_ANOTHER_ACTOR: &[u8] = br#"{"params":{"requestState":"s-1","actorIdentity":{"role":"client","trust_domain":"example.com","subject":"did:example:impostor","keyid":"key-9"}}}"#;

    pub(in crate::http_profile_serve) fn http_request(
        body: &[u8],
    ) -> crate::http_profile_serve::HttpRequest {
        crate::http_profile_serve::HttpRequest {
            method: "POST".into(),
            target_uri: "https://example.test/mcp".into(),
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    /// THE FINAL HOP: the operand is the actor projection of the verified product THIS
    /// exchange carries, and not an identity the request asserts.
    ///
    /// What this does NOT establish, because it is already established: that the product
    /// the exchange carries is the one this exchange's verification returned (THM-0051),
    /// or that the actor in it was resolved through the trust seam (THM-0014, in
    /// THM-0051's own closure). Those are premises here, not conjuncts. This control is
    /// about the one step between them and the key.
    ///
    /// It goes red for the change it exists to catch: a leg deriving the operand from a
    /// request-supplied identifier prepares the impostor's key, and every store-side
    /// separation control stays green while it does (probe M88).
    #[tokio::test]
    async fn the_operand_is_the_carried_products_actor_and_not_one_the_body_asserts() {
        let verified = verified_as("did:example:host-a", "key-1");
        let actor_id = verified.resolved_actor().actor_id();
        let http_req = http_request(BODY_ASSERTING_ANOTHER_ACTOR);
        let ex = Exchange {
            http_req: &http_req,
            verified: &verified,
            actor_id: &actor_id,
            now: 1,
            key: None,
        };

        // A store that answers a MISS and records what it was asked for. The plane must be
        // wired: a deployment holding no capability now refuses this leg outright, and the
        // fact under test is which key a deployment that CAN look one up asks with.
        let store = Arc::new(PeekRecordingStore::default());
        let established = ContinuationPlane::wired(store.clone(), 300)
            .prepare(&ex, "aud")
            .await
            .expect("a store miss is the caller's fact, not a refusal");
        let prep = crate::exchange_state::ExchangeProgress::new().establish(established);

        let carried = continuation_key("aud", &verified.resolved_actor().actor_id(), b"s-1");
        let asserted = continuation_key(
            "aud",
            "client:example.com:did:example:impostor:key-9",
            b"s-1",
        );
        assert_ne!(carried, asserted, "the two identities must differ at all");
        assert_eq!(prep.answer_key(), Some(&carried));
        // The key the STORE was asked with, not only the one the prep reports. A leg that
        // computed the carried key and looked up the asserted one would satisfy the
        // assertion above; this is what probe M88 has to move.
        assert_eq!(store.keys(), vec![carried]);
    }

    /// A store that misses every read and remembers the keys it was asked for.
    #[derive(Default)]
    struct PeekRecordingStore(std::sync::Mutex<Vec<String>>);

    impl PeekRecordingStore {
        fn keys(&self) -> Vec<String> {
            self.0.lock().expect("no test thread panics here").clone()
        }
    }

    impl AsyncContinuationStore for PeekRecordingStore {
        fn store<'a>(
            &'a self,
            _key: &'a str,
            _bases: &'a RetainedBases,
            _ttl_secs: i64,
        ) -> crate::continuation_store::ContinuationFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn peek<'a>(
            &'a self,
            key: &'a str,
        ) -> crate::continuation_store::ContinuationFuture<'a, Option<RetainedBases>> {
            self.0
                .lock()
                .expect("no test thread panics here")
                .push(key.to_owned());
            Box::pin(async { Ok(None) })
        }

        fn consume<'a>(
            &'a self,
            _key: &'a str,
        ) -> crate::continuation_store::ContinuationFuture<'a, bool> {
            Box::pin(async { Ok(false) })
        }
    }

    #[test]
    fn a_prep_with_no_retained_bases_offers_no_binding() {
        // Every way the bases can be absent collapses to one answer, on purpose: the
        // dispatcher must fail closed on `continuation_binding_failed` in all of them, and
        // a continuation that was signed but cannot be bound is never admitted.
        let prep = ContinuationPrep {
            answer_state: Some("s-1".to_owned()),
            answer_key: Some("k-1".to_owned()),
            retained: None,
        };
        assert!(prep.binding().is_none());
        assert!(
            !prep.was_peeked(),
            "nothing was read, so nothing is at stake"
        );
        assert_eq!(prep.answer_key(), Some(&"k-1".to_owned()));
    }
    /// D2b: an outage and a miss are different facts, and NEITHER proceeds unbound.
    ///
    /// The miss leaves no bases, so the binding is absent and the dispatcher fails closed
    /// on `continuation_binding_failed` — a statement about the caller. The outage refuses
    /// here, before admission, as a statement about this deployment. A single `Option`
    /// would report the first for both, which reads as a forged continuation every time the
    /// shared tier blips and hides a genuine splice attempt inside an outage.
    #[test]
    fn a_store_outage_is_refused_before_admission_and_is_not_a_miss() {
        let miss = peeked_or_refusal(Ok(None)).expect("a miss is not a refusal here");
        assert!(
            miss.is_none(),
            "a miss must leave no bases, so the binding fails closed downstream"
        );

        let outage = peeked_or_refusal(Err(ContinuationStoreError::Unavailable {
            details: "the shared tier did not answer".into(),
        }))
        .expect_err("an outage must refuse rather than proceed unbound");
        assert_eq!(outage.status, 503);
        assert_eq!(
            outage.cause,
            crate::refusal::RefusalCause::from(McpReError::ReplayCacheUnavailable)
        );

        let hit = peeked_or_refusal(Ok(Some(RetainedBases {
            previous_request_base: b"req".to_vec(),
            input_required_response_base: b"resp".to_vec(),
        })))
        .expect("a live entry is not a refusal");
        assert!(hit.is_some(), "the positive control: a hit binds");
    }
}
