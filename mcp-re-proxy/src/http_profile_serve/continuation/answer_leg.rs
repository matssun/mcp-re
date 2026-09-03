// SPDX-License-Identifier: Apache-2.0
//! The ANSWER leg: read a live approval, then spend it exactly once (ADR-MCPS-047).
//!
//! Two operations and two products, and every distinction here exists to stop the assembly
//! from collapsing an outcome into a neighbouring one:
//!
//! * the read is a `peek`. It has no side effect, which is what lets a request that is
//!   about to be refused leave a live approval intact — the refusals before the retirement
//!   are free, and they stay free only because nothing above spent anything.
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
    /// A store MISS and a store OUTAGE are refused differently. A miss — never opened,
    /// expired, already answered — leaves no bases, and the binding then fails closed
    /// `continuation_binding_failed`, which is a statement about the CALLER. An outage is a
    /// statement about this DEPLOYMENT, so it is named as one: flattening the two reports a
    /// forged continuation every time the shared tier blips, and hides a genuine splice
    /// attempt inside an outage.
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

    /// CONTINUATION-RETIRED — spend the approval, exactly once.
    ///
    /// ```text
    /// ensures   what the shared tier reported, as a [`Retirement`]
    /// forbids   running the backend
    /// refusal   minted by the CALLER — see [`Retirement`]
    /// ```
    ///
    /// The three non-proceeding outcomes are not the same fact, so this reports what
    /// happened and the caller — which holds the continuation machine — decides both the
    /// refusal and what the exchange may claim about the approval. A stage cannot do the
    /// second, and a stage that refused without it would be stating a retry contract it
    /// cannot know.
    pub(in crate::http_profile_serve) async fn retire(
        &self,
        answer_key: Option<&String>,
    ) -> Retirement {
        let (Some(store), Some(key)) = (&self.store, answer_key) else {
            return Retirement::NotInvolved;
        };
        match store.consume(key).await {
            Ok(true) => Retirement::Retired,
            Ok(false) => Retirement::AlreadyAnswered,
            Err(_) => Retirement::Indeterminate,
        }
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
    /// `None` covers every way the bases can be absent — no store, no `requestState`, a
    /// store miss, an expired or already-answered entry, a store outage — because the
    /// dispatcher must fail closed on `continuation_binding_failed` in all of them. A
    /// continuation that was signed but cannot be bound is never admitted.
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

/// What the shared tier reported when this exchange tried to retire the approval it
/// answers.
///
/// Four values, because the store's `Err` is not the store's `Ok(false)`. A `DEL` whose
/// reply was never read may well have executed, so "there was definitely nothing to
/// retire" and "the entry may or may not be gone" are different facts about a human's
/// approval: they warrant different wire codes, and — the load-bearing part — different
/// claims about whether an ordinary retry can still succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http_profile_serve) enum Retirement {
    /// This deployment runs no store, or this request answers nothing. No approval is at
    /// stake.
    NotInvolved,
    /// THIS call removed the live entry. **The approval is spent.**
    Retired,
    /// The store ANSWERED, and there was no live entry to remove: already answered,
    /// expired, or a splice. A statement about the caller.
    AlreadyAnswered,
    /// The store did not answer. The entry may or may not be gone, and nothing downstream
    /// can find out — the answer leg is the only thing that would have consumed it.
    Indeterminate,
}

#[cfg(test)]
pub(in crate::http_profile_serve) mod tests {
    use super::*;
    use crate::continuation_store::AsyncContinuationStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn a_deployment_with_no_store_retires_nothing() {
        // `NotInvolved` is not "the retirement failed". No approval was ever at stake, so
        // the exchange may claim nothing was spent — which is what the assembly records.
        let plane = ContinuationPlane::disabled();
        assert_eq!(plane.retire(None).await, Retirement::NotInvolved);
        assert_eq!(
            plane.retire(Some(&"k".to_owned())).await,
            Retirement::NotInvolved,
            "a key with nowhere to retire it against is still nothing at stake"
        );
    }

    #[tokio::test]
    async fn the_second_answer_leg_is_told_the_approval_was_already_spent() {
        // One-shot, and the two non-proceeding outcomes are not the same fact. The first
        // leg spends the approval; the second gets `AlreadyAnswered` — a statement about
        // the CALLER — rather than the `Indeterminate` reserved for a tier that did not
        // answer at all.
        let store = Arc::new(crate::continuation_store::InMemoryContinuationStore::new());
        let plane = ContinuationPlane::wired(store.clone(), 300);
        let key = continuation_key("aud", "actor-1", b"s-1");
        store
            .store(
                &key,
                &RetainedBases {
                    previous_request_base: b"req".to_vec(),
                    input_required_response_base: b"resp".to_vec(),
                },
                300,
            )
            .await
            .expect("the in-memory tier accepts an open leg");

        assert_eq!(plane.retire(Some(&key)).await, Retirement::Retired);
        assert_eq!(plane.retire(Some(&key)).await, Retirement::AlreadyAnswered);
    }

    /// A tier that does not answer the SPEND. Its own case, and it has to be reachable.
    ///
    /// The in-memory store cannot produce it — it never fails — so the fourth outcome has
    /// no control without a store that errors on `consume`.
    struct UnansweringStore;

    impl AsyncContinuationStore for UnansweringStore {
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
            _key: &'a str,
        ) -> crate::continuation_store::ContinuationFuture<'a, Option<RetainedBases>> {
            Box::pin(async { Ok(None) })
        }

        fn consume<'a>(
            &'a self,
            _key: &'a str,
        ) -> crate::continuation_store::ContinuationFuture<'a, bool> {
            Box::pin(async {
                Err(ContinuationStoreError::Unavailable {
                    details: "the shared tier did not answer the spend".into(),
                })
            })
        }
    }

    /// The fourth outcome is carried, not collapsed into one of the other three.
    ///
    /// Nothing downstream can find out whether the entry was consumed. Reporting
    /// `AlreadyAnswered` would tell the caller its approval was spent by someone; reporting
    /// `Retired` would claim this call spent it; reporting `NotInvolved` would say nothing
    /// was ever at stake. All three are statements the proxy cannot make here, and each
    /// gives a person's approval a fate the deployment did not observe.
    #[tokio::test]
    async fn a_tier_that_does_not_answer_the_spend_is_its_own_outcome() {
        let plane = ContinuationPlane::wired(Arc::new(UnansweringStore), 300);
        assert_eq!(
            plane.retire(Some(&"k-1".to_owned())).await,
            Retirement::Indeterminate
        );
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

        let established = ContinuationPlane::disabled()
            .prepare(&ex, "aud")
            .await
            .expect("a disabled plane reads nothing and refuses nothing");
        let prep = crate::exchange_state::ExchangeProgress::new().establish(established);

        let carried = continuation_key("aud", &verified.resolved_actor().actor_id(), b"s-1");
        let asserted = continuation_key(
            "aud",
            "client:example.com:did:example:impostor:key-9",
            b"s-1",
        );
        assert_ne!(carried, asserted, "the two identities must differ at all");
        assert_eq!(prep.answer_key(), Some(&carried));
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
