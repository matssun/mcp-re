// SPDX-License-Identifier: Apache-2.0
//! CONTINUATION-RETIRED: spending a human's approval, exactly once (ADR-MCPS-047).
//!
//! Separate from the answer leg's read because it is the other authority in the same
//! sentence. The read decides what this leg may PROCEED on and how an absence is
//! attributed; this decides what the deployment may SAY happened to a person's approval,
//! and the two are independently describable: the read's outcomes are a binding or a
//! refusal, and this one's are four facts about a decision somebody made.
//!
//! Everything here is past the free region. `peek` has no side effect, so every refusal
//! above leaves a live approval intact; `consume` is the spend, and after it there is
//! nothing to be careful about preserving — only something to report honestly.
//!
//! # It reports, and does not decide
//!
//! The refusal for a non-proceeding outcome needs the exchange machine's cross-machine
//! state, which no stage holds. So this states what the tier reported and the assembly —
//! which holds the continuation machine — decides both the refusal and what the exchange
//! may claim. A stage that refused here would be stating a retry contract it cannot know.

use super::ContinuationPlane;

impl ContinuationPlane {
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
    ///
    /// A store-less deployment answering nothing is [`Retirement::NotInvolved`]; a
    /// store-less deployment answering SOMETHING never arrives, because `prepare` refused
    /// it.
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
    /// No approval was involved in this retirement path: this request answers nothing.
    ///
    /// It does NOT cover a deployment that holds no capability while the request needs one
    /// — [`ContinuationPlane::prepare`] refuses that leg before the retirement is reached,
    /// so the combination cannot arrive here. Narrow on purpose: the old wording named two
    /// facts, and the second of them is now a refusal rather than a retirement outcome.
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
mod tests {
    use super::*;
    use crate::continuation_store::AsyncContinuationStore;
    use crate::continuation_store::ContinuationStoreError;
    use crate::continuation_store::RetainedBases;
    use crate::continuation_store::continuation_key;
    use std::sync::Arc;

    #[tokio::test]
    async fn a_request_that_answers_nothing_retires_nothing() {
        // `NotInvolved` is not "the retirement failed". No approval was ever at stake, so
        // the exchange may claim nothing was spent — which is what the assembly records.
        //
        // The narrow reading, and it is narrow because `prepare` now refuses the case the
        // old wording also covered: a deployment holding no capability while the request
        // needs one never reaches a retirement at all.
        assert_eq!(
            ContinuationPlane::disabled().retire(None).await,
            Retirement::NotInvolved
        );
        assert_eq!(
            ContinuationPlane::wired(Arc::new(UnansweringStore), 300)
                .retire(None)
                .await,
            Retirement::NotInvolved,
            "a wired plane answering nothing has nothing at stake either"
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
}
