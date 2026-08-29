// SPDX-License-Identifier: Apache-2.0
//! Everything that must be true before this exchange is allowed to become irreversible,
//! and the two things it spends getting there.
//!
//! The region opens with two free checks — the continuation is READ without being spent,
//! and replay admission decides whether this exact request has been seen — and closes
//! having spent a nonce and, where one is involved, a human's approval. Between them sits
//! ANSWERABLE, which is free and belongs there for that reason: a deployment that cannot
//! sign a reply must find that out while refusing still costs the client nothing.
//!
//! The one fact the region produces is the [`SigningWindow`]. It is snapshotted here, put
//! on the exchange here, and read by every refusal below — so a signer retired mid-exchange
//! cannot turn a signed statement about a possibly-executed backend into an unsigned error.

use mcp_re_core::McpReError;

use crate::async_serve::ServedHttpResponse;
use crate::exchange_state::ContinuationState;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::http_profile_dispatch::dispatch_request_with_async_tier;
use crate::refusal::Refusal;

use super::continuation::Retirement;
use super::signing_window::SigningWindow;
use super::Exchange;
use super::HttpProfileProxy;
use mcp_re_http_profile::RetainedContinuation;

impl HttpProfileProxy {
    /// REPLAY-ADMITTED — async §4 replay admission plus the continuation binding.
    ///
    /// ```text
    /// ensures   Ok  => this exact request has never been admitted before, and any
    ///                  continuation it carries binds to the retained bases
    ///           Err => 409, bound
    /// forbids   running the backend
    /// refusal   free — the nonce is burned strictly last
    /// ```
    async fn replay_admission_stage(
        &self,
        ex: &Exchange<'_>,
        continuation: Option<RetainedContinuation<'_>>,
    ) -> Result<Established<()>, Refusal> {
        // The outcome value is not consulted: admission is the property, and a stage that
        // read the outcome to decide something would be making a second decision the
        // pipeline does not have a state for.
        dispatch_request_with_async_tier(
            ex.verified,
            &self.replay_async,
            continuation,
            &self.dispatch_cfg,
            ex.now,
        )
        .await
        .map(|_| Established::new((), ExchangeEvent::ReplayAdmitted))
        .map_err(|e| Refusal::before_admission(e, 409))
    }

    /// ANSWERABLE — can this request be answered AT ALL?
    ///
    /// ```text
    /// ensures   Ok  => a delegated key exists, so a reply can be signed later
    ///           Err => 503, bound
    /// forbids   retiring a continuation, running the backend
    /// refusal   free — and this is the whole point of asking here
    /// ```
    ///
    /// Asked BEFORE the two irreversible steps. Discovering a missing key only at signing
    /// time meant the tool call had already executed and the client got a 503 — a
    /// transient-looking status it retries, so the action runs twice.
    fn answerable_stage(&self, ex: &Exchange<'_>) -> Result<Established<SigningWindow>, Refusal> {
        // The snapshot is taken ONCE and signs the reply below: `now` is fixed for the
        // whole request, so a key valid here is valid there. The window it opens is what
        // the reply may advertise — this stage does not compute that, the window is it.
        match self.responses.window(ex.now) {
            Some(window) => Ok(Established::new(
                window,
                ExchangeEvent::DelegatedKeySnapshotted,
            )),
            None => Err(Refusal::before_admission(
                McpReError::DelegatedSigningUnavailable,
                503,
            )),
        }
    }

    /// What the correlation store's answer to the one-shot take MEANS for this exchange.
    ///
    /// Three of the four outcomes are statements the client needs: nothing was involved, the
    /// approval is now spent, or the key was already answered. The fourth is this
    /// deployment's own fault and says so — the `DEL` may have executed with its reply lost,
    /// so the approval is recorded as spent BEFORE the refusal is signed.
    fn observe_retirement(
        &self,
        ex: &Exchange<'_>,
        progress: &mut ExchangeProgress,
        retirement: Retirement,
    ) -> Result<(), ServedHttpResponse> {
        match retirement {
            Retirement::NotInvolved => Ok(()),
            // The human's approval is now spent. Every refusal from here to the dispatch
            // must say so: the action did not run, but an ordinary retry cannot make it run
            // either.
            Retirement::Retired => {
                progress.observe_continuation(ContinuationState::Consumed);
                Ok(())
            }
            // The store answered: there was nothing live under this key. A replayed or
            // spliced continuation, and a statement about the caller.
            Retirement::AlreadyAnswered => Err(self.refuse(
                ex,
                Refusal::before_admission(McpReError::ContinuationBindingFailed, 409),
                progress,
            )),
            // The store did not answer, so the `DEL` may have executed with its reply lost.
            // A new elicitation is the correct remedy whether or not the entry survived,
            // whereas the ordinary retry the alternative implies passes replay admission on
            // a fresh nonce and then fails as already-answered, with nothing left to answer.
            // The refusal names the shared tier rather than the caller's continuation,
            // because the fault is this deployment's.
            Retirement::Indeterminate => {
                progress.observe_continuation(ContinuationState::Consumed);
                Err(self.refuse(
                    ex,
                    Refusal::before_admission(McpReError::ReplayCacheUnavailable, 503),
                    progress,
                ))
            }
        }
    }

    /// Take the exchange from *verified and permitted* to *answerable and committed*.
    ///
    /// The continuation is read with a `peek`, so a refusal between the read and the
    /// retirement is still an ordinary retry — which is the whole reason the read is not a
    /// `consume`. The retirement is last, and the [`SigningWindow`] it hands back is put on
    /// the exchange before it happens, so the refusal that a failed retirement produces is
    /// signed under the key the reply itself would have used.
    pub(super) async fn commit_to_answering(
        &self,
        ex: &mut Exchange<'_>,
        progress: &mut ExchangeProgress,
    ) -> Result<SigningWindow, ServedHttpResponse> {
        let prep = match self
            .continuations
            .prepare(ex, self.requests.audience_id())
            .await
        {
            Ok(prep) => progress.establish(prep),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        if prep.was_peeked() {
            progress.observe_continuation(ContinuationState::Peeked);
        }
        match self.replay_admission_stage(ex, prep.binding()).await {
            Ok(admitted) => progress.establish(admitted),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        }
        let window = match self.answerable_stage(ex) {
            Ok(established) => progress.establish(established),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        // Carried on the exchange so every refusal below signs with the key the reply
        // itself would have used, rather than re-asking a signer that may have been
        // retired in between and degrading to an unsigned error.
        ex.key = Some(window.shared());
        let retirement = self.continuations.retire(prep.answer_key()).await;
        self.observe_retirement(ex, progress, retirement)?;
        progress.advance(ExchangeEvent::ContinuationRetired);
        Ok(window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NotInvolved` and `Retired` are the two outcomes that let the exchange continue, and
    /// only one of them spends anything. A reading that collapsed them would make every
    /// continuation-free request claim an approval had been consumed.
    #[test]
    fn only_a_real_retirement_spends_an_approval() {
        let mut untouched = ExchangeProgress::new();
        let mut spent = ExchangeProgress::new();
        untouched.observe_continuation(ContinuationState::Peeked);
        spent.observe_continuation(ContinuationState::Consumed);
        assert_ne!(untouched.retry_semantics(), spent.retry_semantics());
    }
}
