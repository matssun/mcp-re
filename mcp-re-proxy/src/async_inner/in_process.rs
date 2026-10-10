// SPDX-License-Identifier: Apache-2.0
//! An in-process inner whose completion bound is stated by its embedder.
//!
//! The completion bound of an in-process inner is a claim only the code that wrote the
//! closure can make, so it is stated at construction and never assumed. The closure
//! itself is served by the blanket `Fn(&[u8]) -> Vec<u8>` implementation, which states no
//! bound; this type adds that one fact and nothing else.
//!
//! `pub` because integration-test crates link the library, and the blanket implementation
//! it narrows is already `pub`.

use super::AsyncInnerServer;
use super::DispatchCompletionBound;
use super::NotAdmitted;
use super::PreparedInnerDispatch;

/// A closure inner plane together with the completion bound its embedder states for it.
pub struct InProcessInner<F> {
    reply: F,
    bound: DispatchCompletionBound,
}

impl<F> InProcessInner<F> {
    /// Wrap `reply`, stating `bound` as the completion bound of every dispatch.
    pub fn new(reply: F, bound: DispatchCompletionBound) -> Self {
        Self { reply, bound }
    }
}

impl<F> AsyncInnerServer for InProcessInner<F>
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync,
{
    fn prepare<'a>(&'a self, request: &[u8]) -> Result<PreparedInnerDispatch<'a>, NotAdmitted> {
        let prepared = self.reply.prepare(request)?;
        Ok(PreparedInnerDispatch::over(
            move || prepared.dispatch(),
            self.bound,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::DispatchedOutcome;
    use super::*;
    use std::time::Duration;

    /// The bound the embedder gave is the bound the prepared dispatch carries, and the
    /// closure's reply still comes back as a backend reply.
    #[tokio::test]
    async fn an_in_process_inner_states_the_bound_its_embedder_gave() {
        let bound = DispatchCompletionBound::Within(Duration::from_secs(7));
        let inner = InProcessInner::new(|_: &[u8]| b"{}".to_vec(), bound);
        let prepared = inner.prepare(b"{}").expect("an in-process inner prepares");
        assert_eq!(prepared.completion_bound(), bound);
        assert_eq!(
            prepared.dispatch().await,
            DispatchedOutcome::Replied(b"{}".to_vec())
        );
    }
}
